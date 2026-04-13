// functions/api2/consume.js
// v1 - Consume or discard one temporary settings transfer snapshot by (game + email + activation_code)

const VERSION = "settings-transfer-consume-v1";

const SCHEMA_CACHE_TTL_MS = 60_000;
const schemaCache = new Map();

function corsHeaders(req) {
  const origin = req.headers.get("origin") || req.headers.get("Origin") || "";
  const h = {
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store"
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
    h["Vary"] = "Origin";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
}

function json(req, data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders(req),
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders
    }
  });
}

function bad(req, error, status = 400, extra = {}) {
  return json(req, { ok: false, error, ...extra }, status);
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function normalizeCode(v) {
  return String(v || "").trim();
}

function normalizeGame(v) {
  const g = String(v || "").trim().toLowerCase();
  return g || "horof";
}

function normalizeAction(v) {
  const a = String(v || "").trim().toLowerCase();
  return a === "discard" ? "discard" : "consume";
}

function getBearerToken(req) {
  const auth = req.headers.get("authorization") || req.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? String(m[1] || "").trim() : "";
}

function resolveDB(env) {
  return env.DB || env.AUTH_DB || env.HOROF_DB || env.D1 || null;
}

async function getTableColumns(db, tableName) {
  const key = String(tableName || "").trim();
  const now = Date.now();
  const cached = schemaCache.get(key);
  if (cached && (now - cached.ts) < SCHEMA_CACHE_TTL_MS) return cached.cols;

  const rows = await db.prepare(`PRAGMA table_info(${key})`).all();
  const cols = new Set(
    Array.isArray(rows?.results)
      ? rows.results.map((r) => String(r?.name || "").trim()).filter(Boolean)
      : []
  );

  schemaCache.set(key, { ts: now, cols });
  return cols;
}

function pickColumn(cols, candidates) {
  for (const c of candidates) {
    if (cols.has(c)) return c;
  }
  return "";
}

async function ensureTransferTable(db) {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS settings_transfers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      game TEXT NOT NULL,
      email TEXT NOT NULL,
      activation_code TEXT NOT NULL,
      snapshot_json TEXT NOT NULL,
      source_device_id TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(game, email, activation_code)
    );
    CREATE INDEX IF NOT EXISTS idx_settings_transfers_lookup
    ON settings_transfers (game, email, activation_code);
  `);
}

function limitText(v, max = 500) {
  return String(v || "").trim().slice(0, max);
}

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function normalizeQuestionPair(item) {
  const src = item && typeof item === "object" ? item : {};
  return {
    q: limitText(src.q, 500),
    a: limitText(src.a, 220)
  };
}

function normalizeCustomQuestionsMap(raw) {
  const out = {};
  const src = raw && typeof raw === "object" ? raw : {};
  for (const [letter, arr] of Object.entries(src)) {
    const key = String(letter || "").trim();
    if (!key) continue;
    const list = Array.isArray(arr) ? arr : [];
    out[key] = list
      .map(normalizeQuestionPair)
      .filter((x) => x.q && x.a)
      .slice(0, 7);
  }
  return out;
}

function normalizeManualCellRounds(raw) {
  const out = {};
  const src = raw && typeof raw === "object" ? raw : {};
  for (const [roundKey, cfg] of Object.entries(src)) {
    const roundNum = safeNumber(roundKey, 0);
    if (roundNum < 1 || roundNum > 5) continue;

    const item = cfg && typeof cfg === "object" ? cfg : {};
    const cellCount = [4, 5, 6].includes(Number(item.cellCount)) ? Number(item.cellCount) : 5;
    const maxCells = cellCount * cellCount;
    const values = Array.isArray(item.values) ? item.values : [];

    out[String(roundNum)] = {
      cellCount,
      values: values.map((v) => limitText(v, 40)).slice(0, maxCells)
    };
  }
  return out;
}

function normalizeSnapshot(raw) {
  const src = raw && typeof raw === "object" ? raw : {};
  const hostSettings = src.hostSettings && typeof src.hostSettings === "object" ? src.hostSettings : {};

  return {
    updatedAt: safeNumber(src.updatedAt, Date.now()),
    timerSel: Math.max(1, Math.min(50, safeNumber(src.timerSel, 10) || 10)),
    hostSettings: {
      manualCellRounds: normalizeManualCellRounds(hostSettings.manualCellRounds || {}),
      cellContentMode: String(hostSettings.cellContentMode) === "manual" ? "manual" : "default",
      questionMode: String(hostSettings.questionMode) === "custom" ? "custom" : "default",
      soundEnabled: hostSettings.soundEnabled !== false
    },
    customQuestions: normalizeCustomQuestionsMap(src.customQuestions || {}),
    customQuestionsUpdatedAt: safeNumber(src.customQuestionsUpdatedAt, safeNumber(src.updatedAt, Date.now())),
    sourceDeviceId: limitText(src.sourceDeviceId || src.source_device_id, 120)
  };
}

async function readJsonBody(req) {
  try {
    return await req.json();
  } catch {
    return null;
  }
}

async function validateSessionTokenIfPresent(db, token, email) {
  if (!token) return { ok: true, reason: "no_token" };

  try {
    const cols = await getTableColumns(db, "sessions");
    if (!cols.size) return { ok: true, reason: "no_sessions_table" };

    const tokenCol = pickColumn(cols, ["token", "session_token", "auth_token"]);
    const emailCol = pickColumn(cols, ["email", "user_email"]);
    if (!tokenCol || !emailCol) return { ok: true, reason: "sessions_schema_not_supported" };

    const row = await db.prepare(
      `SELECT ${emailCol} AS email FROM sessions WHERE ${tokenCol} = ? LIMIT 1`
    ).bind(token).first();

    if (!row) return { ok: false, error: "INVALID_SESSION" };
    if (normalizeEmail(row.email) !== normalizeEmail(email)) {
      return { ok: false, error: "EMAIL_TOKEN_MISMATCH" };
    }

    return { ok: true, reason: "token_valid" };
  } catch {
    return { ok: true, reason: "token_check_skipped" };
  }
}

async function lookupBoundCodeRecord(db, game, email, activationCode) {
  const tableCandidates = ["codes", "activations", "licenses"];
  const codeCandidates = ["code", "activation_code", "license_code"];
  const emailCandidates = ["used_by_email", "email", "bound_email", "owner_email", "activated_email"];
  const gameCandidates = ["game", "game_key", "product_key", "product", "app"];

  for (const table of tableCandidates) {
    let cols;
    try {
      cols = await getTableColumns(db, table);
    } catch {
      cols = new Set();
    }
    if (!cols || !cols.size) continue;

    const codeCol = pickColumn(cols, codeCandidates);
    const emailCol = pickColumn(cols, emailCandidates);
    const gameCol = pickColumn(cols, gameCandidates);

    if (!codeCol || !emailCol) continue;

    let sql = `SELECT * FROM ${table} WHERE ${codeCol} = ? AND lower(trim(${emailCol})) = ?`;
    const binds = [activationCode, email];

    if (gameCol) {
      sql += ` AND lower(trim(${gameCol})) = ?`;
      binds.push(game);
    }

    sql += ` LIMIT 1`;

    const row = await db.prepare(sql).bind(...binds).first();
    if (row) return row;
  }

  return null;
}

async function verifyOwnership(db, req, game, email, activationCode) {
  if (!email) return { ok: false, error: "MISSING_EMAIL", status: 400 };
  if (!activationCode) return { ok: false, error: "MISSING_ACTIVATION_CODE", status: 400 };

  const token = getBearerToken(req);
  const tokenCheck = await validateSessionTokenIfPresent(db, token, email);
  if (!tokenCheck.ok) {
    return { ok: false, error: tokenCheck.error || "INVALID_SESSION", status: 401 };
  }

  const codeRow = await lookupBoundCodeRecord(db, game, email, activationCode);
  if (!codeRow) {
    return { ok: false, error: "ACCOUNT_OR_CODE_NOT_FOUND", status: 404 };
  }

  return { ok: true, codeRow };
}

function parseStoredSnapshot(row) {
  let parsed = {};
  try {
    parsed = JSON.parse(String(row?.snapshot_json || "{}"));
  } catch {
    parsed = {};
  }
  const snapshot = normalizeSnapshot(parsed);
  if (!snapshot.sourceDeviceId && row?.source_device_id) {
    snapshot.sourceDeviceId = String(row.source_device_id || "").trim();
  }
  return snapshot;
}

async function consumeOrDiscardTransfer(db, game, email, activationCode) {
  try {
    const row = await db.prepare(`
      DELETE FROM settings_transfers
      WHERE id IN (
        SELECT id
        FROM settings_transfers
        WHERE game = ? AND email = ? AND activation_code = ?
        LIMIT 1
      )
      RETURNING game, email, activation_code, snapshot_json, source_device_id, created_at, updated_at
    `).bind(game, email, activationCode).first();

    return row || null;
  } catch {
    const existing = await db.prepare(`
      SELECT id, game, email, activation_code, snapshot_json, source_device_id, created_at, updated_at
      FROM settings_transfers
      WHERE game = ? AND email = ? AND activation_code = ?
      LIMIT 1
    `).bind(game, email, activationCode).first();

    if (!existing) return null;

    await db.prepare(`DELETE FROM settings_transfers WHERE id = ?`).bind(existing.id).run();
    delete existing.id;
    return existing;
  }
}

export async function onRequestOptions(context) {
  return new Response(null, { status: 204, headers: corsHeaders(context.request) });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const db = resolveDB(env);
  if (!db) return bad(request, "DB_NOT_CONFIGURED", 500);

  try {
    await ensureTransferTable(db);

    const body = await readJsonBody(request);
    if (!body || typeof body !== "object") {
      return bad(request, "INVALID_JSON_BODY", 400);
    }

    const game = normalizeGame(body.game);
    const email = normalizeEmail(body.email);
    const activationCode = normalizeCode(body.activation_code);
    const action = normalizeAction(body.action);

    const verified = await verifyOwnership(db, request, game, email, activationCode);
    if (!verified.ok) return bad(request, verified.error, verified.status || 400);

    const row = await consumeOrDiscardTransfer(db, game, email, activationCode);
    if (!row) {
      return bad(request, "TRANSFER_NOT_FOUND", 404, {
        consumed: false,
        discarded: false
      });
    }

    if (action === "discard") {
      return json(request, {
        ok: true,
        action: "discard",
        discarded: true,
        consumed: false,
        game,
        email
      });
    }

    return json(request, {
      ok: true,
      action: "consume",
      consumed: true,
      discarded: false,
      game,
      email,
      created_at: row.created_at || null,
      updated_at: row.updated_at || null,
      snapshot: parseStoredSnapshot(row)
    });
  } catch (err) {
    return bad(request, "SERVER_ERROR", 500, {
      version: VERSION,
      details: String(err?.message || err || "")
    });
  }
}
