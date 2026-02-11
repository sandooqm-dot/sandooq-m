// functions/api2/activate.js
// POST /api2/activate
// v3: Root-cause mode (returns the real DB error inside error text)
// + Smart-detect codes table by scanning tables/columns.

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
  "Access-Control-Max-Age": "86400",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS,
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

export async function onRequestOptions() {
  return new Response(null, { headers: CORS_HEADERS });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeCode(code) {
  return String(code || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "")
    .replace(/[–—−]/g, "-");
}

function parseCookies(cookieHeader) {
  const out = {};
  const s = String(cookieHeader || "");
  s.split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i === -1) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function bearerToken(req) {
  const h = req.headers.get("authorization") || req.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

function nowIso() {
  return new Date().toISOString();
}

async function dbAll(DB, label, sql, binds = []) {
  try {
    return await DB.prepare(sql).bind(...binds).all();
  } catch (e) {
    throw new Error(`${label}: ${String(e?.message || e)}`);
  }
}

async function dbFirst(DB, label, sql, binds = []) {
  try {
    return await DB.prepare(sql).bind(...binds).first();
  } catch (e) {
    throw new Error(`${label}: ${String(e?.message || e)}`);
  }
}

async function dbRun(DB, label, sql, binds = []) {
  try {
    return await DB.prepare(sql).bind(...binds).run();
  } catch (e) {
    throw new Error(`${label}: ${String(e?.message || e)}`);
  }
}

async function tableInfo(DB, tableName) {
  const r = await dbAll(DB, `PRAGMA table_info(${tableName})`, `PRAGMA table_info(${tableName});`);
  return (r?.results || []).map((x) => String(x.name));
}

async function ensureActivationsTable(DB) {
  await dbRun(
    DB,
    "ensureActivationsTable:CREATE",
    `
    CREATE TABLE IF NOT EXISTS activations (
      code TEXT NOT NULL,
      email TEXT,
      device_id TEXT NOT NULL,
      created_at TEXT,
      PRIMARY KEY (code, device_id)
    );
  `
  );

  // add missing columns if table is old
  const cols = await tableInfo(DB, "activations");

  if (!cols.includes("email")) {
    try { await dbRun(DB, "ensureActivationsTable:ADD email", `ALTER TABLE activations ADD COLUMN email TEXT;`); } catch {}
  }
  if (!cols.includes("created_at")) {
    try { await dbRun(DB, "ensureActivationsTable:ADD created_at", `ALTER TABLE activations ADD COLUMN created_at TEXT;`); } catch {}
  }
  if (!cols.includes("device_id")) {
    try { await dbRun(DB, "ensureActivationsTable:ADD device_id", `ALTER TABLE activations ADD COLUMN device_id TEXT;`); } catch {}
  }
  if (!cols.includes("code")) {
    try { await dbRun(DB, "ensureActivationsTable:ADD code", `ALTER TABLE activations ADD COLUMN code TEXT;`); } catch {}
  }
}

async function getSessionEmail(DB, req) {
  let token = bearerToken(req);

  if (!token) {
    const cookies = parseCookies(req.headers.get("Cookie") || "");
    token =
      cookies["sandooq_session_v1"] ||
      cookies["sandooq_session"] ||
      cookies["sandooq_token_v1"] ||
      cookies["token"] ||
      "";
  }

  token = String(token || "").trim();
  if (!token) return { ok: false, error: "UNAUTHORIZED" };

  // sessions قد يكون email أو user_email
  let row = await dbFirst(DB, "getSessionEmail:sessions(email)", `SELECT email FROM sessions WHERE token = ? LIMIT 1`, [token]);
  let email = normalizeEmail(row?.email);

  if (!email) {
    row = await dbFirst(DB, "getSessionEmail:sessions(user_email)", `SELECT user_email FROM sessions WHERE token = ? LIMIT 1`, [token]);
    email = normalizeEmail(row?.user_email);
  }

  if (!email) return { ok: false, error: "SESSION_NOT_FOUND" };
  return { ok: true, email, token };
}

function pickFirst(cols, names) {
  for (const n of names) if (cols.includes(n)) return n;
  return null;
}

async function listTables(DB) {
  const r = await dbAll(
    DB,
    "listTables",
    `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;`
  );
  return (r?.results || []).map((x) => String(x.name));
}

async function detectCodesTable(DB) {
  const tables = await listTables(DB);
  const codeColCandidates = ["code", "activation_code", "license", "key"];

  let best = null;

  for (const t of tables) {
    // تجاهل جداول النظام
    if (t === "sessions" || t === "users" || t === "pending_users" || t === "activations") continue;

    let cols = [];
    try { cols = await tableInfo(DB, t); } catch { continue; }

    const codeCol = pickFirst(cols, codeColCandidates);
    if (!codeCol) continue;

    // score
    const ownerCol = pickFirst(cols, ["used_by_email", "bound_email", "owner_email", "used_email", "email"]);
    const isUsedCol = pickFirst(cols, ["is_used", "used", "activated", "is_activated"]);
    const usedAtCol = pickFirst(cols, ["used_at", "activated_at"]);
    const statusCol = pickFirst(cols, ["status"]);
    const limitCol = pickFirst(cols, ["device_limit", "max_devices", "devices_limit"]);

    let score = 10;
    if (ownerCol) score += 5;
    if (isUsedCol) score += 3;
    if (usedAtCol) score += 2;
    if (statusCol) score += 2;
    if (limitCol) score += 1;

    if (!best || score > best.score) {
      best = { table: t, cols, codeCol, ownerCol, isUsedCol, usedAtCol, statusCol, limitCol, score };
    }
  }

  return { best, tables };
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    if (!env.DB) return json({ ok: false, error: "DB_NOT_BOUND" }, 500);

    const deviceId = String(request.headers.get("X-Device-Id") || "").trim();
    if (!deviceId) return json({ ok: false, error: "MISSING_DEVICE_ID" }, 400);

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON" }, 400);

    const code = normalizeCode(body.code);
    if (!code) return json({ ok: false, error: "MISSING_FIELDS" }, 400);

    // auth -> email
    const ses = await getSessionEmail(env.DB, request);
    if (!ses.ok) return json({ ok: false, error: ses.error }, 401);
    const email = ses.email;

    // ensure activations
    await ensureActivationsTable(env.DB);

    // detect codes table
    const { best, tables } = await detectCodesTable(env.DB);
    if (!best) {
      return json(
        { ok: false, error: `CODES_TABLE_NOT_FOUND|tables=${tables.join(",")}` },
        500
      );
    }

    const {
      table: codesTable,
      codeCol,
      ownerCol,
      isUsedCol,
      usedAtCol,
      statusCol,
      limitCol,
    } = best;

    // load code row
    const codeRow = await dbFirst(
      env.DB,
      "loadCodeRow",
      `SELECT * FROM ${codesTable} WHERE ${codeCol} = ? LIMIT 1`,
      [code]
    );

    if (!codeRow) return json({ ok: false, error: "CODE_NOT_FOUND" }, 404);

    const boundEmail = ownerCol ? normalizeEmail(codeRow[ownerCol]) : "";

    // used by another account
    if (boundEmail && boundEmail !== email) {
      return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    // used flags
    if (!boundEmail && isUsedCol && Number(codeRow[isUsedCol] || 0) === 1) {
      return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
    }
    if (!boundEmail && statusCol && String(codeRow[statusCol] || "").toLowerCase() === "used") {
      return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    // device limit
    let limit = 2;
    if (limitCol) {
      const v = Number(codeRow[limitCol]);
      if (Number.isFinite(v) && v >= 1) limit = v;
    }

    // already on same device?
    const existing = await dbFirst(
      env.DB,
      "checkExistingActivation",
      `SELECT device_id FROM activations WHERE code = ? AND device_id = ? LIMIT 1`,
      [code, deviceId]
    );

    if (!existing) {
      const cntRow = await dbFirst(
        env.DB,
        "countActivations",
        `SELECT COUNT(*) AS n FROM activations WHERE code = ? AND email = ?`,
        [code, email]
      );

      const n = Number(cntRow?.n || 0);
      if (n >= limit) return json({ ok: false, error: "DEVICE_LIMIT_REACHED" }, 409);

      await dbRun(
        env.DB,
        "insertActivation",
        `INSERT INTO activations (code, email, device_id, created_at) VALUES (?, ?, ?, ?)`,
        [code, email, deviceId, nowIso()]
      );
    }

    // bind to email first time
    if (ownerCol && !boundEmail) {
      const sets = [];
      const binds = [];

      sets.push(`${ownerCol} = ?`);
      binds.push(email);

      if (isUsedCol) sets.push(`${isUsedCol} = 1`);
      if (usedAtCol) {
        sets.push(`${usedAtCol} = ?`);
        binds.push(Date.now());
      }
      if (statusCol) {
        sets.push(`${statusCol} = ?`);
        binds.push("used");
      }

      await dbRun(
        env.DB,
        "bindCodeToEmail",
        `UPDATE ${codesTable} SET ${sets.join(", ")} WHERE ${codeCol} = ?`,
        [...binds, code]
      );
    }

    return json({ ok: true, activated: true, email, code, deviceId }, 200);
  } catch (e) {
    // ✅ هنا الجذر: نُرجع سبب السقوط فعليًا داخل error
    const msg = String(e?.message || e || "unknown");
    return json({ ok: false, error: `SERVER_ERROR|${msg}` }, 500);
  }
}

/*
activate.js – api2 – v3
- returns real error inside SERVER_ERROR|...
- smart-detect codes table
*/
