// functions/api2/activate.js
// POST /api2/activate
// v5: safer + prefers `codes` table + atomic bind-to-email + default device limit = 1

const VERSION = "api2-activate-v5-atomic";

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin") || req.headers.get("Origin");
  const h = {
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "cache-control": "no-store",
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
    h["Vary"] = "Origin";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

function json(req, data, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    ...CORS_HEADERS(req),
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });

  for (const [k, v] of Object.entries(extraHeaders || {})) {
    if (Array.isArray(v)) for (const vv of v) headers.append(k, vv);
    else if (v !== undefined && v !== null && v !== "") headers.set(k, String(v));
  }

  return new Response(JSON.stringify({ ...data, version: VERSION }), { status, headers });
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
    if (k) {
      try { out[k] = decodeURIComponent(v); } catch { out[k] = v; }
    }
  });
  return out;
}

function bearerToken(req) {
  const h = req.headers.get("authorization") || req.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

function safeIdent(name) {
  const s = String(name || "");
  if (!/^[A-Za-z0-9_]+$/.test(s)) return null;
  return s;
}

async function dbAll(DB, sql, binds = []) {
  return await DB.prepare(sql).bind(...binds).all();
}
async function dbFirst(DB, sql, binds = []) {
  return await DB.prepare(sql).bind(...binds).first();
}
async function dbRun(DB, sql, binds = []) {
  return await DB.prepare(sql).bind(...binds).run();
}

async function tableInfo(DB, tableName) {
  const t = safeIdent(tableName);
  if (!t) return [];
  const r = await dbAll(DB, `PRAGMA table_info(${t});`);
  return (r?.results || []).map((x) => ({
    name: String(x.name),
    type: String(x.type || ""),
    notnull: Number(x.notnull || 0),
    dflt: x.dflt_value,
  }));
}

function hasCol(cols, name) {
  return cols.includes(name);
}

function nowValueFor(type) {
  const t = String(type || "").toUpperCase();
  // INT -> نخزن ms، غيره -> ISO
  if (t.includes("INT")) return Date.now();
  return new Date().toISOString();
}

async function ensureActivationsTable(DB) {
  // جدول موحّد نستخدمه (وإذا كان موجود لا يغيّر شيء)
  await dbRun(
    DB,
    `
    CREATE TABLE IF NOT EXISTS activations (
      code TEXT NOT NULL,
      email TEXT,
      device_id TEXT NOT NULL,
      activated_at INTEGER NOT NULL,
      created_at INTEGER,
      PRIMARY KEY (code, device_id)
    );
    `
  );

  // نحاول نضيف أعمدة ناقصة لو نسخة قديمة (بدون كسر)
  const info = await tableInfo(DB, "activations");
  const cols = new Set(info.map((x) => x.name));

  async function addCol(sql) { try { await dbRun(DB, sql); } catch {} }

  if (!cols.has("code")) await addCol(`ALTER TABLE activations ADD COLUMN code TEXT;`);
  if (!cols.has("email")) await addCol(`ALTER TABLE activations ADD COLUMN email TEXT;`);
  if (!cols.has("device_id")) await addCol(`ALTER TABLE activations ADD COLUMN device_id TEXT;`);
  if (!cols.has("activated_at")) await addCol(`ALTER TABLE activations ADD COLUMN activated_at INTEGER;`);
  if (!cols.has("created_at")) await addCol(`ALTER TABLE activations ADD COLUMN created_at INTEGER;`);
}

async function getSessionEmail(DB, req) {
  // token من: Bearer ثم Cookie الجديد ثم القديم
  let token = bearerToken(req);
  if (!token) {
    const cookies = parseCookies(req.headers.get("Cookie") || req.headers.get("cookie") || "");
    token =
      cookies["sandooq_token_v1"] ||
      cookies["sandooq_session_v1"] ||
      cookies["sandooq_session"] ||
      cookies["token"] ||
      "";
  }

  token = String(token || "").trim();
  if (!token) return { ok: false, error: "UNAUTHORIZED" };

  // sessions: email أو user_email
  let row = await dbFirst(DB, `SELECT email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`, [token]);
  let email = normalizeEmail(row?.email);

  if (!email) {
    row = await dbFirst(DB, `SELECT user_email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`, [token]);
    email = normalizeEmail(row?.user_email);
  }

  if (!email) return { ok: false, error: "SESSION_NOT_FOUND" };
  return { ok: true, email, token };
}

async function listTables(DB) {
  const r = await dbAll(
    DB,
    `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;`
  );
  return (r?.results || []).map((x) => String(x.name));
}

function pickFirst(cols, names) {
  for (const n of names) if (cols.includes(n)) return n;
  return null;
}

async function detectCodesTable(DB) {
  const tables = await listTables(DB);

  // ✅ الأفضلية المطلقة: codes
  if (tables.includes("codes")) {
    const info = await tableInfo(DB, "codes");
    const cols = info.map((x) => x.name);
    const codeCol = pickFirst(cols, ["code", "activation_code", "license", "key"]);
    if (codeCol) {
      return {
        table: "codes",
        cols,
        codeCol,
        ownerCol: pickFirst(cols, ["used_by_email", "bound_email", "owner_email", "used_email", "email", "user_email"]),
        usedAtCol: pickFirst(cols, ["used_at", "activated_at"]),
        isUsedCol: pickFirst(cols, ["is_used", "used", "activated", "is_activated"]),
        statusCol: pickFirst(cols, ["status"]),
        limitCol: pickFirst(cols, ["device_limit", "max_devices", "devices_limit"]),
        tables,
      };
    }
  }

  // fallback: scan (مع أمان اسماء الجداول)
  const codeColCandidates = ["code", "activation_code", "license", "key"];

  let best = null;

  for (const t of tables) {
    if (!safeIdent(t)) continue;
    if (t === "sessions" || t === "users" || t === "pending_users" || t === "activations") continue;

    let info = [];
    try { info = await tableInfo(DB, t); } catch { continue; }
    const cols = info.map((x) => x.name);

    const codeCol = pickFirst(cols, codeColCandidates);
    if (!codeCol) continue;

    const ownerCol = pickFirst(cols, ["used_by_email", "bound_email", "owner_email", "used_email", "email", "user_email"]);
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

  return { ...(best || {}), tables };
}

async function insertActivation(DB, { code, email, deviceId }) {
  const info = await tableInfo(DB, "activations");
  const cols = info.map((x) => x.name);
  const meta = Object.fromEntries(info.map((x) => [x.name, x]));

  // نحاول Insert OR IGNORE
  const fields = [];
  const binds = [];
  const add = (k, v) => {
    if (!cols.includes(k)) return;
    fields.push(k);
    binds.push(v);
  };

  add("code", code);
  add("email", email);
  add("device_id", deviceId);

  if (cols.includes("activated_at")) add("activated_at", nowValueFor(meta["activated_at"]?.type));
  if (cols.includes("created_at")) add("created_at", nowValueFor(meta["created_at"]?.type));

  // لو فيه NOT NULL بدون default وما انضافت -> نعبيها تلقائياً لو نقدر
  for (const c of info) {
    if (!c.notnull) continue;
    if (c.dflt != null) continue;
    if (fields.includes(c.name)) continue;

    const n = c.name.toLowerCase();
    if (n.endsWith("_at")) { add(c.name, nowValueFor(c.type)); continue; }
    if (n === "activated" || n === "is_activated" || n === "used" || n === "is_used") { add(c.name, 1); continue; }
    if (n === "status") { add(c.name, "used"); continue; }

    // ما نقدر نخمن
    throw new Error(`REQUIRED_COL_MISSING:${c.name}`);
  }

  const placeholders = fields.map(() => "?").join(",");
  const sql = `INSERT OR IGNORE INTO activations (${fields.join(",")}) VALUES (${placeholders})`;
  await dbRun(DB, sql, binds);
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS(request) });
  }
  if (request.method !== "POST") {
    return json(request, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env?.DB) return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);

    const deviceId = String(request.headers.get("X-Device-Id") || "").trim();
    if (!deviceId) return json(request, { ok: false, error: "MISSING_DEVICE_ID" }, 400);

    const body = await request.json().catch(() => null);
    if (!body) return json(request, { ok: false, error: "BAD_JSON" }, 400);

    const code = normalizeCode(body.code);
    if (!code) return json(request, { ok: false, error: "MISSING_FIELDS" }, 400);

    const ses = await getSessionEmail(env.DB, request);
    if (!ses.ok) return json(request, { ok: false, error: ses.error }, 401);
    const email = ses.email;

    await ensureActivationsTable(env.DB);

    const detected = await detectCodesTable(env.DB);
    if (!detected?.table) {
      return json(request, { ok: false, error: `CODES_TABLE_NOT_FOUND|tables=${(detected?.tables || []).join(",")}` }, 500);
    }

    const codesTable = safeIdent(detected.table);
    const codeCol = safeIdent(detected.codeCol);
    const ownerCol = detected.ownerCol ? safeIdent(detected.ownerCol) : null;
    const usedAtCol = detected.usedAtCol ? safeIdent(detected.usedAtCol) : null;
    const isUsedCol = detected.isUsedCol ? safeIdent(detected.isUsedCol) : null;
    const statusCol = detected.statusCol ? safeIdent(detected.statusCol) : null;
    const limitCol = detected.limitCol ? safeIdent(detected.limitCol) : null;

    if (!codesTable || !codeCol) {
      return json(request, { ok: false, error: "CODES_TABLE_BAD_SCHEMA" }, 500);
    }

    const codeRow = await dbFirst(
      env.DB,
      `SELECT * FROM ${codesTable} WHERE ${codeCol} = ? LIMIT 1`,
      [code]
    );

    if (!codeRow) return json(request, { ok: false, error: "CODE_NOT_FOUND" }, 404);

    // ✅ حد الأجهزة: الافتراضي = 1 (أقوى حماية)
    let limit = 1;
    if (limitCol) {
      const v = Number(codeRow[limitCol]);
      if (Number.isFinite(v) && v >= 1) limit = v;
    }

    // ✅ إذا الكود مرتبط بإيميل غير إيميلك -> مرفوض
    const boundEmail = ownerCol ? normalizeEmail(codeRow[ownerCol]) : "";
    if (boundEmail && boundEmail !== email) {
      return json(request, { ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    // احتياط: لو عنده أعمدة used/status
    if (!boundEmail && isUsedCol && Number(codeRow[isUsedCol] || 0) === 1) {
      return json(request, { ok: false, error: "CODE_ALREADY_USED" }, 409);
    }
    if (!boundEmail && statusCol && String(codeRow[statusCol] || "").toLowerCase() === "used") {
      return json(request, { ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    // ✅ لو نفس الجهاز مفعل مسبقًا -> نجاح مباشر
    const alreadyOnThisDevice = await dbFirst(
      env.DB,
      `SELECT 1 AS ok FROM activations WHERE code = ? AND device_id = ? LIMIT 1`,
      [code, deviceId]
    );
    if (alreadyOnThisDevice) {
      return json(request, { ok: true, activated: true, already: true, email, code, deviceId }, 200);
    }

    // ✅ تحقق عدد الأجهزة المفعلة لنفس الإيميل والكود
    const cntRow = await dbFirst(
      env.DB,
      `SELECT COUNT(DISTINCT device_id) AS n FROM activations WHERE code = ? AND (email = ? OR email IS NULL)`,
      [code, email]
    );
    const n = Number(cntRow?.n || 0);
    if (n >= limit) return json(request, { ok: false, error: "DEVICE_LIMIT_REACHED", limit }, 409);

    // ✅ سجّل التفعيل للجهاز
    await insertActivation(env.DB, { code, email, deviceId });

    // ✅ اربط الكود بالإيميل “مرة واحدة” وبشكل ذري (atomic)
    // إذا ownerCol موجود والكود ما كان مربوط قبل
    if (ownerCol && !boundEmail) {
      const sets = [];
      const binds = [];

      sets.push(`${ownerCol} = ?`); binds.push(email);

      if (isUsedCol) sets.push(`${isUsedCol} = 1`);

      if (usedAtCol) { sets.push(`${usedAtCol} = ?`); binds.push(Date.now()); }

      if (statusCol) { sets.push(`${statusCol} = ?`); binds.push("used"); }

      // شرط مهم: ما نربطه إذا انربط بالفعل (حتى لو صارت سباق طلبين)
      const whereExtra = `(${ownerCol} IS NULL OR ${ownerCol} = '')`;

      const res = await dbRun(
        env.DB,
        `UPDATE ${codesTable} SET ${sets.join(", ")} WHERE ${codeCol} = ? AND ${whereExtra}`,
        [...binds, code]
      );

      // لو ما تغيّر شيء، معناها في نفس اللحظة انربط (أو صار مستخدم) → نعيد تحقق سريع
      if ((res?.meta?.changes || 0) === 0) {
        const re = await dbFirst(env.DB, `SELECT ${ownerCol} AS owner FROM ${codesTable} WHERE ${codeCol} = ? LIMIT 1`, [code]);
        const ownerNow = normalizeEmail(re?.owner);
        if (ownerNow && ownerNow !== email) {
          return json(request, { ok: false, error: "CODE_ALREADY_USED" }, 409);
        }
      }
    }

    return json(request, { ok: true, activated: true, email, code, deviceId, limit }, 200);

  } catch (e) {
    const msg = String(e?.message || e || "unknown");
    return json(request, { ok: false, error: `SERVER_ERROR|${msg}` }, 500);
  }
}

/*
activate.js – api2 – إصدار 5 (atomic bind + default device limit=1 + safer table detection)
*/
