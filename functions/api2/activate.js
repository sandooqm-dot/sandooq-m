// functions/api2/activate.js
// Cloudflare Pages Function: POST /api2/activate

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin");
  const h = {
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "cache-control": "no-store",
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

function json(req, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS(req),
      "content-type": "application/json; charset=utf-8",
    },
  });
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

function getCookie(req, name) {
  const cookie = req.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (k === name) return rest.join("=") || "";
  }
  return "";
}

function looksLikeEmail(v) {
  const s = String(v || "").trim();
  return s.includes("@") && s.includes(".");
}

async function tableExists(DB, table) {
  try {
    const r = await DB.prepare(
      `SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1`
    ).bind(table).first();
    return !!r?.name;
  } catch {
    return false;
  }
}

async function tableInfo(DB, table) {
  try {
    const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
    const rows = res?.results || [];
    return rows.map((r) => String(r.name));
  } catch {
    return [];
  }
}

async function findSessionEmail(DB, token) {
  if (!token) return null;

  const cols = new Set(await tableInfo(DB, "sessions"));
  if (!cols.size || !cols.has("token")) return null;

  if (cols.has("email")) {
    const row = await DB.prepare(
      `SELECT email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    ).bind(token).first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  if (cols.has("user_email")) {
    const row = await DB.prepare(
      `SELECT user_email AS email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    ).bind(token).first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  return null;
}

async function ensureActivationsTable(DB) {
  // ننشئ جدول activations إذا ما كان موجود (آمن)
  await DB.prepare(`
    CREATE TABLE IF NOT EXISTS activations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT NOT NULL,
      email TEXT,
      device_id TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `).run();

  await DB.prepare(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_activations_code_device
    ON activations(code, device_id);
  `).run();

  await DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_activations_code
    ON activations(code);
  `).run();

  await DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_activations_email
    ON activations(email);
  `).run();
}

async function getCodeRow(DB, code) {
  const exists = await tableExists(DB, "codes");
  if (!exists) return { error: "CODES_TABLE_NOT_FOUND" };

  const colsArr = await tableInfo(DB, "codes");
  const cols = new Set(colsArr);

  // نحدد عمود الكود (غالبًا "code")
  const codeCol =
    cols.has("code") ? "code" :
    cols.has("activation_code") ? "activation_code" :
    cols.has("key") ? "key" :
    null;

  if (!codeCol) return { error: "CODES_SCHEMA_NO_CODE_COL" };

  const row = await DB.prepare(
    `SELECT * FROM codes WHERE ${codeCol} = ? LIMIT 1`
  ).bind(code).first();

  if (!row) return { error: "CODE_NOT_FOUND" };

  return { row, cols, codeCol };
}

function getBoundEmailFromCodeRow(row) {
  // نقرأ الإيميل من أي عمود معروف
  const candidates = [
    "used_by_email",
    "email",
    "user_email",
    "owner_email",
  ];
  for (const k of candidates) {
    if (row && row[k] != null) {
      const v = String(row[k] || "").trim();
      if (!v) continue;

      // لو كانت مشكلة قديمة (كان ينحفظ deviceId) نتجاهله
      if (!looksLikeEmail(v)) continue;

      return normalizeEmail(v);
    }
  }
  return null;
}

async function getCodeDevices(DB, code) {
  const res = await DB.prepare(
    `SELECT device_id FROM activations WHERE code = ?`
  ).bind(code).all();

  const rows = res?.results || [];
  const set = new Set(rows.map((r) => String(r.device_id || "").trim()).filter(Boolean));
  return set;
}

async function getExistingActivationEmail(DB, code) {
  const row = await DB.prepare(
    `SELECT email FROM activations WHERE code = ? AND email IS NOT NULL AND email != '' ORDER BY rowid DESC LIMIT 1`
  ).bind(code).first();

  return row?.email ? normalizeEmail(row.email) : null;
}

async function updateCodesRow(DB, cols, codeCol, code, email) {
  const sets = [];
  const binds = [];

  // اربط الإيميل
  if (cols.has("used_by_email")) { sets.push("used_by_email = ?"); binds.push(email); }
  else if (cols.has("email")) { sets.push("email = ?"); binds.push(email); }
  else if (cols.has("user_email")) { sets.push("user_email = ?"); binds.push(email); }
  else if (cols.has("owner_email")) { sets.push("owner_email = ?"); binds.push(email); }

  // علّم أنه مستخدم/مفعّل
  if (cols.has("used")) { sets.push("used = 1"); }
  if (cols.has("is_used")) { sets.push("is_used = 1"); }
  if (cols.has("status")) { sets.push("status = 'used'"); }

  const nowIso = new Date().toISOString();
  if (cols.has("used_at")) { sets.push("used_at = ?"); binds.push(nowIso); }
  if (cols.has("activated_at")) { sets.push("activated_at = ?"); binds.push(nowIso); }
  if (cols.has("updated_at")) { sets.push("updated_at = ?"); binds.push(nowIso); }

  if (!sets.length) return;

  binds.push(code);
  await DB.prepare(
    `UPDATE codes SET ${sets.join(", ")} WHERE ${codeCol} = ?`
  ).bind(...binds).run();
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS(request) });
  }
  if (request.method !== "POST") {
    return json(request, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env.DB) return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);

    const body = await request.json().catch(() => ({}));
    const code = normalizeCode(body.code);
    if (!code) return json(request, { ok: false, error: "MISSING_FIELDS" }, 400);

    const deviceId = String(request.headers.get("X-Device-Id") || "").trim();
    if (!deviceId) return json(request, { ok: false, error: "MISSING_DEVICE_ID" }, 400);

    // session token من:
    // 1) Authorization Bearer
    // 2) Cookie: sandooq_session_v1
    // 3) body.token (احتياط)
    const auth = request.headers.get("Authorization") || "";
    const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    const cookieTok = getCookie(request, "sandooq_session_v1");
    const bodyTok = body?.token ? String(body.token).trim() : "";
    const token = bearer || cookieTok || bodyTok;

    if (!token) return json(request, { ok: false, error: "NO_SESSION" }, 401);

    const email = await findSessionEmail(env.DB, token);
    if (!email) return json(request, { ok: false, error: "SESSION_NOT_FOUND" }, 401);

    // تأكد user موجود
    const userRow = await env.DB.prepare(
      `SELECT email, email_verified, is_email_verified, verified, is_verified FROM users WHERE email = ? LIMIT 1`
    ).bind(email).first();

    if (!userRow) return json(request, { ok: false, error: "USER_NOT_FOUND" }, 401);

    // جهّز activations
    await ensureActivationsTable(env.DB);

    // تحقق الكود من جدول codes
    const codeRes = await getCodeRow(env.DB, code);
    if (codeRes.error) return json(request, { ok: false, error: codeRes.error }, 404);

    const { row: codeRow, cols, codeCol } = codeRes;

    // هل الكود مرتبط مسبقًا بإيميل آخر؟
    const boundEmailInCodes = getBoundEmailFromCodeRow(codeRow);
    if (boundEmailInCodes && boundEmailInCodes !== email) {
      return json(request, { ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    // لو جدول activations فيه إيميل مختلف (حماية إضافية)
    const boundEmailInActs = await getExistingActivationEmail(env.DB, code);
    if (boundEmailInActs && boundEmailInActs !== email) {
      return json(request, { ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    // حد الأجهزة = جهازين لكل كود
    const devices = await getCodeDevices(env.DB, code);
    if (devices.has(deviceId)) {
      // نفس الجهاز: اعتبره مفعّل
      return json(request, { ok: true, email, code, activated: true, already: true }, 200);
    }
    if (devices.size >= 2) {
      return json(request, { ok: false, error: "DEVICE_LIMIT_REACHED" }, 409);
    }

    // سجل التفعيل
    await env.DB.prepare(
      `INSERT INTO activations (code, email, device_id, created_at) VALUES (?, ?, ?, ?)`
    ).bind(code, email, deviceId, new Date().toISOString()).run();

    // اربط الكود بالإيميل داخل codes (مرة واحدة)
    if (!boundEmailInCodes) {
      await updateCodesRow(env.DB, cols, codeCol, code, email);
    }

    return json(request, { ok: true, email, code, activated: true }, 200);
  } catch (e) {
    console.log("activate_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
activate.js – api2 – إصدار 1 (Bind code to email + limit 2 devices via activations)
*/
