// functions/api2/verify-email.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-verify-email-v1-session";

  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405, cors);
  }

  if (!env?.DB) {
    return json(
      { ok: false, error: "DB_NOT_BOUND", version: VERSION, message: "Bind D1 as DB" },
      500,
      cors
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON", version: VERSION }, 400, cors);
  }

  const email = String(body?.email || "").trim().toLowerCase();
  const otp = String(body?.otp || body?.code || "").trim();
  const deviceId =
    String(body?.deviceId || "").trim() ||
    String(request.headers.get("X-Device-Id") || "").trim();

  if (!email || !otp) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }
  if (!isValidEmail(email)) {
    return json({ ok: false, error: "INVALID_EMAIL", version: VERSION }, 400, cors);
  }
  if (!/^\d{4,8}$/.test(otp)) {
    return json({ ok: false, error: "INVALID_OTP", version: VERSION }, 400, cors);
  }

  // ---- ensure schema ----
  await ensureUsersColumns(env.DB);
  await ensureEmailOtpsTable(env.DB);
  await ensureSessionsTable(env.DB);
  await ensureUserDevicesTable(env.DB);

  // هل المستخدم موجود؟
  const user = await env.DB.prepare(
    `SELECT email, provider, is_email_verified
     FROM users
     WHERE email = ?
     LIMIT 1`
  ).bind(email).first();

  if (!user) {
    return json({ ok: false, error: "USER_NOT_FOUND", version: VERSION }, 404, cors);
  }

  // إذا متحقق مسبقاً: نرجعه OK (تجربة مستخدم أفضل)
  if (Number(user.is_email_verified || 0) === 1) {
    const resp = await createSessionAndResponse({ env, cors, email, deviceId, VERSION, note: "ALREADY_VERIFIED" });
    return resp;
  }

  // تحقق من OTP
  const pepper = String(env.OTP_PEPPER || "otp_pepper_v1");
  const otpHash = await sha256Hex(otp + "|" + pepper);

  // نأخذ آخر OTP صالح وغير مستخدم
  const row = await env.DB.prepare(
    `SELECT id, otp_hash, expires_at, used_at, attempts
     FROM email_otps
     WHERE email = ?
     ORDER BY id DESC
     LIMIT 1`
  ).bind(email).first();

  if (!row) {
    return json({ ok: false, error: "OTP_NOT_FOUND", version: VERSION }, 404, cors);
  }

  const usedAt = row.used_at ? String(row.used_at) : "";
  const expiresAt = row.expires_at ? String(row.expires_at) : "";
  const attempts = Number(row.attempts || 0);

  if (usedAt) {
    return json({ ok: false, error: "OTP_ALREADY_USED", version: VERSION }, 409, cors);
  }

  const nowMs = Date.now();
  const expMs = expiresAt ? Date.parse(expiresAt) : 0;
  if (!expMs || nowMs > expMs) {
    return json({ ok: false, error: "OTP_EXPIRED", version: VERSION }, 410, cors);
  }

  if (attempts >= 10) {
    return json({ ok: false, error: "TOO_MANY_ATTEMPTS", version: VERSION }, 429, cors);
  }

  if (String(row.otp_hash || "") !== otpHash) {
    await env.DB.prepare(`UPDATE email_otps SET attempts = attempts + 1 WHERE id = ?`)
      .bind(row.id)
      .run()
      .catch(() => {});
    return json({ ok: false, error: "OTP_WRONG", version: VERSION }, 401, cors);
  }

  // نجحت: نعلّم OTP مستخدم + نفعّل الايميل
  const nowIso = new Date().toISOString();

  await env.DB.prepare(`UPDATE email_otps SET used_at = ? WHERE id = ?`)
    .bind(nowIso, row.id)
    .run();

  await env.DB.prepare(
    `UPDATE users
     SET is_email_verified = 1, email_verified_at = ?
     WHERE email = ?`
  ).bind(nowIso, email).run();

  // إنشاء Session + كوكي
  const resp = await createSessionAndResponse({ env, cors, email, deviceId, VERSION, note: "VERIFIED_OK" });
  return resp;
}

/* ---------- helpers ---------- */

async function createSessionAndResponse({ env, cors, email, deviceId, VERSION, note }) {
  const token = randomTokenB64Url(32);
  const tokenHash = await sha256Hex(token + "|" + String(env.SESSION_PEPPER || "sess_pepper_v1"));

  const nowIso = new Date().toISOString();
  const expiresIso = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, email, created_at, expires_at, device_id)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(tokenHash, email, nowIso, expiresIso, deviceId || null).run();

  if (deviceId) {
    try {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO user_devices (email, device_id, first_seen_at, last_seen_at)
         VALUES (?, ?, ?, ?)`
      ).bind(email, deviceId, nowIso, nowIso).run();

      await env.DB.prepare(
        `UPDATE user_devices SET last_seen_at = ? WHERE email = ? AND device_id = ?`
      ).bind(nowIso, email, deviceId).run();
    } catch {}
  }

  const cookieName = String(env.SESSION_COOKIE_NAME || "sandooq_session_v1");
  const cookie = buildCookie(cookieName, token, {
    maxAge: 30 * 24 * 60 * 60,
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "Lax",
  });

  const legacyCookie = buildCookie("sandooq_token_v1", token, {
    maxAge: 30 * 24 * 60 * 60,
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "Lax",
  });

  const headers = new Headers(cors);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.append("Set-Cookie", cookie);
  headers.append("Set-Cookie", legacyCookie);

  return new Response(
    JSON.stringify({
      ok: true,
      version: VERSION,
      email,
      expiresAt: expiresIso,
      note,
    }),
    { status: 200, headers }
  );
}

function json(obj, status, corsHeaders) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(obj), { status, headers });
}

function makeCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowedRaw = String(env?.ALLOWED_ORIGINS || "").trim();
  let allowOrigin = "*";

  if (allowedRaw) {
    const allowed = allowedRaw.split(",").map((s) => s.trim()).filter(Boolean);
    if (allowed.includes("*")) allowOrigin = "*";
    else if (origin && allowed.includes(origin)) allowOrigin = origin;
    else allowOrigin = allowed[0] || "*";
  } else if (origin) {
    allowOrigin = origin;
  }

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Vary": "Origin",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

function randomTokenB64Url(byteLen) {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function buildCookie(name, value, opts) {
  const parts = [`${name}=${value}`];
  if (opts?.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts?.path) parts.push(`Path=${opts.path}`);
  if (opts?.secure) parts.push("Secure");
  if (opts?.httpOnly) parts.push("HttpOnly");
  if (opts?.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  return parts.join("; ");
}

async function ensureUsersColumns(DB) {
  await DB.prepare(`ALTER TABLE users ADD COLUMN is_email_verified INTEGER DEFAULT 0`).run().catch(() => {});
  await DB.prepare(`ALTER TABLE users ADD COLUMN email_verified_at TEXT`).run().catch(() => {});
}

async function ensureEmailOtpsTable(DB) {
  await DB.prepare(
    `CREATE TABLE IF NOT EXISTS email_otps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      attempts INTEGER DEFAULT 0
    )`
  ).run();
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_email_otps_email ON email_otps(email)`).run().catch(() => {});
}

async function ensureSessionsTable(DB) {
  await DB.prepare(
    `CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      device_id TEXT
    )`
  ).run();
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email)`).run().catch(() => {});
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`).run().catch(() => {});
}

async function ensureUserDevicesTable(DB) {
  await DB.prepare(
    `CREATE TABLE IF NOT EXISTS user_devices (
      email TEXT NOT NULL,
      device_id TEXT NOT NULL,
      first_seen_at TEXT,
      last_seen_at TEXT,
      PRIMARY KEY (email, device_id)
    )`
  ).run();
}
