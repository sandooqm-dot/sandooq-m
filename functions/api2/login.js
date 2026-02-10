// functions/api2/login.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-login-v2-verify-gate+session";

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
  const password = String(body?.password || "");
  const deviceId =
    String(body?.deviceId || "").trim() ||
    String(request.headers.get("X-Device-Id") || "").trim();

  if (!email || !password) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }
  if (!isValidEmail(email)) {
    return json({ ok: false, error: "INVALID_EMAIL", version: VERSION }, 400, cors);
  }

  // ---- ensure schema ----
  await ensureUsersColumns(env.DB);
  await ensureSessionsTable(env.DB);
  await ensureUserDevicesTable(env.DB);

  // ---- load user ----
  const user = await env.DB.prepare(
    `SELECT email, provider, password_hash, salt_b64, is_email_verified
     FROM users
     WHERE email = ?
     LIMIT 1`
  ).bind(email).first();

  if (!user) {
    return json({ ok: false, error: "USER_NOT_FOUND", version: VERSION }, 404, cors);
  }

  const provider = String(user.provider || "email");

  // لو حساب ايميل لازم يكون متحقق قبل السماح بالدخول
  if (provider === "email" && Number(user.is_email_verified || 0) !== 1) {
    return json(
      { ok: false, error: "EMAIL_NOT_VERIFIED", version: VERSION, email },
      403,
      cors
    );
  }

  // ---- verify password (provider=email فقط) ----
  if (provider !== "email") {
    // لو حساب Google بيجي من /api2/google (لاحقاً)
    return json(
      { ok: false, error: "WRONG_PROVIDER", version: VERSION, provider },
      409,
      cors
    );
  }

  const saltB64 = String(user.salt_b64 || "");
  const storedHash = String(user.password_hash || "");

  if (!saltB64 || !storedHash) {
    return json({ ok: false, error: "ACCOUNT_NO_PASSWORD", version: VERSION }, 409, cors);
  }

  const saltBytes = base64ToBytes(saltB64);
  const pwBytes = new TextEncoder().encode(password);
  const calcHash = await sha256Base64(concatBytes(saltBytes, pwBytes));

  if (calcHash !== storedHash) {
    return json({ ok: false, error: "BAD_PASSWORD", version: VERSION }, 401, cors);
  }

  // ---- create session ----
  const token = randomTokenB64Url(32); // raw token (we store hash only)
  const tokenHash = await sha256Hex(token + "|" + String(env.SESSION_PEPPER || "sess_pepper_v1"));

  const nowIso = new Date().toISOString();
  const expiresIso = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, email, created_at, expires_at, device_id)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(tokenHash, email, nowIso, expiresIso, deviceId || null).run();

  // ---- upsert device ----
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

  // ---- set cookies ----
  const cookieName = String(env.SESSION_COOKIE_NAME || "sandooq_session_v1");
  const cookie = buildCookie(cookieName, token, {
    maxAge: 30 * 24 * 60 * 60,
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "Lax",
  });

  // كوكي إضافي احتياطي (لو عندك كود قديم يقرأ هذا الاسم)
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
      provider,
      expiresAt: expiresIso,
    }),
    { status: 200, headers }
  );
}

/* ---------- helpers ---------- */

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

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function sha256Base64(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

function base64ToBytes(b64) {
  const bin = atob(String(b64));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
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
