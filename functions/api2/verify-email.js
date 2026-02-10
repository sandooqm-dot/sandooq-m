// functions/api2/verify-email.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-verify-email-v1";

  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405, cors);
  }

  if (!env?.DB) {
    return json({ ok: false, error: "DB_NOT_BOUND", version: VERSION }, 500, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON", version: VERSION }, 400, cors);
  }

  const email = String(body?.email || "").trim().toLowerCase();
  const otp = String(body?.otp || "").trim();

  if (!email || !otp) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }

  // otp لازم يكون أرقام فقط (6)
  if (!/^\d{4,8}$/.test(otp)) {
    return json({ ok: false, error: "OTP_INVALID", version: VERSION }, 400, cors);
  }

  // ---- ensure schema (safe) ----
  await ensureUsersColumns(env.DB);
  await ensureOtpTable(env.DB);

  // ---- fetch otp row ----
  const row = await env.DB.prepare(
    `SELECT email, otp_hash, expires_at, used_at, attempts
     FROM email_otps
     WHERE email = ?
     LIMIT 1`
  ).bind(email).first();

  if (!row) {
    return json({ ok: false, error: "OTP_INVALID", version: VERSION }, 400, cors);
  }

  if (row.used_at) {
    return json({ ok: false, error: "OTP_INVALID", version: VERSION }, 400, cors);
  }

  const now = Date.now();
  const exp = Date.parse(String(row.expires_at || ""));
  if (!exp || exp < now) {
    return json({ ok: false, error: "OTP_EXPIRED", version: VERSION }, 400, cors);
  }

  const attempts = Number(row.attempts || 0);
  if (attempts >= 8) {
    return json({ ok: false, error: "OTP_LOCKED", version: VERSION }, 429, cors);
  }

  const pepper = String(env.OTP_PEPPER || "otp_pepper_v1");
  const wanted = String(row.otp_hash || "");
  const got = await sha256Hex(`${email}|${otp}|${pepper}`);

  if (!timingSafeEqualHex(wanted, got)) {
    // increase attempts
    await env.DB.prepare(
      `UPDATE email_otps SET attempts = attempts + 1 WHERE email = ?`
    ).bind(email).run();

    return json({ ok: false, error: "OTP_INVALID", version: VERSION }, 400, cors);
  }

  const isoNow = new Date().toISOString();

  // mark otp used + mark user verified
  await env.DB.prepare(
    `UPDATE email_otps SET used_at = ?, attempts = attempts WHERE email = ?`
  ).bind(isoNow, email).run();

  await env.DB.prepare(
    `UPDATE users
     SET is_email_verified = 1,
         email_verified_at = COALESCE(email_verified_at, ?)
     WHERE email = ?`
  ).bind(isoNow, email).run();

  return json({ ok: true, version: VERSION }, 200, cors);
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
    const allowed = allowedRaw.split(",").map(s => s.trim()).filter(Boolean);
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

async function ensureOtpTable(DB) {
  await DB.prepare(
    `CREATE TABLE IF NOT EXISTS email_otps (
      email TEXT PRIMARY KEY,
      otp_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      attempts INTEGER DEFAULT 0,
      last_sent_at TEXT
    )`
  ).run();
}

async function ensureUsersColumns(DB) {
  // users table expected موجود، لكن نضيف أعمدة التحقق لو ناقصة
  await DB.prepare(`ALTER TABLE users ADD COLUMN is_email_verified INTEGER DEFAULT 0`).run().catch(() => {});
  await DB.prepare(`ALTER TABLE users ADD COLUMN email_verified_at TEXT`).run().catch(() => {});
}

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

// مقارنة آمنة (تقريبية) للهكس
function timingSafeEqualHex(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
