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
    return json(
      { ok: false, error: "DB_NOT_BOUND", version: VERSION, message: "Bind D1 as DB in Pages Settings -> Bindings" },
      500,
      cors
    );
  }

  let body = null;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON", version: VERSION }, 400, cors);
  }

  const email = normEmail(body?.email);
  const otp = String(body?.otp || "").trim();

  if (!email || !otp) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }

  const now = Date.now();
  const otpSecret = String(env?.OTP_SECRET || "").trim();
  const otpHash = await sha256Hex(new TextEncoder().encode(`${email}|${otp}|${otpSecret || "dev"}`));

  // نبحث عن OTP مطابق وغير مستخدم
  const row = await env.DB.prepare(
    "SELECT id, expires_at, used_at FROM auth_email_otps WHERE email = ? AND otp_hash = ? ORDER BY created_at DESC LIMIT 1"
  )
    .bind(email, otpHash)
    .first();

  if (!row) {
    return json({ ok: false, error: "OTP_INVALID", version: VERSION }, 400, cors);
  }

  if (row.used_at) {
    return json({ ok: false, error: "OTP_INVALID", version: VERSION }, 400, cors);
  }

  if (Number(row.expires_at) <= now) {
    return json({ ok: false, error: "OTP_EXPIRED", version: VERSION }, 400, cors);
  }

  // علّم OTP كمستخدم
  await env.DB.prepare("UPDATE auth_email_otps SET used_at = ? WHERE id = ? AND used_at IS NULL")
    .bind(now, row.id)
    .run();

  // فعّل البريد
  await env.DB.prepare("UPDATE auth_users SET email_verified = 1 WHERE email = ?")
    .bind(email)
    .run();

  // إنشاء Session token
  const token = await makeSessionToken();
  const tokenHash = await sha256Hex(new TextEncoder().encode(token));

  const ttlDays = Number(env?.SESSION_TTL_DAYS || 30);
  const expiresAt = now + ttlDays * 24 * 60 * 60 * 1000;

  await env.DB.prepare(
    "INSERT INTO auth_sessions (token_hash, email, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, NULL)"
  )
    .bind(tokenHash, email, now, expiresAt)
    .run();

  // Cookie للجلسة (عشان الميدلوير)
  const cookie = buildCookie("sandooq_token_v1", token, {
    maxAge: ttlDays * 24 * 60 * 60,
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
  });

  return json(
    { ok: true, version: VERSION, email, token },
    200,
    cors,
    { "Set-Cookie": cookie }
  );
}

/* ---------------- helpers ---------------- */

function json(obj, status, corsHeaders, extraHeaders = {}) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  for (const [k, v] of Object.entries(extraHeaders || {})) headers.set(k, v);
  return new Response(JSON.stringify(obj), { status, headers });
}

function makeCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowedRaw = (env?.ALLOWED_ORIGINS || "").trim();
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

function normEmail(v) {
  return String(v || "").trim().toLowerCase();
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

async function makeSessionToken() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return base64Url(b);
}

function base64Url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function buildCookie(name, value, opts = {}) {
  const parts = [];
  parts.push(`${name}=${encodeURIComponent(value)}`);
  parts.push(`Path=${opts.path || "/"}`);
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite || "Lax"}`);
  return parts.join("; ");
}

// functions/api2/verify-email.js – إصدار 1
