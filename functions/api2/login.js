// functions/api2/login.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-login-v1-cookie";

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
  const password = String(body?.password || "");

  if (!email || !password) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }

  // جلب المستخدم
  const u = await env.DB.prepare(
    "SELECT email, provider, password_hash, salt_b64, email_verified FROM auth_users WHERE email = ? LIMIT 1"
  )
    .bind(email)
    .first();

  if (!u) {
    return json({ ok: false, error: "INVALID_LOGIN", version: VERSION }, 401, cors);
  }

  if (String(u.provider || "email") !== "email") {
    // لاحقاً: Google provider
    return json({ ok: false, error: "INVALID_LOGIN", version: VERSION }, 401, cors);
  }

  // لازم يكون البريد متأكد
  if (Number(u.email_verified || 0) !== 1) {
    return json({ ok: false, error: "EMAIL_NOT_VERIFIED", version: VERSION }, 403, cors);
  }

  // تحقق كلمة المرور (PBKDF2)
  const ok = await verifyPbkdf2(password, String(u.salt_b64 || ""), String(u.password_hash || ""), {
    iterations: Number(env?.PBKDF2_ITERS || 120000),
  });

  if (!ok) {
    return json({ ok: false, error: "INVALID_LOGIN", version: VERSION }, 401, cors);
  }

  // إنشاء Session
  const now = Date.now();
  const token = await makeSessionToken();
  const tokenHash = await sha256Hex(new TextEncoder().encode(token));

  const ttlDays = Number(env?.SESSION_TTL_DAYS || 30);
  const expiresAt = now + ttlDays * 24 * 60 * 60 * 1000;

  await env.DB.prepare(
    "INSERT INTO auth_sessions (token_hash, email, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, NULL)"
  )
    .bind(tokenHash, email, now, expiresAt)
    .run();

  const cookie = buildCookie("sandooq_token_v1", token, {
    maxAge: ttlDays * 24 * 60 * 60,
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
  });

  return json({ ok: true, version: VERSION, email, token }, 200, cors, { "Set-Cookie": cookie });
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

function base64ToBytes(b64) {
  const bin = atob(String(b64 || ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

async function pbkdf2(password, saltBytes, iterations) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    key,
    256
  );

  return new Uint8Array(bits);
}

async function verifyPbkdf2(password, saltB64, expectedHashB64, { iterations = 120000 } = {}) {
  try {
    const saltBytes = base64ToBytes(saltB64);
    const got = await pbkdf2(password, saltBytes, iterations);
    const gotB64 = bytesToBase64(got);
    return timingSafeEqual(gotB64, expectedHashB64);
  } catch {
    return false;
  }
}

function timingSafeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
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

// functions/api2/login.js – إصدار 1
