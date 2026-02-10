// /functions/api2/verify-email.js
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

  if (!env?.JWT_SECRET) {
    return json({ ok: false, error: "MISSING_JWT_SECRET", version: VERSION }, 500, cors);
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

  // Get latest unused otp
  const row = await env.DB.prepare(
    `SELECT id, otp, expires_at, used
     FROM email_otps
     WHERE email = ?
     ORDER BY id DESC
     LIMIT 1`
  ).bind(email).first();

  if (!row) {
    return json({ ok: false, error: "OTP_INVALID", version: VERSION }, 400, cors);
  }

  if (Number(row.used || 0) === 1) {
    return json({ ok: false, error: "OTP_INVALID", version: VERSION }, 400, cors);
  }

  const expiresAt = Date.parse(String(row.expires_at || ""));
  if (!expiresAt || Date.now() > expiresAt) {
    return json({ ok: false, error: "OTP_EXPIRED", version: VERSION }, 400, cors);
  }

  if (String(row.otp || "") !== otp) {
    return json({ ok: false, error: "OTP_INVALID", version: VERSION }, 400, cors);
  }

  const now = new Date().toISOString();

  // Mark otp used
  await env.DB.prepare(`UPDATE email_otps SET used = 1, used_at = ? WHERE id = ?`)
    .bind(now, row.id)
    .run();

  // Mark user verified
  await env.DB.prepare(`UPDATE users SET email_verified = 1, email_verified_at = ? WHERE email = ?`)
    .bind(now, email)
    .run();

  // Issue token + cookie
  const token = await signToken(env.JWT_SECRET, { email }, 60 * 60 * 24 * 30);

  const headers = new Headers(cors);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.append("Set-Cookie", makeAuthCookie(token));

  return new Response(
    JSON.stringify({ ok: true, version: VERSION, email, token }),
    { status: 200, headers }
  );
}

/* ---------- helpers ---------- */

function makeAuthCookie(token) {
  return `sandooq_token_v1=${encodeURIComponent(token)}; Path=/; Max-Age=${60 * 60 * 24 * 30}; Secure; HttpOnly; SameSite=Lax`;
}

function json(obj, status, corsHeaders) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
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
    Vary: "Origin",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };
}

function base64UrlFromBytes(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function bytesFromString(str) {
  return new TextEncoder().encode(str);
}
async function hmacSha256(secret, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    bytesFromString(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return new Uint8Array(sig);
}
async function signToken(secret, payloadObj, ttlSeconds) {
  const header = { alg: "HS256", typ: "JWT" };
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + Math.max(60, Number(ttlSeconds || 0));
  const payload = { ...payloadObj, iat, exp, v: 1 };

  const encHeader = base64UrlFromBytes(bytesFromString(JSON.stringify(header)));
  const encPayload = base64UrlFromBytes(bytesFromString(JSON.stringify(payload)));
  const toSign = bytesFromString(`${encHeader}.${encPayload}`);
  const sigBytes = await hmacSha256(secret, toSign);
  const encSig = base64UrlFromBytes(sigBytes);

  return `${encHeader}.${encPayload}.${encSig}`;
}
