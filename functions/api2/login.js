// /functions/api2/login.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-login-v1";

  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405, cors);
  }

  if (!env || !env.DB) {
    return json(
      {
        ok: false,
        error: "DB_NOT_BOUND",
        version: VERSION,
        message: "env.DB is missing. Pages -> Settings -> Bindings -> D1 must be bound as DB",
      },
      500,
      cors
    );
  }

  if (!env.JWT_SECRET) {
    return json(
      {
        ok: false,
        error: "MISSING_JWT_SECRET",
        version: VERSION,
        message: "Set JWT_SECRET in Cloudflare Pages environment variables.",
      },
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
    String(request.headers.get("X-Device-Id") || body?.deviceId || "").trim();

  if (!email || !password) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }

  const user = await env.DB.prepare(
    `SELECT email, provider, password_hash, salt_b64, email_verified
     FROM users
     WHERE email = ?
     LIMIT 1`
  )
    .bind(email)
    .first();

  if (!user) {
    return json({ ok: false, error: "INVALID_LOGIN", version: VERSION }, 401, cors);
  }

  if (String(user.provider || "") !== "email") {
    return json({ ok: false, error: "USE_GOOGLE_LOGIN", version: VERSION }, 403, cors);
  }

  if (Number(user.email_verified || 0) !== 1) {
    return json({ ok: false, error: "EMAIL_NOT_VERIFIED", version: VERSION }, 403, cors);
  }

  // Verify password: sha256(saltBytes + passwordBytes) base64 === password_hash
  const saltBytes = base64ToBytes(String(user.salt_b64 || ""));
  const pwBytes = new TextEncoder().encode(password);
  const hashB64 = await sha256Base64(concatBytes(saltBytes, pwBytes));

  if (!safeEqualB64(hashB64, String(user.password_hash || ""))) {
    return json({ ok: false, error: "INVALID_LOGIN", version: VERSION }, 401, cors);
  }

  const now = new Date().toISOString();

  // Update last login
  try {
    await env.DB.prepare(`UPDATE users SET last_login_at = ? WHERE email = ?`)
      .bind(now, email)
      .run();
  } catch {}

  // Upsert device (optional)
  if (deviceId) {
    try {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO user_devices (email, device_id, first_seen_at, last_seen_at)
         VALUES (?, ?, ?, ?)`
      )
        .bind(email, deviceId, now, now)
        .run();

      await env.DB.prepare(
        `UPDATE user_devices SET last_seen_at = ? WHERE email = ? AND device_id = ?`
      )
        .bind(now, email, deviceId)
        .run();
    } catch {}
  }

  const token = await signToken(env.JWT_SECRET, { email }, 60 * 60 * 24 * 30); // 30 days

  return json({ ok: true, version: VERSION, email, token }, 200, cors);
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

function base64ToBytes(b64) {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return new Uint8Array(0);
  }
}

function safeEqualB64(a, b) {
  // constant-ish time compare (length + char codes)
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
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
