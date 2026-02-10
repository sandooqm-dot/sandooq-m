// /functions/api2/me.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-me-v1";

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

  // Token from Authorization OR Cookie
  const auth = request.headers.get("Authorization") || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const cookie = request.headers.get("Cookie") || "";
  const cookieTok = getCookie(cookie, "sandooq_token_v1");
  const token = bearer || cookieTok || "";

  const payload = token ? await verifyJwtHS256(env.JWT_SECRET, token) : null;
  const email = String(payload?.email || "").trim().toLowerCase();

  if (!email) {
    return json({ ok: false, error: "UNAUTHORIZED", version: VERSION }, 401, cors);
  }

  // Verified?
  const u = await env.DB.prepare(
    `SELECT email, provider, email_verified
     FROM users
     WHERE email = ?
     LIMIT 1`
  ).bind(email).first();

  if (!u) {
    return json({ ok: false, error: "UNAUTHORIZED", version: VERSION }, 401, cors);
  }

  const verified = Number(u.email_verified || 0) === 1;

  // Activated? (based on activations table)
  const act = await env.DB.prepare(
    `SELECT 1 FROM activations WHERE email = ? LIMIT 1`
  ).bind(email).first();

  const activated = !!act;

  return json(
    { ok: true, version: VERSION, email, verified, activated },
    200,
    cors
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

function getCookie(cookieHeader, name) {
  const parts = cookieHeader.split(";").map((s) => s.trim());
  for (const p of parts) {
    if (!p) continue;
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    const k = p.slice(0, eq).trim();
    const v = p.slice(eq + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return "";
}

function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToBase64Url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function strToBytes(s) {
  return new TextEncoder().encode(s);
}
function safeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
async function hmacSha256(secret, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    strToBytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return new Uint8Array(sig);
}

async function verifyJwtHS256(secret, token) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 3) return null;

    const [h, p, s] = parts;
    const toSign = `${h}.${p}`;

    const sigBytes = await hmacSha256(secret, strToBytes(toSign));
    const expected = bytesToBase64Url(sigBytes);

    if (!safeEqual(expected, s)) return null;

    const payloadJson = new TextDecoder().decode(base64UrlToBytes(p));
    const payload = JSON.parse(payloadJson);

    const now = Math.floor(Date.now() / 1000);
    if (!payload?.exp || now >= Number(payload.exp)) return null;

    return payload;
  } catch {
    return null;
  }
}
