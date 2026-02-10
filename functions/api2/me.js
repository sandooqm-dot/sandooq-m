// functions/api2/me.js
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
    return json(
      { ok: false, error: "DB_NOT_BOUND", version: VERSION, message: "Bind D1 as DB in Pages Settings -> Bindings" },
      500,
      cors
    );
  }

  const token = readToken(request);
  if (!token) {
    return json({ ok: false, error: "UNAUTHORIZED", version: VERSION }, 401, cors);
  }

  const tokenHash = await sha256Hex(new TextEncoder().encode(token));
  const now = Date.now();

  const s = await env.DB.prepare(
    "SELECT email, expires_at, revoked_at FROM auth_sessions WHERE token_hash = ? LIMIT 1"
  )
    .bind(tokenHash)
    .first();

  if (!s) {
    return json({ ok: false, error: "UNAUTHORIZED", version: VERSION }, 401, cors);
  }

  if (s.revoked_at) {
    return json({ ok: false, error: "UNAUTHORIZED", version: VERSION }, 401, cors);
  }

  if (Number(s.expires_at) <= now) {
    return json({ ok: false, error: "UNAUTHORIZED", version: VERSION }, 401, cors);
  }

  // جلب المستخدم
  const u = await env.DB.prepare(
    "SELECT email, provider, email_verified, created_at FROM auth_users WHERE email = ? LIMIT 1"
  )
    .bind(s.email)
    .first();

  if (!u) {
    return json({ ok: false, error: "UNAUTHORIZED", version: VERSION }, 401, cors);
  }

  // هل مفعل اللعبة؟ (وجود سجل في auth_code_links لنفس game_id)
  const gameId = String(env?.GAME_ID || "horof").trim();
  const link = await env.DB.prepare(
    "SELECT code, activated_at FROM auth_code_links WHERE game_id = ? AND email = ? LIMIT 1"
  )
    .bind(gameId, u.email)
    .first();

  return json(
    {
      ok: true,
      version: VERSION,
      email: u.email,
      provider: u.provider,
      email_verified: Number(u.email_verified || 0) === 1,
      activated: !!link,
      game_id: gameId,
      code: link ? link.code : null,
      activated_at: link ? link.activated_at : null,
    },
    200,
    cors
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

function readToken(request) {
  // 1) Authorization: Bearer
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m && m[1]) return m[1].trim();

  // 2) Cookie
  const cookie = request.headers.get("Cookie") || "";
  const token = getCookie(cookie, "sandooq_token_v1");
  if (token) return token;

  return "";
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

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

// functions/api2/me.js – إصدار 1
