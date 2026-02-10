// functions/api2/me.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-me-v1";

  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  // واجهتك ترسل POST
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

  const gameId = (env.GAME_ID || "horof").trim();
  const token = await getTokenFromRequest(request);

  if (!token) {
    return json({ ok: false, error: "NO_SESSION", version: VERSION }, 401, cors);
  }

  try {
    const now = Date.now();
    const tokenHash = await sha256Hex(new TextEncoder().encode(token));

    const sess = await env.DB.prepare(
      "SELECT email, expires_at, revoked_at FROM auth_sessions WHERE token_hash = ? LIMIT 1"
    )
      .bind(tokenHash)
      .first();

    if (!sess || sess.revoked_at || Number(sess.expires_at) <= now) {
      return json({ ok: false, error: "INVALID_SESSION", version: VERSION }, 401, cors);
    }

    const user = await env.DB.prepare(
      "SELECT email, provider, email_verified FROM auth_users WHERE email = ? LIMIT 1"
    )
      .bind(sess.email)
      .first();

    if (!user) {
      return json({ ok: false, error: "USER_NOT_FOUND", version: VERSION }, 401, cors);
    }

    const link = await env.DB.prepare(
      "SELECT code FROM auth_code_links WHERE email = ? AND game_id = ? LIMIT 1"
    )
      .bind(user.email, gameId)
      .first();

    return json(
      {
        ok: true,
        version: VERSION,
        email: user.email,
        provider: user.provider || "email",
        email_verified: !!user.email_verified,
        activated: !!link,
      },
      200,
      cors
    );
  } catch (e) {
    // غالبًا الجداول auth_* ما انعملت لسه
    return json(
      { ok: false, error: "DB_SCHEMA_MISSING", version: VERSION, message: String(e?.message || e) },
      500,
      cors
    );
  }
}

/* ---------------- helpers ---------------- */

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
    "Vary": "Origin",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };
}

async function getTokenFromRequest(request) {
  // 1) Authorization: Bearer
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m && m[1]) return m[1].trim();

  // 2) Cookie: sandooq_token_v1
  const cookie = request.headers.get("Cookie") || "";
  const tok = getCookie(cookie, "sandooq_token_v1");
  return tok || "";
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
