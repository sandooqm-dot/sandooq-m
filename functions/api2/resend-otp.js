// /functions/api2/resend-otp.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-resend-otp-v1";

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
  if (!email) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }

  // user exists?
  const u = await env.DB.prepare(
    `SELECT email_verified FROM users WHERE email = ? LIMIT 1`
  ).bind(email).first();

  if (!u) {
    // ما نكشف وجود البريد (حماية)
    return json({ ok: true, version: VERSION }, 200, cors);
  }

  if (Number(u.email_verified || 0) === 1) {
    return json({ ok: false, error: "EMAIL_ALREADY_VERIFIED", version: VERSION }, 409, cors);
  }

  const now = new Date().toISOString();
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO email_otps (email, otp, expires_at, created_at, used)
     VALUES (?, ?, ?, ?, 0)`
  )
    .bind(email, otp, otpExpiresAt, now)
    .run();

  // الإرسال الفعلي بنضيفه لاحقًا
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
