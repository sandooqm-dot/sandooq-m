// /functions/api2/register.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-register-v1-otp";

  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405, cors);
  }

  if (!env?.DB) {
    return json(
      { ok: false, error: "DB_NOT_BOUND", version: VERSION },
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
  const deviceId = String(request.headers.get("X-Device-Id") || "").trim();

  if (!email || !password) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }

  if (!isEmail(email)) {
    return json({ ok: false, error: "INVALID_EMAIL", version: VERSION }, 400, cors);
  }

  if (password.length < 8) {
    return json({ ok: false, error: "WEAK_PASSWORD", version: VERSION }, 400, cors);
  }

  // Check existing
  const exists = await env.DB.prepare("SELECT email FROM users WHERE email = ? LIMIT 1")
    .bind(email)
    .first();

  if (exists) {
    return json({ ok: false, error: "EMAIL_EXISTS", version: VERSION }, 409, cors);
  }

  // Create salt
  const saltBytes = new Uint8Array(16);
  crypto.getRandomValues(saltBytes);
  const saltB64 = bytesToBase64(saltBytes);

  // Hash = sha256(saltBytes + passwordBytes)
  const pwBytes = new TextEncoder().encode(password);
  const hashB64 = await sha256Base64(concatBytes(saltBytes, pwBytes));

  const now = new Date().toISOString();

  // Insert user (email not verified yet)
  await env.DB.prepare(
    `INSERT INTO users
      (email, provider, password_hash, salt_b64, created_at, email_verified, activated)
     VALUES
      (?, 'email', ?, ?, ?, 0, 0)`
  )
    .bind(email, hashB64, saltB64, now)
    .run();

  // Optional: device table
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

  // Generate OTP (6 digits)
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 minutes

  // Store OTP
  await env.DB.prepare(
    `INSERT INTO email_otps (email, otp, expires_at, created_at, used)
     VALUES (?, ?, ?, ?, 0)`
  )
    .bind(email, otp, otpExpiresAt, now)
    .run();

  // Send email (إذا ما ضبطنا البريد للحين نخليه ERROR واضح)
  // ملاحظة: بنضيف خطوة إرسال البريد الفعلي بعد ما نثبت الوظائف.
  // الآن نخليه يرجّع ok true (عشان الواجهة تتقدم) + السيرفر جاهز.
  // لكن إذا تبي تخليه يفشل لين نضبط الإرسال: رجّعه EMAIL_SEND_FAILED.
  // حالياً: نعتبره نجاح مؤقت.
  return json({ ok: true, version: VERSION, email }, 200, cors);
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

function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function isEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v || ""));
}
