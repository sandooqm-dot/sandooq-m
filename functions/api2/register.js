// functions/api/register.js
// Register (Email+Password) + Send OTP via Resend + Store hashed OTP in D1
// Returns { ok:true } on success, or { ok:false, code:"..." }

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

function getCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowedRaw = (env.ALLOWED_ORIGINS || "").trim();

  // If empty, allow same-origin only (still set no CORS headers)
  if (!allowedRaw) return {};

  // Allow all
  if (allowedRaw === "*" || allowedRaw.includes("*")) {
    return {
      "Access-Control-Allow-Origin": origin || "*",
      "Vary": "Origin",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
    };
  }

  const allowed = allowedRaw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  if (allowed.includes(origin)) {
    return {
      "Access-Control-Allow-Origin": origin,
      "Vary": "Origin",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
    };
  }

  // Not allowed origin → still respond without CORS to block browser
  return {};
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  // Simple & safe validation
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function base64FromBytes(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

async function sha256Base64(text) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return base64FromBytes(new Uint8Array(buf));
}

async function pbkdf2HashBase64(password, saltBytes, iterations = 100000) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );

  return base64FromBytes(new Uint8Array(bits));
}

function randomDigits(len = 6) {
  const a = new Uint8Array(len);
  crypto.getRandomValues(a);
  let out = "";
  for (let i = 0; i < len; i++) out += String(a[i] % 10);
  return out;
}

async function insertUser(db, { email, passwordHashB64, saltB64, nowIso }) {
  // Try multiple schema variants to avoid "no such column" errors
  const variants = [
    {
      sql:
        "INSERT INTO users (email, provider, password_hash, salt_b64, created_at, email_verified, is_email_verified) " +
        "VALUES (?, 'email', ?, ?, ?, 0, 0)",
      args: [email, passwordHashB64, saltB64, nowIso],
    },
    {
      sql:
        "INSERT INTO users (email, provider, password_hash, salt_b64, created_at, is_email_verified) " +
        "VALUES (?, 'email', ?, ?, ?, 0)",
      args: [email, passwordHashB64, saltB64, nowIso],
    },
    {
      sql:
        "INSERT INTO users (email, provider, password_hash, salt_b64, created_at) " +
        "VALUES (?, 'email', ?, ?, ?)",
      args: [email, passwordHashB64, saltB64, nowIso],
    },
  ];

  let lastErr;
  for (const v of variants) {
    try {
      await db.prepare(v.sql).bind(...v.args).run();
      return;
    } catch (e) {
      lastErr = e;
      const msg = String(e && e.message ? e.message : e);
      // If it's a schema mismatch, try next variant
      if (msg.includes("no such column") || msg.includes("has no column")) continue;
      throw e;
    }
  }
  throw lastErr;
}

async function upsertOtp(db, { email, otpHashB64, nowIso, expIso }) {
  // Clear previous OTPs for this email (simple & effective)
  try {
    await db.prepare("DELETE FROM email_otps WHERE email = ?").bind(email).run();
  } catch (_) {
    // ignore
  }

  const variants = [
    {
      sql:
        "INSERT INTO email_otps (email, otp_hash, created_at, expires_at, attempts) " +
        "VALUES (?, ?, ?, ?, 0)",
      args: [email, otpHashB64, nowIso, expIso],
    },
    {
      sql:
        "INSERT INTO email_otps (email, otp_hash, created_at, expires_at) " +
        "VALUES (?, ?, ?, ?)",
      args: [email, otpHashB64, nowIso, expIso],
    },
  ];

  let lastErr;
  for (const v of variants) {
    try {
      await db.prepare(v.sql).bind(...v.args).run();
      return;
    } catch (e) {
      lastErr = e;
      const msg = String(e && e.message ? e.message : e);
      if (msg.includes("no such column") || msg.includes("has no column")) continue;
      if (msg.includes("no such table") && msg.includes("email_otps")) {
        // Table name mismatch fallback (rare)
        await db
          .prepare(
            "INSERT INTO email_otp (email, otp_hash, created_at, expires_at, attempts) VALUES (?, ?, ?, ?, 0)"
          )
          .bind(email, otpHashB64, nowIso, expIso)
          .run();
        return;
      }
      throw e;
    }
  }
  throw lastErr;
}

async function sendOtpEmail({ resendKey, from, to, otp }) {
  const subject = "رمز التحقق - صندوق المسابقات";
  const html = `
  <div style="font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; direction: rtl; text-align: right;">
    <h2>رمز التحقق</h2>
    <p>استخدم الرمز التالي لتأكيد بريدك الإلكتروني:</p>
    <div style="font-size: 28px; letter-spacing: 6px; font-weight: 800; margin: 12px 0;">${otp}</div>
    <p style="color:#666">تنبيه: ينتهي الرمز خلال 10 دقائق.</p>
  </div>`;

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${resendKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from, // e.g. "Sandooq Games <support@sandooq-games.com>"
      to,
      subject,
      html,
    }),
  });

  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = `Resend failed: ${r.status} ${JSON.stringify(data)}`;
    throw new Error(msg);
  }
}

export async function onRequest(context) {
  const { request, env } = context;
  const cors = getCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, code: "METHOD_NOT_ALLOWED" }, 405, cors);
  }

  try {
    if (!env.DB) {
      return json({ ok: false, code: "DB_NOT_BOUND" }, 500, cors);
    }

    const resendKey =
      env.RESEND_API_KEY ||
      env.RESEND_KEY ||
      env.RESEND_TOKEN ||
      env.RESEND;

    if (!resendKey) {
      return json({ ok: false, code: "MISSING_RESEND_KEY" }, 500, cors);
    }

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");

    if (!isValidEmail(email)) {
      return json({ ok: false, code: "INVALID_EMAIL" }, 400, cors);
    }
    if (password.length < 8) {
      return json({ ok: false, code: "WEAK_PASSWORD" }, 400, cors);
    }

    // Check existing user
    const exists = await env.DB
      .prepare("SELECT 1 AS x FROM users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    if (exists && exists.x) {
      return json({ ok: false, code: "EMAIL_EXISTS" }, 409, cors);
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const expIso = new Date(now.getTime() + 10 * 60 * 1000).toISOString(); // +10 min

    // Password hash
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    const saltB64 = base64FromBytes(salt);
    const passwordHashB64 = await pbkdf2HashBase64(password, salt);

    // Create OTP + hash (with pepper)
    const otp = randomDigits(6);
    const pepper = env.OTP_PEPPER || env.JWT_SECRET || "";
    const otpHashB64 = await sha256Base64(`${otp}:${email}:${pepper}`);

    // Insert user + OTP
    await insertUser(env.DB, { email, passwordHashB64, saltB64, nowIso });
    await upsertOtp(env.DB, { email, otpHashB64, nowIso, expIso });

    // Send email
    const fromEmail = env.EMAIL_FROM || env.FROM_EMAIL || "support@sandooq-games.com";
    const from = env.EMAIL_FROM_NAME
      ? `${env.EMAIL_FROM_NAME} <${fromEmail}>`
      : `Sandooq Games <${fromEmail}>`;

    await sendOtpEmail({
      resendKey,
      from,
      to: [email],
      otp,
    });

    return json({ ok: true }, 200, cors);
  } catch (e) {
    console.error("register error:", e);
    return json({ ok: false, code: "DB_SCHEMA_ERROR" }, 500, cors);
  }
}
