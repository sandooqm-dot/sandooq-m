// functions/api2/register.js
// api2-register-v2 (OTP via Resend)

function json(obj, status = 200, corsHeaders, extraHeaders = {}) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  for (const [k, v] of Object.entries(extraHeaders || {})) headers.set(k, v);
  return new Response(JSON.stringify(obj), { status, headers });
}

function makeCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowedRaw = (env.ALLOWED_ORIGINS || "").trim();

  let allowOrigin = "";
  if (!allowedRaw) {
    // لو ما حطيت ALLOWED_ORIGINS: اسمح لنفس الدومين فقط (أكثر أمان)
    allowOrigin = origin || "";
  } else {
    const allowed = allowedRaw.split(",").map(s => s.trim()).filter(Boolean);
    if (allowed.includes("*")) allowOrigin = "*";
    else if (origin && allowed.includes(origin)) allowOrigin = origin;
    else allowOrigin = ""; // غير مسموح
  }

  const h = {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin",
  };
  return h;
}

function b64(bytes) {
  let bin = "";
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

function bytesFromString(s) {
  return new TextEncoder().encode(s);
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

async function hashPasswordPBKDF2(password) {
  const iterations = 210000;
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    bytesFromString(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    keyMaterial,
    256
  );

  const hash = new Uint8Array(bits);
  // format: pbkdf2_sha256$ITER$SALT_B64$HASH_B64
  return `pbkdf2_sha256$${iterations}$${b64(salt)}$${b64(hash)}`;
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function makeOtp6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function sendOtpEmail({ env, toEmail, otp }) {
  const apiKey = (env.RESEND_API_KEY || "").trim();
  const from = (env.RESEND_FROM || "").trim(); // مثال: "صندوق المسابقات <support@sandooq-games.com>"
  const replyTo = (env.RESEND_REPLY_TO || "").trim(); // اختياري

  if (!apiKey) throw new Error("Missing RESEND_API_KEY");
  if (!from) throw new Error("Missing RESEND_FROM");

  const subject = "رمز التحقق - صندوق المسابقات";
  const text = `رمز التحقق الخاص بك هو: ${otp}\nصلاحية الرمز: 10 دقائق.\nإذا لم تطلب هذا الرمز تجاهل الرسالة.`;

  const html = `
  <div dir="rtl" style="font-family:Arial, Tahoma, sans-serif; line-height:1.8">
    <div style="max-width:520px;margin:0 auto;padding:18px;border-radius:14px;background:#ffffff">
      <div style="text-align:center;margin-bottom:8px">
        <div style="font-size:18px;font-weight:700;color:#111">صندوق المسابقات</div>
        <div style="font-size:12px;color:#666">تأكيد البريد الإلكتروني</div>
      </div>

      <div style="margin-top:12px;color:#111">
        هذا هو رمز التحقق الخاص بك:
      </div>

      <div style="margin:16px 0;padding:14px;border-radius:12px;background:#f5f7ff;text-align:center">
        <div style="font-size:34px;font-weight:800;letter-spacing:6px;color:#1a1a1a">${otp}</div>
      </div>

      <div style="font-size:13px;color:#444">
        صلاحية الرمز <b>10 دقائق</b>. إذا لم تطلب هذا الرمز تجاهل الرسالة.
      </div>

      <hr style="border:none;border-top:1px solid #eee;margin:16px 0" />
      <div style="font-size:12px;color:#777;text-align:center">© صندوق المسابقات</div>
    </div>
  </div>`.trim();

  const payload = {
    from,
    to: toEmail,
    subject,
    html,
    text,
  };

  if (replyTo) payload.reply_to = replyTo;

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = data?.message || data?.error || `Resend error ${r.status}`;
    throw new Error(msg);
  }
  return data;
}

export async function onRequest(context) {
  const { request, env } = context;
  const cors = makeCorsHeaders(request, env);

  // لو origin مو مسموح (وما هو *) رجّع 403
  if (cors["Access-Control-Allow-Origin"] === "" && (request.headers.get("Origin") || "")) {
    return json({ ok: false, error: "CORS_NOT_ALLOWED" }, 403, cors);
  }

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON" }, 400, cors);
  }

  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !email.includes("@")) {
    return json({ ok: false, error: "INVALID_EMAIL" }, 400, cors);
  }
  if (password.length < 8) {
    return json({ ok: false, error: "WEAK_PASSWORD" }, 400, cors);
  }

  const db = env.DB;
  if (!db) return json({ ok: false, error: "NO_DB_BINDING" }, 500, cors);

  const now = Date.now();
  const otp = makeOtp6();
  const otpSecret = (env.OTP_SECRET || env.JWT_SECRET || "otp_secret").toString();
  const otpHash = await sha256Hex(bytesFromString(`${email}|${otp}|${otpSecret}`));
  const otpExpiresAt = now + 10 * 60 * 1000;

  // وجود المستخدم؟
  let user = null;
  try {
    user = await db
      .prepare("SELECT id, email_verified_at, otp_last_sent_at FROM users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();
  } catch (e) {
    // لو جدول/أعمدة مختلفة، عطنا خطأ واضح بدل “سيرفر”
    return json({ ok: false, error: "DB_SCHEMA_ERROR", detail: String(e?.message || e) }, 500, cors);
  }

  // Rate limit للإرسال (60 ثانية)
  if (user?.otp_last_sent_at && now - Number(user.otp_last_sent_at) < 60_000) {
    const leftMs = 60_000 - (now - Number(user.otp_last_sent_at));
    return json(
      { ok: false, error: "OTP_RATE_LIMIT", retryAfterSec: Math.ceil(leftMs / 1000) },
      429,
      cors
    );
  }

  // إذا البريد متحقق مسبقًا -> ما نسجل مرة ثانية
  if (user?.email_verified_at) {
    return json({ ok: false, error: "EMAIL_EXISTS" }, 409, cors);
  }

  // خزّن/حدّث المستخدم + OTP
  try {
    const passwordHash = await hashPasswordPBKDF2(password);

    if (user?.id) {
      await db
        .prepare(
          "UPDATE users SET password_hash = ?, otp_hash = ?, otp_expires_at = ?, otp_last_sent_at = ? WHERE email = ?"
        )
        .bind(passwordHash, otpHash, otpExpiresAt, now, email)
        .run();
    } else {
      await db
        .prepare(
          "INSERT INTO users (email, password_hash, created_at, email_verified_at, otp_hash, otp_expires_at, otp_last_sent_at) VALUES (?, ?, ?, NULL, ?, ?, ?)"
        )
        .bind(email, passwordHash, now, otpHash, otpExpiresAt, now)
        .run();
    }
  } catch (e) {
    return json({ ok: false, error: "DB_WRITE_FAILED", detail: String(e?.message || e) }, 500, cors);
  }

  // أرسل OTP عبر Resend
  try {
    await sendOtpEmail({ env, toEmail: email, otp });
  } catch (e) {
    return json({ ok: false, error: "EMAIL_SEND_FAILED", detail: String(e?.message || e) }, 502, cors);
  }

  return json({ ok: true, next: "verify_email" }, 200, cors);
}

// functions/api2/register.js — إصدار 2
