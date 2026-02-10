// functions/api2/resend-otp.js
// api2-resend-otp-v1 (Resend OTP email)

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
    allowOrigin = origin || "";
  } else {
    const allowed = allowedRaw.split(",").map(s => s.trim()).filter(Boolean);
    if (allowed.includes("*")) allowOrigin = "*";
    else if (origin && allowed.includes(origin)) allowOrigin = origin;
    else allowOrigin = "";
  }

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin",
  };
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

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function generateOtp6() {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  const n = arr[0] % 1000000;
  return String(n).padStart(6, "0");
}

async function sendViaResend({ apiKey, from, to, subject, html, text }) {
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to,
      subject,
      html,
      text,
    }),
  });

  const data = await r.json().catch(() => null);
  if (!r.ok) {
    const msg = data?.message || data?.error || `RESEND_HTTP_${r.status}`;
    throw new Error(msg);
  }
  return data; // { id: ... }
}

function otpEmailHtml({ otp }) {
  return `
  <div style="font-family:Arial,Helvetica,sans-serif;direction:rtl;text-align:right">
    <h2 style="margin:0 0 10px">رمز التحقق</h2>
    <p style="margin:0 0 12px">رمزك لتأكيد البريد الإلكتروني هو:</p>
    <div style="font-size:28px;font-weight:700;letter-spacing:4px;background:#f5f5f5;padding:12px 16px;border-radius:10px;display:inline-block">
      ${otp}
    </div>
    <p style="margin:14px 0 0;color:#666">ينتهي خلال 10 دقائق. إذا ما طلبته، تجاهل الرسالة.</p>
    <hr style="border:none;border-top:1px solid #eee;margin:18px 0" />
    <p style="margin:0;color:#999;font-size:12px">© صندوق المسابقات</p>
  </div>
  `.trim();
}

export async function onRequest(context) {
  const { request, env } = context;
  const cors = makeCorsHeaders(request, env);

  if (cors["Access-Control-Allow-Origin"] === "" && (request.headers.get("Origin") || "")) {
    return json({ ok: false, error: "CORS_NOT_ALLOWED" }, 403, cors);
  }

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405, cors);
  }

  const db = env.DB;
  if (!db) return json({ ok: false, error: "NO_DB_BINDING" }, 500, cors);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON" }, 400, cors);
  }

  const email = normalizeEmail(body.email);
  if (!email || !email.includes("@")) {
    return json({ ok: false, error: "INVALID_EMAIL" }, 400, cors);
  }

  const resendKey = (env.RESEND_API_KEY || "").toString().trim();
  if (!resendKey) {
    return json({ ok: false, error: "MISSING_RESEND_API_KEY" }, 500, cors);
  }

  const fromEmail = (env.MAIL_FROM || env.RESEND_FROM || "support@sandooq-games.com").toString().trim();
  const from = `صندوق المسابقات <${fromEmail}>`;

  const now = Date.now();
  const otp = generateOtp6();
  const otpSecret = (env.OTP_SECRET || env.JWT_SECRET || "otp_secret").toString();
  const otpHash = await sha256Hex(bytesFromString(`${email}|${otp}|${otpSecret}`));
  const expiresAt = now + (10 * 60 * 1000); // 10 min

  // 1) Read user + (optional) rate limit
  let user;
  let hasOtpSentAt = true;

  try {
    user = await db
      .prepare("SELECT id, email_verified_at, otp_sent_at FROM users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();
  } catch {
    hasOtpSentAt = false;
    user = await db
      .prepare("SELECT id, email_verified_at FROM users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();
  }

  // أمنياً: لا نفضح هل الإيميل موجود أو لا
  if (!user?.id) {
    return json({ ok: true, queued: true }, 200, cors);
  }

  if (user.email_verified_at) {
    return json({ ok: true, alreadyVerified: true }, 200, cors);
  }

  if (hasOtpSentAt && user.otp_sent_at) {
    const last = Number(user.otp_sent_at) || 0;
    const diff = now - last;
    if (diff < 60_000) {
      const waitSec = Math.ceil((60_000 - diff) / 1000);
      return json({ ok: false, error: "WAIT_BEFORE_RESEND", waitSec }, 429, cors);
    }
  }

  // 2) Update OTP in DB
  try {
    if (hasOtpSentAt) {
      await db
        .prepare("UPDATE users SET otp_hash = ?, otp_expires_at = ?, otp_sent_at = ? WHERE id = ?")
        .bind(otpHash, expiresAt, now, user.id)
        .run();
    } else {
      await db
        .prepare("UPDATE users SET otp_hash = ?, otp_expires_at = ? WHERE id = ?")
        .bind(otpHash, expiresAt, user.id)
        .run();
    }
  } catch (e) {
    return json({ ok: false, error: "DB_WRITE_FAILED", detail: String(e?.message || e) }, 500, cors);
  }

  // 3) Send email
  try {
    const subject = "رمز التحقق - صندوق المسابقات";
    const html = otpEmailHtml({ otp });
    const text = `رمز التحقق: ${otp}\nينتهي خلال 10 دقائق.`;

    const resp = await sendViaResend({
      apiKey: resendKey,
      from,
      to: email,
      subject,
      html,
      text,
    });

    return json({ ok: true, sent: true, resendId: resp?.id || null }, 200, cors);
  } catch (e) {
    return json({ ok: false, error: "EMAIL_SEND_FAILED", detail: String(e?.message || e) }, 500, cors);
  }
}

// functions/api2/resend-otp.js — إصدار 1
