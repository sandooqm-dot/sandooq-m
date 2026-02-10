// functions/api2/register.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-register-v1-otp-mail";

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

  let body = null;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON", version: VERSION }, 400, cors);
  }

  const email = normEmail(body?.email);
  const password = String(body?.password || "");
  const deviceId = String(request.headers.get("X-Device-Id") || "").trim();

  if (!email || !password) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }

  if (!isValidEmail(email)) {
    return json({ ok: false, error: "INVALID_EMAIL", version: VERSION }, 400, cors);
  }

  if (password.length < 8) {
    return json({ ok: false, error: "WEAK_PASSWORD", version: VERSION }, 400, cors);
  }

  // 1) إذا موجود
  const exists = await env.DB.prepare("SELECT email FROM auth_users WHERE email = ? LIMIT 1")
    .bind(email)
    .first();

  if (exists) {
    return json({ ok: false, error: "EMAIL_EXISTS", version: VERSION }, 409, cors);
  }

  // 2) إنشاء المستخدم (PBKDF2)
  const nowIso = new Date().toISOString();
  const createdAtMs = Date.now();

  const { saltB64, hashB64 } = await pbkdf2Hash(password, {
    iterations: Number(env?.PBKDF2_ITERS || 120000),
  });

  await env.DB.prepare(
    "INSERT INTO auth_users (email, provider, password_hash, salt_b64, email_verified, created_at) VALUES (?, 'email', ?, ?, 0, ?)"
  )
    .bind(email, hashB64, saltB64, nowIso)
    .run();

  // 3) توليد OTP وتخزينه (hashed)
  const otp = makeOtp6();
  const otpSecret = String(env?.OTP_SECRET || "").trim();
  const otpHash = await sha256Hex(new TextEncoder().encode(`${email}|${otp}|${otpSecret || "dev"}`));

  const ttlMin = Number(env?.OTP_TTL_MINUTES || 10);
  const expiresAt = createdAtMs + ttlMin * 60 * 1000;

  await env.DB.prepare(
    "INSERT INTO auth_email_otps (email, otp_hash, expires_at, created_at, used_at) VALUES (?, ?, ?, ?, NULL)"
  )
    .bind(email, otpHash, expiresAt, createdAtMs)
    .run();

  // 4) إرسال البريد
  const mailFrom = String(env?.MAIL_FROM || `no-reply@horof.sandooq-games.com`).trim();
  const mailFromName = String(env?.MAIL_FROM_NAME || "صندوق المسابقات").trim();

  const subject = "رمز تأكيد البريد الإلكتروني";
  const text =
    `رمز التحقق الخاص بك هو: ${otp}\n\n` +
    `تنبيه: لا تشارك الرمز مع أي شخص.\n` +
    `صلاحية الرمز: ${ttlMin} دقائق.`;

  const html = `
  <div style="font-family:Arial,Helvetica,sans-serif;direction:rtl;text-align:right;line-height:1.8">
    <h2 style="margin:0 0 10px">تأكيد البريد الإلكتروني</h2>
    <p style="margin:0 0 12px">رمز التحقق الخاص بك هو:</p>
    <div style="font-size:28px;font-weight:800;letter-spacing:3px;background:#f2f2f2;padding:12px 16px;border-radius:12px;display:inline-block">
      ${otp}
    </div>
    <p style="margin:14px 0 0;color:#444">صلاحية الرمز: <b>${ttlMin} دقائق</b></p>
    <p style="margin:6px 0 0;color:#777;font-size:13px">إذا لم تطلب هذا الرمز تجاهل الرسالة.</p>
    <hr style="border:none;border-top:1px solid #eee;margin:16px 0">
    <div style="color:#999;font-size:12px">© صندوق المسابقات</div>
  </div>`;

  try {
    const sent = await sendViaMailchannels({
      toEmail: email,
      fromEmail: mailFrom,
      fromName: mailFromName,
      subject,
      text,
      html,
    });

    if (!sent) {
      // لو تبي تختبر بدون بريد: حط DEBUG_OTP=1 في Bindings (Environment variables)
      if (String(env?.DEBUG_OTP || "") === "1") {
        return json({ ok: true, version: VERSION, email, otp_debug: otp }, 200, cors);
      }
      return json(
        { ok: false, error: "EMAIL_SEND_FAILED", version: VERSION, message: "OTP saved but email sending failed." },
        500,
        cors
      );
    }
  } catch (e) {
    if (String(env?.DEBUG_OTP || "") === "1") {
      return json({ ok: true, version: VERSION, email, otp_debug: otp }, 200, cors);
    }
    return json(
      { ok: false, error: "EMAIL_SEND_FAILED", version: VERSION, message: String(e?.message || e) },
      500,
      cors
    );
  }

  // (اختياري) deviceId موجود لكن ما نستخدمه هنا — الربط بالأجهزة بيكون في /api2/activate
  void deviceId;

  return json({ ok: true, version: VERSION, email }, 200, cors);
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

function normEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function makeOtp6() {
  const b = new Uint32Array(1);
  crypto.getRandomValues(b);
  const n = b[0] % 1000000;
  return String(n).padStart(6, "0");
}

async function pbkdf2Hash(password, { iterations = 120000 } = {}) {
  const saltBytes = new Uint8Array(16);
  crypto.getRandomValues(saltBytes);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    key,
    256
  );

  const hashBytes = new Uint8Array(bits);
  return { saltB64: bytesToBase64(saltBytes), hashB64: bytesToBase64(hashBytes) };
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

async function sendViaMailchannels({ toEmail, fromEmail, fromName, subject, text, html }) {
  const payload = {
    personalizations: [{ to: [{ email: toEmail }] }],
    from: { email: fromEmail, name: fromName || "" },
    subject,
    content: [
      { type: "text/plain", value: text || "" },
      { type: "text/html", value: html || "" },
    ],
  };

  const res = await fetch("https://api.mailchannels.net/tx/v1/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });

  return res.ok;
}

// functions/api2/register.js – إصدار 1
