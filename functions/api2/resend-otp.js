// functions/api2/resend-otp.js
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
  if (!email) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }

  const u = await env.DB.prepare("SELECT email, email_verified FROM auth_users WHERE email = ? LIMIT 1")
    .bind(email)
    .first();

  if (!u) {
    // لا نكشف إذا الإيميل موجود أو لا
    return json({ ok: true, version: VERSION }, 200, cors);
  }

  if (Number(u.email_verified || 0) === 1) {
    return json({ ok: false, error: "ALREADY_VERIFIED", version: VERSION }, 400, cors);
  }

  const now = Date.now();

  // Rate limit بسيط: إذا أرسلنا خلال آخر 30 ثانية لا نعيد
  const recent = await env.DB.prepare(
    "SELECT created_at FROM auth_email_otps WHERE email = ? ORDER BY created_at DESC LIMIT 1"
  )
    .bind(email)
    .first();

  if (recent && (now - Number(recent.created_at || 0) < 30 * 1000)) {
    return json({ ok: false, error: "TOO_MANY_REQUESTS", version: VERSION }, 429, cors);
  }

  const otp = makeOtp6();
  const otpSecret = String(env?.OTP_SECRET || "").trim();
  const otpHash = await sha256Hex(new TextEncoder().encode(`${email}|${otp}|${otpSecret || "dev"}`));

  const ttlMin = Number(env?.OTP_TTL_MINUTES || 10);
  const expiresAt = now + ttlMin * 60 * 1000;

  await env.DB.prepare(
    "INSERT INTO auth_email_otps (email, otp_hash, expires_at, created_at, used_at) VALUES (?, ?, ?, ?, NULL)"
  )
    .bind(email, otpHash, expiresAt, now)
    .run();

  // إرسال البريد
  const mailFrom = String(env?.MAIL_FROM || `no-reply@horof.sandooq-games.com`).trim();
  const mailFromName = String(env?.MAIL_FROM_NAME || "صندوق المسابقات").trim();

  const subject = "إعادة إرسال رمز تأكيد البريد الإلكتروني";
  const text =
    `رمز التحقق الخاص بك هو: ${otp}\n\n` +
    `تنبيه: لا تشارك الرمز مع أي شخص.\n` +
    `صلاحية الرمز: ${ttlMin} دقائق.`;

  const html = `
  <div style="font-family:Arial,Helvetica,sans-serif;direction:rtl;text-align:right;line-height:1.8">
    <h2 style="margin:0 0 10px">إعادة إرسال رمز التحقق</h2>
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
      if (String(env?.DEBUG_OTP || "") === "1") {
        return json({ ok: true, version: VERSION, otp_debug: otp }, 200, cors);
      }
      return json({ ok: false, error: "EMAIL_SEND_FAILED", version: VERSION }, 500, cors);
    }
  } catch (e) {
    if (String(env?.DEBUG_OTP || "") === "1") {
      return json({ ok: true, version: VERSION, otp_debug: otp }, 200, cors);
    }
    return json({ ok: false, error: "EMAIL_SEND_FAILED", version: VERSION }, 500, cors);
  }

  return json({ ok: true, version: VERSION }, 200, cors);
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

function normEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function makeOtp6() {
  const b = new Uint32Array(1);
  crypto.getRandomValues(b);
  const n = b[0] % 1000000;
  return String(n).padStart(6, "0");
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
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

// functions/api2/resend-otp.js – إصدار 1
