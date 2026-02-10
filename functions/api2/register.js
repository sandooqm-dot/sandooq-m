// functions/api2/register.js
export async function onRequest(context) {
  const { request, env } = context;

  const cors = {
    "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: "api2-register-v3" }, 405, cors);
  }

  try {
    const body = await request.json().catch(() => ({}));
    let email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (!email || !email.includes("@")) {
      return json({ ok: false, error: "INVALID_EMAIL", version: "api2-register-v3" }, 400, cors);
    }
    if (password.length < 6) {
      return json({ ok: false, error: "WEAK_PASSWORD", version: "api2-register-v3" }, 400, cors);
    }

    // 1) هل المستخدم موجود؟
    const existing = await env.DB
      .prepare("SELECT id, email_verified FROM users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    // إذا موجود ومفعل فعلاً => ممنوع تسجيل جديد
    if (existing && Number(existing.email_verified) === 1) {
      return json({ ok: false, error: "EMAIL_EXISTS", version: "api2-register-v3" }, 409, cors);
    }

    // 2) Hash كلمة المرور (PBKDF2 iterations = 100000 فقط)
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hashB64 = await pbkdf2B64(password, salt, 100000);
    const saltB64 = toB64(salt);

    const now = Date.now();
    const userId = existing?.id || crypto.randomUUID();

    // 3) إنشاء OTP (6 أرقام كنص)
    const otp = String(Math.floor(Math.random() * 1000000)).padStart(6, "0");
    const expiresAt = now + 10 * 60 * 1000; // 10 دقائق

    // 4) حفظ بيانات المستخدم "غير مفعل" + حفظ/تحديث رمز التحقق
    // ملاحظة: هنا ما راح نخلي EMAIL_EXISTS يعلقك.. لو غير مفعل نحدّث ونرسل OTP جديد.
    if (!existing) {
      await env.DB.prepare(
        `INSERT INTO users (id, email, password_hash, password_salt, email_verified, created_at, updated_at)
         VALUES (?, ?, ?, ?, 0, ?, ?)`
      ).bind(userId, email, hashB64, saltB64, now, now).run();
    } else {
      await env.DB.prepare(
        `UPDATE users
         SET password_hash = ?, password_salt = ?, updated_at = ?
         WHERE id = ?`
      ).bind(hashB64, saltB64, now, userId).run();
    }

    // upsert على email_verifications (نفس الإيميل/اليوزر)
    await env.DB.prepare(
      `INSERT INTO email_verifications (user_id, token, expires_at, created_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         token = excluded.token,
         expires_at = excluded.expires_at,
         created_at = excluded.created_at`
    ).bind(userId, otp, expiresAt, now).run();

    // 5) إرسال الإيميل عبر Resend
    const resendKey = env.RESEND_API_KEY;
    if (!resendKey) {
      return json({ ok: false, error: "MISSING_RESEND_API_KEY", version: "api2-register-v3" }, 500, cors);
    }

    const from = env.RESEND_FROM || "Sandooq Games <onboarding@resend.dev>";
    const subject = "رمز تأكيد البريد الإلكتروني";
    const html = `
      <div style="font-family:Arial,sans-serif;direction:rtl;text-align:right">
        <h2>صندوق المسابقات</h2>
        <p>رمز التحقق الخاص بك هو:</p>
        <div style="font-size:32px;font-weight:bold;letter-spacing:4px">${otp}</div>
        <p>ينتهي خلال 10 دقائق.</p>
      </div>
    `;

    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${resendKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: email,
        subject,
        html,
      }),
    });

    if (!r.ok) {
      const t = await r.text().catch(() => "");
      console.log("resend_failed", r.status, t?.slice?.(0, 200));
      return json({ ok: false, error: "EMAIL_SEND_FAILED", version: "api2-register-v3" }, 500, cors);
    }

    return json({
      ok: true,
      pending: true,
      message: "OTP_SENT",
      version: "api2-register-v3",
    }, 200, cors);

  } catch (e) {
    console.log("register_error", e?.message || e);
    return json({ ok: false, error: "SERVER_ERROR", version: "api2-register-v3" }, 500, cors);
  }
}

function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

function toB64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

async function pbkdf2B64(password, saltU8, iterations) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltU8, iterations },
    key,
    256
  );

  return toB64(new Uint8Array(bits));
}
