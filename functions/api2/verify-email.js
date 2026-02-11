// functions/api2/verify-email.js
// Cloudflare Pages Function: POST /api2/verify-email

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
  "Access-Control-Max-Age": "86400",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS,
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

export async function onRequestOptions() {
  return new Response(null, { headers: CORS_HEADERS });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const otp = String(body.otp ?? "").trim();

    if (!email || !otp) {
      return json({ ok: false, error: "MISSING_FIELDS" }, 400);
    }

    // 1) نجيب بيانات التسجيل المؤقت من pending_users (هو اللي عندك فيه otp فعليًا)
    const pending = await env.DB
      .prepare("SELECT email, password_hash, otp FROM pending_users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    if (!pending) {
      return json({ ok: false, error: "OTP_NOT_FOUND" }, 404);
    }

    // لو ما تطابق
    if (String(pending.otp) !== otp) {
      return json({ ok: false, error: "OTP_NOT_FOUND" }, 404);
    }

    // 2) ننقل الحساب إلى users (الهدف: بعد OTP يصير “مسجل فعليًا” ويقدر يسوي Login)
    // نحاول إدخال بأبسط شكل (email + password_hash) عشان ما نصطدم بأعمدة إضافية.
    try {
      await env.DB
        .prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)")
        .bind(email, pending.password_hash)
        .run();
    } catch (e) {
      // إذا موجود مسبقًا (UNIQUE) نتجاهل ونكمل
      const msg = String(e?.message || "");
      if (!msg.includes("UNIQUE") && !msg.includes("constraint")) throw e;
    }

    // 3) نحذف التسجيل المؤقت (عشان ما يرجع يقول “مسجل مسبقًا” بسبب pending)
    await env.DB.prepare("DELETE FROM pending_users WHERE email = ?").bind(email).run();

    // (اختياري) تنظيف أي OTP قديم إن كان فيه جدول email_otps
    try {
      await env.DB.prepare("DELETE FROM email_otps WHERE email = ?").bind(email).run();
    } catch (_) {}

    return json({ ok: true, email, verified: true });
  } catch (err) {
    console.log("verify_email_error", String(err?.message || err));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
verify-email.js – api2 – إصدار 1
*/
