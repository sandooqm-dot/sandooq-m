export async function onRequest({ request, env }) {
  const cors = {
    "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
  };

  const json = (obj, status = 200) =>
    new Response(JSON.stringify(obj), {
      status,
      headers: { "content-type": "application/json; charset=utf-8", ...cors },
    });

  if (request.method === "OPTIONS") return new Response("", { headers: cors });
  if (request.method !== "POST") return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON" }, 400);
  }

  const email = normalizeEmail(body?.email);
  const password = typeof body?.password === "string" ? body.password : "";

  if (!email || !password) return json({ ok: false, error: "MISSING_FIELDS" }, 400);
  if (!isValidEmail(email)) return json({ ok: false, error: "INVALID_EMAIL" }, 400);
  if (password.length < 6) return json({ ok: false, error: "WEAK_PASSWORD" }, 400);

  // لو الإيميل صار "مؤكد" قبل كذا (موجود في users) نمنع التسجيل
  const existingUser = await env.DB.prepare(
    `SELECT email FROM users WHERE email = ? LIMIT 1`
  ).bind(email).first();

  if (existingUser) {
    return json({ ok: false, error: "EMAIL_EXISTS" }, 409);
  }

  // نخزن التسجيل مؤقت في pending_users فقط (بدون users)
  const now = new Date().toISOString();
  const password_hash = await hashPasswordPBKDF2(password, env.PASSWORD_PEPPER || "");

  await env.DB.prepare(
    `INSERT INTO pending_users (email, password_hash, created_at, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(email) DO UPDATE SET
       password_hash = excluded.password_hash,
       updated_at = excluded.updated_at`
  ).bind(email, password_hash, now, now).run();

  // OTP جديد
  const otp = genOTP6();
  const expires_at = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 دقائق

  await env.DB.prepare(`DELETE FROM email_otps WHERE email = ?`).bind(email).run();
  await env.DB.prepare(
    `INSERT INTO email_otps (email, otp, expires_at, created_at) VALUES (?, ?, ?, ?)`
  ).bind(email, otp, expires_at, now).run();

  // إرسال عبر Resend
  const sent = await sendOtpWithResend(env, email, otp);
  if (!sent.ok) {
    return json({ ok: false, error: "EMAIL_SEND_FAILED", detail: sent.detail }, 500);
  }

  return json({ ok: true, email, expires_at });
}

/* ---------------- helpers ---------------- */

function normalizeEmail(v) {
  return (typeof v === "string" ? v.trim().toLowerCase() : "");
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function genOTP6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function hashPasswordPBKDF2(password, pepper) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password + pepper),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  // مهم: Cloudflare ما يدعم فوق 100000
  const iterations = 100000;

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    256
  );

  const hash = new Uint8Array(bits);
  return `pbkdf2$${iterations}$${b64(salt)}$${b64(hash)}`;
}

function b64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

async function sendOtpWithResend(env, toEmail, otp) {
  const apiKey = env.RESEND_API_KEY;
  const from = env.RESEND_FROM; // مثال: "Sandooq <onboarding@resend.dev>"
  if (!apiKey || !from) {
    return { ok: false, detail: "Missing RESEND_API_KEY or RESEND_FROM" };
  }

  const subject = "رمز تأكيد البريد";
  const html = `
    <div style="font-family:Arial;direction:rtl;text-align:right">
      <h2>رمز التحقق</h2>
      <p>رمزك هو:</p>
      <div style="font-size:28px;font-weight:bold;letter-spacing:3px">${otp}</div>
      <p style="color:#666">ينتهي خلال 10 دقائق.</p>
    </div>
  `;

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [toEmail],
      subject,
      html,
    }),
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    return { ok: false, detail: `Resend ${r.status}: ${t}` };
  }

  return { ok: true };
}
