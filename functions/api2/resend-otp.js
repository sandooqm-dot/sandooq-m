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
  if (!isValidEmail(email)) {
    return json({ ok: false, error: "INVALID_EMAIL", version: VERSION }, 400, cors);
  }

  // ---- ensure schema ----
  await ensureUsersColumns(env.DB);
  await ensureOtpTable(env.DB);

  // لازم يكون الحساب موجود (إنشاء الحساب يسويه /api2/register)
  const user = await env.DB.prepare(
    `SELECT email, is_email_verified
     FROM users
     WHERE email = ?
     LIMIT 1`
  ).bind(email).first();

  if (!user) {
    return json({ ok: false, error: "USER_NOT_FOUND", version: VERSION }, 404, cors);
  }

  if (Number(user.is_email_verified || 0) === 1) {
    // خلاص متأكد
    return json({ ok: true, version: VERSION, alreadyVerified: true }, 200, cors);
  }

  const now = Date.now();
  const isoNow = new Date().toISOString();

  // rate limit: لا تعيد الإرسال قبل 60 ثانية
  const prev = await env.DB.prepare(
    `SELECT last_sent_at FROM email_otps WHERE email = ? LIMIT 1`
  ).bind(email).first();

  if (prev?.last_sent_at) {
    const last = Date.parse(String(prev.last_sent_at));
    if (last && (now - last) < 60_000) {
      return json({ ok: false, error: "OTP_TOO_SOON", version: VERSION }, 429, cors);
    }
  }

  // توليد OTP (6 أرقام)
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const pepper = String(env.OTP_PEPPER || "otp_pepper_v1");
  const otpHash = await sha256Hex(`${email}|${otp}|${pepper}`);

  // صلاحية 10 دقائق
  const expiresAt = new Date(now + 10 * 60_000).toISOString();

  // upsert otp row
  await env.DB.prepare(
    `INSERT INTO email_otps (email, otp_hash, expires_at, used_at, attempts, last_sent_at)
     VALUES (?, ?, ?, NULL, 0, ?)
     ON CONFLICT(email) DO UPDATE SET
       otp_hash = excluded.otp_hash,
       expires_at = excluded.expires_at,
       used_at = NULL,
       attempts = 0,
       last_sent_at = excluded.last_sent_at`
  ).bind(email, otpHash, expiresAt, isoNow).run();

  // إرسال الإيميل عبر MailChannels (Cloudflare-friendly)
  const fromEmail = String(env.MAIL_FROM || "").trim(); // مثال: no-reply@horofgame.com
  const fromName = String(env.MAIL_FROM_NAME || "صندوق المسابقات").trim();
  const subject = String(env.OTP_SUBJECT || "رمز التحقق").trim();

  if (!fromEmail) {
    // للتجربة: لو ما ضبطت MAIL_FROM بنرجّع خطأ واضح
    // (وتقدر تشغّل وضع DEBUG لإظهار الرمز)
    const resp = { ok: false, error: "MAIL_NOT_CONFIGURED", version: VERSION };
    if (String(env.OTP_DEBUG || "0") === "1") resp.debugOtp = otp;
    return json(resp, 500, cors);
  }

  const html = buildHtml(fromName, otp);
  const text = `رمز التحقق: ${otp}\n\nإذا ما طلبت الرمز تجاهل الرسالة.`;

  const mailRes = await sendMailchannels({
    to: email,
    fromEmail,
    fromName,
    subject,
    html,
    text,
  });

  if (!mailRes.ok) {
    const resp = { ok: false, error: "MAIL_SEND_FAILED", version: VERSION, detail: mailRes.detail };
    if (String(env.OTP_DEBUG || "0") === "1") resp.debugOtp = otp;
    return json(resp, 502, cors);
  }

  const out = { ok: true, version: VERSION };
  if (String(env.OTP_DEBUG || "0") === "1") out.debugOtp = otp; // للتجربة فقط
  return json(out, 200, cors);
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
  const allowedRaw = String(env?.ALLOWED_ORIGINS || "").trim();
  let allowOrigin = "*";

  if (allowedRaw) {
    const allowed = allowedRaw.split(",").map(s => s.trim()).filter(Boolean);
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

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function ensureOtpTable(DB) {
  await DB.prepare(
    `CREATE TABLE IF NOT EXISTS email_otps (
      email TEXT PRIMARY KEY,
      otp_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      attempts INTEGER DEFAULT 0,
      last_sent_at TEXT
    )`
  ).run();
}

async function ensureUsersColumns(DB) {
  await DB.prepare(`ALTER TABLE users ADD COLUMN is_email_verified INTEGER DEFAULT 0`).run().catch(() => {});
  await DB.prepare(`ALTER TABLE users ADD COLUMN email_verified_at TEXT`).run().catch(() => {});
}

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

function buildHtml(brand, otp) {
  return `
  <div style="font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif;line-height:1.8">
    <h2 style="margin:0 0 10px">${escapeHtml(brand)}</h2>
    <p style="margin:0 0 10px">رمز التحقق الخاص بك هو:</p>
    <div style="font-size:28px;font-weight:900;letter-spacing:3px;background:#f2f2f2;padding:10px 14px;border-radius:10px;display:inline-block">
      ${escapeHtml(otp)}
    </div>
    <p style="margin:14px 0 0;color:#666">مدة صلاحية الرمز 10 دقائق. إذا ما طلبت الرمز تجاهل الرسالة.</p>
  </div>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

async function sendMailchannels({ to, fromEmail, fromName, subject, html, text }) {
  try {
    const payload = {
      personalizations: [{ to: [{ email: to }] }],
      from: { email: fromEmail, name: fromName },
      subject,
      content: [
        { type: "text/plain", value: text },
        { type: "text/html", value: html },
      ],
    };

    const r = await fetch("https://api.mailchannels.net/tx/v1/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!r.ok) {
      const t = await r.text().catch(() => "");
      return { ok: false, detail: `HTTP_${r.status}:${t.slice(0, 200)}` };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, detail: String(e?.message || e) };
  }
}
