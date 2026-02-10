// functions/api2/register.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-register-v2-otp-mailchannels";

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
  const password = String(body?.password || "");

  if (!email || !password) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }
  if (!isValidEmail(email)) {
    return json({ ok: false, error: "INVALID_EMAIL", version: VERSION }, 400, cors);
  }
  if (password.length < 8) {
    return json({ ok: false, error: "WEAK_PASSWORD", version: VERSION }, 400, cors);
  }

  // ---- ensure schema ----
  await ensureUsersColumns(env.DB);
  await ensureEmailOtpsTable(env.DB);

  // Existing?
  const exists = await env.DB.prepare(
    `SELECT email FROM users WHERE email = ? LIMIT 1`
  ).bind(email).first();

  if (exists) {
    return json({ ok: false, error: "EMAIL_EXISTS", version: VERSION }, 409, cors);
  }

  // ---- password hash (salt + sha256) ----
  const saltBytes = new Uint8Array(16);
  crypto.getRandomValues(saltBytes);
  const saltB64 = bytesToBase64(saltBytes);

  const pwBytes = new TextEncoder().encode(password);
  const hashB64 = await sha256Base64(concatBytes(saltBytes, pwBytes));

  const nowIso = new Date().toISOString();

  // Insert user (غير متحقق)
  await env.DB.prepare(
    `INSERT INTO users (email, provider, password_hash, salt_b64, created_at, is_email_verified)
     VALUES (?, 'email', ?, ?, ?, 0)`
  ).bind(email, hashB64, saltB64, nowIso).run();

  // ---- create OTP ----
  const otp = String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
  const pepper = String(env.OTP_PEPPER || "otp_pepper_v1");
  const otpHash = await sha256Hex(otp + "|" + pepper);

  const expIso = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 minutes

  await env.DB.prepare(
    `INSERT INTO email_otps (email, otp_hash, created_at, expires_at, used_at, attempts)
     VALUES (?, ?, ?, ?, NULL, 0)`
  ).bind(email, otpHash, nowIso, expIso).run();

  // ---- send email via MailChannels ----
  const fromEmail = String(env.MAIL_FROM || "").trim();      // مثال: no-reply@yourdomain.com
  const fromName  = String(env.MAIL_FROM_NAME || "صندوق المسابقات").trim();
  const subject   = String(env.OTP_SUBJECT || "رمز التحقق").trim();

  // لو البريد غير مضبوط: نسمح بالاختبار عبر OTP_DEBUG
  if (!fromEmail) {
    const out = { ok: true, version: VERSION, email, mail: "NOT_CONFIGURED" };
    if (String(env.OTP_DEBUG || "0") === "1") out.debugOtp = otp; // للاختبار فقط
    return json(out, 200, cors);
  }

  const html = buildHtml(fromName, otp);
  const text = `رمز التحقق: ${otp}\n\nمدة صلاحية الرمز 10 دقائق. إذا ما طلبت الرمز تجاهل الرسالة.`;

  const sendRes = await sendMailchannels({
    to: email,
    fromEmail,
    fromName,
    subject,
    html,
    text,
  });

  if (!sendRes.ok) {
    // ما نخرب إنشاء الحساب — لكن نرجع خطأ واضح عشان تعرف أنه الإرسال فشل
    const out = { ok: false, error: "MAIL_SEND_FAILED", version: VERSION, detail: sendRes.detail };
    if (String(env.OTP_DEBUG || "0") === "1") out.debugOtp = otp;
    return json(out, 502, cors);
  }

  const out = { ok: true, version: VERSION, email };
  if (String(env.OTP_DEBUG || "0") === "1") out.debugOtp = otp;
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

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
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

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

async function ensureUsersColumns(DB) {
  await DB.prepare(`ALTER TABLE users ADD COLUMN is_email_verified INTEGER DEFAULT 0`).run().catch(() => {});
  await DB.prepare(`ALTER TABLE users ADD COLUMN email_verified_at TEXT`).run().catch(() => {});
}

async function ensureEmailOtpsTable(DB) {
  await DB.prepare(
    `CREATE TABLE IF NOT EXISTS email_otps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      attempts INTEGER DEFAULT 0
    )`
  ).run();
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_email_otps_email ON email_otps(email)`).run().catch(() => {});
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

// functions/api2/register.js – api2-register-v2-otp-mailchannels
