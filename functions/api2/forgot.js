// functions/api2/forgot.js
// POST /api2/forgot
// Sends password reset email (Resend) and stores reset token in D1

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin");
  const h = {
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "cache-control": "no-store",
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

function json(req, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS(req),
      "content-type": "application/json; charset=utf-8",
    },
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  // بسيط وعملي
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function base64urlFromBytes(arr) {
  let s = "";
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function makeToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return base64urlFromBytes(arr);
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(String(str));
  const digest = await crypto.subtle.digest("SHA-256", data);
  const b = new Uint8Array(digest);
  let hex = "";
  for (const x of b) hex += x.toString(16).padStart(2, "0");
  return hex;
}

async function ensureResetTable(DB) {
  // جدول بسيط وقوي + يشتغل حتى لو ما سويت migration
  await DB.prepare(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used_at INTEGER
    );
  `).run();

  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(email);`).run();
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_password_resets_expires ON password_resets(expires_at);`).run();
}

async function sendResend(env, toEmail, resetLink) {
  const apiKey = String(env.RESEND_API_KEY || "").trim();

  // ✅ التعديل الوحيد: دعم RESEND_FROM (اسمك الحالي) + دعم MAIL_FROM (لو نسخة قديمة)
  const from = String(env.RESEND_FROM || env.MAIL_FROM || "").trim();

  if (!apiKey || !from) {
    return { ok: false, error: "MAIL_NOT_CONFIGURED" };
  }

  const subject = "استعادة كلمة المرور - صندوق المسابقات";
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.8">
      <h2>استعادة كلمة المرور</h2>
      <p>اضغط الزر التالي لتغيير كلمة المرور:</p>
      <p>
        <a href="${resetLink}"
           style="display:inline-block;padding:12px 18px;border-radius:10px;background:#6d4bff;color:#fff;text-decoration:none;font-weight:700">
           تغيير كلمة المرور
        </a>
      </p>
      <p>إذا ما طلبت الاستعادة، تجاهل الرسالة.</p>
      <p style="color:#666;font-size:12px">الرابط صالح لمدة 30 دقيقة.</p>
    </div>
  `.trim();

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${apiKey}`,
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
    return { ok: false, error: "MAIL_SEND_FAILED", detail: t.slice(0, 400) };
  }

  return { ok: true };
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS(request) });
  }
  if (request.method !== "POST") {
    return json(request, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env?.DB) return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body?.email);

    if (!email) return json(request, { ok: false, error: "MISSING_FIELDS" }, 400);
    if (!isValidEmail(email)) return json(request, { ok: false, error: "INVALID_EMAIL" }, 400);

    await ensureResetTable(env.DB);

    // لا نكشف هل الإيميل موجود أو لا (أمان)
    const u = await env.DB.prepare(`SELECT email FROM users WHERE email = ? LIMIT 1`).bind(email).first();
    if (!u?.email) {
      return json(request, { ok: true }, 200);
    }

    // نلغي الروابط السابقة لهذا الإيميل (عشان ما تتكدس)
    await env.DB.prepare(`DELETE FROM password_resets WHERE email = ? AND used_at IS NULL`).bind(email).run();

    const token = makeToken(32);
    const tokenHash = await sha256Hex(token);

    const now = Date.now();
    const expires = now + 30 * 60 * 1000; // 30 دقيقة

    await env.DB.prepare(
      `INSERT INTO password_resets (email, token_hash, created_at, expires_at) VALUES (?,?,?,?)`
    ).bind(email, tokenHash, now, expires).run();

    const origin = new URL(request.url).origin;
    const resetLink = `${origin}/activate?reset=1&token=${encodeURIComponent(token)}`;

    const mail = await sendResend(env, email, resetLink);
    if (!mail.ok) {
      // عشان واجهتك تطلع نفس رسالة الصورة
      return json(request, { ok: false, error: mail.error }, 500);
    }

    return json(request, { ok: true }, 200);
  } catch (e) {
    console.log("forgot_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
forgot.js – api2 – إصدار 2 (RESEND_FROM supported + legacy MAIL_FROM)
*/
