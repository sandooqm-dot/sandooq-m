// functions/api2/reset.js
// POST /api2/reset  -> يرسل رابط إعادة تعيين كلمة المرور على الإيميل

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

function b64url(bytes) {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function makeToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return b64url(arr);
}

async function sha256B64Url(str) {
  const data = new TextEncoder().encode(String(str || ""));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return b64url(new Uint8Array(digest));
}

async function ensureResetTable(DB) {
  await DB.prepare(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT
    )
  `).run();

  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(email)`).run();
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token_hash)`).run();
}

async function sendResendEmail(apiKey, from, to, subject, html) {
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ from, to, subject, html }),
  });

  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, json: j };
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
    if (!email) return json(request, { ok: false, error: "MISSING_EMAIL" }, 400);

    // نجهّز جدول الاستعادة (مرة واحدة)
    await ensureResetTable(env.DB);

    // (اختياري) تأكد الإيميل موجود بدون ما نفضح النتيجة للعميل
    const user = await env.DB.prepare(`SELECT email, provider FROM users WHERE email=? LIMIT 1`)
      .bind(email)
      .first();

    // لو المستخدم غير موجود: نرجع ok برضه (حتى ما نكشف)
    if (!user?.email) {
      return json(request, { ok: true }, 200);
    }

    // لو حسابه Google: نخليه ok (وتقدر لاحقًا تعرض له رسالة “ادخل بجوجل” من الواجهة)
    if (String(user.provider || "").toLowerCase() === "google") {
      return json(request, { ok: true }, 200);
    }

    const resendKey = String(env.RESEND_API_KEY || "").trim();
    const from = String(env.RESEND_FROM || env.MAIL_FROM || "").trim(); // RESEND_FROM هو الأساس عندك

    if (!resendKey) return json(request, { ok: false, error: "RESEND_API_KEY_MISSING" }, 500);
    if (!from) return json(request, { ok: false, error: "RESEND_FROM_MISSING" }, 500);

    // توليد توكن + حفظ هاش
    const token = makeToken(32);
    const tokenHash = await sha256B64Url(token);

    const now = new Date();
    const createdAt = now.toISOString();
    const exp = new Date(now.getTime() + 30 * 60 * 1000); // 30 دقيقة
    const expiresAt = exp.toISOString();

    await env.DB.prepare(`
      INSERT INTO password_resets (email, token_hash, created_at, expires_at)
      VALUES (?, ?, ?, ?)
    `).bind(email, tokenHash, createdAt, expiresAt).run();

    const origin = new URL(request.url).origin;
    const link = `${origin}/activate?reset=${encodeURIComponent(token)}`;

    const subject = "إعادة تعيين كلمة المرور - صندوق المسابقات";
    const html = `
      <div style="font-family:Arial,sans-serif;direction:rtl;text-align:right">
        <h2>إعادة تعيين كلمة المرور</h2>
        <p>اضغط الرابط التالي لتعيين كلمة مرور جديدة (صالح لمدة 30 دقيقة):</p>
        <p><a href="${link}">${link}</a></p>
        <p style="color:#666;font-size:12px">إذا ما طلبت الاستعادة تجاهل الرسالة.</p>
      </div>
    `;

    const sent = await sendResendEmail(resendKey, from, email, subject, html);
    if (!sent.ok) {
      console.log("reset_send_failed", sent.status, sent.json);
      return json(request, { ok: false, error: "MAIL_SEND_FAILED" }, 500);
    }

    return json(request, { ok: true }, 200);
  } catch (e) {
    console.log("reset_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
reset.js – api2 – إصدار 1 (Resend: RESEND_API_KEY + RESEND_FROM)
*/
