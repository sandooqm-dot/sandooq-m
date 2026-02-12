// functions/api2/forgot.js
// POST /api2/forgot  { email }

const CORS_HEADERS = (req, env) => {
  const origin = req.headers.get("origin") || "";
  const allowed = String(env?.ALLOWED_ORIGINS || "").trim();

  const h = {
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "cache-control": "no-store",
    "Vary": "Origin",
  };

  if (origin && allowed) {
    const list = allowed.split(",").map(s => s.trim()).filter(Boolean);
    if (list.includes(origin)) {
      h["Access-Control-Allow-Origin"] = origin;
      h["Access-Control-Allow-Credentials"] = "true";
      return h;
    }
  }

  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

function json(req, env, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS(req, env), "content-type": "application/json; charset=utf-8" },
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function b64url(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(text)));
  const arr = Array.from(new Uint8Array(buf));
  return arr.map(b => b.toString(16).padStart(2, "0")).join("");
}

async function ensureTable(DB) {
  await DB.prepare(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL
    );
  `).run();

  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_pwreset_email ON password_resets(email);`).run();
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_pwreset_hash ON password_resets(token_hash);`).run();
}

async function sendEmail(env, to, subject, text, html) {
  const fromEmail =
    String(env.MAIL_FROM || env.FROM_EMAIL || "").trim();
  const fromName =
    String(env.MAIL_FROM_NAME || "صندوق المسابقات").trim();

  // 1) Resend (إذا موجود)
  const resendKey = String(env.RESEND_API_KEY || "").trim();
  if (resendKey && fromEmail) {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${resendKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from: `${fromName} <${fromEmail}>`,
        to: [to],
        subject,
        html,
        text,
      }),
    });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      throw new Error("RESEND_FAILED: " + (j?.message || r.status));
    }
    return;
  }

  // 2) MailChannels (بدون مفتاح غالبًا على Cloudflare)
  if (fromEmail) {
    const r = await fetch("https://api.mailchannels.net/tx/v1/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: fromEmail, name: fromName },
        subject,
        content: [
          { type: "text/plain", value: text },
          { type: "text/html", value: html },
        ],
      }),
    });

    if (!r.ok) {
      const t = await r.text().catch(() => "");
      throw new Error("MAILCHANNELS_FAILED: " + r.status + " " + t);
    }
    return;
  }

  throw new Error("MAIL_NOT_CONFIGURED");
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS(request, env) });
  }
  if (request.method !== "POST") {
    return json(request, env, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env.DB) return json(request, env, { ok: false, error: "DB_NOT_BOUND" }, 500);

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body?.email);
    if (!email) return json(request, env, { ok: false, error: "MISSING_FIELDS" }, 400);
    if (!email.includes("@")) return json(request, env, { ok: false, error: "INVALID_EMAIL" }, 400);

    // ما نكشف هل الإيميل موجود أو لا (أمان)
    const user = await env.DB.prepare(
      `SELECT 1 AS ok FROM users WHERE email = ? LIMIT 1`
    ).bind(email).first();

    // جهّز الجدول
    await ensureTable(env.DB);

    // لو المستخدم موجود: نسوي توكن ونخزنه ونرسل
    if (user?.ok) {
      const raw = b64url(crypto.getRandomValues(new Uint8Array(32)));
      const pepper = String(env.RESET_TOKEN_PEPPER || env.JWT_SECRET || "").trim();
      const tokenHash = await sha256Hex(raw + ":" + pepper);

      const now = Date.now();
      const expiresAt = new Date(now + 30 * 60 * 1000).toISOString(); // 30 دقيقة
      const createdAt = new Date(now).toISOString();

      await env.DB.prepare(
        `INSERT INTO password_resets (email, token_hash, expires_at, created_at)
         VALUES (?, ?, ?, ?)`
      ).bind(email, tokenHash, expiresAt, createdAt).run();

      const origin = new URL(request.url).origin;
      const resetLink = `${origin}/activate?reset=1&token=${encodeURIComponent(raw)}`;

      const subject = "استعادة كلمة المرور - صندوق المسابقات";
      const text =
`طلبت استعادة كلمة المرور لحسابك في صندوق المسابقات.

افتح الرابط لإعادة تعيين كلمة المرور:
${resetLink}

إذا ما أنت اللي طلبت، تجاهل الرسالة.`;

      const html = `
        <div style="font-family:system-ui,-apple-system,Segoe UI,Arial;line-height:1.8">
          <h2 style="margin:0 0 8px">استعادة كلمة المرور</h2>
          <p>تم طلب استعادة كلمة المرور لحسابك في <b>صندوق المسابقات</b>.</p>
          <p><a href="${resetLink}" style="display:inline-block;padding:10px 14px;border-radius:10px;background:#6d4bff;color:#fff;text-decoration:none;font-weight:700">إعادة تعيين كلمة المرور</a></p>
          <p style="color:#555">إذا ما أنت اللي طلبت، تجاهل الرسالة.</p>
          <p style="color:#999;font-size:12px">الرابط صالح لمدة 30 دقيقة.</p>
        </div>
      `;

      try {
        await sendEmail(env, email, subject, text, html);
      } catch (mailErr) {
        console.log("forgot_mail_error", String(mailErr?.message || mailErr));
        return json(request, env, { ok: false, error: "MAIL_SEND_FAILED" }, 500);
      }
    }

    return json(request, env, { ok: true }, 200);
  } catch (e) {
    console.log("forgot_error", String(e?.message || e));
    return json(request, env, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
forgot.js – api2 – v1
Requires (recommended):
MAIL_FROM=your@domain.com
(optional) RESEND_API_KEY=...
(optional) RESET_TOKEN_PEPPER=...
*/
