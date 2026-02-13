// functions/api2/resend-otp.js
// Cloudflare Pages Function: POST /api2/resend-otp
// ✅ متوافق مع التدفق الجديد: OTP داخل pending_users (قبل إنشاء users)
// ✅ تعديل: error code -> OTP_TOO_SOON (متوافق مع translateErr في activate.html)

const VERSION = "api2-resend-otp-v3-pending-otp-too-soon";

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin") || req.headers.get("Origin");
  const h = {
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
    h["Vary"] = "Origin";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

function json(req, data, status = 200) {
  return new Response(JSON.stringify({ ...data, version: VERSION }), {
    status,
    headers: {
      ...CORS_HEADERS(req),
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function generateOtp6() {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  const n = arr[0] % 1000000;
  return String(n).padStart(6, "0");
}

async function ensurePendingUsers(DB) {
  try {
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS pending_users (
        email TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        otp TEXT NOT NULL,
        otp_expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `).run();
    return true;
  } catch (e) {
    console.log("resend_otp_schema_create_failed", String(e?.message || e));
    return false;
  }
}

async function sendViaResend({ apiKey, from, to, subject, html, text }) {
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from, to, subject, html, text }),
  });

  const data = await r.json().catch(() => null);
  if (!r.ok) {
    const msg = data?.message || data?.error || `RESEND_HTTP_${r.status}`;
    throw new Error(msg);
  }
  return data;
}

function otpEmailHtml({ otp }) {
  return `
  <div style="font-family:Arial,Helvetica,sans-serif;direction:rtl;text-align:right">
    <h2 style="margin:0 0 10px">صندوق المسابقات</h2>
    <p style="margin:0 0 12px">رمزك لتأكيد البريد الإلكتروني هو:</p>
    <div style="font-size:32px;font-weight:800;letter-spacing:4px;background:#f5f5f5;padding:12px 16px;border-radius:10px;display:inline-block">
      ${otp}
    </div>
    <p style="margin:14px 0 0;color:#666">ينتهي خلال 10 دقائق. إذا ما طلبته، تجاهل الرسالة.</p>
  </div>
  `.trim();
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS(request) });
  }
  if (request.method !== "POST") {
    return json(request, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env?.DB) return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);

    const okSchema = await ensurePendingUsers(env.DB);
    if (!okSchema) return json(request, { ok: false, error: "SCHEMA_CREATE_FAILED" }, 500);

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);

    if (!email || !email.includes("@")) {
      return json(request, { ok: false, error: "INVALID_EMAIL" }, 400);
    }

    const resendKey = String(env.RESEND_API_KEY || "").trim();
    if (!resendKey) {
      return json(request, { ok: false, error: "MISSING_RESEND_API_KEY" }, 500);
    }

    const from = String(env.RESEND_FROM || env.MAIL_FROM || "Sandooq Games <onboarding@resend.dev>").trim();

    // ✅ نجيب pending row (بدون ما نفضح وجود الإيميل أمنياً)
    const pending = await env.DB.prepare(
      "SELECT email, updated_at FROM pending_users WHERE email = ? LIMIT 1"
    ).bind(email).first();

    // لو ما هو موجود: نرجع ok (بدون تسريب)
    if (!pending?.email) {
      return json(request, { ok: true, queued: true }, 200);
    }

    // ✅ Rate limit: مرة كل 60 ثانية
    const now = Date.now();
    const last = Number(pending.updated_at || 0);
    const diff = now - last;

    if (last && diff < 60_000) {
      const waitSec = Math.ceil((60_000 - diff) / 1000);

      // ✅ (التعديل المهم) نخلي الكود اللي الواجهة تعرفه
      return json(request, { ok: false, error: "OTP_TOO_SOON", waitSec }, 429);
    }

    // ✅ نولد OTP جديد ونحدثه في pending_users
    const otp = generateOtp6();
    const expiresAt = now + (10 * 60 * 1000);

    await env.DB.prepare(
      "UPDATE pending_users SET otp = ?, otp_expires_at = ?, updated_at = ? WHERE email = ?"
    ).bind(otp, expiresAt, now, email).run();

    // ✅ إرسال البريد
    const subject = "رمز تأكيد البريد الإلكتروني";
    const html = otpEmailHtml({ otp });
    const text = `رمز التحقق: ${otp}\nينتهي خلال 10 دقائق.`;

    const resp = await sendViaResend({
      apiKey: resendKey,
      from,
      to: email,
      subject,
      html,
      text,
    });

    return json(request, { ok: true, sent: true, resendId: resp?.id || null }, 200);

  } catch (e) {
    console.log("resend_otp_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
resend-otp.js – api2 – إصدار 3 (pending_users flow + rate limit + OTP_TOO_SOON for UI)
*/
