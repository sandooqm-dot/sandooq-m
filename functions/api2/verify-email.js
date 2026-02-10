export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON" }, 400);
  }

  const email = String(body.email || "").trim().toLowerCase();
  const otp = String(body.otp || body.code || "").trim();

  if (!email || !otp) {
    return json({ ok: false, error: "MISSING_FIELDS" }, 400);
  }

  const DB =
    env.DB || env.AUTH_DB || env.DATABASE || env.AUTH_DATABASE || null;

  if (!DB) {
    return json({ ok: false, error: "DB_BINDING_MISSING" }, 500);
  }

  try {
    // نجيب آخر OTP لهذا الإيميل من جدول email_otps (حسب سكيمتك اللي بالصورة)
    const row = await DB.prepare(
      `SELECT id, otp_hash, expires_at, used_at, attempts
       FROM email_otps
       WHERE email = ?
       ORDER BY id DESC
       LIMIT 1`
    )
      .bind(email)
      .first();

    if (!row) return json({ ok: false, error: "OTP_NOT_FOUND" }, 400);

    const nowIso = new Date().toISOString();

    if (row.used_at) return json({ ok: false, error: "OTP_ALREADY_USED" }, 400);

    const expMs = Date.parse(row.expires_at || "");
    if (!row.expires_at || Number.isNaN(expMs) || Date.now() > expMs) {
      return json({ ok: false, error: "OTP_EXPIRED" }, 400);
    }

    const attempts = Number(row.attempts || 0);
    if (attempts >= 10) return json({ ok: false, error: "OTP_LOCKED" }, 400);

    // لازم نفس طريقة الهاش تكون ثابتة بين register و verify-email
    const secret = env.OTP_SECRET || env.AUTH_SECRET || env.JWT_SECRET || "sandooq";
    const computed = await sha256Hex(`${secret}|${email}|${otp}`);
    const stored = String(row.otp_hash || "");

    const match = timingSafeEqualHex(computed, stored);

    if (!match) {
      await DB.prepare(`UPDATE email_otps SET attempts = ? WHERE id = ?`)
        .bind(attempts + 1, row.id)
        .run();
      return json({ ok: false, error: "OTP_INVALID" }, 400);
    }

    // نجاح: نعلّم الـ OTP كمستخدم + نوثق الإيميل
    await DB.prepare(`UPDATE email_otps SET used_at = ? WHERE id = ?`)
      .bind(nowIso, row.id)
      .run();

    await DB.prepare(
      `UPDATE users
       SET is_email_verified = 1,
           email_verified = 1,
           email_verified_at = ?
       WHERE email = ?`
    )
      .bind(nowIso, email)
      .run();

    // نسوي Session Token (عشان /api2/me يشتغل مباشرة)
    const token = makeToken();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();

    await DB.prepare(
      `INSERT INTO sessions (token, email, created_at, expires_at)
       VALUES (?, ?, ?, ?)`
    )
      .bind(token, email, nowIso, expiresAt)
      .run();

    return json({ ok: true, token, email }, 200);
  } catch (err) {
    console.error("verify-email error:", err);
    return json({ ok: false, error: "DB_SCHEMA_ERROR" }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function makeToken() {
  // توكن طويل عشوائي
  return (
    crypto.randomUUID().replaceAll("-", "") +
    crypto.randomUUID().replaceAll("-", "")
  );
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
