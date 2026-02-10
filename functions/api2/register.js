export async function onRequest(context) {
  const { request, env } = context;

  // ===== Helpers =====
  const json = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      },
    });

  const normalizeEmail = (s) => String(s || "").trim().toLowerCase();
  const enc = new TextEncoder();

  function b64(bytes) {
    let bin = "";
    const arr = new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    return btoa(bin);
  }

  async function sha256Hex(str) {
    const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
    const arr = new Uint8Array(buf);
    return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function randBytes(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return a;
  }

  function genOtp6() {
    return String(Math.floor(100000 + Math.random() * 900000));
  }

  async function pbkdf2Hash(password, saltB64, iterations = 100000) {
    // ⚠️ لا ترفعها عن 100000 (مشاكل على بعض الأجهزة/المتصفحات)
    const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations,
      },
      key,
      256
    );
    return b64(bits);
  }

  async function ensureSchema(db) {
    // جدول users (مرن + متوافق)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        pass_hash TEXT,
        pass_salt TEXT,
        pass_iter INTEGER,
        password_hash TEXT,
        password_salt TEXT,
        password_iter INTEGER,
        email_verified INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER,
        updated_at INTEGER,
        otp_code TEXT,
        otp_hash TEXT,
        otp_expires_at INTEGER
      );
    `);

    // فهارس
    await db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);`);

    // لو قاعدة قديمة ناقصها أعمدة، نضيفها بهدوء
    const alters = [
      `ALTER TABLE users ADD COLUMN pass_hash TEXT`,
      `ALTER TABLE users ADD COLUMN pass_salt TEXT`,
      `ALTER TABLE users ADD COLUMN pass_iter INTEGER`,
      `ALTER TABLE users ADD COLUMN password_hash TEXT`,
      `ALTER TABLE users ADD COLUMN password_salt TEXT`,
      `ALTER TABLE users ADD COLUMN password_iter INTEGER`,
      `ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE users ADD COLUMN created_at INTEGER`,
      `ALTER TABLE users ADD COLUMN updated_at INTEGER`,
      `ALTER TABLE users ADD COLUMN otp_code TEXT`,
      `ALTER TABLE users ADD COLUMN otp_hash TEXT`,
      `ALTER TABLE users ADD COLUMN otp_expires_at INTEGER`,
    ];

    for (const sql of alters) {
      try { await db.exec(sql); } catch (_) {}
    }
  }

  async function sendOtp(env, toEmail, otpCode) {
    // Resend
    const key = env.RESEND_API_KEY;
    const from = env.RESEND_FROM || "Sandooq <onboarding@resend.dev>";
    const appName = env.APP_NAME || "صندوق المسابقات";

    if (!key) return { ok: false, error: "MISSING_RESEND_KEY" };

    const subject = `رمز التحقق - ${appName}`;
    const html = `
      <div style="font-family:Arial,sans-serif;direction:rtl;text-align:right">
        <h2>${appName}</h2>
        <p>رمز التحقق الخاص بك هو:</p>
        <div style="font-size:28px;font-weight:bold;letter-spacing:4px">${otpCode}</div>
        <p style="color:#666">ينتهي خلال 10 دقائق.</p>
      </div>
    `;

    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${key}`,
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
      return { ok: false, error: "RESEND_FAILED", detail: t.slice(0, 300) };
    }
    return { ok: true };
  }

  // ===== Route =====
  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON" }, 400);
  }

  const email = normalizeEmail(body.email);
  const password = String(body.password || body.pass || "");

  if (!email || !email.includes("@")) return json({ ok: false, error: "BAD_EMAIL" }, 400);
  if (!password || password.length < 6) return json({ ok: false, error: "WEAK_PASSWORD" }, 400);
  if (!env.DB) return json({ ok: false, error: "NO_DB_BINDING" }, 500);

  const db = env.DB;
  const now = Date.now();
  const otp = genOtp6();
  const otpExpires = now + 10 * 60 * 1000; // 10 دقائق
  const otpHash = await sha256Hex(`${otp}:${env.OTP_PEPPER || "otp_pepper_v1"}`);

  // salt + pbkdf2 100000
  const saltB64 = b64(randBytes(16));
  let passHash;
  try {
    passHash = await pbkdf2Hash(password, saltB64, 100000);
  } catch (e) {
    // هنا غالبًا مشكلة iterations لو كانت عالية
    return json({ ok: false, error: "HASH_FAILED", detail: String(e?.message || e) }, 500);
  }

  try {
    await ensureSchema(db);

    // تنظيف قديم: أي حساب غير موثق وقديم جدًا (7 أيام) نحذفه تلقائيًا
    try {
      await db
        .prepare(`DELETE FROM users WHERE COALESCE(email_verified,0)=0 AND COALESCE(created_at,0) < ?`)
        .bind(now - 7 * 24 * 60 * 60 * 1000)
        .run();
    } catch (_) {}

    const existing = await db
      .prepare(`SELECT id, COALESCE(email_verified,0) AS email_verified FROM users WHERE email = ?`)
      .bind(email)
      .first();

    if (existing && Number(existing.email_verified) === 1) {
      // موجود وموثّق = ممنوع
      return json({ ok: false, error: "EMAIL_EXISTS" }, 409);
    }

    if (existing) {
      // موجود لكنه غير موثّق: نحدّثه (بدون ما نقفلك)
      await db
        .prepare(`
          UPDATE users
          SET
            pass_hash = ?, pass_salt = ?, pass_iter = ?,
            password_hash = ?, password_salt = ?, password_iter = ?,
            otp_code = ?, otp_hash = ?, otp_expires_at = ?,
            updated_at = ?
          WHERE email = ?
        `)
        .bind(
          passHash, saltB64, 100000,
          passHash, saltB64, 100000,
          otp, otpHash, otpExpires,
          now,
          email
        )
        .run();
    } else {
      // جديد: ننشئه "غير موثّق"
      await db
        .prepare(`
          INSERT INTO users
            (email, pass_hash, pass_salt, pass_iter, password_hash, password_salt, password_iter, email_verified, created_at, updated_at, otp_code, otp_hash, otp_expires_at)
          VALUES
            (?,     ?,        ?,         ?,        ?,             ?,            ?,             0,             ?,         ?,         ?,        ?,        ?)
        `)
        .bind(
          email,
          passHash, saltB64, 100000,
          passHash, saltB64, 100000,
          now, now,
          otp, otpHash, otpExpires
        )
        .run();
    }

    // إرسال OTP بعد نجاح الحفظ
    const sent = await sendOtp(env, email, otp);
    if (!sent.ok) {
      return json({ ok: false, error: sent.error, detail: sent.detail || "" }, 500);
    }

    return json({ ok: true, otpSent: true });
  } catch (e) {
    return json({ ok: false, error: "SERVER_ERROR", detail: String(e?.message || e) }, 500);
  }
}
