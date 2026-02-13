// functions/api2/register.js
// Cloudflare Pages Function: POST /api2/register

const VERSION = "api2-register-v5-schema-guard";

export async function onRequest(context) {
  const { request, env } = context;

  const origin = request.headers.get("Origin") || request.headers.get("origin") || "";
  const cors = {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Access-Control-Allow-Credentials": "true",
    "Cache-Control": "no-store",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }
  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405, cors);
  }

  try {
    if (!env?.DB) {
      return json({ ok: false, error: "DB_NOT_BOUND", version: VERSION }, 500, cors);
    }

    // ✅ تأكد من وجود الجداول + الأعمدة المطلوبة
    const schemaOk = await ensureSchema(env.DB);
    if (!schemaOk.ok) {
      return json({ ok: false, ...schemaOk, version: VERSION }, 500, cors);
    }

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");

    if (!email || !email.includes("@")) {
      return json({ ok: false, error: "INVALID_EMAIL", version: VERSION }, 400, cors);
    }
    if (password.length < 6) {
      return json({ ok: false, error: "WEAK_PASSWORD", version: VERSION }, 400, cors);
    }

    // ✅ إذا الإيميل موجود في users = مسجل فعليًا (تم OTP سابقاً)
    const exists = await env.DB.prepare(
      "SELECT 1 AS ok FROM users WHERE email=? LIMIT 1"
    ).bind(email).first();

    if (exists?.ok) {
      return json({ ok: false, error: "EMAIL_EXISTS", version: VERSION }, 409, cors);
    }

    // ✅ Hash (PBKDF2 iterations = 100000)
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hashB64 = await pbkdf2B64(password, salt, 100000);
    const saltB64 = toB64(salt);

    // ✅ OTP
    const otp = String(Math.floor(Math.random() * 1000000)).padStart(6, "0");
    const now = Date.now();
    const exp = now + 10 * 60 * 1000;

    // ✅ نخزن مؤقتًا في pending_users فقط
    await env.DB.prepare("DELETE FROM pending_users WHERE email=?").bind(email).run();

    await env.DB.prepare(
      `INSERT INTO pending_users (email, password_hash, password_salt, otp, otp_expires_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(email, hashB64, saltB64, otp, exp, now, now).run();

    // ✅ إرسال OTP
    if (!env.RESEND_API_KEY) {
      return json({ ok: false, error: "MISSING_RESEND_API_KEY", version: VERSION }, 500, cors);
    }

    const from = env.RESEND_FROM || "Sandooq Games <onboarding@resend.dev>";
    const subject = "رمز تأكيد البريد الإلكتروني";
    const html = `
      <div style="font-family:Arial,sans-serif;direction:rtl;text-align:right">
        <h2>صندوق المسابقات</h2>
        <p>رمز التحقق الخاص بك هو:</p>
        <div style="font-size:32px;font-weight:bold;letter-spacing:4px">${otp}</div>
        <p>ينتهي خلال 10 دقائق.</p>
      </div>
    `;

    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ from, to: email, subject, html }),
    });

    if (!r.ok) {
      const t = await r.text().catch(() => "");
      console.log("resend_failed", r.status, (t || "").slice(0, 200));
      return json({ ok: false, error: "EMAIL_SEND_FAILED", version: VERSION }, 500, cors);
    }

    return json({ ok: true, pending: true, message: "OTP_SENT", version: VERSION }, 200, cors);

  } catch (e) {
    console.log("register_error", e?.message || e);
    return json({ ok: false, error: "SERVER_ERROR", version: VERSION }, 500, cors);
  }
}

function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...extraHeaders },
  });
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

async function tableCols(DB, table) {
  try {
    const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
    return new Set((res?.results || []).map((r) => String(r.name)));
  } catch {
    return new Set();
  }
}

function missingCols(colsSet, required) {
  const missing = [];
  for (const c of required) if (!colsSet.has(c)) missing.push(c);
  return missing;
}

async function ensureSchema(DB) {
  // ✅ أنشئ الجداول لو ما كانت موجودة (حل جذري يمنع أخطاء missing table)
  try {
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        provider TEXT DEFAULT 'email',
        password_hash TEXT,
        password_salt TEXT,
        is_email_verified INTEGER DEFAULT 0,
        created_at INTEGER,
        updated_at INTEGER
      );
    `).run();

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
  } catch (e) {
    console.log("schema_create_failed", e?.message || e);
    return { ok: false, error: "SCHEMA_CREATE_FAILED" };
  }

  // ✅ تحقق من الأعمدة (لو عندك جدول قديم غلط، نطلع لك أسماء الأعمدة الناقصة)
  const usersCols = await tableCols(DB, "users");
  const pendingCols = await tableCols(DB, "pending_users");

  const missUsers = missingCols(usersCols, ["email"]);
  if (missUsers.length) {
    return { ok: false, error: "USERS_SCHEMA_MISSING_REQUIRED_COLS", missing: missUsers };
  }

  const missPending = missingCols(pendingCols, [
    "email",
    "password_hash",
    "password_salt",
    "otp",
    "otp_expires_at",
    "created_at",
    "updated_at",
  ]);
  if (missPending.length) {
    return { ok: false, error: "PENDING_USERS_SCHEMA_MISSING_REQUIRED_COLS", missing: missPending };
  }

  return { ok: true };
}

function toB64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

async function pbkdf2B64(password, saltU8, iterations) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltU8, iterations },
    key,
    256
  );

  return toB64(new Uint8Array(bits));
}

/*
register.js – api2 – إصدار 5 (Schema Guard + Create tables if missing)
*/
