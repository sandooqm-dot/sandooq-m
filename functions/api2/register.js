// functions/api2/register.js
// Cloudflare Pages Function: POST /api2/register

const VERSION = "api2-register-v6-compat";

export async function onRequest(context) {
  const { request, env } = context;

  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }
  if (request.method !== "POST") {
    return json(cors, { ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405);
  }

  try {
    if (!env?.DB) {
      return json(cors, { ok: false, error: "DB_NOT_BOUND", version: VERSION }, 500);
    }

    // ✅ تأكد من وجود الجداول + أضف الأعمدة الناقصة لو احتجنا
    const schemaOk = await ensureSchema(env.DB);
    if (!schemaOk.ok) {
      return json(cors, { ok: false, ...schemaOk, version: VERSION }, 500);
    }

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");

    if (!email || !email.includes("@")) {
      return json(cors, { ok: false, error: "INVALID_EMAIL", version: VERSION }, 400);
    }

    // ✅ واجهتك تشترط 8 — نخليها 8 هنا كمان
    if (password.length < 8) {
      return json(cors, { ok: false, error: "WEAK_PASSWORD", version: VERSION }, 400);
    }

    // ✅ إذا الإيميل موجود في users = مسجل فعلياً
    const exists = await env.DB.prepare(
      "SELECT 1 AS ok FROM users WHERE email=? LIMIT 1"
    ).bind(email).first();

    if (exists?.ok) {
      return json(cors, { ok: false, error: "EMAIL_EXISTS", version: VERSION }, 409);
    }

    // ✅ Hash (PBKDF2)
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hashB64 = await pbkdf2B64(password, salt, 100000);
    const saltB64 = toB64(salt);

    // ✅ OTP
    const otp = String(Math.floor(Math.random() * 1000000)).padStart(6, "0");
    const now = Date.now();
    const exp = now + 10 * 60 * 1000;

    // ✅ نظّف أي طلب سابق لنفس الإيميل
    await env.DB.prepare("DELETE FROM pending_users WHERE email=?").bind(email).run();

    // ✅ إدخال مرن حسب الأعمدة الموجودة (password_salt + salt_b64)
    await insertPending(env.DB, {
      email,
      password_hash: hashB64,
      password_salt: saltB64,
      salt_b64: saltB64,
      otp,
      otp_expires_at: exp,
      created_at: now,
      updated_at: now,
    });

    // ✅ إرسال OTP عبر Resend
    if (!env.RESEND_API_KEY) {
      // ما نخلي pending عالق لو البريد غير مضبوط
      await env.DB.prepare("DELETE FROM pending_users WHERE email=?").bind(email).run();
      return json(cors, { ok: false, error: "MISSING_RESEND_API_KEY", version: VERSION }, 500);
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

      // لا نخلي pending يعلق المستخدم
      await env.DB.prepare("DELETE FROM pending_users WHERE email=?").bind(email).run();

      return json(cors, { ok: false, error: "EMAIL_SEND_FAILED", version: VERSION }, 500);
    }

    // (اختياري) Debug OTP وقت الاختبار فقط
    const debugOtp = String(env.DEBUG_OTP || "").trim() === "1" ? otp : undefined;

    return json(
      cors,
      { ok: true, pending: true, message: "OTP_SENT", version: VERSION, ...(debugOtp ? { debugOtp } : {}) },
      200
    );

  } catch (e) {
    console.log("register_error", e?.message || e);
    return json(cors, { ok: false, error: "SERVER_ERROR", version: VERSION }, 500);
  }
}

/* ---------- helpers ---------- */

function json(corsHeaders, obj, status = 200) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(obj), { status, headers });
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function makeCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || request.headers.get("origin") || "";
  const allowedRaw = String(env?.ALLOWED_ORIGINS || "").trim();

  let allowOrigin = origin || "*";

  if (allowedRaw) {
    const allowed = allowedRaw.split(",").map(s => s.trim()).filter(Boolean);
    if (allowed.includes("*")) {
      allowOrigin = origin || "*";
    } else if (origin && allowed.includes(origin)) {
      allowOrigin = origin;
    } else {
      allowOrigin = allowed[0] || (origin || "*");
    }
  }

  const h = {
    "Access-Control-Allow-Origin": allowOrigin,
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
  };

  // credentials ممنوع مع "*"
  if (allowOrigin !== "*") {
    h["Access-Control-Allow-Credentials"] = "true";
  }

  return h;
}

async function tableCols(DB, table) {
  try {
    const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
    return new Set((res?.results || []).map((r) => String(r.name)));
  } catch {
    return new Set();
  }
}

async function tableExists(DB, table) {
  try {
    const r = await DB.prepare(
      `SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1`
    ).bind(table).first();
    return !!r?.name;
  } catch {
    return false;
  }
}

async function ensureSchema(DB) {
  try {
    // users (واسع ومتوافق)
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        provider TEXT DEFAULT 'email',
        password_hash TEXT,
        password_salt TEXT,
        salt_b64 TEXT,
        verified INTEGER DEFAULT 0,
        is_email_verified INTEGER DEFAULT 0,
        created_at TEXT,
        updated_at TEXT,
        last_login_at TEXT,
        google_sub TEXT
      );
    `).run();

    // pending_users
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS pending_users (
        email TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        salt_b64 TEXT,
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

  // ✅ لو الجداول موجودة لكن ناقصها أعمدة، نضيفها
  try {
    if (!(await tableExists(DB, "users"))) {
      return { ok: false, error: "USERS_TABLE_MISSING" };
    }
    if (!(await tableExists(DB, "pending_users"))) {
      return { ok: false, error: "PENDING_USERS_TABLE_MISSING" };
    }

    const u = await tableCols(DB, "users");
    if (!u.has("email")) {
      return { ok: false, error: "USERS_SCHEMA_MISSING_REQUIRED_COLS", missing: ["email"] };
    }

    // أضف أعمدة توافقية لو ناقصة
    await addColIfMissing(DB, "users", u, "provider", "TEXT DEFAULT 'email'");
    await addColIfMissing(DB, "users", u, "password_hash", "TEXT");
    await addColIfMissing(DB, "users", u, "password_salt", "TEXT");
    await addColIfMissing(DB, "users", u, "salt_b64", "TEXT");
    await addColIfMissing(DB, "users", u, "verified", "INTEGER DEFAULT 0");
    await addColIfMissing(DB, "users", u, "is_email_verified", "INTEGER DEFAULT 0");
    await addColIfMissing(DB, "users", u, "created_at", "TEXT");
    await addColIfMissing(DB, "users", u, "updated_at", "TEXT");
    await addColIfMissing(DB, "users", u, "last_login_at", "TEXT");
    await addColIfMissing(DB, "users", u, "google_sub", "TEXT");

    const p = await tableCols(DB, "pending_users");
    const requiredP = ["email","password_hash","password_salt","otp","otp_expires_at","created_at","updated_at"];
    const missingP = requiredP.filter(x => !p.has(x));
    if (missingP.length) {
      // نقدر نضيف أغلبها بـ ALTER (ما نقدر نضمن NOT NULL لكل شي على جدول قديم)
      await addColIfMissing(DB, "pending_users", p, "password_hash", "TEXT");
      await addColIfMissing(DB, "pending_users", p, "password_salt", "TEXT");
      await addColIfMissing(DB, "pending_users", p, "salt_b64", "TEXT");
      await addColIfMissing(DB, "pending_users", p, "otp", "TEXT");
      await addColIfMissing(DB, "pending_users", p, "otp_expires_at", "INTEGER");
      await addColIfMissing(DB, "pending_users", p, "created_at", "INTEGER");
      await addColIfMissing(DB, "pending_users", p, "updated_at", "INTEGER");

      const p2 = await tableCols(DB, "pending_users");
      const still = requiredP.filter(x => !p2.has(x));
      if (still.length) {
        return { ok: false, error: "PENDING_USERS_SCHEMA_MISSING_REQUIRED_COLS", missing: still };
      }
    }

    return { ok: true };
  } catch (e) {
    console.log("schema_guard_failed", e?.message || e);
    return { ok: false, error: "SCHEMA_GUARD_FAILED" };
  }
}

async function addColIfMissing(DB, table, colsSet, colName, colDef) {
  if (colsSet.has(colName)) return;
  try {
    await DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${colName} ${colDef};`).run();
    colsSet.add(colName);
  } catch {
    // نتجاهل (يمكن موجود/محجوز) — ونكمل
  }
}

async function insertPending(DB, data) {
  const cols = await tableCols(DB, "pending_users");

  // لازم الحد الأدنى موجود
  if (!cols.has("email")) throw new Error("pending_users missing email");

  const values = new Map();
  values.set("email", data.email);

  // أسماء محتملة للملح
  if (cols.has("password_hash")) values.set("password_hash", data.password_hash);
  if (cols.has("password_salt")) values.set("password_salt", data.password_salt);
  if (cols.has("salt_b64")) values.set("salt_b64", data.salt_b64);

  if (cols.has("otp")) values.set("otp", data.otp);
  if (cols.has("otp_expires_at")) values.set("otp_expires_at", data.otp_expires_at);
  if (cols.has("created_at")) values.set("created_at", data.created_at);
  if (cols.has("updated_at")) values.set("updated_at", data.updated_at);

  const insertCols = Array.from(values.keys());
  const qs = insertCols.map(() => "?").join(",");
  const sql = `INSERT INTO pending_users (${insertCols.join(",")}) VALUES (${qs})`;

  await DB.prepare(sql).bind(...insertCols.map(k => values.get(k))).run();
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
register.js – api2 – إصدار 6 (CORS صحيح + 8 chars + schema compat + salt_b64 mirror)
*/
