// functions/api2/login.js
// Cloudflare Pages Function: POST /api2/login
// ✅ إصلاح: رسائل عربية بدل الأكواد + تمييز حساب Google + عدم كسر دخول الإيميل/باسورد

const VERSION = "api2-login-v3-ar-messages-google-safe";

const CORS_HEADERS = (req, env) => {
  const origin = req.headers.get("Origin") || req.headers.get("origin") || "";
  const allowedRaw = String(env?.ALLOWED_ORIGINS || "").trim();

  let allowOrigin = origin || "*";
  if (allowedRaw) {
    const allowed = allowedRaw.split(",").map(s => s.trim()).filter(Boolean);
    if (allowed.includes("*")) allowOrigin = "*";
    else if (origin && allowed.includes(origin)) allowOrigin = origin;
    else allowOrigin = allowed[0] || "*";
  }

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
  };
};

function json(req, env, data, status = 200, extra = {}) {
  const headers = new Headers({
    ...CORS_HEADERS(req, env),
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  for (const [k, v] of Object.entries(extra || {})) {
    if (Array.isArray(v)) for (const vv of v) headers.append(k, vv);
    else if (v !== undefined && v !== null && v !== "") headers.set(k, String(v));
  }
  return new Response(JSON.stringify({ ...data, version: VERSION }), { status, headers });
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function setCookie(token) {
  const maxAge = 30 * 24 * 60 * 60; // 30 يوم
  const a = `sandooq_token_v1=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; Secure; SameSite=Lax; HttpOnly`;
  const b = `sandooq_session_v1=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; Secure; SameSite=Lax; HttpOnly`;
  return [a, b];
}

function clearCookie(name) {
  return `${name}=; Path=/; Max-Age=0; Secure; SameSite=Lax; HttpOnly`;
}

async function tableCols(DB, table) {
  try {
    const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
    return new Set((res?.results || []).map(r => String(r.name)));
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

function b64ToU8(b64) {
  const bin = atob(String(b64 || ""));
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function toB64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

async function pbkdf2B64(password, saltU8, iterations = 100000) {
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

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(String(str || ""));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

function makeToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  let s = btoa(String.fromCharCode(...arr))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return s;
}

async function insertSession(DB, token, email) {
  // نلتزم بنفس منطق me.js: sessions.token + sessions.email (أو user_email)
  if (!(await tableExists(DB, "sessions"))) {
    // إنشاء minimal إذا ما كان موجود
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT,
        email TEXT,
        created_at TEXT
      );
    `).run();
  }

  const cols = await tableCols(DB, "sessions");
  const now = new Date().toISOString();

  const insertCols = [];
  const vals = [];
  const bind = [];

  const add = (c, v) => {
    if (cols.has(c)) {
      insertCols.push(c);
      vals.push("?");
      bind.push(v);
    }
  };

  // الأسماء المحتملة
  add("token", token);
  add("email", email);
  add("user_email", email);
  add("created_at", now);

  // إذا ما تعرفنا على أي عمود (جدول غريب) نحاول بطريقة مباشرة
  if (!insertCols.length) {
    // آخر حل: حاول إدخال token/email/created_at حتى لو ما كان موجود (راح يفشل ويطلع للأعلى)
    await DB.prepare(`INSERT INTO sessions (token,email,created_at) VALUES (?,?,?)`)
      .bind(token, email, now).run();
    return;
  }

  const sql = `INSERT INTO sessions (${insertCols.join(",")}) VALUES (${vals.join(",")})`;
  await DB.prepare(sql).bind(...bind).run();
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS(request, env) });
  }
  if (request.method !== "POST") {
    return json(request, env, { ok: false, error: "الطريقة غير مسموحة." }, 405);
  }

  try {
    if (!env?.DB) {
      return json(request, env, { ok: false, error: "قاعدة البيانات غير مربوطة." }, 500);
    }

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");

    if (!email || !email.includes("@")) {
      return json(request, env, { ok: false, error: "اكتب بريد صحيح." }, 400);
    }
    if (!password) {
      return json(request, env, { ok: false, error: "اكتب كلمة المرور." }, 400);
    }

    // users لازم موجود
    if (!(await tableExists(env.DB, "users"))) {
      return json(request, env, { ok: false, error: "قاعدة المستخدمين غير جاهزة." }, 500);
    }

    const user = await env.DB.prepare(`SELECT * FROM users WHERE email=? LIMIT 1`)
      .bind(email).first();

    if (!user) {
      // ✅ عربي بدل EMAIL_NOT_REGISTERED
      return json(request, env, {
        ok: false,
        error: "هذا البريد غير مسجّل. اضغط (إنشاء حساب جديد) أو تأكد من الكتابة.",
      }, 401);
    }

    const provider = String(user.provider || "email").toLowerCase();

    // اقرأ بيانات كلمة المرور بأكثر من اسم (توافق)
    const hash = String(user.password_hash || user.pass_hash || user.pw_hash || user.hash || "").trim();

    const saltB64 =
      String(user.password_salt || user.salt_b64 || user.salt || "").trim();

    const hasRealPassword = !!(hash && hash !== "GOOGLE" && (saltB64 || hash.length === 64)); // 64 = sha256 hex legacy

    // ✅ لو حساب Google فقط (بدون كلمة مرور) → رسالة عربية واضحة
    if (provider === "google" && !hasRealPassword) {
      return json(request, env, {
        ok: false,
        error: "هذا البريد مسجّل عبر Google. اضغط زر (الدخول بواسطة حساب Google).",
      }, 401);
    }

    // تحقق كلمة المرور (PBKDF2 الجديد أو SHA256 القديم)
    let ok = false;

    // PBKDF2 (الأساسي)
    if (hash && saltB64) {
      const saltU8 = b64ToU8(saltB64);
      const computed = await pbkdf2B64(password, saltU8, 100000);
      ok = (computed === hash);
    } else if (hash && hash.length === 64) {
      // legacy sha256 hex
      const computedHex = await sha256Hex(password);
      ok = (computedHex === hash.toLowerCase());
    }

    if (!ok) {
      return json(request, env, { ok: false, error: "كلمة المرور غير صحيحة." }, 401);
    }

    // ✅ نجاح: أنشئ جلسة + كوكيز
    const token = makeToken(32);
    await insertSession(env.DB, token, email);

    return json(
      request,
      env,
      { ok: true, token, email, provider: provider || "email" },
      200,
      { "Set-Cookie": setCookie(token) }
    );

  } catch (e) {
    console.log("login_error", String(e?.message || e));
    // لا نطلع إنجليزي للمستخدم
    return json(request, env, { ok: false, error: "صار خطأ في السيرفر. جرّب مرة ثانية." }, 500);
  }
}

/*
login.js – api2 – إصدار 3 (Arabic messages + Google-only detection + safe compatibility)
*/
