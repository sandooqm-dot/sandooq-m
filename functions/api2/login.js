// functions/api2/login.js
// Cloudflare Pages Function: POST /api2/login
// ✅ Fix: supports password_salt + salt_b64, provider google guard, sessions compat (token + token_hash), always JSON

const VERSION = "api2-login-v3-saltfix-sessions-compat";

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

function json(req, data, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    ...CORS_HEADERS(req),
    "Content-Type": "application/json; charset=utf-8",
  });
  for (const [k, v] of Object.entries(extraHeaders || {})) {
    if (Array.isArray(v)) for (const vv of v) headers.append(k, vv);
    else if (v !== undefined && v !== null && v !== "") headers.set(k, String(v));
  }
  return new Response(JSON.stringify({ ...data, version: VERSION }), { status, headers });
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function getHeader(req, name) {
  return req.headers.get(name) || req.headers.get(name.toLowerCase()) || "";
}

function getCookie(req, name) {
  const cookie = req.headers.get("cookie") || req.headers.get("Cookie") || "";
  const parts = cookie.split(";").map((s) => s.trim()).filter(Boolean);
  for (const p of parts) {
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    const k = p.slice(0, eq).trim();
    const v = p.slice(eq + 1);
    if (k === name) {
      try { return decodeURIComponent(v); } catch { return v; }
    }
  }
  return "";
}

function setAuthCookie(token) {
  const maxAge = 30 * 24 * 60 * 60; // 30 يوم
  return `sandooq_token_v1=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; Secure; SameSite=Lax; HttpOnly`;
}
function setLegacyCookie(token) {
  const maxAge = 30 * 24 * 60 * 60;
  return `sandooq_session_v1=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; Secure; SameSite=Lax; HttpOnly`;
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

async function ensureUsersTable(DB) {
  // ما نمسح شيء — بس نضمن وجود جدول users الأساسي
  await DB.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      provider TEXT DEFAULT 'email',
      password_hash TEXT,
      password_salt TEXT,
      salt_b64 TEXT,
      is_email_verified INTEGER DEFAULT 0,
      email_verified INTEGER DEFAULT 0,
      created_at INTEGER,
      updated_at INTEGER
    );
  `).run();
}

async function ensureSessionsCompat(DB) {
  // ✅ نضمن sessions موجود + الأعمدة اللي نحتاجها موجودة (بدون تخريب)
  if (!(await tableExists(DB, "sessions"))) {
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT,
        token_hash TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        device_id TEXT
      );
    `).run();
    return;
  }

  const cols = await tableCols(DB, "sessions");

  // نضيف أعمدة ناقصة لو قدرنا
  const addCol = async (name, typeSql) => {
    if (cols.has(name)) return;
    try {
      await DB.prepare(`ALTER TABLE sessions ADD COLUMN ${name} ${typeSql};`).run();
    } catch {}
  };

  // مهم لـ me.js و _middleware.js
  await addCol("token", "TEXT");
  await addCol("email", "TEXT");
  await addCol("user_email", "TEXT");
  await addCol("used_by_email", "TEXT");

  // للـ logout.js
  await addCol("token_hash", "TEXT");
  await addCol("created_at", "INTEGER");
  await addCol("expires_at", "INTEGER");
  await addCol("device_id", "TEXT");
}

function toB64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

function b64ToU8(b64) {
  const bin = atob(String(b64 || ""));
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

async function pbkdf2B64(password, saltB64, iterations = 100000) {
  const saltU8 = b64ToU8(saltB64);
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
  return btoa(String.fromCharCode(...arr))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function isVerifiedFromUserRow(u) {
  return (
    u?.is_email_verified === 1 ||
    u?.email_verified === 1 ||
    u?.verified === 1 ||
    u?.is_verified === 1
  );
}

async function insertSession(DB, token, email, deviceId, env) {
  await ensureSessionsCompat(DB);
  const cols = await tableCols(DB, "sessions");

  const now = Date.now();
  const expiresAt = now + 30 * 24 * 60 * 60 * 1000; // 30 يوم

  const pepper = String(env.SESSION_PEPPER || "sess_pepper_v1");
  const tokenHash = await sha256Hex(token + "|" + pepper);

  const insertCols = [];
  const qs = [];
  const bind = [];

  const add = (name, val) => {
    if (cols.has(name)) {
      insertCols.push(name);
      qs.push("?");
      bind.push(val);
    }
  };

  add("token_hash", tokenHash);
  add("token", token);

  // نخدم كل أسماء الإيميل المحتملة
  if (cols.has("email")) add("email", email);
  else if (cols.has("user_email")) add("user_email", email);
  else if (cols.has("used_by_email")) add("used_by_email", email);

  add("created_at", now);
  add("expires_at", expiresAt);
  add("device_id", deviceId || "");

  // لو ما فيه أي عمود إيميل معروف = مصيبة
  if (!insertCols.includes("email") && !insertCols.includes("user_email") && !insertCols.includes("used_by_email")) {
    throw new Error("SESSIONS_SCHEMA_NO_EMAIL_COL");
  }

  const sql = `INSERT OR REPLACE INTO sessions (${insertCols.join(",")}) VALUES (${qs.join(",")})`;
  await DB.prepare(sql).bind(...bind).run();
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

    await ensureUsersTable(env.DB);

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");

    if (!email || !email.includes("@") || password.length < 1) {
      return json(request, { ok: false, error: "MISSING_FIELDS" }, 400);
    }

    const user = await env.DB.prepare(`SELECT * FROM users WHERE email = ? LIMIT 1`)
      .bind(email)
      .first();

    // ✅ هذا اللي تبيه: إذا الإيميل غير مسجل
    if (!user) {
      return json(request, { ok: false, error: "EMAIL_NOT_REGISTERED" }, 404);
    }

    // ✅ لو الحساب Google لا نحاول بكلمة مرور
    const provider = String(user.provider || "email").toLowerCase();
    const storedHash = String(user.password_hash || "");
    if (provider === "google" || storedHash === "GOOGLE") {
      return json(request, { ok: false, error: "USE_GOOGLE_LOGIN" }, 409);
    }

    // ✅ لازم يكون موثّق OTP
    const verified = isVerifiedFromUserRow(user);
    if (!verified) {
      return json(request, { ok: false, error: "EMAIL_NOT_VERIFIED" }, 403);
    }

    // ✅ تحقق كلمة المرور:
    // 1) PBKDF2 باستخدام salt_b64 أو password_salt
    // 2) Legacy SHA256 hex (لو ما فيه salt)
    const saltB64 = String(user.salt_b64 || user.password_salt || user.salt || "").trim();

    let ok = false;

    if (saltB64) {
      const calc = await pbkdf2B64(password, saltB64, 100000);
      ok = calc === storedHash;
    } else {
      // legacy: sha256 hex
      const hex = await sha256Hex(password);
      ok = hex === storedHash;
    }

    if (!ok) {
      return json(request, { ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    // ✅ أنشئ جلسة + كوكيز
    const token = makeToken(32);
    const deviceId = String(getHeader(request, "X-Device-Id") || getCookie(request, "sandooq_device_id_v1") || "").trim();

    await insertSession(env.DB, token, email, deviceId, env);

    return json(
      request,
      { ok: true, token, email, verified: true },
      200,
      { "Set-Cookie": [setAuthCookie(token), setLegacyCookie(token)] }
    );

  } catch (e) {
    console.log("login_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
login.js – api2 – إصدار 3 (Fix PBKDF2 salt mismatch + sessions compat + EMAIL_NOT_REGISTERED + USE_GOOGLE_LOGIN)
*/
