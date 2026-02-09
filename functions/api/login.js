// functions/api/login.js
export async function onRequest(context) {
  const { request, env } = context;

  // ===== CORS =====
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  const allowOrigin = allowed.includes(origin) ? origin : (allowed[0] || "*");

  const corsHeaders = {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
    // لو بتستخدم كوكي للسشن
    "Access-Control-Allow-Credentials": "true",
  };

  function json(obj, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        ...corsHeaders,
        ...extraHeaders,
      },
    });
  }

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  if (!env.DB) return json({ ok: false, error: "DB_NOT_BOUND" }, 500);
  const db = env.DB;

  // ===== Helpers =====
  function nowISO() { return new Date().toISOString(); }

  function headerDeviceId(req) {
    return req.headers.get("X-Device-Id") || "";
  }

  function readDeviceId(req) {
    const u = new URL(req.url);
    const q = (u.searchParams.get("deviceId") || "").toString().trim();
    return q || headerDeviceId(req);
  }

  const PBKDF2_ITER = 100000;

  function toB64(bytes) {
    let s = "";
    const arr = new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
  }

  function fromB64(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function pbkdf2Hash(password, saltB64) {
    const enc = new TextEncoder();
    const salt = fromB64(saltB64);

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: PBKDF2_ITER,
        hash: "SHA-256",
      },
      keyMaterial,
      256
    );

    return toB64(bits);
  }

  function safeEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string") return false;
    if (a.length !== b.length) return false;
    let out = 0;
    for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return out === 0;
  }

  function randomSid() {
    // token قوي لسشن
    const bytes = crypto.getRandomValues(new Uint8Array(24));
    // base64url
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  async function ensureTables() {
    // users (لا نستخدم email_verified ولا provider هنا)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt_b64 TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);

    // sessions
    await db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        device_id TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
    `);
  }

  async function migrateUsersTableIfNeeded() {
    // لو كان عندك جدول قديم، نضيف الأعمدة الناقصة بدل ما نطيّح
    const info = await db.prepare(`PRAGMA table_info(users);`).all();
    const rows = info?.results || [];
    const cols = new Set(rows.map(r => r.name));

    async function addCol(name, type, defSql = "") {
      if (!cols.has(name)) {
        await db.exec(`ALTER TABLE users ADD COLUMN ${name} ${type} ${defSql};`);
      }
    }

    await addCol("password_hash", "TEXT", ""); // NOTE: ما نقدر NOT NULL هنا لأن الجدول قديم
    await addCol("salt_b64", "TEXT", "");
    await addCol("created_at", "TEXT", "");
  }

  // ===== Main =====
  try {
    await ensureTables();
    await migrateUsersTableIfNeeded();

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON" }, 400);

    const email = (body.email || "").toString().trim().toLowerCase();
    const password = (body.password || "").toString();
    const deviceId = (body.deviceId || "").toString().trim() || readDeviceId(request);

    if (!email || !password) return json({ ok: false, error: "MISSING_FIELDS" }, 400);

    const user = await db
      .prepare(`SELECT email, password_hash, salt_b64 FROM users WHERE email = ?`)
      .bind(email)
      .first();

    if (!user) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    if (!user.password_hash || !user.salt_b64) {
      return json({ ok: false, error: "USER_SCHEMA_INVALID" }, 500);
    }

    const computed = await pbkdf2Hash(password, user.salt_b64);
    if (!safeEqual(computed, user.password_hash)) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    // إنشاء سشن 30 يوم
    const sid = randomSid();
    const maxAge = 60 * 60 * 24 * 30;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + maxAge * 1000).toISOString();

    await db.prepare(`
      INSERT INTO sessions (sid, email, device_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(sid, email, deviceId || null, nowISO(), expiresAt).run();

    const setCookie =
      `sid=${sid}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;

    return json(
      { ok: true, email, sid, expiresAt },
      200,
      { "Set-Cookie": setCookie }
    );

  } catch (e) {
    return json({
      ok: false,
      error: "LOGIN_FAILED",
      message: String(e?.message || e)
    }, 500);
  }
}

// login.js — إصدار 1 (Fix: remove email_verified dependency + sessions)
