// functions/api/login.js
export async function onRequest(context) {
  const { request, env } = context;

  // ===== CORS =====
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  const corsHeaders = {
    "Access-Control-Allow-Origin": allowed.includes(origin) ? origin : (allowed[0] || "*"),
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
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

  // GET ping (عشان تتأكد إن الملف الصحيح متطبق)
  if (request.method === "GET") {
    return json({ ok: true, version: "login-v4-clean" }, 200);
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: "login-v4-clean" }, 405);
  }

  if (!env.DB) return json({ ok: false, error: "DB_NOT_BOUND", version: "login-v4-clean" }, 500);
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

  // نفس إعداد register
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
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  function b64url(bytes) {
    const b64 = toB64(bytes);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  async function sha256Hex(str) {
    const enc = new TextEncoder();
    const digest = await crypto.subtle.digest("SHA-256", enc.encode(str));
    const arr = new Uint8Array(digest);
    let hex = "";
    for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
    return hex;
  }

  async function ensureTables() {
    // users (نفس register.js)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt_b64 TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);

    // sessions (توكِن جلسة)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        device_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
    `);

    // code_ownership (اختياري، بس مفيد لاحقاً لـ me)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS code_ownership (
        code TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        linked_at TEXT NOT NULL
      );
    `);
  }

  try {
    await ensureTables();

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON", version: "login-v4-clean" }, 400);

    const email = (body.email || "").toString().trim().toLowerCase();
    const password = (body.password || "").toString();
    const deviceId = (body.deviceId || "").toString().trim() || readDeviceId(request);

    if (!email || !password) {
      return json({ ok: false, error: "MISSING_FIELDS", version: "login-v4-clean" }, 400);
    }
    if (!deviceId) {
      return json({ ok: false, error: "MISSING_DEVICE", version: "login-v4-clean" }, 400);
    }

    const user = await db.prepare(
      `SELECT email, password_hash, salt_b64 FROM users WHERE email = ?`
    ).bind(email).first();

    if (!user) {
      return json({ ok: false, error: "INVALID_CREDENTIALS", version: "login-v4-clean" }, 401);
    }

    const computed = await pbkdf2Hash(password, user.salt_b64);
    if (!safeEqual(computed, user.password_hash)) {
      return json({ ok: false, error: "INVALID_CREDENTIALS", version: "login-v4-clean" }, 401);
    }

    // اصنع توكن (نرجعه للعميل) ونخزن هاش فقط
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const token = b64url(raw);
    const tokenHash = await sha256Hex(token);

    // صلاحية 30 يوم
    const createdAt = nowISO();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

    await db.prepare(`
      INSERT OR REPLACE INTO sessions (token_hash, email, device_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(tokenHash, email, deviceId, createdAt, expiresAt).run();

    // (اختياري) رجّع له هل فيه كود مرتبط
    const owned = await db.prepare(`SELECT code FROM code_ownership WHERE email = ?`).bind(email).first();

    return json({
      ok: true,
      version: "login-v4-clean",
      email,
      token,
      expiresAt,
      linkedCode: owned?.code || null
    }, 200);

  } catch (e) {
    return json({
      ok: false,
      error: "LOGIN_FAILED",
      version: "login-v4-clean",
      message: String(e?.message || e)
    }, 500);
  }
}
