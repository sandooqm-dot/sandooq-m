// functions/api/login.js
export async function onRequest(context) {
  const { request, env } = context;

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

  // GET = فحص سريع فقط
  if (request.method === "GET") {
    return json({ ok: true, version: "login-v8-fixed-no-duration" }, 200);
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  if (!env.DB) return json({ ok: false, error: "DB_NOT_BOUND" }, 500);
  const db = env.DB;

  function nowISO() { return new Date().toISOString(); }

  function headerDeviceId(req) {
    return req.headers.get("X-Device-Id") || "";
  }

  function readDeviceId(req) {
    const u = new URL(req.url);
    const q = (u.searchParams.get("deviceId") || "").toString().trim();
    return q || headerDeviceId(req);
  }

  // PBKDF2 settings
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

  async function ensureTables() {
    // نفس سكيمة register.js (بدون أي duration/meta)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt_b64 TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);

    await db.exec(`
      CREATE TABLE IF NOT EXISTS activations (
        code TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        activated_at TEXT NOT NULL
      );
    `);

    await db.exec(`
      CREATE TABLE IF NOT EXISTS code_ownership (
        code TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        linked_at TEXT NOT NULL
      );
    `);

    // (اختياري لاحقًا) جلسات
    await db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        device_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
    `);
  }

  function randomIdB64Url(lenBytes = 32) {
    const bytes = crypto.getRandomValues(new Uint8Array(lenBytes));
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function makeCookie(name, value, maxAgeSeconds) {
    // HttpOnly + Secure (https) + SameSite=Lax
    return `${name}=${value}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Lax`;
  }

  try {
    await ensureTables();

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON" }, 400);

    const email = (body.email || "").toString().trim().toLowerCase();
    const password = (body.password || "").toString();
    const deviceId = (body.deviceId || "").toString().trim() || readDeviceId(request);

    if (!email || !password) return json({ ok: false, error: "MISSING_FIELDS" }, 400);

    const user = await db.prepare(`
      SELECT email, password_hash, salt_b64
      FROM users
      WHERE email = ?
    `).bind(email).first();

    if (!user) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    const calc = await pbkdf2Hash(password, user.salt_b64);
    if (calc !== user.password_hash) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    // لو الحساب مرتبط بكود، وتوفر deviceId، نتحقق أنه نفس جهاز التفعيل
    const ownership = await db.prepare(`
      SELECT code FROM code_ownership WHERE email = ? LIMIT 1
    `).bind(email).first();

    let linkedCode = ownership?.code || null;

    if (linkedCode && deviceId) {
      const act = await db.prepare(`SELECT device_id FROM activations WHERE code = ?`)
        .bind(linkedCode).first();

      if (!act) return json({ ok: false, error: "ACTIVATE_FIRST" }, 409);
      if (act.device_id !== deviceId) return json({ ok: false, error: "CODE_BOUND_TO_OTHER_DEVICE" }, 409);
    }

    // إنشاء Session (30 يوم)
    const sessionId = randomIdB64Url(32);
    const createdAt = nowISO();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

    await db.prepare(`
      INSERT INTO sessions (session_id, email, device_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(sessionId, email, deviceId || "", createdAt, expiresAt).run();

    const setCookie = makeCookie("sdq_session", sessionId, 30 * 24 * 60 * 60);

    return json(
      { ok: true, email, linkedCode, expiresAt, version: "login-v8-fixed-no-duration" },
      200,
      { "Set-Cookie": setCookie }
    );

  } catch (e) {
    return json({
      ok: false,
      error: "LOGIN_FAILED",
      message: String(e?.message || e),
      version: "login-v8-fixed-no-duration"
    }, 500);
  }
}
