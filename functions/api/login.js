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
  };

  if (allowOrigin !== "*") {
    corsHeaders["Access-Control-Allow-Credentials"] = "true";
  }

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

  // GET = فحص سريع إن الملف نازل صح
  if (request.method === "GET") {
    return json({ ok: true, version: "login-v5-no-duration" }, 200);
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

  // PBKDF2 settings (Cloudflare cap ~100000)
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

  function timingSafeEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string") return false;
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= (a.charCodeAt(i) ^ b.charCodeAt(i));
    return r === 0;
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
      { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
      keyMaterial,
      256
    );

    return toB64(bits);
  }

  function randomIdB64url(byteLen = 32) {
    const bytes = crypto.getRandomValues(new Uint8Array(byteLen));
    // base64url
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
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

    // code ownership (اختياري)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS code_ownership (
        code TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        linked_at TEXT NOT NULL
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

    await db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email);`);
  }

  // ===== Main =====
  try {
    await ensureTables();

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON" }, 400);

    const email = (body.email || "").toString().trim().toLowerCase();
    const password = (body.password || "").toString();
    const deviceId = (body.deviceId || "").toString().trim() || readDeviceId(request);

    if (!email || !password) {
      return json({ ok: false, error: "MISSING_FIELDS" }, 400);
    }

    const user = await db.prepare(
      `SELECT email, password_hash, salt_b64 FROM users WHERE email = ?`
    ).bind(email).first();

    if (!user) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    const computed = await pbkdf2Hash(password, user.salt_b64);
    if (!timingSafeEqual(computed, user.password_hash)) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    // جلسة دخول
    const sid = randomIdB64url(32);
    const createdAt = nowISO();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(); // 30 يوم

    await db.prepare(`
      INSERT INTO sessions (sid, email, device_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(sid, email, deviceId || null, createdAt, expiresAt).run();

    const owned = await db.prepare(
      `SELECT code FROM code_ownership WHERE email = ? LIMIT 1`
    ).bind(email).first();

    const cookie = [
      `sid=${sid}`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      `Max-Age=${60 * 60 * 24 * 30}`,
    ].join("; ");

    return json({
      ok: true,
      email,
      session: { sid, expiresAt },
      linkedCode: owned?.code || null
    }, 200, { "Set-Cookie": cookie });

  } catch (e) {
    return json({
      ok: false,
      error: "LOGIN_FAILED",
      version: "login-v5-no-duration",
      message: String(e?.message || e)
    }, 500);
  }
}
