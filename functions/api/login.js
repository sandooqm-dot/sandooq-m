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
    "Access-Control-Allow-Credentials": "true",
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

  // PBKDF2 settings (must match register)
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

  function randomId(len = 32) {
    const bytes = crypto.getRandomValues(new Uint8Array(len));
    // base64url
    return btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  async function ensureTables() {
    // users (same schema as register.js عندك الآن)
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
        device_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
    `);
  }

  // ===== Main =====
  try {
    await ensureTables();

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON" }, 400);

    const email = (body.email || "").toString().trim().toLowerCase();
    const password = (body.password || "").toString();
    const deviceId = (body.deviceId || "").toString().trim() || readDeviceId(request);

    if (!email || !password) return json({ ok: false, error: "MISSING_FIELDS" }, 400);
    if (!deviceId) return json({ ok: false, error: "MISSING_DEVICE" }, 400);

    const user = await db
      .prepare(`SELECT email, password_hash, salt_b64 FROM users WHERE email = ?`)
      .bind(email)
      .first();

    if (!user) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    const expected = await pbkdf2Hash(password, user.salt_b64);
    if (expected !== user.password_hash) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    // create session (7 days)
    const sid = randomId(32);
    const createdAt = nowISO();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    await db.prepare(`
      INSERT OR REPLACE INTO sessions (sid, email, device_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(sid, email, deviceId, createdAt, expiresAt).run();

    const cookie = [
      `sid=${sid}`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      `Max-Age=${7 * 24 * 60 * 60}`,
    ].join("; ");

    return json(
      { ok: true, email },
      200,
      { "Set-Cookie": cookie }
    );

  } catch (e) {
    return json({
      ok: false,
      error: "LOGIN_FAILED",
      message: String(e?.message || e)
    }, 500);
  }
}
