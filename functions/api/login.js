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

  // GET للتأكد إن الكود الجديد اننشر فعلاً
  if (request.method === "GET") {
    return json({ ok: true, version: "login-v2" }, 200);
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
      { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
      keyMaterial,
      256
    );

    return toB64(bits);
  }

  async function ensureTables() {
    // لازم تكون نفس register.js
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
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        device_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
    `);
  }

  function randomToken() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return toB64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  }

  function addDaysISO(days) {
    const d = new Date();
    d.setDate(d.getDate() + days);
    return d.toISOString();
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

    const user = await db.prepare(`
      SELECT email, password_hash, salt_b64
      FROM users
      WHERE email = ?
    `).bind(email).first();

    if (!user) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    const hash = await pbkdf2Hash(password, user.salt_b64);
    if (hash !== user.password_hash) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    const token = randomToken();
    const now = nowISO();
    const expires = addDaysISO(30);

    await db.prepare(`
      INSERT OR REPLACE INTO sessions (token, email, device_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(token, email, deviceId, now, expires).run();

    // Cookie
    const cookie = [
      `sandooq_session=${token}`,
      "Path=/",
      "HttpOnly",
      "SameSite=Lax",
      "Secure",
      `Max-Age=${30 * 24 * 60 * 60}`
    ].join("; ");

    return json({ ok: true, email, expiresAt: expires }, 200, { "Set-Cookie": cookie });

  } catch (e) {
    return json({ ok: false, error: "LOGIN_FAILED", message: String(e?.message || e) }, 500);
  }
}
