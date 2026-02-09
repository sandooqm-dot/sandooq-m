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

  // Health check (عشان تتأكد النسخة وصلت)
  if (request.method === "GET") {
    return json({ ok: true, version: "login-v6-clean" }, 200);
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: "login-v6-clean" }, 405);
  }

  if (!env.DB) return json({ ok: false, error: "DB_NOT_BOUND", version: "login-v6-clean" }, 500);
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

  // PBKDF2 settings (Cloudflare cap: 100000)
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

  function b64url(bytes) {
    return toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function safeEqual(a, b) {
    a = String(a || "");
    b = String(b || "");
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= (a.charCodeAt(i) ^ b.charCodeAt(i));
    return diff === 0;
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
        session_id TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        device_id TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
    `);

    // موجودة عندك من قبل غالبًا، نخليها احتياط
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
  }

  // ===== Main =====
  try {
    await ensureTables();

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON", version: "login-v6-clean" }, 400);

    const email = (body.email || "").toString().trim().toLowerCase();
    const password = (body.password || "").toString();
    const deviceId = (body.deviceId || "").toString().trim() || readDeviceId(request);

    if (!email || !password) {
      return json({ ok: false, error: "MISSING_FIELDS", version: "login-v6-clean" }, 400);
    }

    const user = await db
      .prepare(`SELECT email, password_hash, salt_b64 FROM users WHERE email = ?`)
      .bind(email)
      .first();

    if (!user) {
      return json({ ok: false, error: "INVALID_CREDENTIALS", version: "login-v6-clean" }, 401);
    }

    const computed = await pbkdf2Hash(password, user.salt_b64);
    if (!safeEqual(computed, user.password_hash)) {
      return json({ ok: false, error: "INVALID_CREDENTIALS", version: "login-v6-clean" }, 401);
    }

    // Create session (30 days)
    const sid = b64url(crypto.getRandomValues(new Uint8Array(32)));
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

    await db.prepare(`
      INSERT INTO sessions (session_id, email, device_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(sid, email, deviceId || null, nowISO(), expiresAt).run();

    const maxAge = 30 * 24 * 60 * 60;

    return json({
      ok: true,
      version: "login-v6-clean",
      email,
      sessionId: sid,
      expiresAt
    }, 200, {
      "Set-Cookie": `sandooq_session=${sid}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`,
    });

  } catch (e) {
    return json({
      ok: false,
      error: "LOGIN_FAILED",
      version: "login-v6-clean",
      message: String(e?.message || e)
    }, 500);
  }
}
