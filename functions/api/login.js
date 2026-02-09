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

  // Health check (يفيدك تتأكد أن آخر نسخة نزلت)
  if (request.method === "GET") {
    return json({ ok: true, version: "login-v7-session" }, 200);
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

  function readDeviceId(req, body) {
    const fromBody = (body?.deviceId || "").toString().trim();
    if (fromBody) return fromBody;
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

  function randId(len = 32) {
    const b = crypto.getRandomValues(new Uint8Array(len));
    // base64url
    let s = "";
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function addDaysISO(days) {
    const d = new Date();
    d.setDate(d.getDate() + days);
    return d.toISOString();
  }

  function cookieHeader(name, value, maxAgeSeconds) {
    const parts = [
      `${name}=${value}`,
      `Max-Age=${maxAgeSeconds}`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
    ];
    return parts.join("; ");
  }

  async function ensureTables() {
    // users (نفس register)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt_b64 TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);

    // activations: code <-> device_id
    await db.exec(`
      CREATE TABLE IF NOT EXISTS activations (
        code TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        activated_at TEXT NOT NULL
      );
    `);

    // code ownership
    await db.exec(`
      CREATE TABLE IF NOT EXISTS code_ownership (
        code TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        linked_at TEXT NOT NULL
      );
    `);

    // sessions (لـ /api/me بعدين)
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

  // ===== Main =====
  try {
    await ensureTables();

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON" }, 400);

    const email = (body.email || "").toString().trim().toLowerCase();
    const password = (body.password || "").toString();
    const deviceId = readDeviceId(request, body);

    if (!email || !password) {
      return json({ ok: false, error: "MISSING_FIELDS" }, 400);
    }
    if (!deviceId) {
      return json({ ok: false, error: "MISSING_DEVICE" }, 400);
    }

    const user = await db
      .prepare(`SELECT email, password_hash, salt_b64 FROM users WHERE email = ?`)
      .bind(email)
      .first();

    if (!user) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    const calc = await pbkdf2Hash(password, user.salt_b64);
    if (calc !== user.password_hash) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    // لو الحساب مرتبط بكود → لازم نفس جهاز التفعيل
    const owned = await db
      .prepare(`SELECT code FROM code_ownership WHERE email = ? LIMIT 1`)
      .bind(email)
      .first();

    let linkedCode = owned?.code || null;

    if (linkedCode) {
      const act = await db
        .prepare(`SELECT code, device_id FROM activations WHERE code = ?`)
        .bind(linkedCode)
        .first();

      if (!act) {
        return json({ ok: false, error: "ACTIVATE_FIRST" }, 409);
      }
      if (act.device_id !== deviceId) {
        return json({ ok: false, error: "ACCOUNT_BOUND_TO_OTHER_DEVICE" }, 409);
      }
    }

    // Create session
    const sessionId = randId(32);
    const createdAt = nowISO();
    const expiresAt = addDaysISO(30);

    await db.prepare(`
      INSERT INTO sessions (session_id, email, device_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(sessionId, email, deviceId, createdAt, expiresAt).run();

    const setCookie = cookieHeader("sandooq_session", sessionId, 30 * 24 * 60 * 60);

    return json(
      {
        ok: true,
        email,
        token: sessionId,         // للتجربة في Hoppscotch إذا احتجته
        linkedCode,
        version: "login-v7-session",
      },
      200,
      { "Set-Cookie": setCookie }
    );

  } catch (e) {
    return json({
      ok: false,
      error: "LOGIN_FAILED",
      message: String(e?.message || e),
      version: "login-v7-session",
    }, 500);
  }
}
