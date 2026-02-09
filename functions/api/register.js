// functions/api/register.js
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

  function randomSaltB64() {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    return toB64(salt);
  }

  async function ensureTables() {
    // ✅ نستخدم prepare().run بدل exec (عشان نكسر مشكلة duration)
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt_b64 TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `).run();

    await db.prepare(`
      CREATE TABLE IF NOT EXISTS activations (
        code TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        activated_at TEXT NOT NULL
      );
    `).run();

    await db.prepare(`
      CREATE TABLE IF NOT EXISTS code_ownership (
        code TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        linked_at TEXT NOT NULL
      );
    `).run();
  }

  // ===== Main =====
  try {
    await ensureTables();

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON" }, 400);

    const email = (body.email || "").toString().trim().toLowerCase();
    const password = (body.password || "").toString();
    const code = (body.code || "").toString().trim();
    const deviceId = (body.deviceId || "").toString().trim() || readDeviceId(request);

    if (!email || !password) return json({ ok: false, error: "MISSING_FIELDS" }, 400);

    // لو أرسل كود، لازم يكون مُفعل أولاً على جهاز (activate) قبل الربط بالحساب
    if (code) {
      if (!deviceId) return json({ ok: false, error: "MISSING_DEVICE" }, 400);

      const act = await db.prepare(`SELECT code, device_id FROM activations WHERE code = ?`)
        .bind(code)
        .first();

      if (!act) return json({ ok: false, error: "ACTIVATE_FIRST" }, 409);

      // لازم نفس الجهاز اللي فَعّل الكود
      if (act.device_id !== deviceId) {
        return json({ ok: false, error: "CODE_BOUND_TO_OTHER_DEVICE" }, 409);
      }
    }

    // هل المستخدم موجود؟
    const existing = await db.prepare(`SELECT email FROM users WHERE email = ?`)
      .bind(email)
      .first();

    if (existing) return json({ ok: false, error: "EMAIL_EXISTS" }, 409);

    const saltB64 = randomSaltB64();
    const passwordHash = await pbkdf2Hash(password, saltB64);

    await db.prepare(`
      INSERT INTO users (email, password_hash, salt_b64, created_at)
      VALUES (?, ?, ?, ?)
    `).bind(email, passwordHash, saltB64, nowISO()).run();

    // لو فيه كود، اربطه بالإيميل
    if (code) {
      await db.prepare(`
        INSERT OR REPLACE INTO code_ownership (code, email, linked_at)
        VALUES (?, ?, ?)
      `).bind(code, email, nowISO()).run();
    }

    return json({
      ok: true,
      email,
      pbkdf2Iterations: PBKDF2_ITER,
      linkedCode: code || null
    }, 200);

  } catch (e) {
    return json({
      ok: false,
      error: "REGISTER_FAILED",
      message: String(e?.message || e)
    }, 500);
  }
}
