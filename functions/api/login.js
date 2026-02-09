// functions/api/login.js
export async function onRequest(context) {
  const { request, env } = context;

  const VERSION = "login-v3-debug-stage";

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

  // GET = fingerprint (يعلمنا 100% وش الملف اللي شغال)
  if (request.method === "GET") {
    return json({ ok: true, version: VERSION }, 200);
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405);
  }

  if (!env.DB) return json({ ok: false, error: "DB_NOT_BOUND", version: VERSION }, 500);
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

  function randomTokenUrlSafe() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const b64 = toB64(bytes);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
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

  // ===== Main with stage debugging =====
  let stage = "start";
  try {
    stage = "ensureTables";
    await ensureTables();

    stage = "parseBody";
    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON", version: VERSION, stage }, 400);

    stage = "readFields";
    const email = (body.email || "").toString().trim().toLowerCase();
    const password = (body.password || "").toString();
    const deviceId = (body.deviceId || "").toString().trim() || readDeviceId(request);

    if (!email || !password) return json({ ok: false, error: "MISSING_FIELDS", version: VERSION, stage }, 400);
    if (!deviceId) return json({ ok: false, error: "MISSING_DEVICE", version: VERSION, stage }, 400);

    stage = "selectUser";
    const user = await db
      .prepare(`SELECT email, password_hash, salt_b64 FROM users WHERE email = ?`)
      .bind(email)
      .first();

    if (!user) return json({ ok: false, error: "INVALID_CREDENTIALS", version: VERSION, stage }, 401);

    stage = "hashPassword";
    const hash = await pbkdf2Hash(password, user.salt_b64);
    if (hash !== user.password_hash) {
      return json({ ok: false, error: "INVALID_CREDENTIALS", version: VERSION, stage }, 401);
    }

    stage = "codeOwnership";
    const owned = await db
      .prepare(`SELECT code FROM code_ownership WHERE email = ? LIMIT 1`)
      .bind(email)
      .first();

    const linkedCode = owned?.code || null;

    if (linkedCode) {
      stage = "checkActivation";
      const act = await db
        .prepare(`SELECT code, device_id FROM activations WHERE code = ?`)
        .bind(linkedCode)
        .first();

      if (!act) return json({ ok: false, error: "ACTIVATE_FIRST", version: VERSION, stage }, 409);
      if (act.device_id !== deviceId) {
        return json({ ok: false, error: "CODE_BOUND_TO_OTHER_DEVICE", version: VERSION, stage }, 409);
      }
    }

    stage = "makeSession";
    const token = randomTokenUrlSafe();
    const createdAt = nowISO();
    const maxAgeSec = 60 * 60 * 24 * 30;
    const expiresAt = new Date(Date.now() + maxAgeSec * 1000).toISOString();

    stage = "insertSession";
    await db.prepare(`
      INSERT INTO sessions (token, email, device_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(token, email, deviceId, createdAt, expiresAt).run();

    stage = "done";
    const setCookie = `sandooq_session=${token}; Path=/; Max-Age=${maxAgeSec}; HttpOnly; Secure; SameSite=Lax`;

    return json({
      ok: true,
      version: VERSION,
      stage,
      email,
      token,
      linkedCode,
      expiresInSec: maxAgeSec
    }, 200, { "Set-Cookie": setCookie });

  } catch (e) {
    return json({
      ok: false,
      error: "LOGIN_FAILED",
      version: VERSION,
      stage,
      message: String(e?.message || e)
    }, 500);
  }
}
