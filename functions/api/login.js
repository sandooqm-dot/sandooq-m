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
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };

  function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders },
    });
  }

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  // ===== Helpers =====
  function isValidEmail(email) {
    return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  }
  function normEmail(email) {
    return (email || "").toString().trim().toLowerCase();
  }

  function base64urlToBytes(s) {
    s = (s || "").replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
    return diff === 0;
  }

  async function verifyPbkdf2(password, stored) {
    // stored format: pbkdf2$<iters>$<saltB64url>$<hashB64url>
    if (!stored || typeof stored !== "string") return false;
    const parts = stored.split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;

    const iterations = Number(parts[1]);
    if (!Number.isFinite(iterations) || iterations < 1000) return false;

    const saltBytes = base64urlToBytes(parts[2]);
    const expectedHash = base64urlToBytes(parts[3]);

    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
      keyMaterial,
      expectedHash.length * 8
    );

    const got = new Uint8Array(bits);
    return timingSafeEqual(got, expectedHash);
  }

  function nowISO() {
    return new Date().toISOString();
  }

  function base64url(bytes) {
    let str = btoa(String.fromCharCode(...bytes));
    return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  async function newSessionToken() {
    const rnd = crypto.getRandomValues(new Uint8Array(32));
    return base64url(rnd);
  }

  // ===== DB Guard =====
  if (!env?.DB) return json({ ok: false, error: "DB_NOT_BOUND" }, 500);
  const db = env.DB;

  // ===== Parse Body =====
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "INVALID_JSON" }, 400);
  }

  const email = normEmail(body?.email ?? "");
  const password = (body?.password ?? "").toString();

  if (!isValidEmail(email)) return json({ ok: false, error: "INVALID_EMAIL" }, 400);
  if (!password || password.length < 8) return json({ ok: false, error: "WEAK_PASSWORD" }, 400);

  try {
    // ===== Ensure tables (fresh start friendly) =====
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password_hash TEXT,
        email_verified INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        last_login_at TEXT NOT NULL
      );
    `).run();

    await db.prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
    `).run();

    // ===== Lookup user =====
    const user = await db
      .prepare("SELECT email, password_hash, email_verified FROM users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    if (!user?.email) {
      // لا نوضح هل الإيميل موجود أو لا (أمان)
      return json({ ok: false, error: "INVALID_LOGIN" }, 401);
    }

    const passOk = await verifyPbkdf2(password, user.password_hash || "");
    if (!passOk) return json({ ok: false, error: "INVALID_LOGIN" }, 401);

    if (Number(user.email_verified) !== 1) {
      return json({ ok: false, error: "EMAIL_NOT_VERIFIED" }, 403);
    }

    // ===== Create session =====
    const token = await newSessionToken();
    const createdAt = nowISO();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

    await db.batch([
      db.prepare("UPDATE users SET last_login_at = ? WHERE email = ?")
        .bind(createdAt, email),

      db.prepare("INSERT INTO sessions (token, email, created_at, expires_at) VALUES (?, ?, ?, ?)")
        .bind(token, email, createdAt, expiresAt),
    ]);

    return json({ ok: true, email, token, expires_at: expiresAt }, 200);
  } catch (e) {
    return json({ ok: false, error: "LOGIN_FAILED", message: String(e?.message || e) }, 500);
  }
}
