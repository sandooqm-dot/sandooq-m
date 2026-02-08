// functions/api/register.js
export async function onRequest(context) {
  const { request, env } = context;

  // ===== Helpers =====
  function json(obj, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders, ...extraHeaders },
    });
  }

  function isValidEmail(email) {
    return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  }

  function isValidPassword(pw) {
    // ✅ 8 أحرف على الأقل (ممتاز)
    return typeof pw === "string" && pw.length >= 8;
  }

  function normEmail(email) {
    return email.trim().toLowerCase();
  }

  function nowISO() {
    return new Date().toISOString();
  }

  function base64url(bytes) {
    let str = btoa(String.fromCharCode(...bytes));
    return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  async function pbkdf2Hash(password) {
    const enc = new TextEncoder();
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const iterations = 210000;
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
      keyMaterial,
      256
    );

    const hashBytes = new Uint8Array(bits);
    const salt = base64url(saltBytes);
    const hash = base64url(hashBytes);
    return `pbkdf2$${iterations}$${salt}$${hash}`;
  }

  async function newSessionToken() {
    const rnd = crypto.getRandomValues(new Uint8Array(32));
    return base64url(rnd);
  }

  // ===== CORS =====
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);

  const corsHeaders = {
    "Access-Control-Allow-Origin": allowed.includes(origin) ? origin : (allowed[0] || "*"),
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  // ===== DB =====
  if (!env?.DB) {
    return json({ ok: false, error: "DB_NOT_BOUND" }, 500);
  }
  const db = env.DB;

  // ===== Parse Body =====
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "INVALID_JSON" }, 400);
  }

  const emailRaw = body?.email ?? "";
  const password = body?.password ?? "";

  const email = normEmail(emailRaw);

  if (!isValidEmail(email)) return json({ ok: false, error: "INVALID_EMAIL" }, 400);
  if (!isValidPassword(password)) return json({ ok: false, error: "WEAK_PASSWORD" }, 400);

  // ===== Check existing user =====
  try {
    const existing = await db
      .prepare("SELECT email FROM users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    if (existing?.email) {
      return json({ ok: false, error: "EMAIL_EXISTS" }, 409);
    }

    // ===== Create user + session =====
    const createdAt = nowISO();
    const passHash = await pbkdf2Hash(password);
    const token = await newSessionToken();

    // Session 30 يوم
    const maxAge = 30 * 24 * 60 * 60; // seconds
    const expiresAt = new Date(Date.now() + maxAge * 1000).toISOString();

    // ✅ كوكي جلسة (مفيد لاحقًا لـ /api/me بدون query string)
    const cookie =
      `sndq_session=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;

    await db.batch([
      db.prepare(
        "INSERT INTO users (email, provider, password_hash, created_at, last_login_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(email, "password", passHash, createdAt, createdAt),

      db.prepare(
        "INSERT INTO sessions (token, email, created_at, expires_at) VALUES (?, ?, ?, ?)"
      ).bind(token, email, createdAt, expiresAt),
    ]);

    return json(
      { ok: true, email, token, expires_at: expiresAt },
      200,
      { "Set-Cookie": cookie }
    );
  } catch (e) {
    return json({ ok: false, error: "REGISTER_FAILED", detail: String(e?.message || e) }, 500);
  }
}
