// functions/api/register.js
export async function onRequest(context) {
  const { request, env } = context;

  // ===== CORS (يدعم الكوكيز) =====
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const allowOrigin =
    (origin && (allowed.length === 0 || allowed.includes(origin))) ? origin : (allowed[0] || origin || "*");

  const corsHeaders = {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
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

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  if (!env?.DB) {
    return json({ ok: false, error: "DB_NOT_BOUND" }, 500);
  }

  // ===== Helpers =====
  function isValidEmail(email) {
    return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  }

  function isValidPassword(pw) {
    return typeof pw === "string" && pw.length >= 8;
  }

  function normEmail(email) {
    return email.trim().toLowerCase();
  }

  function normalizeCode(code) {
    return (code || "")
      .toString()
      .trim()
      .toUpperCase()
      .replace(/[–—−]/g, "-")
      .replace(/\s+/g, "");
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

  function cookieHeader(token) {
    // 30 يوم
    const maxAge = 30 * 24 * 60 * 60;
    // HttpOnly + Secure + SameSite=Lax ممتازة للدخول من نفس الموقع
    return `sndq_session=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
  }

  // ===== Parse Body =====
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "INVALID_JSON" }, 400);
  }

  const emailRaw = body?.email ?? "";
  const password = body?.password ?? "";
  const codeRaw = body?.code ?? "";

  const email = normEmail(emailRaw);
  const code = normalizeCode(codeRaw);

  if (!isValidEmail(email)) return json({ ok: false, error: "INVALID_EMAIL" }, 400);
  if (!isValidPassword(password)) return json({ ok: false, error: "WEAK_PASSWORD" }, 400);
  if (!code) return json({ ok: false, error: "CODE_REQUIRED" }, 400);

  const db = env.DB;

  // ===== DB Checks =====
  const existing = await db.prepare("SELECT email FROM users WHERE email = ? LIMIT 1")
    .bind(email)
    .first();

  if (existing?.email) {
    return json({ ok: false, error: "EMAIL_EXISTS" }, 409);
  }

  const codeRow = await db.prepare("SELECT code, is_used, used_by_email FROM codes WHERE code = ? LIMIT 1")
    .bind(code)
    .first();

  if (!codeRow?.code) {
    return json({ ok: false, error: "CODE_NOT_FOUND" }, 404);
  }

  // إذا الكود مستخدم بإيميل ثاني
  if (Number(codeRow.is_used) === 1 && codeRow.used_by_email && codeRow.used_by_email !== email) {
    return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
  }

  // ===== Create user + mark code + session =====
  const createdAt = nowISO();
  const passHash = await pbkdf2Hash(password);
  const token = await newSessionToken();

  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  const stmts = [
    db.prepare(
      "INSERT INTO users (email, provider, password_hash, code, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(email, "password", passHash, code, createdAt, createdAt),

    db.prepare(
      "UPDATE codes SET is_used = 1, used_by_email = ?, used_at = ? WHERE code = ? AND (is_used = 0 OR used_by_email = ?)"
    ).bind(email, createdAt, code, email),

    db.prepare(
      "INSERT INTO sessions (token, email, created_at, expires_at) VALUES (?, ?, ?, ?)"
    ).bind(token, email, createdAt, expires),
  ];

  try {
    await db.batch(stmts);

    return json(
      {
        ok: true,
        email,
        code,
        token, // نخليه مؤقتًا للواجهة، وبعد ما نرتب /api/me بنعتمد الكوكيز فقط
        expires_at: expires,
      },
      200,
      { "Set-Cookie": cookieHeader(token) }
    );
  } catch (e) {
    return json({ ok: false, error: "REGISTER_FAILED" }, 500);
  }
}
