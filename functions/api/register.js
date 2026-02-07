// functions/api/register.js
export async function onRequest(context) {
  const { request, env } = context;

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

  // ===== Helpers =====
  function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  function isValidEmail(email) {
    return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  }

  function isValidPassword(pw) {
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
    // PBKDF2-SHA256
    const enc = new TextEncoder();
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const iterations = 210000; // قوي ومناسب
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: saltBytes,
        iterations,
      },
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
  const code = typeof codeRaw === "string" ? codeRaw.trim() : "";

  if (!isValidEmail(email)) return json({ ok: false, error: "INVALID_EMAIL" }, 400);
  if (!isValidPassword(password)) return json({ ok: false, error: "WEAK_PASSWORD" }, 400);
  if (!code) return json({ ok: false, error: "CODE_REQUIRED" }, 400);

  // ===== DB Checks =====
  const db = env.DB;

  // هل الايميل موجود؟
  const existing = await db.prepare("SELECT email FROM users WHERE email = ? LIMIT 1")
    .bind(email)
    .first();
  if (existing?.email) {
    return json({ ok: false, error: "EMAIL_EXISTS" }, 409);
  }

  // هل الكود موجود؟
  const codeRow = await db.prepare("SELECT code, is_used, used_by_email FROM codes WHERE code = ? LIMIT 1")
    .bind(code)
    .first();

  if (!codeRow?.code) {
    return json({ ok: false, error: "CODE_NOT_FOUND" }, 404);
  }

  // هل الكود مستخدم من ايميل ثاني؟
  if (Number(codeRow.is_used) === 1 && codeRow.used_by_email && codeRow.used_by_email !== email) {
    return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
  }

  // ===== Create User + Mark Code + Create Session =====
  const createdAt = nowISO();
  const passHash = await pbkdf2Hash(password);
  const token = await newSessionToken();

  // جلسة 30 يوم
  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  // نستخدم batch عشان نقلل فرص التعارض
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
    const res = await db.batch(stmts);

    // نتأكد أن تحديث الكود تم فعلاً
    const updateRes = res?.[1];
    if (updateRes?.success === false) {
      return json({ ok: false, error: "CODE_UPDATE_FAILED" }, 500);
    }

    return json({
      ok: true,
      email,
      code,
      token,
      expires_at: expires,
    });

  } catch (e) {
    // لو صار تضارب
    return json({ ok: false, error: "REGISTER_FAILED" }, 500);
  }
}
