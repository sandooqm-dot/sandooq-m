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
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };

  function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  if (request.method !== "POST") return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);

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
  const deviceIdRaw = body?.deviceId ?? "";

  const email = normEmail(emailRaw);
  const code = typeof codeRaw === "string" ? codeRaw.trim().toUpperCase() : "";
  const deviceId = typeof deviceIdRaw === "string" ? deviceIdRaw.trim() : "";

  if (!isValidEmail(email)) return json({ ok: false, error: "INVALID_EMAIL" }, 400);
  if (!isValidPassword(password)) return json({ ok: false, error: "WEAK_PASSWORD" }, 400);
  if (!code) return json({ ok: false, error: "CODE_REQUIRED" }, 400);
  if (!deviceId) return json({ ok: false, error: "DEVICE_REQUIRED" }, 400);

  const db = env.DB;

  // ===== Email exists? =====
  const existing = await db.prepare("SELECT email FROM users WHERE email = ? LIMIT 1")
    .bind(email)
    .first();

  if (existing?.email) {
    return json({ ok: false, error: "EMAIL_EXISTS" }, 409);
  }

  // ===== Code exists? =====
  const codeRow = await db.prepare("SELECT code, is_used, used_by_email FROM codes WHERE code = ? LIMIT 1")
    .bind(code)
    .first();

  if (!codeRow?.code) {
    return json({ ok: false, error: "CODE_NOT_FOUND" }, 404);
  }

  // ===== Must be activated on THIS device first =====
  const act = await db.prepare("SELECT code, device_id FROM activations WHERE code = ? LIMIT 1")
    .bind(code)
    .first();

  if (!act?.code) {
    return json({ ok: false, error: "CODE_NOT_ACTIVATED_ON_DEVICE" }, 409);
  }

  if (act.device_id !== deviceId) {
    return json({ ok: false, error: "CODE_ACTIVATED_ON_OTHER_DEVICE" }, 409);
  }

  // ===== If code already bound to another email, block =====
  if (codeRow.used_by_email && codeRow.used_by_email !== email) {
    return json({ ok: false, error: "CODE_ALREADY_USED_BY_ANOTHER_EMAIL" }, 409);
  }

  // ===== Create user + bind code to email + create session =====
  const createdAt = nowISO();
  const passHash = await pbkdf2Hash(password);
  const token = await newSessionToken();

  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  const stmts = [
    db.prepare(
      "INSERT INTO users (email, provider, password_hash, code, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(email, "password", passHash, code, createdAt, createdAt),

    // bind code to email (do not touch activations table)
    db.prepare(
      "UPDATE codes SET used_by_email = ?, is_used = 1, used_at = COALESCE(used_at, ?) WHERE code = ? AND (used_by_email IS NULL OR used_by_email = ?)"
    ).bind(email, createdAt, code, email),

    db.prepare(
      "INSERT INTO sessions (token, email, created_at, expires_at) VALUES (?, ?, ?, ?)"
    ).bind(token, email, createdAt, expires),
  ];

  try {
    const res = await db.batch(stmts);
    const upd = res?.[1];

    // if update didn't apply (someone else bound it)
    if (upd && upd.success === false) {
      return json({ ok: false, error: "CODE_BIND_FAILED" }, 500);
    }

    return json({
      ok: true,
      email,
      code,
      token,
      expires_at: expires,
    });

  } catch (e) {
    return json({ ok: false, error: "REGISTER_FAILED" }, 500);
  }
}
