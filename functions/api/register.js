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

  function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: { "Content-Type": "application/json", ...corsHeaders },
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

  // (مهم) بعض النسخ القديمة كانت تخزن deviceId داخل used_by_email
  // هنا نكتشفه ونعتبره "ليس ايميل"
  function looksLikeLegacyDeviceId(v) {
    if (!v || typeof v !== "string") return false;
    const s = v.trim();
    if (s.includes("@")) return false;        // ايميل غالباً
    if (s.length < 16) return false;
    // UUID-like: contains dashes and long
    return s.includes("-") && s.length >= 20;
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

  // ===== Ensure activations table exists (safe) =====
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS activations ( code TEXT PRIMARY KEY, device_id TEXT NOT NULL, activated_at TEXT NOT NULL )"
  ).run();

  // ===== 1) email exists? =====
  const existing = await db.prepare("SELECT email FROM users WHERE email = ? LIMIT 1")
    .bind(email)
    .first();
  if (existing?.email) {
    return json({ ok: false, error: "EMAIL_EXISTS" }, 409);
  }

  // ===== 2) code exists? =====
  const codeRow = await db.prepare("SELECT code, is_used, used_by_email, used_at FROM codes WHERE code = ? LIMIT 1")
    .bind(code)
    .first();

  if (!codeRow?.code) {
    return json({ ok: false, error: "CODE_NOT_FOUND" }, 404);
  }

  // ===== 3) code activated on which device? (source of truth) =====
  const act = await db.prepare("SELECT code, device_id, activated_at FROM activations WHERE code = ? LIMIT 1")
    .bind(code)
    .first();

  // لازم يكون فيه تفعيل قبل التسجيل (تفعيل = ربط كود بجهاز)
  if (!act?.code) {
    return json({ ok: false, error: "CODE_NOT_ACTIVATED" }, 409);
  }

  // لو مفعل على جهاز ثاني -> ممنوع
  if (act.device_id !== deviceId) {
    return json({ ok: false, error: "CODE_ALREADY_USED_ON_ANOTHER_DEVICE" }, 409);
  }

  // ===== 4) code already linked to another email? =====
  let usedBy = codeRow.used_by_email;

  // لو كان used_by_email فيه deviceId قديم، نتجاهله ونعتبره فارغ (وبنستبدله بإيميل الآن)
  if (looksLikeLegacyDeviceId(usedBy)) {
    usedBy = null;
  }

  if (Number(codeRow.is_used) === 1 && usedBy && usedBy !== email) {
    return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
  }

  // ===== Create User + Link code to email + Create Session =====
  const createdAt = nowISO();
  const passHash = await pbkdf2Hash(password);
  const token = await newSessionToken();

  // session 30 days
  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  const stmts = [
    db.prepare(
      "INSERT INTO users (email, provider, password_hash, code, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(email, "password", passHash, code, createdAt, createdAt),

    // هنا ربط الإيميل بالكود (بدون أي علاقة بالـ deviceId)
    db.prepare(
      "UPDATE codes SET is_used = 1, used_by_email = ?, used_at = ? WHERE code = ? AND (used_by_email IS NULL OR used_by_email = ? OR used_by_email NOT LIKE '%@%')"
    ).bind(email, createdAt, code, email),

    db.prepare(
      "INSERT INTO sessions (token, email, created_at, expires_at) VALUES (?, ?, ?, ?)"
    ).bind(token, email, createdAt, expires),
  ];

  try {
    const res = await db.batch(stmts);

    // تأكد أن تحديث الكود تم
    const upd = res?.[1];
    const changed = upd?.meta?.changes ?? upd?.changes ?? null;

    if (changed === 0) {
      return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
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

/*
اسم النسخة: register.js – إصدار 2 (Fix legacy deviceId in used_by_email + use activations as device source)
*/
