// functions/api/register.js
export async function onRequest(context) {
  const { request, env } = context;

  // ===== CORS =====
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
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
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);

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

  function looksLikeLegacyDeviceValue(v) {
    // بعض النسخ القديمة كانت تخزّن deviceId في used_by_email بالغلط (ليس ايميل)
    // أي قيمة لا تحتوي @ نعتبرها "ليست ايميل" ونسمح بتحديثها لإيميل.
    return typeof v === "string" && v.length >= 10 && !v.includes("@");
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
  let code = typeof codeRaw === "string" ? codeRaw.trim() : "";
  const deviceId = typeof deviceIdRaw === "string" ? deviceIdRaw.trim() : "";

  if (!isValidEmail(email)) return json({ ok: false, error: "INVALID_EMAIL" }, 400);
  if (!isValidPassword(password)) return json({ ok: false, error: "WEAK_PASSWORD" }, 400);

  // لازم يكون عندنا (code) أو (deviceId) عشان نعرف أي كود نربطه بالحساب
  if (!code && !deviceId) {
    return json({ ok: false, error: "CODE_OR_DEVICE_REQUIRED" }, 400);
  }

  const db = env.DB;

  // ===== لو الكود غير موجود، جيبه من activations عبر deviceId =====
  if (!code && deviceId) {
    // تأكد جدول activations موجود (لا نكسر لو ناسي ينشئه)
    await db
      .prepare(
        "CREATE TABLE IF NOT EXISTS activations (code TEXT PRIMARY KEY, device_id TEXT NOT NULL, activated_at TEXT NOT NULL)"
      )
      .run();

    const act = await db
      .prepare("SELECT code FROM activations WHERE device_id = ? LIMIT 1")
      .bind(deviceId)
      .first();

    if (!act?.code) {
      return json({ ok: false, error: "NO_ACTIVATION_FOR_DEVICE" }, 403);
    }
    code = String(act.code).trim();
  }

  // ===== هل الايميل موجود؟ =====
  const existing = await db.prepare("SELECT email FROM users WHERE email = ? LIMIT 1").bind(email).first();
  if (existing?.email) return json({ ok: false, error: "EMAIL_EXISTS" }, 409);

  // ===== هل الكود موجود؟ =====
  const codeRow = await db
    .prepare("SELECT code, is_used, used_by_email, used_at FROM codes WHERE code = ? LIMIT 1")
    .bind(code)
    .first();

  if (!codeRow?.code) return json({ ok: false, error: "CODE_NOT_FOUND" }, 404);

  // ===== منع استخدام الكود بحساب ثاني (مع استثناء بيانات قديمة كانت تخزن deviceId) =====
  const used = Number(codeRow.is_used) === 1;
  const usedBy = codeRow.used_by_email;

  if (used && usedBy && usedBy !== email && !looksLikeLegacyDeviceValue(usedBy)) {
    return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
  }

  // ===== Create User + Mark Code + Create Session =====
  const createdAt = nowISO();
  const passHash = await pbkdf2Hash(password);
  const token = await newSessionToken();

  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  // نضمن وجود جدول sessions
  await db
    .prepare(
      "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, email TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL)"
    )
    .run();

  // نضمن وجود جدول users
  await db
    .prepare(
      "CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, provider TEXT NOT NULL, password_hash TEXT, code TEXT, created_at TEXT NOT NULL, last_login_at TEXT NOT NULL)"
    )
    .run();

  // نضمن وجود جدول activations (لأننا بنعتمد عليه لاحقاً)
  await db
    .prepare(
      "CREATE TABLE IF NOT EXISTS activations (code TEXT PRIMARY KEY, device_id TEXT NOT NULL, activated_at TEXT NOT NULL)"
    )
    .run();

  const stmts = [
    db.prepare(
      "INSERT INTO users (email, provider, password_hash, code, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(email, "password", passHash, code, createdAt, createdAt),

    // نخلي used_by_email = ايميل (وإذا كان فيها legacy deviceId نسمح نستبدله)
    db.prepare(
      "UPDATE codes SET is_used = 1, used_by_email = ?, used_at = ? WHERE code = ? AND (used_by_email IS NULL OR used_by_email = ? OR used_by_email NOT LIKE '%@%')"
    ).bind(email, createdAt, code, email),

    db.prepare("INSERT INTO sessions (token, email, created_at, expires_at) VALUES (?, ?, ?, ?)").bind(
      token,
      email,
      createdAt,
      expires
    ),
  ];

  try {
    const res = await db.batch(stmts);
    const updateRes = res?.[1];

    // إذا ما تم تحديث صف الكود (يعني الكود أخذته جهة ثانية بإيميل مختلف)
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
  } catch {
    return json({ ok: false, error: "REGISTER_FAILED" }, 500);
  }
}
