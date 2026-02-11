export async function onRequest(context) {
  const { request, env } = context;

  const origin = request.headers.get("origin");

  const json = (data, status = 200, extraHeaders = {}) =>
    new Response(JSON.stringify(data), {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        ...(origin ? { "access-control-allow-origin": origin } : {}),
        "access-control-allow-credentials": "true",
        "access-control-allow-headers": "content-type, authorization, x-device-id",
        "access-control-allow-methods": "POST, OPTIONS",
        ...extraHeaders,
      },
    });

  if (request.method === "OPTIONS") return json({ ok: true }, 200);
  if (request.method !== "POST")
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);

  try {
    if (!env.DB) return json({ ok: false, error: "DB_NOT_BOUND" }, 500);

    const body = await request.json().catch(() => ({}));
    const emailRaw = (body.email || "").toString().trim();
    const password = (body.password || "").toString();

    const email = emailRaw.toLowerCase();
    if (!email || !password) return json({ ok: false, error: "MISSING_FIELDS" }, 400);

    // 1) Get user
    const userRow = await env.DB.prepare(
      `SELECT * FROM users WHERE email = ? LIMIT 1`
    ).bind(email).first();

    // نفس رسالة الخطأ (ما نكشف هل الإيميل موجود أو لا)
    if (!userRow) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    // لو الحساب مو email provider (مثلاً Google) ما ينفع بكلمة مرور
    const provider = String(userRow.provider || "email");
    if (provider !== "email") return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    // تأكد من التحقق
    const verified =
      Number(userRow.is_email_verified ?? userRow.email_verified ?? 0) === 1;
    if (!verified) return json({ ok: false, error: "EMAIL_NOT_VERIFIED" }, 401);

    const storedHash = String(userRow.password_hash || "");
    if (!storedHash) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    // 2) Verify password (يدعم:
    // - pbkdf2$ITER$SALT_B64$HASH_B64
    // - PBKDF2 salt في عمود salt_b64 + hash في password_hash
    // - legacy sha256 base64)
    const ok = await verifyPassword(userRow, password);
    if (!ok) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    // 3) Create session token + set cookie
    const token = await createSessionIfPossible(env.DB, userRow);

    if (!token) {
      // لو ما قدرنا نسوي جلسة لا نكمل (لأن /me يعتمد على الكوكي)
      return json({ ok: false, error: "SESSION_CREATE_FAILED" }, 500);
    }

    const maxAge = 30 * 24 * 60 * 60; // 30 يوم
    const cookie =
      `sandooq_session_v1=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;

    return json({ ok: true }, 200, { "set-cookie": cookie });
  } catch (e) {
    console.log("login_error", String(e?.message || e));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/* ---------------- Password verify ---------------- */

async function verifyPassword(userRow, password) {
  const stored = String(userRow.password_hash || "");

  // A) pbkdf2$ITER$SALT$HASH
  if (stored.startsWith("pbkdf2$")) {
    const parts = stored.split("$");
    if (parts.length !== 4) return false;

    const iter = parseInt(parts[1], 10);
    const saltB64 = parts[2];
    const hashB64 = parts[3];

    if (!Number.isFinite(iter) || iter < 10000) return false;

    const salt = b64ToBytes(saltB64);
    if (!salt || salt.length < 8) return false;

    const derivedB64 = await pbkdf2B64(password, salt, iter, 32);
    return timingSafeEqualStr(normB64(derivedB64), normB64(hashB64));
  }

  // B) PBKDF2: salt في عمود منفصل salt_b64 + hash في password_hash
  const saltB64 = String(userRow.salt_b64 || "");
  if (saltB64) {
    const salt = b64ToBytes(saltB64);
    if (!salt || salt.length < 8) return false;

    const iterRaw =
      userRow.pbkdf2_iter ?? userRow.iter ?? userRow.iterations ?? userRow.kdf_iter;
    let iter = parseInt(String(iterRaw || "100000"), 10);
    if (!Number.isFinite(iter) || iter < 10000) iter = 100000;

    const derivedB64 = await pbkdf2B64(password, salt, iter, 32);
    return timingSafeEqualStr(normB64(derivedB64), normB64(stored));
  }

  // C) Legacy: base64(sha256(password))
  const legacy = await sha256B64(password);
  return timingSafeEqualStr(normB64(legacy), normB64(stored));
}

function normB64(s) {
  return String(s || "").replace(/=+$/g, "");
}

async function sha256B64(str) {
  const data = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bytesToB64(new Uint8Array(hash));
}

async function pbkdf2B64(password, saltBytes, iterations, keyLenBytes) {
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
    keyLenBytes * 8
  );

  return bytesToB64(new Uint8Array(bits));
}

/* ---------------- Sessions ---------------- */

let _sessionsColsCache = null;

async function getSessionsCols(DB) {
  if (_sessionsColsCache) return _sessionsColsCache;
  const rows = await DB.prepare(`PRAGMA table_info(sessions);`).all();
  const cols = new Set((rows?.results || []).map((r) => String(r.name)));
  _sessionsColsCache = cols;
  return cols;
}

function b64url(bytes) {
  const b64 = bytesToB64(bytes);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function createSessionIfPossible(DB, userRow) {
  try {
    const cols = await getSessionsCols(DB);
    if (!cols.has("token")) return null;

    const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
    const token = b64url(tokenBytes);

    const createdAt = new Date().toISOString();

    const fields = ["token"];
    const placeholders = ["?"];
    const binds = [token];

    if (cols.has("email")) {
      fields.push("email");
      placeholders.push("?");
      binds.push(String(userRow.email || "").toLowerCase());
    } else if (cols.has("user_email")) {
      fields.push("user_email");
      placeholders.push("?");
      binds.push(String(userRow.email || "").toLowerCase());
    }

    if (cols.has("created_at")) {
      fields.push("created_at");
      placeholders.push("?");
      binds.push(createdAt);
    }

    await DB.prepare(
      `INSERT INTO sessions (${fields.join(",")}) VALUES (${placeholders.join(",")})`
    ).bind(...binds).run();

    return token;
  } catch (e) {
    console.log("session_create_failed", String(e?.message || e));
    return null;
  }
}

/* ---------------- Utils ---------------- */

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64ToBytes(b64) {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    const ca = a.charCodeAt(i) || 0;
    const cb = b.charCodeAt(i) || 0;
    diff |= ca ^ cb;
  }
  return diff === 0;
}
