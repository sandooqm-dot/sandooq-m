// functions/api2/login.js
// POST /api2/login
// إصلاح: دعم salted SHA-256 باستخدام salt_b64 الموجود في users

export async function onRequest(context) {
  const { request, env } = context;

  const json = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "access-control-allow-origin": request.headers.get("origin") || "*",
        "access-control-allow-headers": "content-type, authorization, x-device-id",
        "access-control-allow-methods": "POST, OPTIONS",
        "cache-control": "no-store",
      },
    });

  if (request.method === "OPTIONS") return json({ ok: true }, 200);
  if (request.method !== "POST") return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);

  try {
    if (!env.DB) return json({ ok: false, error: "DB_NOT_BOUND" }, 500);

    const body = await request.json().catch(() => ({}));
    const emailRaw = (body.email || "").toString().trim();
    const password = (body.password || "").toString();
    const email = emailRaw.toLowerCase();

    if (!email || !password) return json({ ok: false, error: "MISSING_FIELDS" }, 400);

    // 1) Get user
    const userRow = await env.DB
      .prepare(`SELECT * FROM users WHERE email = ? LIMIT 1`)
      .bind(email)
      .first();

    // لا نكشف هل الإيميل موجود
    if (!userRow) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    const storedHash = (userRow.password_hash || "").toString().trim();
    if (!storedHash) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    // 2) Verify password (يدعم: PBKDF2 + SHA256 legacy + SHA256 salted)
    const ok = await verifyPassword(storedHash, password, userRow);

    if (!ok) return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    // 3) Create session token (إذا جدول sessions يدعمها)
    const token = await createSessionIfPossible(env.DB, userRow);

    return json({ ok: true, token }, 200);
  } catch (e) {
    console.log("login_error", String(e?.message || e));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/* ---------------- Password verify ----------------
   ندعم:
   1) pbkdf2$ITER$SALT_B64$HASH_B64
   2) legacy: base64(sha256(password))
   3) salted sha256 باستخدام userRow.salt_b64:
      - sha256( passwordBytes + saltBytes )
      - sha256( saltBytes + passwordBytes )
      - sha256( password + saltB64String )
      - sha256( saltB64String + password )
---------------------------------------------------*/

async function verifyPassword(stored, password, userRow) {
  // PBKDF2 format
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
    return timingSafeEqualStr(derivedB64, hashB64);
  }

  // --- 1) Legacy: sha256(password) ---
  const legacy = await sha256B64(password);
  if (timingSafeEqualStr(legacy, stored)) return true;

  // --- 2) Salted sha256 (إذا عندنا salt_b64) ---
  const saltB64 = (userRow?.salt_b64 || userRow?.salt || "").toString().trim();
  if (!saltB64) return false;

  const saltBytes = b64ToBytes(saltB64);

  // 2A) bytes(password) + saltBytes
  if (saltBytes) {
    const cand1 = await sha256B64Bytes(concatBytes(utf8Bytes(password), saltBytes));
    if (timingSafeEqualStr(cand1, stored)) return true;

    // 2B) saltBytes + bytes(password)
    const cand2 = await sha256B64Bytes(concatBytes(saltBytes, utf8Bytes(password)));
    if (timingSafeEqualStr(cand2, stored)) return true;
  }

  // 2C) password + saltB64 (كسلسلة)
  const cand3 = await sha256B64(password + saltB64);
  if (timingSafeEqualStr(cand3, stored)) return true;

  // 2D) saltB64 + password (كسلسلة)
  const cand4 = await sha256B64(saltB64 + password);
  if (timingSafeEqualStr(cand4, stored)) return true;

  return false;
}

function utf8Bytes(str) {
  return new TextEncoder().encode(str);
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function sha256B64(str) {
  const data = utf8Bytes(str);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bytesToB64(new Uint8Array(hash));
}

async function sha256B64Bytes(bytes) {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
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
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations,
    },
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

    const now = new Date();
    const createdAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();

    const fields = [];
    const placeholders = [];
    const binds = [];

    fields.push("token");
    placeholders.push("?");
    binds.push(token);

    if (cols.has("email")) {
      fields.push("email");
      placeholders.push("?");
      binds.push(String(userRow.email || "").toLowerCase());
    } else if (cols.has("user_email")) {
      fields.push("user_email");
      placeholders.push("?");
      binds.push(String(userRow.email || "").toLowerCase());
    }

    if (cols.has("user_id") && userRow.id != null) {
      fields.push("user_id");
      placeholders.push("?");
      binds.push(userRow.id);
    }

    if (cols.has("created_at")) {
      fields.push("created_at");
      placeholders.push("?");
      binds.push(createdAt);
    }
    if (cols.has("expires_at")) {
      fields.push("expires_at");
      placeholders.push("?");
      binds.push(expiresAt);
    }

    await DB.prepare(
      `INSERT INTO sessions (${fields.join(",")}) VALUES (${placeholders.join(",")})`
    ).bind(...binds).run();

    return token;
  } catch (e) {
    console.log("session_create_skip", String(e?.message || e));
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

/*
login.js – api2 – إصدار 2 (Fix salted SHA256 using salt_b64)
*/
