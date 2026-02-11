export async function onRequest(context) {
  const { request, env } = context;

  // --- CORS / JSON helpers ---
  const json = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "access-control-allow-origin": request.headers.get("origin") || "*",
        "access-control-allow-headers": "content-type, authorization, x-device-id",
        "access-control-allow-methods": "POST, OPTIONS",
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

    if (!email || !password) {
      return json({ ok: false, error: "MISSING_FIELDS" }, 400);
    }

    // 1) Get user
    const userRow = await env.DB.prepare(
      `SELECT * FROM users WHERE email = ? LIMIT 1`
    ).bind(email).first();

    // نفس رسالة الخطأ (ما نكشف هل الإيميل موجود أو لا)
    if (!userRow) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    const storedHash = (userRow.password_hash || "").toString();
    if (!storedHash) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    // 2) Verify password (يدعم صيغتين)
    const ok = await verifyPassword(storedHash, password);

    if (!ok) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

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
   1) legacy: password_hash = base64(sha256(password))
   2) pbkdf2$ITER$SALT_B64$HASH_B64  (للمستقبل)
---------------------------------------------------*/

async function verifyPassword(stored, password) {
  // PBKDF2 format: pbkdf2$100000$<saltB64>$<hashB64>
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

  // Legacy: base64(sha256(password))
  const legacy = await sha256B64(password);
  return timingSafeEqualStr(legacy, stored);
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
  // base64url (بدون + / وبدون =)
  const b64 = bytesToB64(bytes);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function createSessionIfPossible(DB, userRow) {
  try {
    const cols = await getSessionsCols(DB);

    // لازم يكون فيه token على الأقل
    if (!cols.has("token")) return null;

    const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
    const token = b64url(tokenBytes);

    const now = new Date();
    const createdAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 يوم

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
    return null; // ما نوقف تسجيل الدخول لو السيشن ما نفع
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
  // مقارنة ثابتة الزمن على مستوى النص (قريبة من constant-time)
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
