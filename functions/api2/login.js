export async function onRequest(context) {
  const { request, env } = context;

  // --- CORS / JSON helpers ---
  const json = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
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
    const userRow = await env.DB
      .prepare(`SELECT * FROM users WHERE email = ? LIMIT 1`)
      .bind(email)
      .first();

    if (!userRow) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    const storedHash = (userRow.password_hash || "").toString().trim();
    const saltB64 = (userRow.salt_b64 || "").toString().trim(); // مهم جدًا

    if (!storedHash) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    // 2) Verify password (يدعم: pbkdf2$... / pbkdf2(hash+salt columns) / legacy sha256)
    const ok = await verifyPassword(storedHash, password, saltB64);

    if (!ok) {
      return json({ ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    // 3) Create session token (لازم يرجع Token فعلي)
    const token = await createSessionIfPossible(env.DB, userRow);
    if (!token) {
      console.log("login_session_create_failed", String(userRow.email || ""));
      return json({ ok: false, error: "SESSION_CREATE_FAILED" }, 500);
    }

    // 4) رجّع التوكن بأكثر من اسم (عشان أي واجهة قديمة/جديدة تشتغل)
    return json(
      {
        ok: true,
        token,
        authToken: token,
        sessionToken: token,
        access_token: token,
        email: String(userRow.email || "").toLowerCase(),
      },
      200
    );
  } catch (e) {
    console.log("login_error", String(e?.message || e));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/* ---------------- Password verify ----------------
   ندعم:
   1) pbkdf2$ITER$SALT_B64$HASH_B64
   2) DB columns: password_hash(base64) + salt_b64(base64) مع PBKDF2 ثابت (100000)
   3) legacy: password_hash = base64(sha256(password))
---------------------------------------------------*/

async function verifyPassword(stored, password, saltB64) {
  // (1) PBKDF2 format: pbkdf2$100000$<saltB64>$<hashB64>
  if (stored.startsWith("pbkdf2$")) {
    const parts = stored.split("$");
    if (parts.length !== 4) return false;

    const iter = parseInt(parts[1], 10);
    const saltB64x = parts[2];
    const hashB64 = parts[3];

    if (!Number.isFinite(iter) || iter < 10000) return false;

    const salt = b64ToBytes(saltB64x);
    if (!salt || salt.length < 8) return false;

    const derivedB64 = await pbkdf2B64(password, salt, iter, 32);
    return timingSafeEqualStr(derivedB64, hashB64);
  }

  // (2) PBKDF2 using DB columns (password_hash + salt_b64)
  // شائع جدًا: hash طول 44 (32 bytes base64) + salt طول 24 (16 bytes base64)
  if (saltB64 && looksBase64(saltB64) && stored.length === 44) {
    const salt = b64ToBytes(saltB64);
    if (salt && salt.length >= 8) {
      // نفس الرقم الشائع
      const derivedB64 = await pbkdf2B64(password, salt, 100000, 32);
      if (timingSafeEqualStr(derivedB64, stored)) return true;

      // احتياط (بعض الناس يستخدمون 120k)
      const derivedB64_120 = await pbkdf2B64(password, salt, 120000, 32);
      if (timingSafeEqualStr(derivedB64_120, stored)) return true;
    }
  }

  // (3) Legacy: base64(sha256(password))
  const legacy = await sha256B64(password);
  return timingSafeEqualStr(legacy, stored);
}

function looksBase64(s) {
  // فحص بسيط جدًا
  return /^[A-Za-z0-9+/=]+$/.test(s);
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

    fields.push("token"); placeholders.push("?"); binds.push(token);

    if (cols.has("email")) {
      fields.push("email"); placeholders.push("?"); binds.push(String(userRow.email || "").toLowerCase());
    } else if (cols.has("user_email")) {
      fields.push("user_email"); placeholders.push("?"); binds.push(String(userRow.email || "").toLowerCase());
    }

    if (cols.has("user_id") && userRow.id != null) {
      fields.push("user_id"); placeholders.push("?"); binds.push(userRow.id);
    }

    if (cols.has("created_at")) {
      fields.push("created_at"); placeholders.push("?"); binds.push(createdAt);
    }
    if (cols.has("expires_at")) {
      fields.push("expires_at"); placeholders.push("?"); binds.push(expiresAt);
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
login.js – api2 – إصدار 4 (Support PBKDF2 with salt_b64 + token aliases)
*/
