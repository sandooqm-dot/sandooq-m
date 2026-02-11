// functions/api2/login.js
// Cloudflare Pages Function: POST /api2/login

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin");
  // لو فيه origin نخليه (أفضل مع المتصفحات)، لو ما فيه نخليها *
  const h = {
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

function json(req, data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS(req),
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

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
function b64url(bytes) {
  const b64 = bytesToB64(bytes);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
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

/**
 * يدعم 3 حالات:
 * 1) pbkdf2$ITER$SALT_B64$HASH_B64 داخل password_hash
 * 2) PBKDF2 مع salt_b64 منفصل (password_hash=HASH_B64 + salt_b64 موجود)
 * 3) legacy: password_hash = base64(sha256(password))
 */
async function verifyUserPassword(userRow, password) {
  const stored = String(userRow?.password_hash || "").trim();
  if (!stored) return false;

  // (1) pbkdf2 داخل النص
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

  // (2) pbkdf2 مع salt_b64 منفصل
  const saltB64 =
    (userRow?.salt_b64 != null ? String(userRow.salt_b64) : "") ||
    (userRow?.password_salt != null ? String(userRow.password_salt) : "") ||
    (userRow?.salt != null ? String(userRow.salt) : "");

  if (saltB64) {
    const salt = b64ToBytes(String(saltB64).trim());
    if (salt && salt.length >= 8) {
      const iterRaw =
        userRow?.pbkdf2_iter ??
        userRow?.iterations ??
        userRow?.iter ??
        userRow?.iteration ??
        100000;
      const iter = parseInt(String(iterRaw), 10);
      const safeIter = Number.isFinite(iter) && iter >= 10000 ? iter : 100000;

      const derivedB64 = await pbkdf2B64(password, salt, safeIter, 32);
      if (timingSafeEqualStr(derivedB64, stored)) return true;
    }
  }

  // (3) legacy sha256
  const legacy = await sha256B64(password);
  return timingSafeEqualStr(legacy, stored);
}

async function insertSession(DB, token, email) {
  const createdAt = new Date().toISOString();

  // نحاول أولاً (token,email,created_at) مثل جدولك
  try {
    await DB.prepare(
      `INSERT INTO sessions (token, email, created_at) VALUES (?,?,?)`
    ).bind(token, email, createdAt).run();
    return true;
  } catch (e1) {
    // لو كان اسم العمود user_email بدل email
    try {
      await DB.prepare(
        `INSERT INTO sessions (token, user_email, created_at) VALUES (?,?,?)`
      ).bind(token, email, createdAt).run();
      return true;
    } catch (e2) {
      console.log("session_insert_failed", String(e1?.message || e1), String(e2?.message || e2));
      return false;
    }
  }
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS(request) });
  }
  if (request.method !== "POST") {
    return json(request, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env.DB) return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");

    if (!email || !password) {
      return json(request, { ok: false, error: "MISSING_FIELDS" }, 400);
    }

    const userRow = await env.DB
      .prepare(`SELECT * FROM users WHERE email = ? LIMIT 1`)
      .bind(email)
      .first();

    if (!userRow) {
      return json(request, { ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    // منع الدخول لو البريد غير مُتحقق (حسب أعمدتك)
    const isVerified =
      userRow.is_email_verified === 1 ||
      userRow.email_verified === 1 ||
      userRow.verified === 1 ||
      userRow.is_verified === 1;

    if (!isVerified) {
      return json(request, { ok: false, error: "EMAIL_NOT_VERIFIED" }, 403);
    }

    const ok = await verifyUserPassword(userRow, password);
    if (!ok) {
      return json(request, { ok: false, error: "INVALID_CREDENTIALS" }, 401);
    }

    // ✅ هنا نضمن توكن دائمًا
    const token = b64url(crypto.getRandomValues(new Uint8Array(32)));

    const inserted = await insertSession(env.DB, token, email);
    if (!inserted) {
      return json(request, { ok: false, error: "SESSION_CREATE_FAILED" }, 500);
    }

    // اختياري: كوكي HttpOnly (يفيدنا لاحقًا في /me لو بغيناه كوكي)
    const cookie =
      `sandooq_session_v1=${token}; Max-Age=${30 * 24 * 60 * 60}; Path=/; Secure; SameSite=Lax; HttpOnly`;

    return json(request, { ok: true, token }, 200, {
      "Set-Cookie": cookie,
    });
  } catch (e) {
    console.log("login_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
login.js – api2 – إصدار 3 (Always returns token + supports salt_b64 PBKDF2 + sets cookie)
*/
