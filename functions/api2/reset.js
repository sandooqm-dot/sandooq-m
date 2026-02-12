// functions/api2/reset.js
// POST /api2/reset  { token, newPassword }

const CORS_HEADERS = (req, env) => {
  const origin = req.headers.get("origin") || "";
  const allowed = String(env?.ALLOWED_ORIGINS || "").trim();

  const h = {
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "cache-control": "no-store",
    "Vary": "Origin",
  };

  if (origin && allowed) {
    const list = allowed.split(",").map(s => s.trim()).filter(Boolean);
    if (list.includes(origin)) {
      h["Access-Control-Allow-Origin"] = origin;
      h["Access-Control-Allow-Credentials"] = "true";
      return h;
    }
  }

  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

function json(req, env, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS(req, env), "content-type": "application/json; charset=utf-8" },
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function b64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64url(bytes) {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function nowIso() {
  return new Date().toISOString();
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(text)));
  const arr = Array.from(new Uint8Array(buf));
  return arr.map(b => b.toString(16).padStart(2, "0")).join("");
}

async function ensureTable(DB) {
  await DB.prepare(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL
    );
  `).run();
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_pwreset_hash ON password_resets(token_hash);`).run();
}

async function tableCols(DB, table) {
  const r = await DB.prepare(`PRAGMA table_info(${table});`).all().catch(() => null);
  return new Set((r?.results || []).map(x => String(x.name)));
}

async function pbkdf2B64(password, saltBytes, iterations = 120000, length = 32) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(password)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    key,
    length * 8
  );
  const out = new Uint8Array(bits);
  return b64(out); // نخزنها base64 عادي
}

async function updateUserPassword(DB, email, newPassword) {
  email = normalizeEmail(email);

  const cols = await tableCols(DB, "users");
  if (!cols.has("email")) throw new Error("USERS_NO_EMAIL_COL");

  // نفضّل PBKDF2 لو عندك salt_b64 + password_hash
  const hasSalt = cols.has("salt_b64");
  const hasPwHash = cols.has("password_hash") || cols.has("pass_hash") || cols.has("pw_hash") || cols.has("hash");

  if (!hasPwHash) throw new Error("USERS_NO_PASSWORD_COL");

  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = b64(saltBytes);

  let pwHash = "";
  if (hasSalt) {
    pwHash = await pbkdf2B64(newPassword, saltBytes);
  } else {
    // legacy: sha256(password)
    pwHash = await sha256Hex(String(newPassword));
  }

  // اختَر اسم عمود كلمة المرور الموجود
  const pwCol =
    cols.has("password_hash") ? "password_hash" :
    cols.has("pass_hash") ? "pass_hash" :
    cols.has("pw_hash") ? "pw_hash" :
    "hash";

  const sets = [];
  const binds = [];

  sets.push(`${pwCol} = ?`); binds.push(pwHash);

  if (hasSalt) { sets.push(`salt_b64 = ?`); binds.push(saltB64); }

  // تحديثات اختيارية إذا موجودة
  if (cols.has("updated_at")) { sets.push(`updated_at = ?`); binds.push(nowIso()); }
  if (cols.has("last_login_at")) { sets.push(`last_login_at = ?`); binds.push(nowIso()); }

  binds.push(email);

  await DB.prepare(`UPDATE users SET ${sets.join(", ")} WHERE email = ?`).bind(...binds).run();
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS(request, env) });
  }
  if (request.method !== "POST") {
    return json(request, env, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env.DB) return json(request, env, { ok: false, error: "DB_NOT_BOUND" }, 500);

    const body = await request.json().catch(() => ({}));
    const tokenRaw = String(body?.token || "").trim();
    const newPassword = String(body?.newPassword || body?.password || "").trim();

    if (!tokenRaw || !newPassword) {
      return json(request, env, { ok: false, error: "MISSING_FIELDS" }, 400);
    }
    if (newPassword.length < 8) {
      return json(request, env, { ok: false, error: "WEAK_PASSWORD" }, 400);
    }

    await ensureTable(env.DB);

    const pepper = String(env.RESET_TOKEN_PEPPER || env.JWT_SECRET || "").trim();
    const tokenHash = await sha256Hex(tokenRaw + ":" + pepper);

    // لازم يكون غير مستخدم + غير منتهي
    const row = await env.DB.prepare(
      `SELECT id, email, expires_at, used_at
       FROM password_resets
       WHERE token_hash = ?
       ORDER BY id DESC
       LIMIT 1`
    ).bind(tokenHash).first();

    if (!row?.id) {
      return json(request, env, { ok: false, error: "TOKEN_INVALID" }, 400);
    }

    if (row.used_at) {
      return json(request, env, { ok: false, error: "TOKEN_USED" }, 400);
    }

    const exp = Date.parse(String(row.expires_at || ""));
    if (!exp || Date.now() > exp) {
      return json(request, env, { ok: false, error: "TOKEN_EXPIRED" }, 400);
    }

    const email = normalizeEmail(row.email);
    if (!email) return json(request, env, { ok: false, error: "USER_NOT_FOUND" }, 400);

    // تأكد المستخدم موجود
    const u = await env.DB.prepare(`SELECT 1 AS ok FROM users WHERE email = ? LIMIT 1`)
      .bind(email).first();
    if (!u?.ok) return json(request, env, { ok: false, error: "USER_NOT_FOUND" }, 400);

    // حدّث كلمة المرور
    await updateUserPassword(env.DB, email, newPassword);

    // علّم التوكن مستخدم
    await env.DB.prepare(`UPDATE password_resets SET used_at = ? WHERE id = ?`)
      .bind(nowIso(), row.id).run();

    return json(request, env, { ok: true }, 200);
  } catch (e) {
    console.log("reset_error", String(e?.message || e));
    return json(request, env, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
reset.js – api2 – v1
يدعم PBKDF2 إذا users فيها salt_b64، وإلا يرجع sha256 legacy.
*/
