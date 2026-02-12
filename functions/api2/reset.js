// functions/api2/reset.js
// POST /api2/reset
// Resets password using token from password_resets table
// Fix: Cloudflare PBKDF2 iterations must be <= 100000

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin");
  const h = {
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "cache-control": "no-store",
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

function json(req, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS(req),
      "content-type": "application/json; charset=utf-8",
    },
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function base64FromBytes(arr) {
  let s = "";
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s);
}

function makeSalt(bytes = 16) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return a;
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(String(str));
  const digest = await crypto.subtle.digest("SHA-256", data);
  const b = new Uint8Array(digest);
  let hex = "";
  for (const x of b) hex += x.toString(16).padStart(2, "0");
  return hex;
}

async function pbkdf2Hash(password, saltBytes, iterations = 100000, dkLenBytes = 32) {
  // Cloudflare limit: iterations <= 100000
  const it = Math.min(Math.max(1, Number(iterations) || 1), 100000);

  const pwKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(password)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: it,
    },
    pwKey,
    dkLenBytes * 8
  );

  return { iters: it, bytes: new Uint8Array(bits) };
}

async function tableInfo(DB, table) {
  const r = await DB.prepare(`PRAGMA table_info(${table});`).all();
  return (r?.results || []);
}

async function tableExists(DB, table) {
  const r = await DB.prepare(
    `SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1`
  ).bind(table).first();
  return !!r?.name;
}

function pickHashCol(cols) {
  const candidates = ["password_hash", "pass_hash", "pw_hash", "hash"];
  for (const c of candidates) if (cols.has(c)) return c;
  return "";
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
    if (!env?.DB) return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);

    const body = await request.json().catch(() => ({}));
    const token = String(body?.token || "").trim();
    const password = String(body?.password || "").trim();

    if (!token) return json(request, { ok: false, error: "RESET_TOKEN_NOT_FOUND" }, 400);
    if (!password) return json(request, { ok: false, error: "MISSING_PASSWORD" }, 400);
    if (password.length < 8) return json(request, { ok: false, error: "WEAK_PASSWORD" }, 400);

    // لازم جدول password_resets موجود (يتسوّى من forgot.js)
    if (!(await tableExists(env.DB, "password_resets"))) {
      return json(request, { ok: false, error: "RESET_TOKEN_NOT_FOUND" }, 400);
    }

    const tokenHash = await sha256Hex(token);
    const now = Date.now();

    const row = await env.DB.prepare(
      `SELECT email, expires_at, used_at
       FROM password_resets
       WHERE token_hash = ?
       LIMIT 1`
    ).bind(tokenHash).first();

    if (!row) return json(request, { ok: false, error: "RESET_TOKEN_NOT_FOUND" }, 400);
    if (row.used_at) return json(request, { ok: false, error: "RESET_TOKEN_NOT_FOUND" }, 400);
    if (Number(row.expires_at || 0) < now) return json(request, { ok: false, error: "RESET_TOKEN_EXPIRED" }, 400);

    const email = normalizeEmail(row.email);
    if (!email) return json(request, { ok: false, error: "MISSING_EMAIL" }, 400);

    // hash new password (PBKDF2 max 100000)
    const salt = makeSalt(16);
    const { iters, bytes } = await pbkdf2Hash(password, salt, 100000, 32);

    const passwordHashB64 = base64FromBytes(bytes);
    const saltB64 = base64FromBytes(salt);

    // Update users table safely حسب الأعمدة الموجودة
    const info = await tableInfo(env.DB, "users");
    const cols = new Set(info.map((x) => String(x.name)));

    const hashCol = pickHashCol(cols);
    if (!hashCol) {
      console.log("reset_error_detail", "USERS_SCHEMA_MISSING_PASSWORD_COL");
      return json(request, { ok: false, error: "USERS_SCHEMA_MISSING_PASSWORD_COL" }, 500);
    }

    const sets = [];
    const binds = [];

    sets.push(`${hashCol} = ?`);
    binds.push(passwordHashB64);

    if (cols.has("salt_b64")) {
      sets.push(`salt_b64 = ?`);
      binds.push(saltB64);
    }
    if (cols.has("pbkdf2_iters")) {
      sets.push(`pbkdf2_iters = ?`);
      binds.push(iters);
    }
    if (cols.has("updated_at")) {
      sets.push(`updated_at = ?`);
      binds.push(new Date().toISOString());
    }

    // لا نكشف وجود المستخدم: لو ما وُجد نعتبرها ok برضو
    await env.DB.prepare(
      `UPDATE users SET ${sets.join(", ")} WHERE email = ?`
    ).bind(...binds, email).run();

    // mark token used
    await env.DB.prepare(
      `UPDATE password_resets SET used_at = ? WHERE token_hash = ?`
    ).bind(now, tokenHash).run();

    return json(request, { ok: true }, 200);
  } catch (e) {
    console.log("reset_error_detail", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
reset.js – api2 – إصدار 1.1 (PBKDF2 iterations <= 100000 fix)
*/
