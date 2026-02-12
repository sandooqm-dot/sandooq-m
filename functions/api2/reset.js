// functions/api2/reset.js
// POST /api2/reset
// Reset password using token stored in D1 password_resets (created by /api2/forgot)

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

function isStrongEnough(pw) {
  return String(pw || "").length >= 8;
}

async function tableCols(DB, table) {
  const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
  return new Set((res?.results || []).map((r) => String(r.name)));
}

async function tableExists(DB, table) {
  const r = await DB.prepare(
    `SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1`
  ).bind(table).first();
  return !!r?.name;
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(String(str));
  const digest = await crypto.subtle.digest("SHA-256", data);
  const b = new Uint8Array(digest);
  let hex = "";
  for (const x of b) hex += x.toString(16).padStart(2, "0");
  return hex;
}

function b64FromBytes(arr) {
  return btoa(String.fromCharCode(...arr));
}

async function pbkdf2Base64(password, saltBytes, iterations = 210000, length = 32) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(String(password)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    key,
    length * 8
  );

  return b64FromBytes(new Uint8Array(bits));
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

    const auth = request.headers.get("Authorization") || "";
    const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

    const token =
      String(body?.token || body?.reset_token || body?.resetToken || bearer || "").trim();

    const password =
      String(body?.password || body?.new_password || body?.newPassword || "").trim();

    const maybeEmail = body?.email ? normalizeEmail(body.email) : "";

    if (!token) return json(request, { ok: false, error: "RESET_TOKEN_NOT_FOUND" }, 400);
    if (!password) return json(request, { ok: false, error: "MISSING_PASSWORD" }, 400);
    if (!isStrongEnough(password)) return json(request, { ok: false, error: "WEAK_PASSWORD" }, 400);

    if (!(await tableExists(env.DB, "password_resets"))) {
      return json(request, { ok: false, error: "RESET_TOKEN_NOT_FOUND" }, 400);
    }

    const now = Date.now();
    const tokenHash = await sha256Hex(token);

    const row = await env.DB.prepare(
      `SELECT email, expires_at, used_at
         FROM password_resets
        WHERE token_hash = ?
        LIMIT 1`
    ).bind(tokenHash).first();

    if (!row) return json(request, { ok: false, error: "RESET_TOKEN_NOT_FOUND" }, 400);
    if (row.used_at) return json(request, { ok: false, error: "RESET_TOKEN_USED" }, 400);
    if (Number(row.expires_at || 0) < now) return json(request, { ok: false, error: "RESET_TOKEN_EXPIRED" }, 400);

    const email = normalizeEmail(row.email);
    if (maybeEmail && maybeEmail !== email) {
      return json(request, { ok: false, error: "EMAIL_MISMATCH" }, 400);
    }

    const uCols = await tableCols(env.DB, "users");

    const hashCol =
      (uCols.has("password_hash") && "password_hash") ||
      (uCols.has("pass_hash") && "pass_hash") ||
      (uCols.has("pw_hash") && "pw_hash") ||
      (uCols.has("hash") && "hash") ||
      "";

    if (!hashCol) {
      return json(request, { ok: false, error: "USERS_SCHEMA_MISSING_PASSWORD_COL", detail: `users cols: ${Array.from(uCols).join(",")}` }, 500);
    }

    let newHash = "";
    let newSaltB64 = "";

    if (uCols.has("salt_b64")) {
      const salt = new Uint8Array(16);
      crypto.getRandomValues(salt);
      newSaltB64 = b64FromBytes(salt);
      newHash = await pbkdf2Base64(password, salt, 210000, 32);
    } else {
      newHash = await sha256Hex(password);
    }

    const sets = [];
    const binds = [];

    sets.push(`${hashCol} = ?`);
    binds.push(newHash);

    if (uCols.has("salt_b64")) {
      sets.push(`salt_b64 = ?`);
      binds.push(newSaltB64);
    }

    if (uCols.has("updated_at")) {
      sets.push(`updated_at = ?`);
      binds.push(new Date().toISOString());
    }

    binds.push(email);

    await env.DB.prepare(
      `UPDATE users SET ${sets.join(", ")} WHERE email = ?`
    ).bind(...binds).run();

    await env.DB.prepare(
      `UPDATE password_resets SET used_at = ? WHERE token_hash = ?`
    ).bind(now, tokenHash).run();

    return json(request, { ok: true }, 200);

  } catch (e) {
    const detail = String(e?.message || e?.stack || e).slice(0, 500);
    console.log("reset_error_detail", detail);
    return json(request, { ok: false, error: "SERVER_ERROR", detail }, 500);
  }
}

/*
reset.js – api2 – إصدار 2 (returns error detail to debug)
*/
