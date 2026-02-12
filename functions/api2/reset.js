// functions/api2/reset.js
// POST /api2/reset
// Reset password using token only (accepts JSON or form body)

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

async function sha256Hex(str) {
  const data = new TextEncoder().encode(String(str));
  const digest = await crypto.subtle.digest("SHA-256", data);
  const b = new Uint8Array(digest);
  let hex = "";
  for (const x of b) hex += x.toString(16).padStart(2, "0");
  return hex;
}

async function pbkdf2HashB64(password, saltBytes, iterations = 100000) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(String(password)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    key,
    256
  );
  return base64FromBytes(new Uint8Array(bits));
}

async function tableCols(DB, table) {
  const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
  return new Set((res?.results || []).map((r) => String(r.name)));
}

async function ensureResetTable(DB) {
  await DB.prepare(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used_at INTEGER
    );
  `).run();

  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(email);`).run();
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_password_resets_expires ON password_resets(expires_at);`).run();
}

function pickPasswordHashColumn(cols) {
  const candidates = ["password_hash", "pass_hash", "pw_hash", "hash", "password"];
  for (const c of candidates) if (cols.has(c)) return c;
  return null;
}

// ✅ robust body parser: JSON OR urlencoded OR form-data-like (best effort)
async function readBodyAny(request) {
  const ct = (request.headers.get("content-type") || "").toLowerCase();

  // try json first when content-type says json
  if (ct.includes("application/json")) {
    const j = await request.json().catch(() => null);
    if (j && typeof j === "object") return j;
  }

  // fallback: read text and parse
  const text = await request.text().catch(() => "");
  if (!text) return {};

  // maybe json even if content-type wrong
  if (text.trim().startsWith("{")) {
    const j = (() => { try { return JSON.parse(text); } catch { return null; } })();
    if (j && typeof j === "object") return j;
  }

  // urlencoded
  try {
    const sp = new URLSearchParams(text);
    const obj = {};
    for (const [k, v] of sp.entries()) obj[k] = v;
    return obj;
  } catch {
    return {};
  }
}

function pickFirst(body, keys) {
  for (const k of keys) {
    const v = body?.[k];
    if (v !== undefined && v !== null && String(v).trim() !== "") return String(v).trim();
  }
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

    const url = new URL(request.url);

    const body = await readBodyAny(request);

    // token ممكن يجي من body أو من query
    const token =
      pickFirst(body, ["token", "reset_token", "t"]) ||
      String(url.searchParams.get("token") || url.searchParams.get("t") || "").trim();

    // password ممكن يجي بأكثر من اسم
    const password =
      pickFirst(body, ["password", "new_password", "newPassword", "pass", "pw", "p1", "password1"]);

    const password2 =
      pickFirst(body, ["password2", "confirm_password", "confirmPassword", "p2", "password_confirm"]);

    if (!token) return json(request, { ok: false, error: "MISSING_TOKEN" }, 400);
    if (!password) return json(request, { ok: false, error: "MISSING_PASSWORD" }, 400);
    if (password.length < 8) return json(request, { ok: false, error: "WEAK_PASSWORD" }, 400);

    // لو فيه تأكيد كلمة مرور وتختلف
    if (password2 && password2 !== password) {
      return json(request, { ok: false, error: "PASSWORD_MISMATCH" }, 400);
    }

    await ensureResetTable(env.DB);

    const tokenHash = await sha256Hex(token);
    const row = await env.DB.prepare(
      `SELECT id, email, expires_at, used_at FROM password_resets WHERE token_hash = ? LIMIT 1`
    ).bind(tokenHash).first();

    if (!row?.id) return json(request, { ok: false, error: "RESET_TOKEN_NOT_FOUND" }, 400);
    if (row.used_at) return json(request, { ok: false, error: "RESET_TOKEN_USED" }, 400);

    const now = Date.now();
    if (Number(row.expires_at) < now) {
      return json(request, { ok: false, error: "RESET_TOKEN_EXPIRED" }, 400);
    }

    const email = normalizeEmail(row.email);
    if (!email) return json(request, { ok: false, error: "MISSING_EMAIL" }, 400);

    const userCols = await tableCols(env.DB, "users");
    const hashCol = pickPasswordHashColumn(userCols);
    if (!hashCol) return json(request, { ok: false, error: "USERS_NO_PASSWORD_COL" }, 500);

    // ✅ PBKDF2 لو salt_b64 موجود، وإلا SHA256 توافق قديم
    if (userCols.has("salt_b64")) {
      const saltBytes = new Uint8Array(16);
      crypto.getRandomValues(saltBytes);
      const saltB64 = base64FromBytes(saltBytes);
      const hashB64 = await pbkdf2HashB64(password, saltBytes, 100000);

      await env.DB.prepare(
        `UPDATE users SET ${hashCol} = ?, salt_b64 = ? WHERE email = ?`
      ).bind(hashB64, saltB64, email).run();
    } else {
      const sha = await sha256Hex(password);
      await env.DB.prepare(
        `UPDATE users SET ${hashCol} = ? WHERE email = ?`
      ).bind(sha, email).run();
    }

    await env.DB.prepare(
      `UPDATE password_resets SET used_at = ? WHERE id = ?`
    ).bind(now, row.id).run();

    return json(request, { ok: true }, 200);
  } catch (e) {
    console.log("reset_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
reset.js – api2 – إصدار 2 (robust body parse + fixes MISSING_PASSWORD)
*/
