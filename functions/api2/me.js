// functions/api2/me.js
// Cloudflare Pages Function: POST /api2/me

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

function getCookie(req, name) {
  const cookie = req.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (k === name) return rest.join("=") || "";
  }
  return "";
}

async function tableCols(DB, table) {
  try {
    const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
    const cols = new Set((res?.results || []).map((r) => String(r.name)));
    return cols;
  } catch {
    return new Set();
  }
}

async function tableExists(DB, table) {
  try {
    const r = await DB.prepare(
      `SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1`
    ).bind(table).first();
    return !!r?.name;
  } catch {
    return false;
  }
}

async function findSessionEmail(DB, token) {
  if (!token) return null;

  const cols = await tableCols(DB, "sessions");
  if (!cols.size || !cols.has("token")) return null;

  // أفضلية: email ثم user_email
  if (cols.has("email")) {
    const row = await DB.prepare(
      `SELECT email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    ).bind(token).first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  if (cols.has("user_email")) {
    const row = await DB.prepare(
      `SELECT user_email AS email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    ).bind(token).first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  // لو ما فيه أعمدة بريد، ما نقدر
  return null;
}

function isVerifiedFromUserRow(u) {
  // عندك ظاهر بالصورة: email_verified و is_email_verified
  return (
    u?.is_email_verified === 1 ||
    u?.email_verified === 1 ||
    u?.verified === 1 ||
    u?.is_verified === 1
  );
}

async function isActivated(DB, email, deviceId) {
  email = normalizeEmail(email);

  // نحاول من جدول activations إن وجد
  if (await tableExists(DB, "activations")) {
    const cols = await tableCols(DB, "activations");
    const where = [];
    const binds = [];

    if (cols.has("email")) { where.push("email = ?"); binds.push(email); }
    if (cols.has("user_email")) { where.push("user_email = ?"); binds.push(email); }
    if (cols.has("used_by_email")) { where.push("used_by_email = ?"); binds.push(email); }

    // لو فيه device_id نضيفه كخيار (OR) إذا توفر
    if (deviceId && cols.has("device_id")) {
      where.push("device_id = ?");
      binds.push(deviceId);
    }

    if (where.length) {
      const row = await DB.prepare(
        `SELECT 1 AS ok FROM activations WHERE (${where.join(" OR ")}) LIMIT 1`
      ).bind(...binds).first();
      if (row) return true;
    }
  }

  // نحاول من جدول codes إن وجد (بعض النسخ تربط الكود بالإيميل)
  if (await tableExists(DB, "codes")) {
    const cols = await tableCols(DB, "codes");
    const where = [];
    const binds = [];

    if (cols.has("used_by_email")) { where.push("used_by_email = ?"); binds.push(email); }
    if (cols.has("email")) { where.push("email = ?"); binds.push(email); }
    if (cols.has("user_email")) { where.push("user_email = ?"); binds.push(email); }

    if (where.length) {
      const row = await DB.prepare(
        `SELECT 1 AS ok FROM codes WHERE (${where.join(" OR ")}) LIMIT 1`
      ).bind(...binds).first();
      if (row) return true;
    }
  }

  // ما لقينا مصدر تفعيل
  return false;
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

    // token من:
    // 1) Authorization: Bearer
    // 2) Cookie: sandooq_session_v1
    // 3) body.token (احتياط)
    const auth = request.headers.get("Authorization") || "";
    const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    const cookieTok = getCookie(request, "sandooq_session_v1");
    const body = await request.json().catch(() => ({}));
    const bodyTok = body?.token ? String(body.token).trim() : "";

    const token = bearer || cookieTok || bodyTok;
    if (!token) return json(request, { ok: false, error: "NO_SESSION" }, 401);

    const email = await findSessionEmail(env.DB, token);
    if (!email) return json(request, { ok: false, error: "SESSION_NOT_FOUND" }, 401);

    // user
    const userRow = await env.DB.prepare(
      `SELECT * FROM users WHERE email = ? LIMIT 1`
    ).bind(email).first();

    if (!userRow) {
      return json(request, { ok: false, error: "USER_NOT_FOUND" }, 401);
    }

    const verified = isVerifiedFromUserRow(userRow);

    const deviceId = request.headers.get("X-Device-Id") || "";
    const activated = await isActivated(env.DB, email, deviceId);

    return json(request, {
      ok: true,
      email,
      verified,
      activated,
      provider: userRow.provider || "email",
    }, 200);
  } catch (e) {
    console.log("me_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
me.js – api2 – إصدار 1 (Cookie/Bearer session → returns verified + activated)
*/
