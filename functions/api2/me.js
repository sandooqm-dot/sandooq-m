// functions/api2/me.js
// Cloudflare Pages Function: POST /api2/me

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin");
  const h = {
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

// ✅ دعم headers إضافية (مثل Set-Cookie)
function json(req, data, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    ...CORS_HEADERS(req),
    "Content-Type": "application/json; charset=utf-8",
  });

  for (const [k, v] of Object.entries(extraHeaders || {})) {
    if (Array.isArray(v)) {
      for (const vv of v) headers.append(k, vv);
    } else if (v !== undefined && v !== null && v !== "") {
      headers.set(k, String(v));
    }
  }

  return new Response(JSON.stringify(data), { status, headers });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function getCookie(req, name) {
  const cookie = req.headers.get("cookie") || req.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (k === name) {
      const raw = rest.join("=") || "";
      try {
        return decodeURIComponent(raw);
      } catch {
        return raw;
      }
    }
  }
  return "";
}

// ✅ Cookie للجلسة (للـ Middleware)
function setAuthCookie(token) {
  // 30 يوم
  return `sandooq_token_v1=${encodeURIComponent(
    token
  )}; Path=/; Max-Age=2592000; Secure; SameSite=Lax; HttpOnly`;
}

// ✅ نخلي القديم شغال كمان
function setLegacyCookie(token) {
  return `sandooq_session_v1=${encodeURIComponent(
    token
  )}; Path=/; Max-Age=2592000; Secure; SameSite=Lax; HttpOnly`;
}

function clearAuthCookie() {
  return `sandooq_token_v1=; Path=/; Max-Age=0; Secure; SameSite=Lax; HttpOnly`;
}
function clearLegacyCookie() {
  return `sandooq_session_v1=; Path=/; Max-Age=0; Secure; SameSite=Lax; HttpOnly`;
}

async function tableCols(DB, table) {
  try {
    const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
    return new Set((res?.results || []).map((r) => String(r.name)));
  } catch {
    return new Set();
  }
}

async function tableExists(DB, table) {
  try {
    const r = await DB.prepare(
      `SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1`
    )
      .bind(table)
      .first();
    return !!r?.name;
  } catch {
    return false;
  }
}

async function findSessionEmail(DB, token) {
  if (!token) return null;

  const cols = await tableCols(DB, "sessions");
  if (!cols.size || !cols.has("token")) return null;

  if (cols.has("email")) {
    const row = await DB.prepare(
      `SELECT email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    )
      .bind(token)
      .first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  if (cols.has("user_email")) {
    const row = await DB.prepare(
      `SELECT user_email AS email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    )
      .bind(token)
      .first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  return null;
}

function isVerifiedFromUserRow(u) {
  return (
    u?.is_email_verified === 1 ||
    u?.email_verified === 1 ||
    u?.verified === 1 ||
    u?.is_verified === 1
  );
}

// ✅ نفس منطق _middleware.js (عشان ما يصير تضارب)
async function isActivated(DB, email) {
  email = normalizeEmail(email);

  // 1) activations
  if (await tableExists(DB, "activations")) {
    const cols = await tableCols(DB, "activations");
    const where = [];
    const binds = [];

    if (cols.has("email")) {
      where.push("email = ?");
      binds.push(email);
    }
    if (cols.has("user_email")) {
      where.push("user_email = ?");
      binds.push(email);
    }
    if (cols.has("used_by_email")) {
      where.push("used_by_email = ?");
      binds.push(email);
    }

    if (where.length) {
      const row = await DB.prepare(
        `SELECT 1 AS ok FROM activations WHERE (${where.join(" OR ")}) LIMIT 1`
      )
        .bind(...binds)
        .first();
      if (row) return true;
    }
  }

  // 2) codes (بعض النسخ تربط الكود بالإيميل)
  if (await tableExists(DB, "codes")) {
    const cols = await tableCols(DB, "codes");
    const where = [];
    const binds = [];

    if (cols.has("used_by_email")) {
      where.push("used_by_email = ?");
      binds.push(email);
    }
    if (cols.has("email")) {
      where.push("email = ?");
      binds.push(email);
    }
    if (cols.has("user_email")) {
      where.push("user_email = ?");
      binds.push(email);
    }

    if (where.length) {
      const row = await DB.prepare(
        `SELECT 1 AS ok FROM codes WHERE (${where.join(" OR ")}) LIMIT 1`
      )
        .bind(...binds)
        .first();
      if (row) return true;
    }
  }

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
    if (!env.DB) {
      return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);
    }

    // token من:
    // 1) Authorization: Bearer
    // 2) Cookie: sandooq_token_v1
    // 3) Cookie: sandooq_session_v1
    // 4) body.token (احتياط)
    const auth = request.headers.get("Authorization") || "";
    const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

    const cookieTokNew = getCookie(request, "sandooq_token_v1");
    const cookieTokOld = getCookie(request, "sandooq_session_v1");

    const body = await request.json().catch(() => ({}));
    const bodyTok = body?.token ? String(body.token).trim() : "";

    const token = bearer || cookieTokNew || cookieTokOld || bodyTok;
    if (!token) {
      return json(
        request,
        { ok: false, error: "NO_SESSION" },
        401,
        { "Set-Cookie": [clearAuthCookie(), clearLegacyCookie()] }
      );
    }

    const email = await findSessionEmail(env.DB, token);
    if (!email) {
      return json(
        request,
        { ok: false, error: "SESSION_NOT_FOUND" },
        401,
        { "Set-Cookie": [clearAuthCookie(), clearLegacyCookie()] }
      );
    }

    const userRow = await env.DB.prepare(
      `SELECT * FROM users WHERE email = ? LIMIT 1`
    )
      .bind(email)
      .first();

    if (!userRow) {
      return json(
        request,
        { ok: false, error: "USER_NOT_FOUND" },
        401,
        { "Set-Cookie": [clearAuthCookie(), clearLegacyCookie()] }
      );
    }

    const verified = isVerifiedFromUserRow(userRow);
    const activated = await isActivated(env.DB, email);

    // ✅ زرع Cookie (عشان /app ما يعلّق)
    return json(
      request,
      {
        ok: true,
        email,
        verified,
        activated,
        provider: userRow.provider || "email",
      },
      200,
      { "Set-Cookie": [setAuthCookie(token), setLegacyCookie(token)] }
    );
  } catch (e) {
    console.log("me_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
me.js – api2 – إصدار 3 (توحيد منطق التفعيل مع _middleware.js لمنع التضارب/اللوب)
*/
