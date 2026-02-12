// functions/app/_middleware.js
// Protect /app/* : if no valid session OR not activated => redirect to /activate

function getCookie(req, name) {
  const cookie = req.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (k === name) return rest.join("=") || "";
  }
  return "";
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
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

  return null;
}

async function isActivated(DB, email) {
  email = normalizeEmail(email);

  if (await tableExists(DB, "activations")) {
    const cols = await tableCols(DB, "activations");
    const where = [];
    const binds = [];

    if (cols.has("email")) { where.push("email = ?"); binds.push(email); }
    if (cols.has("user_email")) { where.push("user_email = ?"); binds.push(email); }
    if (cols.has("used_by_email")) { where.push("used_by_email = ?"); binds.push(email); }

    if (where.length) {
      const row = await DB.prepare(
        `SELECT 1 AS ok FROM activations WHERE (${where.join(" OR ")}) LIMIT 1`
      ).bind(...binds).first();
      if (row) return true;
    }
  }

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

  return false;
}

export async function onRequest(context) {
  const { request, env, next } = context;

  // لازم يكون عندنا DB مربوط
  if (!env?.DB) {
    return Response.redirect(new URL("/activate", request.url).toString(), 302);
  }

  // token من الكوكي
  const token = getCookie(request, "sandooq_session_v1");
  if (!token) {
    return Response.redirect(new URL("/activate", request.url).toString(), 302);
  }

  const email = await findSessionEmail(env.DB, token);
  if (!email) {
    return Response.redirect(new URL("/activate", request.url).toString(), 302);
  }

  const activated = await isActivated(env.DB, email);
  if (!activated) {
    return Response.redirect(new URL("/activate", request.url).toString(), 302);
  }

  const res = await next();
  res.headers.set("cache-control", "no-store");
  return res;
}

/*
app/_middleware.js – إصدار 1 (Protect /app/*)
*/
