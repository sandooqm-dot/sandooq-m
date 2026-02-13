// functions/_middleware.js
// حماية /app: لازم يكون فيه session token + لازم يكون الحساب مُفعّل (Activated)

function getCookie(req, name) {
  const cookie = req.headers.get("cookie") || req.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (k === name) return rest.join("=") || "";
  }
  return "";
}

function clearCookie(name) {
  return `${name}=; Path=/; Max-Age=0; Secure; SameSite=Lax; HttpOnly`;
}

function withNoStore(res) {
  try {
    res.headers.set("Cache-Control", "no-store");
    res.headers.set("Pragma", "no-cache");
    res.headers.set("Vary", "Cookie, Authorization");
  } catch {}
  return res;
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

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

async function findSessionEmail(DB, token) {
  if (!token) return null;

  const cols = await tableCols(DB, "sessions");
  if (!cols.size || !cols.has("token")) return null;

  // أكثر الأعمدة شيوعًا
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

  // احتياط لو كان الاسم قديم
  if (cols.has("used_by_email")) {
    const row = await DB.prepare(
      `SELECT used_by_email AS email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    ).bind(token).first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  return null;
}

async function isActivatedViaUsers(DB, email) {
  email = normalizeEmail(email);
  if (!(await tableExists(DB, "users"))) return false;

  const cols = await tableCols(DB, "users");
  if (!cols.size) return false;

  // تحديد عمود الإيميل
  let emailCol = null;
  if (cols.has("email")) emailCol = "email";
  else if (cols.has("user_email")) emailCol = "user_email";
  else return false;

  // أفضلية: is_activated / activated (قيمة 1)
  if (cols.has("is_activated")) {
    const row = await DB.prepare(
      `SELECT 1 AS ok FROM users WHERE ${emailCol} = ? AND is_activated = 1 LIMIT 1`
    ).bind(email).first();
    return !!row;
  }

  if (cols.has("activated")) {
    const row = await DB.prepare(
      `SELECT 1 AS ok FROM users WHERE ${emailCol} = ? AND activated = 1 LIMIT 1`
    ).bind(email).first();
    return !!row;
  }

  // بدائل: activated_at أو activation_code (غير فارغة)
  if (cols.has("activated_at")) {
    const row = await DB.prepare(
      `SELECT 1 AS ok FROM users WHERE ${emailCol} = ? AND activated_at IS NOT NULL AND activated_at != '' LIMIT 1`
    ).bind(email).first();
    return !!row;
  }

  if (cols.has("activation_code")) {
    const row = await DB.prepare(
      `SELECT 1 AS ok FROM users WHERE ${emailCol} = ? AND activation_code IS NOT NULL AND activation_code != '' LIMIT 1`
    ).bind(email).first();
    return !!row;
  }

  if (cols.has("activated_code")) {
    const row = await DB.prepare(
      `SELECT 1 AS ok FROM users WHERE ${emailCol} = ? AND activated_code IS NOT NULL AND activated_code != '' LIMIT 1`
    ).bind(email).first();
    return !!row;
  }

  return false;
}

async function isActivated(DB, email) {
  email = normalizeEmail(email);

  // 0) الأفضل: users (لو فيه عمود تفعيل)
  const viaUsers = await isActivatedViaUsers(DB, email);
  if (viaUsers) return true;

  // 1) activations
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

  // 2) codes (بعض النسخ تربط الكود بالإيميل)
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

function redirectToActivate(url) {
  const next = url.pathname + (url.search || "");
  const dest = `/activate?next=${encodeURIComponent(next)}`;
  return withNoStore(new Response(null, {
    status: 302,
    headers: { "Location": dest }
  }));
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // ✅ مسارات لازم تمر دائمًا
  if (
    path.startsWith("/cdn-cgi/") ||
    path.startsWith("/api2/") ||
    path.startsWith("/activate") ||
    path === "/logo.png" ||
    path === "/favicon.ico" ||
    path === "/robots.txt"
  ) {
    return next();
  }

  // ✅ الحماية فقط على /app وملفاته
  if (!path.startsWith("/app")) {
    return next();
  }

  // السماح لـ OPTIONS (Preflight) بدون لفّة تحويل
  if (request.method === "OPTIONS") {
    return next();
  }

  // لازم DB عشان نتحقق
  if (!env?.DB) {
    return withNoStore(new Response("DB_NOT_BOUND", { status: 500 }));
  }

  // token من:
  // 1) Cookie الجديد sandooq_token_v1
  // 2) Cookie القديم sandooq_session_v1
  // 3) Authorization Bearer (احتياط)
  const auth = request.headers.get("Authorization") || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

  const tokNew = getCookie(request, "sandooq_token_v1");
  const tokOld = getCookie(request, "sandooq_session_v1");
  const token = tokNew || tokOld || bearer;

  if (!token) {
    return redirectToActivate(url);
  }

  const email = await findSessionEmail(env.DB, token);
  if (!email) {
    const r = redirectToActivate(url);
    r.headers.append("Set-Cookie", clearCookie("sandooq_token_v1"));
    r.headers.append("Set-Cookie", clearCookie("sandooq_session_v1"));
    return r;
  }

  const activated = await isActivated(env.DB, email);
  if (!activated) {
    return redirectToActivate(url);
  }

  // ✅ كل شيء تمام
  return next();
}

/*
_middleware.js – إصدار 3 (Users-first activation + no-store headers + extra safety)
*/
