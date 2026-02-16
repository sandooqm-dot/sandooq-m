// functions/_middleware.js
// حماية /app: لازم يكون فيه session token + لازم يكون الحساب مُفعّل (Activated)
// v8: Fix لاعبين الانتظار -> اللعبة: السماح للاعب بالدخول حتى لو انتقل للعبة بدون role بالـ URL
//     (نعتمد على role=player أو Referer من play/waiting أو Cookie خفيف للاعب)

const ALLOW_GUEST_PLAYERS = true;

const SCHEMA_TTL_MS = 60_000; // دقيقة (يخفف ضغط PRAGMA)
const schemaCache = new Map(); // table -> { ts, cols:Set }

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function getCookie(req, name) {
  const cookie = req.headers.get("cookie") || req.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (k === name) {
      const raw = (rest.join("=") || "").trim();
      if (!raw) return "";
      try { return decodeURIComponent(raw); } catch { return raw; }
    }
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

async function getCols(DB, table) {
  const now = Date.now();
  const cached = schemaCache.get(table);
  if (cached && (now - cached.ts) < SCHEMA_TTL_MS) return cached.cols;

  try {
    const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
    const cols = new Set((res?.results || []).map((r) => String(r.name)));
    schemaCache.set(table, { ts: now, cols });
    return cols;
  } catch {
    const cols = new Set();
    schemaCache.set(table, { ts: now, cols });
    return cols;
  }
}

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

async function findSessionEmail(DB, env, token) {
  if (!token) return null;

  const cols = await getCols(DB, "sessions");
  if (!cols.size) return null;

  // 1) sessions.token (الأسلوب الحالي عندك)
  if (cols.has("token")) {
    // أعمدة الإيميل المحتملة
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
    if (cols.has("used_by_email")) {
      const row = await DB.prepare(
        `SELECT used_by_email AS email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
      ).bind(token).first();
      return row?.email ? normalizeEmail(row.email) : null;
    }
    return null;
  }

  // 2) sessions.token_hash (متوافق مع logout.js)
  if (cols.has("token_hash")) {
    const pepper = String(env?.SESSION_PEPPER || "sess_pepper_v1");
    const tokenHash = await sha256Hex(token + "|" + pepper);

    // أعمدة الإيميل المحتملة
    if (cols.has("email")) {
      const row = await DB.prepare(
        `SELECT email FROM sessions WHERE token_hash = ? LIMIT 1`
      ).bind(tokenHash).first();
      return row?.email ? normalizeEmail(row.email) : null;
    }
    if (cols.has("user_email")) {
      const row = await DB.prepare(
        `SELECT user_email AS email FROM sessions WHERE token_hash = ? LIMIT 1`
      ).bind(tokenHash).first();
      return row?.email ? normalizeEmail(row.email) : null;
    }
    if (cols.has("used_by_email")) {
      const row = await DB.prepare(
        `SELECT used_by_email AS email FROM sessions WHERE token_hash = ? LIMIT 1`
      ).bind(tokenHash).first();
      return row?.email ? normalizeEmail(row.email) : null;
    }
    return null;
  }

  return null;
}

async function isActivatedViaUsers(DB, email) {
  email = normalizeEmail(email);

  const cols = await getCols(DB, "users");
  if (!cols.size) return false;

  let emailCol = null;
  if (cols.has("email")) emailCol = "email";
  else if (cols.has("user_email")) emailCol = "user_email";
  else return false;

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

  // 0) الأفضل: users
  if (await isActivatedViaUsers(DB, email)) return true;

  // 1) activations
  const aCols = await getCols(DB, "activations");
  if (aCols.size) {
    const where = [];
    const binds = [];
    if (aCols.has("email")) { where.push("email = ?"); binds.push(email); }
    if (aCols.has("user_email")) { where.push("user_email = ?"); binds.push(email); }
    if (aCols.has("used_by_email")) { where.push("used_by_email = ?"); binds.push(email); }

    if (where.length) {
      const row = await DB.prepare(
        `SELECT 1 AS ok FROM activations WHERE (${where.join(" OR ")}) LIMIT 1`
      ).bind(...binds).first();
      if (row) return true;
    }
  }

  // 2) codes
  const cCols = await getCols(DB, "codes");
  if (cCols.size) {
    const where = [];
    const binds = [];
    if (cCols.has("used_by_email")) { where.push("used_by_email = ?"); binds.push(email); }
    if (cCols.has("email")) { where.push("email = ?"); binds.push(email); }
    if (cCols.has("user_email")) { where.push("user_email = ?"); binds.push(email); }

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

// ✅ تحديد إن كان الطلب “لاعب” حتى لو ما انحط role=player في رابط صفحة اللعبة
function isGuestPlayerRequest(request, url) {
  // 1) من الـ URL
  const role = (url.searchParams.get("role") || "").toLowerCase();
  if (role === "player") return true;

  // 2) من Cookie (اختياري لو تحب تستخدمه لاحقًا)
  const cRole =
    (getCookie(request, "sandooq_role") || getCookie(request, "sandooq_player_role") || "").toLowerCase();
  if (cRole === "player") return true;

  const cGuest = (getCookie(request, "sandooq_guest_player") || getCookie(request, "sandooq_guest") || "");
  if (cGuest === "1" || cGuest.toLowerCase() === "true") return true;

  // 3) من Referer (هذا هو المهم لحالتك: play.html -> game_full.html بدون باراميترات)
  const ref = request.headers.get("referer") || request.headers.get("Referer") || "";
  if (ref) {
    // fallback سريع
    if (ref.includes("role=player")) return true;

    try {
      const ru = new URL(ref);
      const rRole = (ru.searchParams.get("role") || "").toLowerCase();
      if (rRole === "player") return true;

      const fromWaiting =
        ru.pathname.endsWith("/play.html") ||
        ru.pathname.endsWith("/waiting.html") ||
        ru.pathname.endsWith("/join.html");

      // إذا جاي من صفحة انتظار/انضمام ومعه pid+code نعتبره لاعب
      if (fromWaiting) {
        const pid = ru.searchParams.get("pid");
        const code = ru.searchParams.get("code") || ru.searchParams.get("room") || ru.searchParams.get("roomId");
        if (pid && code) return true;
      }
    } catch {}
  }

  return false;
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

  // ✅ تحديد الصفحات المحمية
  const protectGameFull =
    path === "/game_full.html" ||
    path === "/game_full" ||
    path === "/game_full/" ||
    path === "/app/game_full.html" ||
    path === "/app/game_full" ||
    path === "/app/game_full/";

  // ✅✅ إصلاح المشكلة: السماح للاعب يدخل صفحة اللعبة حتى لو الرابط ما فيه role=player
  if (ALLOW_GUEST_PLAYERS && protectGameFull) {
    if (isGuestPlayerRequest(request, url)) {
      return next();
    }
  }

  const needsProtection = path.startsWith("/app") || protectGameFull;

  // إذا ما يحتاج حماية، مرّره
  if (!needsProtection) return next();

  // السماح لـ OPTIONS
  if (request.method === "OPTIONS") return next();

  // لازم DB
  if (!env?.DB) return withNoStore(new Response("DB_NOT_BOUND", { status: 500 }));

  // token من cookie أو Authorization
  const auth = request.headers.get("Authorization") || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

  const tokNew = getCookie(request, "sandooq_token_v1");
  const tokOld = getCookie(request, "sandooq_session_v1");
  const token = tokNew || tokOld || bearer;

  if (!token) return redirectToActivate(url);

  const email = await findSessionEmail(env.DB, env, token);
  if (!email) {
    const r = redirectToActivate(url);
    r.headers.append("Set-Cookie", clearCookie("sandooq_token_v1"));
    r.headers.append("Set-Cookie", clearCookie("sandooq_session_v1"));
    return r;
  }

  const activated = await isActivated(env.DB, email);
  if (!activated) return redirectToActivate(url);

  return next();
}

/*
_middleware.js – إصدار 8 (Fix: allow players via role/cookie/referer so they don't get sent to /activate)
*/
