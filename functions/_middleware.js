// functions/_middleware.js
// حماية /app: لازم يكون فيه session token + لازم يكون الحساب مُفعّل (Activated)
// v10: السماح لشاشة العرض بالدخول المباشر بدون تسجيل دخول إذا كان الرابط خاص بالعرض
//      مع الإبقاء على حماية المقدم، والسماح للاعب كما هو

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

  if (await isActivatedViaUsers(DB, email)) return true;

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

// ✅ تحديد اللاعب حتى لو صفحة اللعبة فُتحت بدون role بالـ URL
function isGuestPlayerRequest(request, url) {
  const sp = url.searchParams;

  // (0) Flags سريعة (أنت ترسلها من join.html)
  const view = (sp.get("view") || "").toLowerCase();
  if (view === "player") return true;

  const role = (sp.get("role") || "").toLowerCase();
  if (role === "player") return true;

  const guestFlag = (sp.get("guest") || sp.get("player") || sp.get("isPlayer") || "").toLowerCase();
  if (guestFlag === "1" || guestFlag === "true" || guestFlag === "yes") return true;

  // (1) pid + code
  const pid = sp.get("pid");
  const code = sp.get("code") || sp.get("room") || sp.get("roomId");
  if (pid && code) return true;

  // (2) Cookies للدور (القديمة)
  const cRole = (getCookie(request, "sandooq_role") || "").toLowerCase();
  if (cRole === "player") return true;

  const cGuest = (getCookie(request, "sandooq_guest_player") || "").toLowerCase();
  if (cGuest === "1" || cGuest === "true" || cGuest === "yes") return true;

  // (3) Cookies بديلة: pid + room_code (أنت تخزنهم)
  const cPid = getCookie(request, "sandooq_pid");
  const cCode = getCookie(request, "sandooq_room_code");
  if (cPid && cCode) return true;

  // (4) Referer من صفحات انتظار/انضمام (أوسع من السابق)
  const ref = request.headers.get("referer") || request.headers.get("Referer") || "";
  if (ref) {
    if (ref.includes("role=player") || ref.includes("guest=1") || ref.includes("player=1") || ref.includes("view=player")) return true;

    try {
      const ru = new URL(ref);
      const rRole = (ru.searchParams.get("role") || "").toLowerCase();
      const rView = (ru.searchParams.get("view") || "").toLowerCase();
      const rGuest = (ru.searchParams.get("guest") || ru.searchParams.get("player") || "").toLowerCase();

      if (rRole === "player" || rView === "player" || rGuest === "1" || rGuest === "true") return true;

      const fromWaiting = /\/(play|waiting|wait|lobby|join)\.html$/i.test(ru.pathname);
      const rpid = ru.searchParams.get("pid");
      const rcode = ru.searchParams.get("code") || ru.searchParams.get("room") || ru.searchParams.get("roomId");
      if (fromWaiting && ((rpid && rcode) || (rcode && (rGuest === "1" || rRole === "player" || rView === "player")))) return true;
    } catch {}
  }

  return false;
}

// ✅ تحديد شاشة العرض: رابط عام لا يحتاج تسجيل دخول
function isDisplayScreenRequest(request, url) {
  const sp = url.searchParams;
  const path = url.pathname.toLowerCase();

  // 1) مسارات شائعة إذا وُجدت
  if (
    path.includes("/display") ||
    path.includes("/screen") ||
    path.includes("/tv") ||
    path.endsWith("/display.html") ||
    path.endsWith("/screen.html") ||
    path.endsWith("/tv.html") ||
    path.endsWith("/monitor.html")
  ) {
    return true;
  }

  // 2) بارامترات شائعة لشاشة العرض
  const view = (sp.get("view") || "").toLowerCase();
  const role = (sp.get("role") || "").toLowerCase();
  const mode = (sp.get("mode") || "").toLowerCase();

  if (["screen", "display", "tv", "monitor"].includes(view)) return true;
  if (["screen", "display", "tv", "monitor"].includes(role)) return true;
  if (["screen", "display", "tv", "monitor"].includes(mode)) return true;

  const flagNames = ["screen", "display", "tv", "isScreen", "isDisplay", "isTv"];
  for (const name of flagNames) {
    const val = (sp.get(name) || "").toLowerCase();
    if (val === "1" || val === "true" || val === "yes") return true;
  }

  // 3) كوكيز محتملة إن وجدت
  const cRole = (getCookie(request, "sandooq_role") || "").toLowerCase();
  if (["screen", "display", "tv", "monitor"].includes(cRole)) return true;

  const cView = (getCookie(request, "sandooq_view") || "").toLowerCase();
  if (["screen", "display", "tv", "monitor"].includes(cView)) return true;

  const cScreen = (getCookie(request, "sandooq_display_screen") || "").toLowerCase();
  if (cScreen === "1" || cScreen === "true" || cScreen === "yes") return true;

  // 4) Referer إذا فُتح الرابط من صفحة اللوبي
  const ref = request.headers.get("referer") || request.headers.get("Referer") || "";
  if (ref) {
    if (
      ref.includes("view=screen") ||
      ref.includes("view=display") ||
      ref.includes("view=tv") ||
      ref.includes("role=screen") ||
      ref.includes("role=display") ||
      ref.includes("mode=screen") ||
      ref.includes("mode=display") ||
      ref.includes("mode=tv") ||
      ref.includes("screen=1") ||
      ref.includes("display=1") ||
      ref.includes("tv=1")
    ) {
      return true;
    }

    try {
      const ru = new URL(ref);
      const rv = (ru.searchParams.get("view") || "").toLowerCase();
      const rr = (ru.searchParams.get("role") || "").toLowerCase();
      const rm = (ru.searchParams.get("mode") || "").toLowerCase();
      const rs = (ru.searchParams.get("screen") || "").toLowerCase();
      const rd = (ru.searchParams.get("display") || "").toLowerCase();
      const rt = (ru.searchParams.get("tv") || "").toLowerCase();

      if (["screen", "display", "tv", "monitor"].includes(rv)) return true;
      if (["screen", "display", "tv", "monitor"].includes(rr)) return true;
      if (["screen", "display", "tv", "monitor"].includes(rm)) return true;
      if (["1", "true", "yes"].includes(rs)) return true;
      if (["1", "true", "yes"].includes(rd)) return true;
      if (["1", "true", "yes"].includes(rt)) return true;
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
  const protectRootGameFull =
    path === "/game_full.html" ||
    path === "/game_full" ||
    path === "/game_full/";

  const protectApp = path.startsWith("/app");

  // ✅ السماح للاعب (guest) بالدخول بدون تأمين
  if (ALLOW_GUEST_PLAYERS) {
    if ((protectRootGameFull || protectApp) && isGuestPlayerRequest(request, url)) {
      return next();
    }
  }

  // ✅ السماح لشاشة العرض بالدخول المباشر بدون تسجيل دخول
  if (protectRootGameFull || protectApp) {
    if (isDisplayScreenRequest(request, url)) {
      return next();
    }
  }

  const needsProtection = protectApp || protectRootGameFull;

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
_middleware.js – إصدار 10
التعديل:
- إضافة isDisplayScreenRequest
- السماح لرابط شاشة العرض بالدخول المباشر بدون تسجيل دخول
- الإبقاء على حماية المقدم كما هي
- الإبقاء على السماح للاعب كما هو
*/
