// functions/_middleware.js
// حماية /app و game_full للنظام القديم + دعم دخول الموقع الجديد عبر sg_token
// يدعم منتجين منفصلين يفتحان نفس اللعبة:
// - horof
// - horof-edu

const ALLOW_GUEST_PLAYERS = true;

const SCHEMA_TTL_MS = 60_000;
const schemaCache = new Map();

const NEW_AUTH_API_BASE = "https://sandooq-games-api.sandooq-m.workers.dev";
const NEW_SITE_TOKEN_COOKIE = "sandooq_site_token_v1";
const NEW_SITE_GAME_COOKIE = "sandooq_site_game_v1";
const NEW_GAME_ENTRY_PATH = "/app";

const NEW_TOKEN_QUERY_KEYS = [
  "sg_token",
  "sandooq_token",
  "access_token",
  "token"
];

const NEW_GAME_QUERY_KEYS = [
  "sg_game",
  "game_id",
  "game"
];

const ALLOWED_SITE_GAMES = new Set([
  "horof",
  "horof-edu"
]);

const HOROF_SHARED_GAME_IDS = new Set([
  "horof",
  "horof-edu"
]);

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeAnyGameId(gameId) {
  return String(gameId || "").trim().toLowerCase();
}

function normalizeGameId(gameId) {
  const value = normalizeAnyGameId(gameId);
  return ALLOWED_SITE_GAMES.has(value) ? value : "";
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

function buildSessionCookie(name, value, url) {
  const secure = url.protocol === "https:" ? "; Secure" : "";
  return `${name}=${encodeURIComponent(value)}; Path=/; SameSite=Lax${secure}`;
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

  for (let i = 0; i < arr.length; i++) {
    hex += arr[i].toString(16).padStart(2, "0");
  }

  return hex;
}

async function findSessionEmail(DB, env, token) {
  if (!token) return null;

  const cols = await getCols(DB, "sessions");
  if (!cols.size) return null;

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

    if (aCols.has("email")) {
      where.push("email = ?");
      binds.push(email);
    }

    if (aCols.has("user_email")) {
      where.push("user_email = ?");
      binds.push(email);
    }

    if (aCols.has("used_by_email")) {
      where.push("used_by_email = ?");
      binds.push(email);
    }

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

    if (cCols.has("used_by_email")) {
      where.push("used_by_email = ?");
      binds.push(email);
    }

    if (cCols.has("email")) {
      where.push("email = ?");
      binds.push(email);
    }

    if (cCols.has("user_email")) {
      where.push("user_email = ?");
      binds.push(email);
    }

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

function readFirstQueryValue(url, keys) {
  for (const key of keys) {
    const value = String(url.searchParams.get(key) || "").trim();
    if (value) return value;
  }

  return "";
}

function hasNewAccessQuery(url) {
  const keys = [
    ...NEW_TOKEN_QUERY_KEYS,
    ...NEW_GAME_QUERY_KEYS,
    "sg_temp",
    "temporary",
    "is_temporary"
  ];

  return keys.some(key => url.searchParams.has(key));
}

function createTemporaryDeviceToken() {
  try {
    if (crypto.randomUUID) return "horof_site_" + crypto.randomUUID();
  } catch {}

  try {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return "horof_site_" + Array.from(bytes).map(byte => byte.toString(16).padStart(2, "0")).join("");
  } catch {}

  return "horof_site_" + Date.now().toString(36) + Math.random().toString(36).slice(2);
}

function redirectToUrl(targetUrl, cookies = []) {
  const headers = new Headers();
  headers.set("Location", targetUrl.toString());
  headers.set("Cache-Control", "no-store");
  headers.set("Pragma", "no-cache");
  headers.set("Vary", "Cookie, Authorization");

  cookies.forEach(cookie => headers.append("Set-Cookie", cookie));

  return new Response(null, {
    status: 302,
    headers
  });
}

function redirectToCleanUrl(currentUrl, cookies = []) {
  const target = new URL(currentUrl.toString());

  [
    ...NEW_TOKEN_QUERY_KEYS,
    ...NEW_GAME_QUERY_KEYS,
    "sg_temp",
    "temporary",
    "is_temporary"
  ].forEach(key => target.searchParams.delete(key));

  return redirectToUrl(target, cookies);
}

function isNewSystemLanding(path, url) {
  const cleanPath = String(path || "").toLowerCase();

  return (
    hasNewAccessQuery(url) &&
    (
      cleanPath === "/" ||
      cleanPath === "/index" ||
      cleanPath === "/index.html"
    )
  );
}

function getRequestedGameCandidates(request, url) {
  const gameFromQuery = normalizeGameId(readFirstQueryValue(url, NEW_GAME_QUERY_KEYS));
  const gameFromCookie = normalizeGameId(getCookie(request, NEW_SITE_GAME_COOKIE));

  if (gameFromQuery) return [gameFromQuery];
  if (gameFromCookie) return [gameFromCookie];

  return Array.from(ALLOWED_SITE_GAMES);
}

function isAllowedAccessResponse(data) {
  if (!data || typeof data !== "object") return false;

  return (
    data.allowed === true ||
    data.access === true ||
    data.can_play === true ||
    data.canPlay === true ||
    data.has_access === true ||
    data.hasAccess === true ||
    data.permitted === true ||
    data?.access?.allowed === true ||
    data?.game?.allowed === true ||
    (data.ok === true && (
      data.allowed !== false &&
      (
        data.access === true ||
        data.can_play === true ||
        data.canPlay === true ||
        data.has_access === true ||
        data.hasAccess === true ||
        data?.access?.allowed === true
      )
    ))
  );
}

function extractOwnedGameIds(data) {
  const ids = new Set();

  function addId(value) {
    const id = normalizeAnyGameId(value);
    if (id) ids.add(id);
  }

  function readGameObject(game) {
    if (!game || typeof game !== "object") return;

    addId(game.id);
    addId(game.slug);
    addId(game.game_id);
    addId(game.gameId);
    addId(game.product_id);
    addId(game.productId);
    addId(game.key);
  }

  function readArray(list) {
    if (!Array.isArray(list)) return;

    list.forEach(item => {
      if (!item) return;
      if (typeof item === "string") addId(item);
      else readGameObject(item);
    });
  }

  if (!data || typeof data !== "object") return ids;

  readArray(data.games);
  readArray(data.owned_games);
  readArray(data.ownedGames);
  readArray(data.entitlements);
  readArray(data.products);
  readArray(data.library);

  if (data.customer && typeof data.customer === "object") {
    readArray(data.customer.games);
    readArray(data.customer.owned_games);
    readArray(data.customer.ownedGames);
    readArray(data.customer.entitlements);
    readArray(data.customer.products);
    readArray(data.customer.library);
  }

  return ids;
}

function ownedGamesAllowRequestedGame(ownedIds, requestedGameId) {
  const requested = normalizeGameId(requestedGameId);
  if (!requested) return false;

  if (ownedIds.has(requested)) return true;

  if (HOROF_SHARED_GAME_IDS.has(requested)) {
    for (const id of HOROF_SHARED_GAME_IDS) {
      if (ownedIds.has(id)) return true;
    }
  }

  return false;
}

async function verifyViaGameAccessEndpoint(token, gameId) {
  try {
    const apiResponse = await fetch(`${NEW_AUTH_API_BASE}/api/game/access`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({
        game_id: gameId,
        device_token: createTemporaryDeviceToken(),
        device_name: `Horof Site Access - ${gameId}`,
        is_temporary: true
      }),
      cache: "no-store"
    });

    let data = {};
    try {
      data = await apiResponse.json();
    } catch {}

    return apiResponse.ok && isAllowedAccessResponse(data);
  } catch {
    return false;
  }
}

async function verifyViaAccountMe(token, gameId) {
  try {
    const apiResponse = await fetch(`${NEW_AUTH_API_BASE}/api/account/me`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": `Bearer ${token}`
      },
      cache: "no-store"
    });

    let data = {};
    try {
      data = await apiResponse.json();
    } catch {}

    if (!apiResponse.ok || !data || data.ok === false) return false;

    const ownedIds = extractOwnedGameIds(data);
    return ownedGamesAllowRequestedGame(ownedIds, gameId);
  } catch {
    return false;
  }
}

async function checkNewSystemAccess(request, env, url) {
  const tokenFromQuery = readFirstQueryValue(url, NEW_TOKEN_QUERY_KEYS);
  const tokenFromCookie = getCookie(request, NEW_SITE_TOKEN_COOKIE);
  const token = tokenFromQuery || tokenFromCookie;

  if (!token) {
    return { allowed: false };
  }

  const gameCandidates = getRequestedGameCandidates(request, url);

  for (const gameId of gameCandidates) {
    if (!gameId) continue;

    const allowedByAccess = await verifyViaGameAccessEndpoint(token, gameId);
    const allowedByAccount = allowedByAccess ? true : await verifyViaAccountMe(token, gameId);

    if (allowedByAccess || allowedByAccount) {
      const cookiesToSet = [];

      if (tokenFromQuery) {
        cookiesToSet.push(buildSessionCookie(NEW_SITE_TOKEN_COOKIE, token, url));
      }

      cookiesToSet.push(buildSessionCookie(NEW_SITE_GAME_COOKIE, gameId, url));

      return {
        allowed: true,
        gameId,
        cookies: cookiesToSet,
        redirectCleanUrl: hasNewAccessQuery(url)
      };
    }
  }

  return { allowed: false };
}

function appendSetCookies(response, cookies = []) {
  if (!cookies.length) return response;

  const headers = new Headers(response.headers);
  cookies.forEach(cookie => headers.append("Set-Cookie", cookie));
  headers.set("Cache-Control", "no-store");
  headers.set("Pragma", "no-cache");
  headers.set("Vary", "Cookie, Authorization");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function isGuestPlayerRequest(request, url) {
  const sp = url.searchParams;

  const view = (sp.get("view") || "").toLowerCase();
  if (view === "player") return true;

  const role = (sp.get("role") || "").toLowerCase();
  if (role === "player") return true;

  const guestFlag = (sp.get("guest") || sp.get("player") || sp.get("isPlayer") || "").toLowerCase();
  if (guestFlag === "1" || guestFlag === "true" || guestFlag === "yes") return true;

  const pid = sp.get("pid");
  const code = sp.get("code") || sp.get("room") || sp.get("roomId");
  if (pid && code) return true;

  const cRole = (getCookie(request, "sandooq_role") || "").toLowerCase();
  if (cRole === "player") return true;

  const cGuest = (getCookie(request, "sandooq_guest_player") || "").toLowerCase();
  if (cGuest === "1" || cGuest === "true" || cGuest === "yes") return true;

  const cPid = getCookie(request, "sandooq_pid");
  const cCode = getCookie(request, "sandooq_room_code");
  if (cPid && cCode) return true;

  const ref = request.headers.get("referer") || request.headers.get("Referer") || "";

  if (ref) {
    if (
      ref.includes("role=player") ||
      ref.includes("guest=1") ||
      ref.includes("player=1") ||
      ref.includes("view=player")
    ) {
      return true;
    }

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

function isDisplayScreenRequest(request, url) {
  const sp = url.searchParams;
  const path = url.pathname.toLowerCase();

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

  const cRole = (getCookie(request, "sandooq_role") || "").toLowerCase();
  if (["screen", "display", "tv", "monitor"].includes(cRole)) return true;

  const cView = (getCookie(request, "sandooq_view") || "").toLowerCase();
  if (["screen", "display", "tv", "monitor"].includes(cView)) return true;

  const cScreen = (getCookie(request, "sandooq_display_screen") || "").toLowerCase();
  if (cScreen === "1" || cScreen === "true" || cScreen === "yes") return true;

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

  const isActivatePath = path.startsWith("/activate");

  if (isActivatePath && (hasNewAccessQuery(url) || getCookie(request, NEW_SITE_TOKEN_COOKIE))) {
    const siteAccess = await checkNewSystemAccess(request, env, url);

    if (siteAccess.allowed) {
      const target = new URL(NEW_GAME_ENTRY_PATH, url.origin);
      return redirectToUrl(target, siteAccess.cookies || []);
    }
  }

  if (
    path.startsWith("/cdn-cgi/") ||
    path.startsWith("/api2/") ||
    isActivatePath ||
    path === "/logo.png" ||
    path === "/favicon.ico" ||
    path === "/robots.txt"
  ) {
    return next();
  }

  const protectRootGameFull =
    path === "/game_full.html" ||
    path === "/game_full" ||
    path === "/game_full/";

  const protectApp = path.startsWith("/app");

  const siteAccessLanding = isNewSystemLanding(path, url);

  if (ALLOW_GUEST_PLAYERS) {
    if ((protectRootGameFull || protectApp) && isGuestPlayerRequest(request, url)) {
      return next();
    }
  }

  if (protectRootGameFull || protectApp) {
    if (isDisplayScreenRequest(request, url)) {
      return next();
    }
  }

  const needsProtection = protectApp || protectRootGameFull || siteAccessLanding;

  if (!needsProtection) return next();

  if (request.method === "OPTIONS") return next();

  const siteAccess = await checkNewSystemAccess(request, env, url);

  if (siteAccess.allowed) {
    if (siteAccessLanding) {
      const target = new URL(NEW_GAME_ENTRY_PATH, url.origin);
      return redirectToUrl(target, siteAccess.cookies || []);
    }

    if (siteAccess.redirectCleanUrl) {
      return redirectToCleanUrl(url, siteAccess.cookies || []);
    }

    const response = await next();
    return appendSetCookies(response, siteAccess.cookies || []);
  }

  if (!env?.DB) {
    return withNoStore(new Response("DB_NOT_BOUND", { status: 500 }));
  }

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
