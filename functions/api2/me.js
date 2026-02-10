// functions/api2/me.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-me-v2-session";

  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405, cors);
  }

  if (!env?.DB) {
    return json({ ok: false, error: "DB_NOT_BOUND", version: VERSION }, 500, cors);
  }

  // جلب session token من الكوكي
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookieName = String(env.SESSION_COOKIE_NAME || "sandooq_session_v1");
  const token =
    getCookie(cookieHeader, cookieName) ||
    getCookie(cookieHeader, "sandooq_token_v1") ||
    "";

  if (!token) {
    return unauth(cors, VERSION);
  }

  // ensure schema
  await ensureUsersColumns(env.DB);
  await ensureSessionsTable(env.DB);

  const pepper = String(env.SESSION_PEPPER || "sess_pepper_v1");
  const tokenHash = await sha256Hex(token + "|" + pepper);

  const nowIso = new Date().toISOString();

  const sess = await env.DB.prepare(
    `SELECT email, expires_at
     FROM sessions
     WHERE token_hash = ?
     LIMIT 1`
  ).bind(tokenHash).first();

  if (!sess) {
    return unauth(cors, VERSION, true);
  }

  const exp = String(sess.expires_at || "");
  if (!exp || exp <= nowIso) {
    // انتهت الجلسة
    try {
      await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(tokenHash).run();
    } catch {}
    return unauth(cors, VERSION, true);
  }

  const email = String(sess.email || "").trim().toLowerCase();
  if (!email) {
    return unauth(cors, VERSION, true);
  }

  const u = await env.DB.prepare(
    `SELECT email, provider, is_email_verified
     FROM users
     WHERE email = ?
     LIMIT 1`
  ).bind(email).first();

  if (!u) {
    return unauth(cors, VERSION, true);
  }

  const verified = Number(u.is_email_verified || 0) === 1;

  // activated?
  let activated = false;
  try {
    const act = await env.DB.prepare(
      `SELECT 1 FROM activations WHERE email = ? LIMIT 1`
    ).bind(email).first();
    activated = !!act;
  } catch {
    activated = false;
  }

  return json(
    { ok: true, version: VERSION, email, verified, activated },
    200,
    cors
  );
}

/* ---------- helpers ---------- */

function json(obj, status, corsHeaders) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(obj), { status, headers });
}

function unauth(cors, VERSION, clearCookies = false) {
  const headers = new Headers(cors);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  if (clearCookies) {
    headers.append("Set-Cookie", clearCookie(String("sandooq_session_v1")));
    headers.append("Set-Cookie", clearCookie(String("sandooq_token_v1")));
  }
  return new Response(JSON.stringify({ ok: false, error: "UNAUTHORIZED", version: VERSION }), {
    status: 401,
    headers,
  });
}

function clearCookie(name) {
  return `${name}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`;
}

function makeCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowedRaw = String(env?.ALLOWED_ORIGINS || "").trim();
  let allowOrigin = "*";

  if (allowedRaw) {
    const allowed = allowedRaw.split(",").map((s) => s.trim()).filter(Boolean);
    if (allowed.includes("*")) allowOrigin = "*";
    else if (origin && allowed.includes(origin)) allowOrigin = origin;
    else allowOrigin = allowed[0] || "*";
  } else if (origin) {
    allowOrigin = origin;
  }

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    Vary: "Origin",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };
}

function getCookie(cookieHeader, name) {
  const parts = String(cookieHeader || "").split(";").map((s) => s.trim());
  for (const p of parts) {
    if (!p) continue;
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    const k = p.slice(0, eq).trim();
    const v = p.slice(eq + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return "";
}

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

async function ensureUsersColumns(DB) {
  await DB.prepare(`ALTER TABLE users ADD COLUMN is_email_verified INTEGER DEFAULT 0`).run().catch(() => {});
  await DB.prepare(`ALTER TABLE users ADD COLUMN email_verified_at TEXT`).run().catch(() => {});
}

async function ensureSessionsTable(DB) {
  await DB.prepare(
    `CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      device_id TEXT
    )`
  ).run();
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email)`).run().catch(() => {});
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`).run().catch(() => {});
}
