// functions/api2/logout.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-logout-v1";

  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405, cors);
  }

  if (!env?.DB) {
    // حتى لو DB مو مربوط، نرجّع كوكي فارغ عشان يسجل خروج
    return clearAndRespond(cors, env, VERSION, true);
  }

  // نحاول نحذف السيشن من DB (اختياري)
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookieName = String(env?.SESSION_COOKIE_NAME || "sandooq_session_v1");
  const token =
    getCookie(cookieHeader, cookieName) ||
    getCookie(cookieHeader, "sandooq_token_v1") ||
    "";

  try {
    await ensureSessionsTable(env.DB);
    if (token) {
      const pepper = String(env.SESSION_PEPPER || "sess_pepper_v1");
      const tokenHash = await sha256Hex(token + "|" + pepper);
      await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(tokenHash).run();
    }
  } catch {}

  return clearAndRespond(cors, env, VERSION, false);
}

/* ---------- helpers ---------- */

function json(obj, status, corsHeaders) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(obj), { status, headers });
}

function clearAndRespond(cors, env, VERSION, dbMissing) {
  const headers = new Headers(cors);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");

  // نمسح الكوكيين
  const mainName = String(env?.SESSION_COOKIE_NAME || "sandooq_session_v1");
  headers.append("Set-Cookie", clearCookie(mainName));
  headers.append("Set-Cookie", clearCookie("sandooq_token_v1"));

  const body = { ok: true, version: VERSION };
  if (dbMissing) body.note = "DB_MISSING_BUT_COOKIES_CLEARED";

  return new Response(JSON.stringify(body), { status: 200, headers });
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
    "Vary": "Origin",
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
}
