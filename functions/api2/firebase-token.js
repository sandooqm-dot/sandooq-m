// functions/api2/firebase-token.js
// POST /api2/firebase-token
// يرجّع Firebase Custom Token للمستخدم (بعد التحقق من session + activated)
// يحتاج ENV:
// - FIREBASE_PROJECT_ID
// - FIREBASE_CLIENT_EMAIL
// - FIREBASE_PRIVATE_KEY   (خزنها كنص، ولو فيها \n خليها \\n)
// اختياري:
// - SESSION_COOKIE_NAME (افتراضي: sandooq_session_v1)
// - SESSION_PEPPER (لو عندك sessions.token_hash بدل token)

const VERSION = "api2-firebase-token-v1";

export async function onRequest(context) {
  const { request, env } = context;

  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }
  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405, cors);
  }

  try {
    if (!env?.DB) return json({ ok: false, error: "DB_NOT_BOUND", version: VERSION }, 500, cors);

    // 1) اقرأ session token من Cookie أو Authorization
    const cookieHeader = request.headers.get("Cookie") || request.headers.get("cookie") || "";
    const cookieName = String(env?.SESSION_COOKIE_NAME || "sandooq_session_v1");

    const auth = request.headers.get("Authorization") || "";
    const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

    const token =
      getCookie(cookieHeader, "sandooq_token_v1") ||
      getCookie(cookieHeader, cookieName) ||
      bearer ||
      "";

    if (!token) {
      return json({ ok: false, error: "NO_SESSION", version: VERSION }, 401, cors);
    }

    // 2) جيب الإيميل من sessions
    const email = await findSessionEmail(env.DB, token, env);
    if (!email) {
      return json({ ok: false, error: "INVALID_SESSION", version: VERSION }, 401, cors);
    }

    // 3) لازم يكون Activated
    const activated = await isActivated(env.DB, email);
    if (!activated) {
      return json({ ok: false, error: "NOT_ACTIVATED", version: VERSION }, 403, cors);
    }

    // 4) جهّز Firebase Custom Token
    const projectId = String(env.FIREBASE_PROJECT_ID || "").trim();
    const clientEmail = String(env.FIREBASE_CLIENT_EMAIL || "").trim();
    let privateKey = String(env.FIREBASE_PRIVATE_KEY || "").trim();

    if (!projectId || !clientEmail || !privateKey) {
      return json({ ok: false, error: "FIREBASE_ENV_MISSING", version: VERSION }, 500, cors);
    }

    // لو مخزن \n كـ \\n
    privateKey = privateKey.replace(/\\n/g, "\n");

    const uid = await stableUidFromEmail(email);
    const firebaseToken = await mintFirebaseCustomToken({
      clientEmail,
      privateKeyPem: privateKey,
      uid,
      claims: {
        email,
        activated: true,
      },
    });

    return json(
      { ok: true, email, uid, firebaseToken, version: VERSION },
      200,
      cors
    );

  } catch (e) {
    console.log("firebase_token_error", String(e?.stack || e));
    return json({ ok: false, error: "SERVER_ERROR", version: VERSION }, 500, cors);
  }
}

/* ---------------- helpers ---------------- */

function json(obj, status, corsHeaders) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(obj), { status, headers });
}

function makeCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || request.headers.get("origin") || "";
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
    if (k === name) {
      try { return decodeURIComponent(v); } catch { return v; }
    }
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

async function findSessionEmail(DB, token, env) {
  if (!token) return null;
  if (!(await tableExists(DB, "sessions"))) return null;

  const cols = await tableCols(DB, "sessions");
  if (!cols.size) return null;

  // حدّد عمود الإيميل
  const emailCol =
    cols.has("email") ? "email" :
    cols.has("user_email") ? "user_email" :
    cols.has("used_by_email") ? "used_by_email" :
    null;

  if (!emailCol) return null;

  // 1) لو sessions فيها token (السيناريو الشائع عندك)
  if (cols.has("token")) {
    const row = await DB.prepare(
      `SELECT ${emailCol} AS email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    ).bind(token).first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  // 2) لو sessions فيها token_hash (سيناريو قديم)
  if (cols.has("token_hash")) {
    const pepper = String(env?.SESSION_PEPPER || "sess_pepper_v1");
    const tokenHash = await sha256Hex(token + "|" + pepper);

    const row = await DB.prepare(
      `SELECT ${emailCol} AS email FROM sessions WHERE token_hash = ? ORDER BY rowid DESC LIMIT 1`
    ).bind(tokenHash).first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  return null;
}

async function isActivated(DB, email) {
  email = normalizeEmail(email);

  // A) users (لو فيها أعمدة تفعيل)
  if (await tableExists(DB, "users")) {
    const cols = await tableCols(DB, "users");
    const emailCol = cols.has("email") ? "email" : (cols.has("user_email") ? "user_email" : null);

    if (emailCol) {
      if (cols.has("is_activated")) {
        const r = await DB.prepare(
          `SELECT 1 AS ok FROM users WHERE ${emailCol}=? AND is_activated=1 LIMIT 1`
        ).bind(email).first();
        if (r) return true;
      }
      if (cols.has("activated")) {
        const r = await DB.prepare(
          `SELECT 1 AS ok FROM users WHERE ${emailCol}=? AND activated=1 LIMIT 1`
        ).bind(email).first();
        if (r) return true;
      }
      if (cols.has("activated_at")) {
        const r = await DB.prepare(
          `SELECT 1 AS ok FROM users WHERE ${emailCol}=? AND activated_at IS NOT NULL AND activated_at!='' LIMIT 1`
        ).bind(email).first();
        if (r) return true;
      }
      if (cols.has("activation_code")) {
        const r = await DB.prepare(
          `SELECT 1 AS ok FROM users WHERE ${emailCol}=? AND activation_code IS NOT NULL AND activation_code!='' LIMIT 1`
        ).bind(email).first();
        if (r) return true;
      }
      if (cols.has("activated_code")) {
        const r = await DB.prepare(
          `SELECT 1 AS ok FROM users WHERE ${emailCol}=? AND activated_code IS NOT NULL AND activated_code!='' LIMIT 1`
        ).bind(email).first();
        if (r) return true;
      }
    }
  }

  // B) activations table
  if (await tableExists(DB, "activations")) {
    const cols = await tableCols(DB, "activations");
    const where = [];
    const binds = [];

    if (cols.has("email")) { where.push("email=?"); binds.push(email); }
    if (cols.has("user_email")) { where.push("user_email=?"); binds.push(email); }
    if (cols.has("used_by_email")) { where.push("used_by_email=?"); binds.push(email); }

    if (where.length) {
      const r = await DB.prepare(
        `SELECT 1 AS ok FROM activations WHERE (${where.join(" OR ")}) LIMIT 1`
      ).bind(...binds).first();
      if (r) return true;
    }
  }

  // C) codes table
  if (await tableExists(DB, "codes")) {
    const cols = await tableCols(DB, "codes");
    const where = [];
    const binds = [];

    if (cols.has("used_by_email")) { where.push("used_by_email=?"); binds.push(email); }
    if (cols.has("email")) { where.push("email=?"); binds.push(email); }
    if (cols.has("user_email")) { where.push("user_email=?"); binds.push(email); }

    if (where.length) {
      const r = await DB.prepare(
        `SELECT 1 AS ok FROM codes WHERE (${where.join(" OR ")}) LIMIT 1`
      ).bind(...binds).first();
      if (r) return true;
    }
  }

  return false;
}

async function stableUidFromEmail(email) {
  const h = await sha256Hex(normalizeEmail(email));
  return "u_" + h.slice(0, 28); // ثابت + قصير
}

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

function b64urlFromBytes(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlFromJson(obj) {
  const s = JSON.stringify(obj);
  const u8 = new TextEncoder().encode(s);
  return b64urlFromBytes(u8);
}

function pemToPkcs8Bytes(pem) {
  const clean = String(pem || "")
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s+/g, "");
  const bin = atob(clean);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function mintFirebaseCustomToken({ clientEmail, privateKeyPem, uid, claims }) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 60 * 60; // 1 hour

  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: clientEmail,
    sub: clientEmail,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: now,
    exp,
    uid,
    claims: claims || {},
  };

  const encHeader = b64urlFromJson(header);
  const encPayload = b64urlFromJson(payload);
  const toSign = `${encHeader}.${encPayload}`;

  const keyData = pemToPkcs8Bytes(privateKeyPem);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sigBuf = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    new TextEncoder().encode(toSign)
  );

  const sig = b64urlFromBytes(new Uint8Array(sigBuf));
  return `${toSign}.${sig}`;
}

/*
api2/firebase-token.js – إصدار 1
*/
