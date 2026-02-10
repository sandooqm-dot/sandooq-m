// /functions/api2/activate.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-activate-v2-cookie-auth";

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

  if (!env?.JWT_SECRET) {
    return json({ ok: false, error: "MISSING_JWT_SECRET", version: VERSION }, 500, cors);
  }

  // Auth: Authorization OR Cookie
  const auth = request.headers.get("Authorization") || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookieTok = getCookie(cookieHeader, "sandooq_token_v1");
  const token = bearer || cookieTok || "";

  const payload = token ? await verifyToken(env.JWT_SECRET, token) : null;
  const email = String(payload?.email || "").trim().toLowerCase();
  if (!email) {
    const headers = new Headers(cors);
    headers.set("Content-Type", "application/json; charset=utf-8");
    headers.set("Cache-Control", "no-store");
    headers.append("Set-Cookie", clearAuthCookie());
    return new Response(JSON.stringify({ ok: false, error: "UNAUTHORIZED", version: VERSION }), {
      status: 401,
      headers,
    });
  }

  const deviceId = String(request.headers.get("X-Device-Id") || "").trim();
  if (!deviceId) {
    return json({ ok: false, error: "MISSING_DEVICE_ID", version: VERSION }, 400, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON", version: VERSION }, 400, cors);
  }

  const code = normCode(body?.code);
  if (!code) {
    return json({ ok: false, error: "MISSING_CODE", version: VERSION }, 400, cors);
  }

  const now = new Date().toISOString();

  // 1) Code exists?
  const codeRow = await env.DB.prepare(
    `SELECT code, used_by_email, used_at
     FROM codes
     WHERE code = ?
     LIMIT 1`
  ).bind(code).first();

  if (!codeRow) {
    return json({ ok: false, error: "CODE_NOT_FOUND", version: VERSION }, 404, cors);
  }

  const usedBy = String(codeRow.used_by_email || "").trim().toLowerCase();

  // Code already used by another email
  if (usedBy && usedBy !== email) {
    return json({ ok: false, error: "CODE_ALREADY_USED", version: VERSION }, 409, cors);
  }

  // Already activated on this device? (idempotent)
  const alreadyOnDevice = await env.DB.prepare(
    `SELECT 1 FROM activations WHERE email = ? AND device_id = ? LIMIT 1`
  ).bind(email, deviceId).first();

  if (alreadyOnDevice) {
    await bestEffortMarkUserActivated(env.DB, email, now);

    const headers = new Headers(cors);
    headers.set("Content-Type", "application/json; charset=utf-8");
    headers.set("Cache-Control", "no-store");
    // ✅ نثبت الكوكي مرة ثانية (يساعد الميدلوير مباشرة)
    headers.append("Set-Cookie", makeAuthCookie(token));
    return new Response(JSON.stringify({ ok: true, version: VERSION, activated: true }), {
      status: 200,
      headers,
    });
  }

  // Device limit (2 devices) — (موجود لكن نظامنا يسمح بالدخول بعد أول تفعيل على مستوى الحساب)
  const cntRow = await env.DB.prepare(
    `SELECT COUNT(DISTINCT device_id) AS c FROM activations WHERE email = ?`
  ).bind(email).first();

  const deviceCount = Number(cntRow?.c || 0);
  if (deviceCount >= 2) {
    return json({ ok: false, error: "DEVICE_LIMIT_REACHED", version: VERSION }, 409, cors);
  }

  // 2) Claim code for this email (if not claimed yet)
  if (!usedBy) {
    const upd = await env.DB.prepare(
      `UPDATE codes
       SET used_by_email = ?, used_at = ?
       WHERE code = ? AND (used_by_email IS NULL OR TRIM(used_by_email) = '')`
    ).bind(email, now, code).run();

    if ((upd?.meta?.changes || 0) === 0) {
      const again = await env.DB.prepare(
        `SELECT used_by_email FROM codes WHERE code = ? LIMIT 1`
      ).bind(code).first();
      const nowUsedBy = String(again?.used_by_email || "").trim().toLowerCase();
      if (nowUsedBy && nowUsedBy !== email) {
        return json({ ok: false, error: "CODE_ALREADY_USED", version: VERSION }, 409, cors);
      }
    }
  }

  // 3) Insert activation record
  try {
    await env.DB.prepare(
      `INSERT INTO activations (email, device_id, code, activated_at)
       VALUES (?, ?, ?, ?)`
    ).bind(email, deviceId, code, now).run();
  } catch {
    const okNow = await env.DB.prepare(
      `SELECT 1 FROM activations WHERE email = ? AND device_id = ? LIMIT 1`
    ).bind(email, deviceId).first();

    if (!okNow) {
      return json({ ok: false, error: "ACTIVATION_FAILED", version: VERSION }, 500, cors);
    }
  }

  await bestEffortMarkUserActivated(env.DB, email, now);

  // ✅ ثبت الكوكي مرة ثانية
  const headers = new Headers(cors);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.append("Set-Cookie", makeAuthCookie(token));

  return new Response(JSON.stringify({ ok: true, version: VERSION, activated: true }), {
    status: 200,
    headers,
  });
}

/* ---------- helpers ---------- */

function json(obj, status, corsHeaders) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(obj), { status, headers });
}

function makeCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowedRaw = (env?.ALLOWED_ORIGINS || "").trim();
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

function normCode(v) {
  return String(v || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "")
    .replace(/[–—−]/g, "-");
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

function makeAuthCookie(token) {
  return `sandooq_token_v1=${encodeURIComponent(token)}; Path=/; Max-Age=${60 * 60 * 24 * 30}; Secure; HttpOnly; SameSite=Lax`;
}

function clearAuthCookie() {
  return `sandooq_token_v1=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`;
}

/* ---------- JWT verify (HS256) ---------- */

function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToBase64Url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function strToBytes(s) {
  return new TextEncoder().encode(s);
}
function safeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
async function hmacSha256(secret, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    strToBytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return new Uint8Array(sig);
}

async function verifyToken(secret, token) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 3) return null;

    const [h, p, s] = parts;
    const toSign = `${h}.${p}`;
    const sigBytes = await hmacSha256(secret, strToBytes(toSign));
    const expected = bytesToBase64Url(sigBytes);

    if (!safeEqual(expected, s)) return null;

    const payloadJson = new TextDecoder().decode(base64UrlToBytes(p));
    const payload = JSON.parse(payloadJson);

    const now = Math.floor(Date.now() / 1000);
    if (!payload?.exp || now >= Number(payload.exp)) return null;

    return payload;
  } catch {
    return null;
  }
}

/* ---------- best-effort activated flag ---------- */

async function bestEffortMarkUserActivated(DB, email, now) {
  try {
    await DB.prepare(`UPDATE users SET activated = 1 WHERE email = ?`).bind(email).run();
  } catch {}
  try {
    await DB.prepare(`UPDATE users SET activated_at = ? WHERE email = ?`).bind(now, email).run();
  } catch {}
}

// functions/api2/activate.js – api2-activate-v2-cookie-auth
