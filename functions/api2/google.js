export async function onRequest(context) {
  const { request, env } = context;

  // CORS/Preflight (احتياط)
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(request),
    });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405, request);
  }

  const DB = env.DB;
  if (!DB) return json({ ok: false, error: "DB_NOT_BOUND" }, 500, request);

  const GOOGLE_CLIENT_ID = (env.GOOGLE_CLIENT_ID || "").trim();
  if (!GOOGLE_CLIENT_ID) {
    return json({ ok: false, error: "GOOGLE_CLIENT_ID_MISSING" }, 500, request);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON" }, 400, request);
  }

  // نتقبل أكثر من اسم للحقل عشان المرونة
  const idToken =
    (body && (body.credential || body.id_token || body.idToken || body.token)) || "";

  if (!idToken || typeof idToken !== "string") {
    return json({ ok: false, error: "MISSING_GOOGLE_TOKEN" }, 400, request);
  }

  try {
    // ✅ تحقق JWT محليًا (بدون Google tokeninfo)
    const payload = await verifyGoogleIdToken(idToken, GOOGLE_CLIENT_ID);

    const email = String(payload.email || "").trim().toLowerCase();
    const emailVerified = !!payload.email_verified;

    if (!email) return json({ ok: false, error: "GOOGLE_NO_EMAIL" }, 400, request);
    if (!emailVerified) return json({ ok: false, error: "GOOGLE_EMAIL_NOT_VERIFIED" }, 403, request);

    // ✅ تأكد من وجود المستخدم/إنشائه (بدون كلمة مرور)
    // ملاحظة: بعض الجداول عندك حقول NOT NULL، لذلك نخلي password_hash/salt_b64 فاضية بدل NULL
    await DB.prepare(
      `INSERT INTO users (email, password_hash, salt_b64, verified, created_at)
       VALUES (?, '', '', 1, datetime('now'))
       ON CONFLICT(email) DO UPDATE SET verified=1`
    ).bind(email).run();

    // ✅ أنشئ Session + Cookie
    const token = randomToken(32);
    await DB.prepare(
      `INSERT INTO sessions (token, email, created_at) VALUES (?, ?, datetime('now'))`
    ).bind(token, email).run();

    const headers = {
      ...corsHeaders(request),
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": buildCookie("sandooq_token_v1", token, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
        maxAge: 60 * 60 * 24 * 30, // 30 يوم
      }),
    };

    return new Response(JSON.stringify({ ok: true, email }), { status: 200, headers });
  } catch (e) {
    // نخلي الرسالة مختصرة للعميل
    const code = (e && e.code) ? String(e.code) : "GOOGLE_TOKEN_INVALID";
    return json({ ok: false, error: code }, 403, request);
  }
}

/* =========================
   Helpers
========================= */

function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  // نفس الدومين غالبًا، بس نخليه آمن
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Allow-Credentials": "true",
  };
}

function json(obj, status, request) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      ...corsHeaders(request),
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

function buildCookie(name, value, opt = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opt.path || "/"}`);
  if (opt.maxAge != null) parts.push(`Max-Age=${opt.maxAge}`);
  if (opt.httpOnly) parts.push("HttpOnly");
  if (opt.secure) parts.push("Secure");
  parts.push(`SameSite=${opt.sameSite || "Lax"}`);
  return parts.join("; ");
}

function randomToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return base64url(arr);
}

function base64url(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlToBytes(b64u) {
  const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64u.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToJson(b64u) {
  const bytes = b64urlToBytes(b64u);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text);
}

async function verifyGoogleIdToken(idToken, clientId) {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    const err = new Error("bad_jwt");
    err.code = "GOOGLE_TOKEN_BAD_JWT";
    throw err;
  }

  const [h64, p64, s64] = parts;
  const header = b64urlToJson(h64);
  const payload = b64urlToJson(p64);

  if (header.alg !== "RS256" || !header.kid) {
    const err = new Error("bad_alg");
    err.code = "GOOGLE_TOKEN_BAD_ALG";
    throw err;
  }

  const now = Math.floor(Date.now() / 1000);

  // iss
  const iss = String(payload.iss || "");
  if (iss !== "accounts.google.com" && iss !== "https://accounts.google.com") {
    const err = new Error("bad_iss");
    err.code = "GOOGLE_TOKEN_BAD_ISS";
    throw err;
  }

  // aud
  if (String(payload.aud || "") !== clientId) {
    const err = new Error("bad_aud");
    err.code = "GOOGLE_TOKEN_BAD_AUD";
    throw err;
  }

  // exp
  const exp = Number(payload.exp || 0);
  if (!exp || exp < now) {
    const err = new Error("expired");
    err.code = "GOOGLE_TOKEN_EXPIRED";
    throw err;
  }

  // signature verify
  const key = await getGoogleKey(header.kid);
  const data = new TextEncoder().encode(`${h64}.${p64}`);
  const sig = b64urlToBytes(s64);

  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    sig,
    data
  );

  if (!ok) {
    const err = new Error("bad_sig");
    err.code = "GOOGLE_TOKEN_BAD_SIG";
    throw err;
  }

  return payload;
}

let _googleJwksCache = { at: 0, keys: null };

async function getGoogleKey(kid) {
  const jwks = await getGoogleJwks();
  const jwk = (jwks.keys || []).find(k => k.kid === kid);

  if (!jwk) {
    const err = new Error("kid_not_found");
    err.code = "GOOGLE_KID_NOT_FOUND";
    throw err;
  }

  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

async function getGoogleJwks() {
  // كاش 6 ساعات
  const now = Date.now();
  if (_googleJwksCache.keys && (now - _googleJwksCache.at) < 6 * 60 * 60 * 1000) {
    return _googleJwksCache.keys;
  }

  const res = await fetch("https://www.googleapis.com/oauth2/v3/certs", {
    method: "GET",
    headers: { "Accept": "application/json" },
  });

  if (!res.ok) {
    const err = new Error("jwks_fetch_failed");
    err.code = "GOOGLE_JWKS_FETCH_FAILED";
    throw err;
  }

  const data = await res.json();
  _googleJwksCache = { at: now, keys: data };
  return data;
}
