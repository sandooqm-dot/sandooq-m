// functions/api2/firebase-token.js
// GET/POST /api2/firebase-token
// ✅ يرجّع Firebase Custom Token فقط للمستخدم المسجّل + المُفعّل

const VERSION = "api2-firebase-token-v3-get-post-auth";

const ALLOWED_AUD = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

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

function parseAllowedOrigins(env) {
  const raw = String(env?.ALLOWED_ORIGINS || "").trim();
  if (!raw) return null; // لو فاضي ما نطبّق تقييد CORS
  return new Set(raw.split(",").map(s => s.trim()).filter(Boolean));
}

function corsHeaders(req, env) {
  const origin = req.headers.get("origin") || req.headers.get("Origin") || "";
  const allowed = parseAllowedOrigins(env);

  const h = {
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Vary": "Origin",
  };

  // ✅ لو فيه Origin (طلبات fetch) نقيده بقائمة مسموحة
  if (origin) {
    if (allowed && !allowed.has(origin)) {
      // لا نضيف Allow-Origin هنا (بيخلي المتصفح يرفض)
      return h;
    }
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    // فتح مباشر من شريط العنوان (غالبًا بدون Origin)
    h["Access-Control-Allow-Origin"] = "*";
  }

  return h;
}

function json(req, env, data, status = 200) {
  return new Response(JSON.stringify({ ...data, version: VERSION }), {
    status,
    headers: {
      ...corsHeaders(req, env),
      "Content-Type": "application/json; charset=utf-8",
    },
  });
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
  if (!(await tableExists(DB, "sessions"))) return null;

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

  if (cols.has("used_by_email")) {
    const row = await DB.prepare(
      `SELECT used_by_email AS email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    ).bind(token).first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  return null;
}

async function isActivated(DB, email) {
  email = normalizeEmail(email);

  // users (أفضلية)
  if (await tableExists(DB, "users")) {
    const cols = await tableCols(DB, "users");
    const emailCol = cols.has("email") ? "email" : (cols.has("user_email") ? "user_email" : null);

    if (emailCol) {
      if (cols.has("is_activated")) {
        const row = await DB.prepare(
          `SELECT 1 AS ok FROM users WHERE ${emailCol}=? AND is_activated=1 LIMIT 1`
        ).bind(email).first();
        if (row) return true;
      }
      if (cols.has("activated")) {
        const row = await DB.prepare(
          `SELECT 1 AS ok FROM users WHERE ${emailCol}=? AND activated=1 LIMIT 1`
        ).bind(email).first();
        if (row) return true;
      }
      if (cols.has("activated_at")) {
        const row = await DB.prepare(
          `SELECT 1 AS ok FROM users WHERE ${emailCol}=? AND activated_at IS NOT NULL AND activated_at!='' LIMIT 1`
        ).bind(email).first();
        if (row) return true;
      }
      if (cols.has("activation_code")) {
        const row = await DB.prepare(
          `SELECT 1 AS ok FROM users WHERE ${emailCol}=? AND activation_code IS NOT NULL AND activation_code!='' LIMIT 1`
        ).bind(email).first();
        if (row) return true;
      }
    }
  }

  // activations
  if (await tableExists(DB, "activations")) {
    const cols = await tableCols(DB, "activations");
    const where = [];
    const binds = [];

    if (cols.has("email")) { where.push("email=?"); binds.push(email); }
    if (cols.has("user_email")) { where.push("user_email=?"); binds.push(email); }
    if (cols.has("used_by_email")) { where.push("used_by_email=?"); binds.push(email); }

    if (where.length) {
      const row = await DB.prepare(
        `SELECT 1 AS ok FROM activations WHERE (${where.join(" OR ")}) LIMIT 1`
      ).bind(...binds).first();
      if (row) return true;
    }
  }

  // codes (احتياط)
  if (await tableExists(DB, "codes")) {
    const cols = await tableCols(DB, "codes");
    const where = [];
    const binds = [];

    if (cols.has("used_by_email")) { where.push("used_by_email=?"); binds.push(email); }
    if (cols.has("email")) { where.push("email=?"); binds.push(email); }
    if (cols.has("user_email")) { where.push("user_email=?"); binds.push(email); }

    if (where.length) {
      const row = await DB.prepare(
        `SELECT 1 AS ok FROM codes WHERE (${where.join(" OR ")}) LIMIT 1`
      ).bind(...binds).first();
      if (row) return true;
    }
  }

  return false;
}

function b64urlFromBytes(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlFromJson(obj) {
  const txt = JSON.stringify(obj);
  const u8 = new TextEncoder().encode(txt);
  return b64urlFromBytes(u8);
}

function pemToArrayBuffer(pem) {
  const clean = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(clean);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8.buffer;
}

async function importPkcs8PrivateKey(pem) {
  const pkcs8 = pemToArrayBuffer(pem);
  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

async function signRs256(data, key) {
  const sig = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    new TextEncoder().encode(data)
  );
  return b64urlFromBytes(new Uint8Array(sig));
}

async function sha256B64url(str) {
  const dig = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return b64urlFromBytes(new Uint8Array(dig));
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(request, env) });
  }

  if (request.method !== "GET" && request.method !== "POST") {
    return json(request, env, { ok: false, error: "METHOD_NOT_ALLOWED", message: "الطريقة غير مسموحة" }, 405);
  }

  try {
    if (!env?.DB) {
      return json(request, env, { ok: false, error: "DB_NOT_BOUND", message: "قاعدة البيانات غير مربوطة" }, 500);
    }

    // ✅ حماية CORS للطلبات اللي فيها Origin
    const origin = request.headers.get("origin") || request.headers.get("Origin") || "";
    const allowed = parseAllowedOrigins(env);
    if (origin && allowed && !allowed.has(origin)) {
      return json(request, env, { ok: false, error: "ORIGIN_NOT_ALLOWED", message: "مصدر الطلب غير مسموح" }, 403);
    }

    // ✅ لازم مفاتيح Firebase Service Account
    const projectId = String(env.FIREBASE_PROJECT_ID || "").trim();
    const clientEmail = String(env.FIREBASE_CLIENT_EMAIL || "").trim();
    let privateKey = String(env.FIREBASE_PRIVATE_KEY || "").trim();

    if (!projectId || !clientEmail || !privateKey) {
      return json(request, env, { ok: false, error: "FIREBASE_SERVICE_ACCOUNT_MISSING" }, 500);
    }

    // ✅ Cloudflare Secrets غالبًا تكون \\n
    privateKey = privateKey.replace(/\\n/g, "\n");

    // ✅ لازم جلسة (Cookie أو Bearer)
    const auth = request.headers.get("Authorization") || "";
    const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

    const tokNew = getCookie(request, "sandooq_token_v1");
    const tokOld = getCookie(request, "sandooq_session_v1");
    const token = tokNew || tokOld || bearer;

    if (!token) {
      return json(request, env, { ok: false, error: "NO_SESSION", message: "سجّل دخولك أولاً" }, 401);
    }

    const email = await findSessionEmail(env.DB, token);
    if (!email) {
      return json(request, env, { ok: false, error: "INVALID_SESSION", message: "الجلسة غير صالحة" }, 401);
    }

    const activated = await isActivated(env.DB, email);
    if (!activated) {
      return json(request, env, { ok: false, error: "NOT_ACTIVATED", message: "الحساب غير مُفعّل" }, 403);
    }

    // ✅ UID ثابت من الإيميل (آمن + مناسب للفirebase)
    const uidHash = await sha256B64url(email);
    const uid = `u_${uidHash.slice(0, 28)}`;

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: clientEmail,
      sub: clientEmail,
      aud: ALLOWED_AUD,
      iat: now,
      exp: now + 60 * 60, // 1 hour
      uid,
      claims: { email },
    };

    const header = { alg: "RS256", typ: "JWT" };
    const unsigned = `${b64urlFromJson(header)}.${b64urlFromJson(payload)}`;

    const key = await importPkcs8PrivateKey(privateKey);
    const signature = await signRs256(unsigned, key);
    const customToken = `${unsigned}.${signature}`;

    return json(request, env, { ok: true, token: customToken }, 200);

  } catch (e) {
    console.log("firebase_token_error", String(e?.message || e));
    return json(request, env, { ok: false, error: "SERVER_ERROR", message: "حدث خطأ بالسيرفر" }, 500);
  }
}

/*
firebase-token.js – api2 – إصدار 3 (GET+POST + session/activation guard + RS256 custom token)
*/
