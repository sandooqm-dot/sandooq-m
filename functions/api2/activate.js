// functions/api2/activate.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "api2-activate-v1-code-device";

  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405, cors);
  }

  if (!env?.DB) {
    return json(
      { ok: false, error: "DB_NOT_BOUND", version: VERSION, message: "Bind D1 as DB in Pages Settings -> Bindings" },
      500,
      cors
    );
  }

  const token = readToken(request);
  if (!token) {
    return json({ ok: false, error: "UNAUTHORIZED", version: VERSION }, 401, cors);
  }

  const deviceId = String(request.headers.get("X-Device-Id") || "").trim();
  if (!deviceId) {
    return json({ ok: false, error: "MISSING_DEVICE", version: VERSION }, 400, cors);
  }

  let body = null;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON", version: VERSION }, 400, cors);
  }

  const code = normCode(body?.code);
  if (!code) {
    return json({ ok: false, error: "MISSING_FIELDS", version: VERSION }, 400, cors);
  }

  const now = Date.now();
  const gameId = String(env?.GAME_ID || "horof").trim();
  const deviceLimit = Number(env?.DEVICE_LIMIT || 2);

  // 1) تحقق Session -> email
  const tokenHash = await sha256Hex(new TextEncoder().encode(token));
  const s = await env.DB.prepare(
    "SELECT email, expires_at, revoked_at FROM auth_sessions WHERE token_hash = ? LIMIT 1"
  )
    .bind(tokenHash)
    .first();

  if (!s || s.revoked_at || Number(s.expires_at) <= now) {
    return json({ ok: false, error: "UNAUTHORIZED", version: VERSION }, 401, cors);
  }

  const email = String(s.email || "");

  // 2) لازم البريد متأكد
  const u = await env.DB.prepare("SELECT email_verified FROM auth_users WHERE email = ? LIMIT 1")
    .bind(email)
    .first();

  if (!u || Number(u.email_verified || 0) !== 1) {
    return json({ ok: false, error: "EMAIL_NOT_VERIFIED", version: VERSION }, 403, cors);
  }

  // 3) هل هذا الحساب مفعل سابقاً للعبة؟ (إذا مفعل نسمح ربط جهاز جديد فقط)
  const existingLink = await env.DB.prepare(
    "SELECT code FROM auth_code_links WHERE game_id = ? AND email = ? LIMIT 1"
  )
    .bind(gameId, email)
    .first();

  if (existingLink) {
    const linkedCode = String(existingLink.code || "");

    // لو يحاول يدخل كود غير اللي مرتبط بحسابه -> مرفوض
    if (linkedCode !== code) {
      return json({ ok: false, error: "CODE_ALREADY_USED", version: VERSION }, 409, cors);
    }

    // ربط جهاز (حد جهازين)
    const count = await env.DB.prepare(
      "SELECT COUNT(1) as c FROM auth_activations WHERE game_id = ? AND code = ?"
    )
      .bind(gameId, linkedCode)
      .first();

    const c = Number(count?.c || 0);
    if (c >= deviceLimit) {
      // إذا الجهاز نفسه موجود أصلاً نسمح
      const already = await env.DB.prepare(
        "SELECT 1 FROM auth_activations WHERE game_id = ? AND code = ? AND device_id = ? LIMIT 1"
      )
        .bind(gameId, linkedCode, deviceId)
        .first();

      if (!already) {
        return json({ ok: false, error: "DEVICE_LIMIT_REACHED", version: VERSION }, 409, cors);
      }
    }

    // upsert
    await env.DB.prepare(
      "INSERT OR IGNORE INTO auth_activations (game_id, code, device_id, email, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
      .bind(gameId, linkedCode, deviceId, email, now, now)
      .run();

    await env.DB.prepare(
      "UPDATE auth_activations SET last_seen_at = ? WHERE game_id = ? AND code = ? AND device_id = ?"
    )
      .bind(now, gameId, linkedCode, deviceId)
      .run();

    return json({ ok: true, version: VERSION, email, game_id: gameId, activated: true }, 200, cors);
  }

  // 4) أول مرة تفعيل: تحقق الكود من جدول الأكواد
  const codeRow = await env.DB.prepare(
    "SELECT code, used_by_email FROM auth_codes WHERE game_id = ? AND code = ? LIMIT 1"
  )
    .bind(gameId, code)
    .first();

  if (!codeRow) {
    return json({ ok: false, error: "CODE_NOT_FOUND", version: VERSION }, 404, cors);
  }

  // إذا مرتبط بإيميل آخر -> مرفوض
  if (codeRow.used_by_email && String(codeRow.used_by_email) !== email) {
    return json({ ok: false, error: "CODE_ALREADY_USED", version: VERSION }, 409, cors);
  }

  // 5) ربط الكود بالحساب (مرة واحدة)
  // - علّم الكود مستخدم بهذا الإيميل
  await env.DB.prepare(
    "UPDATE auth_codes SET used_by_email = ?, used_at = COALESCE(used_at, ?) WHERE game_id = ? AND code = ?"
  )
    .bind(email, now, gameId, code)
    .run();

  // - سجل الربط (unique على game_id+email)
  await env.DB.prepare(
    "INSERT OR IGNORE INTO auth_code_links (game_id, email, code, activated_at) VALUES (?, ?, ?, ?)"
  )
    .bind(gameId, email, code, now)
    .run();

  // 6) ربط الجهاز (حد جهازين)
  const count2 = await env.DB.prepare(
    "SELECT COUNT(1) as c FROM auth_activations WHERE game_id = ? AND code = ?"
  )
    .bind(gameId, code)
    .first();

  const c2 = Number(count2?.c || 0);
  if (c2 >= deviceLimit) {
    return json({ ok: false, error: "DEVICE_LIMIT_REACHED", version: VERSION }, 409, cors);
  }

  await env.DB.prepare(
    "INSERT OR IGNORE INTO auth_activations (game_id, code, device_id, email, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(gameId, code, deviceId, email, now, now)
    .run();

  await env.DB.prepare(
    "UPDATE auth_activations SET last_seen_at = ? WHERE game_id = ? AND code = ? AND device_id = ?"
  )
    .bind(now, gameId, code, deviceId)
    .run();

  return json({ ok: true, version: VERSION, email, game_id: gameId, activated: true }, 200, cors);
}

/* ---------------- helpers ---------------- */

function json(obj, status, corsHeaders, extraHeaders = {}) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  for (const [k, v] of Object.entries(extraHeaders || {})) headers.set(k, v);
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
    "Vary": "Origin",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };
}

function readToken(request) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m && m[1]) return m[1].trim();

  const cookie = request.headers.get("Cookie") || "";
  const token = getCookie(cookie, "sandooq_token_v1");
  if (token) return token;

  return "";
}

function getCookie(cookieHeader, name) {
  const parts = cookieHeader.split(";").map((s) => s.trim());
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

function normCode(v) {
  return String(v || "").trim().toUpperCase().replace(/\s+/g, "").replace(/[–—−]/g, "-");
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

// functions/api2/activate.js – إصدار 1
