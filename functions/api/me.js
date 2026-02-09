v2-clean
// functions/api/me.js
export async function onRequest(context) {
  const { request, env } = context;

  //  CORS 
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  const corsHeaders = {
    "Access-Control-Allow-Origin": allowed.includes(origin) ? origin : (allowed[0] || "*"),
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };

  function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders },
    });
  }

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (!env?.DB) return json({ ok: false, error: "DB_NOT_BOUND" }, 500);
  const db = env.DB;

  //  Helpers 
  function nowISO() {
    return new Date().toISOString();
  }

  function getBearerToken(req) {
    const h = req.headers.get("Authorization") || "";
    if (h.toLowerCase().startsWith("bearer ")) return h.slice(7).trim();
    return "";
  }

  function getCookie(req, name) {
    const cookie = req.headers.get("Cookie") || "";
    const parts = cookie.split(";").map(s => s.trim());
    for (const p of parts) {
      if (!p) continue;
      const i = p.indexOf("=");
      if (i === -1) continue;
      const k = p.slice(0, i).trim();
      const v = p.slice(i + 1).trim();
      if (k === name) return decodeURIComponent(v);
    }
    return "";
  }

  // ✅ deviceId مهم لحد جهازين
  const headerDeviceId = request.headers.get("X-Device-Id") || "";
  const url = new URL(request.url);
  const deviceId = (headerDeviceId || url.searchParams.get("deviceId") || "").toString().trim();

  //  Ensure tables 
  try {
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        password_hash TEXT,
        code TEXT,
        created_at TEXT NOT NULL,
        last_login_at TEXT NOT NULL
      );
    `).run();

    await db.prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
    `).run();

    // ✅ جدول أجهزة المستخدم (حد جهازين)
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS user_devices (
        email TEXT NOT NULL,
        device_id TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY (email, device_id)
      );
    `).run();
  } catch (e) {
    return json({ ok: false, error: "ME_TABLES_FAILED", message: String(e?.message || e) }, 500);
  }

  //  Get token 
  const token =
    getBearerToken(request) ||
    getCookie(request, "sandooq_token") ||
    getCookie(request, "token");

  if (!token) return json({ ok: false, error: "NO_SESSION" }, 401);

  //  Validate session 
  try {
    const session = await db
      .prepare("SELECT token, email, expires_at FROM sessions WHERE token = ? LIMIT 1")
      .bind(token)
      .first();

    if (!session?.token) return json({ ok: false, error: "INVALID_SESSION" }, 401);

    const exp = new Date(session.expires_at).getTime();
    if (!Number.isFinite(exp) || exp <= Date.now()) {
      return json({ ok: false, error: "SESSION_EXPIRED" }, 401);
    }

    const user = await db
      .prepare("SELECT email, provider, code, created_at, last_login_at FROM users WHERE email = ? LIMIT 1")
      .bind(session.email)
      .first();

    if (!user?.email) return json({ ok: false, error: "USER_NOT_FOUND" }, 401);

    //  Device limit (2 devices max) 
    // ملاحظة: المتصفح الخفي غالبًا يغيّر الـ deviceId عندكم، فهنا يظهر كجهاز جديد.
    // هذا بالضبط اللي يسبب "تجاوزت حد الأجهزة" لو شارك الإيميل.
    if (!deviceId) {
      // نخليه خطأ واضح عشان نقدر نضبطه في الواجهة
      return json({ ok: false, error: "DEVICE_REQUIRED" }, 400);
    }

    const now = nowISO();

    const existingDevice = await db
      .prepare("SELECT device_id FROM user_devices WHERE email = ? AND device_id = ? LIMIT 1")
      .bind(user.email, deviceId)
      .first();

    if (!existingDevice?.device_id) {
      const cntRow = await db
        .prepare("SELECT COUNT(*) AS c FROM user_devices WHERE email = ?")
        .bind(user.email)
        .first();

      const c = Number(cntRow?.c || 0);

      if (c >= 2) {
        return json({ ok: false, error: "DEVICE_LIMIT_REACHED", limit: 2 }, 403);
      }

      await db.prepare(
        "INSERT INTO user_devices (email, device_id, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?)"
      ).bind(user.email, deviceId, now, now).run();
    } else {
      await db.prepare(
        "UPDATE user_devices SET last_seen_at = ? WHERE email = ? AND device_id = ?"
      ).bind(now, user.email, deviceId).run();
    }

    // تحديث last_login_at (خفيف)
    await db.prepare("UPDATE users SET last_login_at = ? WHERE email = ?")
      .bind(now, user.email).run();

    return json({
      ok: true,
      email: user.email,
      provider: user.provider,
      // code هنا “اللي مرتبط بالحساب” (إذا ربطناه لاحقًا)
      code: user.code || null,
      device_limit: 2
    }, 200);
  } catch (e) {
    return json({ ok: false, error: "ME_FAILED", message: String(e?.message || e) }, 500);
  }
}
