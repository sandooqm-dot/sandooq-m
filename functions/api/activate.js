// functions/api/activate.js
// ✅ توافق قوي: نفس منطق /api/verify (بدون العبث بـ used_by_email)
// يرجّع { ok, valid, code } عشان الصفحات القديمة ما تنكسر

export async function onRequest(context) {
  const { request, env } = context;

  const origin = request.headers.get("Origin") || "*";
  const corsHeaders = {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Device-Id",
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin",
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (request.method !== "POST") {
    return new Response(JSON.stringify({ ok: false, valid: false, error: "METHOD_NOT_ALLOWED" }), {
      status: 405,
      headers: corsHeaders,
    });
  }

  try {
    if (!env?.DB) {
      return new Response(JSON.stringify({ ok: false, valid: false, error: "DB_NOT_BOUND" }), {
        status: 500,
        headers: corsHeaders,
      });
    }

    const body = await request.json().catch(() => ({}));

    // code + deviceId can come from body or header
    const rawCode = (body.code || "").toString();
    const headerDevice = request.headers.get("X-Device-Id");
    const rawDeviceId = (body.deviceId || headerDevice || "").toString();

    // Normalize code (نفس اللي اتفقنا عليه)
    const code = rawCode
      .trim()
      .toUpperCase()
      .replace(/[–—−]/g, "-")
      .replace(/\s+/g, "")
      .replace(/[^A-Z0-9-]/g, ""); // تنظيف آمن

    const deviceId = rawDeviceId.trim();

    // نرجّع 200 مع ok=false عشان الواجهات القديمة ما تعلق
    if (!code) {
      return new Response(JSON.stringify({ ok: false, valid: false, error: "MISSING_CODE" }), {
        status: 200,
        headers: corsHeaders,
      });
    }
    if (!deviceId) {
      return new Response(JSON.stringify({ ok: false, valid: false, error: "DEVICE_REQUIRED" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    const db = env.DB;

    // 1) Ensure activations table exists
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS activations (
        code TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        activated_at TEXT NOT NULL
      );
    `).run();

    // 2) Check code exists in codes table
    const codeRow = await db
      .prepare(`SELECT code, is_used FROM codes WHERE code = ? LIMIT 1;`)
      .bind(code)
      .first();

    if (!codeRow?.code) {
      return new Response(JSON.stringify({ ok: false, valid: false, error: "CODE_NOT_FOUND" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    // 3) Check activation record
    const actRow = await db
      .prepare(`SELECT code, device_id, activated_at FROM activations WHERE code = ? LIMIT 1;`)
      .bind(code)
      .first();

    // already activated
    if (actRow?.code) {
      if ((actRow.device_id || "") === deviceId) {
        return new Response(JSON.stringify({
          ok: true,
          valid: true,
          status: "ALREADY_ACTIVATED",
          code,
          deviceId,
          activatedAt: actRow.activated_at,
        }), {
          status: 200,
          headers: corsHeaders,
        });
      }

      return new Response(JSON.stringify({
        ok: false,
        valid: false,
        error: "CODE_ALREADY_USED_ON_ANOTHER_DEVICE",
        code,
      }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    // 4) First activation: mark codes.is_used=1 + used_at ONLY
    const now = new Date().toISOString();

    await db
      .prepare(`UPDATE codes SET is_used = 1, used_at = ? WHERE code = ?;`)
      .bind(now, code)
      .run();

    // 5) Insert activation record
    await db
      .prepare(`INSERT INTO activations (code, device_id, activated_at) VALUES (?, ?, ?);`)
      .bind(code, deviceId, now)
      .run();

    return new Response(JSON.stringify({
      ok: true,
      valid: true,
      status: "ACTIVATED",
      code,
      deviceId,
      activatedAt: now,
    }), {
      status: 200,
      headers: corsHeaders,
    });

  } catch (e) {
    return new Response(JSON.stringify({
      ok: false,
      valid: false,
      error: "HTTP_500",
      message: String(e?.message || e),
    }), {
      status: 500,
      headers: corsHeaders,
    });
  }
}
