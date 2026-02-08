// functions/api/verify.js
export async function onRequest(context) {
  const { request, env } = context;

  // --- CORS ---
  const origin = request.headers.get("Origin") || "*";
  const corsHeaders = {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Device-Id",
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
    }

  if (request.method !== "POST") {
    return new Response(JSON.stringify({ ok: false, error: "METHOD_NOT_ALLOWED" }), {
      status: 405,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const body = await request.json().catch(() => ({}));

    // code + deviceId can come from body or header
    const rawCode = (body.code || "").toString();
    const headerDevice = request.headers.get("X-Device-Id");
    const rawDeviceId = (body.deviceId || headerDevice || "").toString();

    const code = rawCode.trim().toUpperCase();
    const deviceId = rawDeviceId.trim();

    if (!code) {
      return new Response(JSON.stringify({ ok: false, error: "MISSING_CODE" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    if (!deviceId) {
      return new Response(JSON.stringify({ ok: false, error: "DEVICE_REQUIRED" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const db = env.DB;

    // 1) Ensure activations table exists (safe)
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

    if (!codeRow) {
      return new Response(JSON.stringify({ ok: false, error: "INVALID_CODE" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 3) Check if code already activated to a device
    const actRow = await db
      .prepare(`SELECT code, device_id, activated_at FROM activations WHERE code = ? LIMIT 1;`)
      .bind(code)
      .first();

    // If already activated:
    if (actRow) {
      // Same device => ok
      if (actRow.device_id === deviceId) {
        return new Response(JSON.stringify({
          ok: true,
          status: "ALREADY_ACTIVATED",
          code,
          deviceId,
          activatedAt: actRow.activated_at,
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Different device => reject
      return new Response(JSON.stringify({
        ok: false,
        error: "CODE_USED_OTHER_DEVICE",
        code,
      }), {
        status: 409,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 4) First activation: mark codes.is_used=1 + used_at only (NO used_by_email here)
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
      status: "ACTIVATED",
      code,
      deviceId,
      activatedAt: now,
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (err) {
    return new Response(JSON.stringify({
      ok: false,
      error: "HTTP_500",
      message: (err && err.message) ? err.message : "Unknown error",
    }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
}
