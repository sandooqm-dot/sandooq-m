// functions/api/verify.js
export async function onRequest(context) {
  const { request, env } = context;

  // --- CORS (Fix: لا نستخدم "*" مع Credentials) ---
  const originHeader = request.headers.get("Origin");
  const allowOrigin = originHeader && originHeader !== "null" ? originHeader : "*";

  const corsHeaders = {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Device-Id",
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

    // 2) Ensure code exists
    const codeRow = await db
      .prepare(`SELECT code, is_used, used_at FROM codes WHERE code = ? LIMIT 1;`)
      .bind(code)
      .first();

    if (!codeRow) {
      return new Response(JSON.stringify({ ok: false, error: "INVALID_CODE" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 3) If already activated, enforce device lock
    const existingAct = await db
      .prepare(`SELECT code, device_id, activated_at FROM activations WHERE code = ? LIMIT 1;`)
      .bind(code)
      .first();

    if (existingAct) {
      if (existingAct.device_id === deviceId) {
        // Same device => ok
        // (نضمن أيضًا أن codes.is_used=1)
        if (Number(codeRow.is_used) !== 1) {
          const nowFix = new Date().toISOString();
          await db
            .prepare(`UPDATE codes SET is_used = 1, used_at = COALESCE(used_at, ?) WHERE code = ?;`)
            .bind(nowFix, code)
            .run();
        }

        return new Response(JSON.stringify({
          ok: true,
          status: "ALREADY_ACTIVATED",
          code,
          deviceId,
          activatedAt: existingAct.activated_at,
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      return new Response(JSON.stringify({
        ok: false,
        error: "CODE_USED_OTHER_DEVICE",
        code,
      }), {
        status: 409,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 4) First activation (Atomic-ish):
    // - أول شيء نسجل activations
    // - بعدها نعلّم codes is_used=1
    const now = new Date().toISOString();

    // حاول ندخل سجل التفعيل. لو صار سباق طلبين، واحد فقط ينجح.
    const insertRes = await db
      .prepare(`INSERT INTO activations (code, device_id, activated_at) VALUES (?, ?, ?);`)
      .bind(code, deviceId, now)
      .run();

    // لو فشل الإدخال لأي سبب، نعيد نقرأ ونحكم
    // (D1 أحيانًا يرجع success=false أو خطأ constraint في exception)
    // هنا نتحقق بحالتين: بعد الإدخال نقرأ السجل ونقارن الجهاز.
    const actAfter = await db
      .prepare(`SELECT code, device_id, activated_at FROM activations WHERE code = ? LIMIT 1;`)
      .bind(code)
      .first();

    if (!actAfter) {
      // هذا يعني الإدخال ما تم فعليًا
      return new Response(JSON.stringify({
        ok: false,
        error: "ACTIVATION_NOT_SAVED",
        code,
      }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (actAfter.device_id !== deviceId) {
      // انحجز على جهاز ثاني (سباق)
      return new Response(JSON.stringify({
        ok: false,
        error: "CODE_USED_OTHER_DEVICE",
        code,
      }), {
        status: 409,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 5) Mark code as used ONLY AFTER activation exists
    await db
      .prepare(`UPDATE codes SET is_used = 1, used_at = COALESCE(used_at, ?) WHERE code = ?;`)
      .bind(now, code)
      .run();

    return new Response(JSON.stringify({
      ok: true,
      status: "ACTIVATED",
      code,
      deviceId,
      activatedAt: actAfter.activated_at,
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
