// functions/api/verify.js  (Fix: block used codes with empty binding)
export async function onRequest(context) {
  const { request, env } = context;

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "content-type": "application/json; charset=utf-8",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  if (request.method !== "POST") {
    return new Response(JSON.stringify({ ok: false, error: "METHOD_NOT_ALLOWED" }), {
      status: 405,
      headers: corsHeaders,
    });
  }

  try {
    if (!env?.DB) {
      return new Response(JSON.stringify({ ok: false, error: "DB_NOT_BOUND" }), {
        status: 500,
        headers: corsHeaders,
      });
    }

    const body = await request.json().catch(() => ({}));
    let code = (body.code || "").toString();
    const deviceId = (body.deviceId || "").toString().trim();

    // Normalize code
    code = code
      .trim()
      .toUpperCase()
      .replace(/[–—−]/g, "-")
      .replace(/\s+/g, "");

    if (!code) {
      return new Response(JSON.stringify({ ok: false, valid: false, error: "MISSING_CODE" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    if (!deviceId) {
      return new Response(JSON.stringify({ ok: false, valid: false, error: "MISSING_DEVICE" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    // Read row
    const row = await env.DB.prepare(
      "SELECT code, is_used, used_by_email, used_at FROM codes WHERE code = ? LIMIT 1"
    )
      .bind(code)
      .first();

    if (!row) {
      return new Response(JSON.stringify({ ok: false, valid: false, error: "CODE_NOT_FOUND" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    const isUsed = Number(row.is_used) === 1;
    const usedBy = (row.used_by_email || "").toString().trim();

    // ✅ IMPORTANT FIX:
    // إذا الكود مستخدم لكن بدون ربط (used_by_email فاضي) => نرفض (لأنه مستخدم مسبقاً/بيانات ناقصة)
    if (isUsed && !usedBy) {
      return new Response(
        JSON.stringify({ ok: false, valid: false, error: "CODE_ALREADY_USED" }),
        { status: 200, headers: corsHeaders }
      );
    }

    // إذا مستخدم على جهاز ثاني
    if (isUsed && usedBy && usedBy !== deviceId) {
      return new Response(
        JSON.stringify({ ok: false, valid: false, error: "CODE_ALREADY_USED_ON_ANOTHER_DEVICE" }),
        { status: 200, headers: corsHeaders }
      );
    }

    // إذا مستخدم على نفس الجهاز => نسمح
    if (isUsed && usedBy === deviceId) {
      return new Response(JSON.stringify({ ok: true, valid: true, code }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    // أول تفعيل: نربط الكود بالجهاز
    const upd = await env.DB.prepare(
      "UPDATE codes SET is_used = 1, used_by_email = ?, used_at = datetime('now') WHERE code = ? AND is_used = 0"
    )
      .bind(deviceId, code)
      .run();

    // لو ما صار تحديث فعلي
    const changes = upd?.meta?.changes ?? 0;
    if (!changes) {
      return new Response(
        JSON.stringify({ ok: false, valid: false, error: "ACTIVATION_FAILED" }),
        { status: 200, headers: corsHeaders }
      );
    }

    return new Response(JSON.stringify({ ok: true, valid: true, code }), {
      status: 200,
      headers: corsHeaders,
    });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: String(e?.message || e) }), {
      status: 500,
      headers: corsHeaders,
    });
  }
}
