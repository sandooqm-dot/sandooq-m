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
    return new Response(JSON.stringify({ ok: false, error: "Method not allowed" }), {
      status: 405,
      headers: corsHeaders,
    });
  }

  try {
    if (!env?.DB) {
      return new Response(JSON.stringify({ ok: false, error: "DB not bound" }), {
        status: 500,
        headers: corsHeaders,
      });
    }

    const body = await request.json().catch(() => ({}));
    let codeRaw = (body.code || "").toString();
    const deviceId = (body.deviceId || "").toString().trim();

    // Normalize code (قوي)
    // - حذف المسافات
    // - توحيد الشرطات
    // - uppercase
    const normalized = codeRaw
      .trim()
      .toUpperCase()
      .replace(/[–—−]/g, "-")
      .replace(/\s+/g, "");

    // نسخة بدون أي شرطات (للمطابقة لو DB مخزّن كذا)
    const compact = normalized.replace(/-/g, "");

    // أحيانًا البعض ينسخ الكود ومعه رموز غريبة.. نخليه أحرف/أرقام/شرطة فقط
    const safeNormalized = normalized.replace(/[^A-Z0-9-]/g, "");
    const safeCompact = safeNormalized.replace(/-/g, "");

    if (!safeNormalized) {
      return new Response(JSON.stringify({ ok: false, error: "MISSING_CODE" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    if (!deviceId) {
      return new Response(JSON.stringify({ ok: false, error: "MISSING_DEVICE" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    // نبحث بأكثر من طريقة:
    // 1) code = ?
    // 2) REPLACE(code,'-','') = ?  (يطابق لو القاعدة مخزنة بدون شرطات)
    // 3) نفس الشيء مع safeNormalized/safeCompact (تنظيف أقوى)
    const row = await env.DB.prepare(
      `
      SELECT code, is_used, used_by_email
      FROM codes
      WHERE code = ?
         OR REPLACE(code, '-', '') = ?
         OR code = ?
         OR REPLACE(code, '-', '') = ?
      LIMIT 1
      `
    )
      .bind(safeNormalized, safeCompact, normalized, compact)
      .first();

    if (!row) {
      // Debug سريع: هل جدول codes فاضي أو فيه بيانات؟
      let total = null;
      try {
        const c = await env.DB.prepare("SELECT COUNT(1) as n FROM codes").first();
        total = c?.n ?? null;
      } catch (e) {}

      return new Response(
        JSON.stringify({
          ok: false,
          valid: false,
          error: "INVALID_CODE",
          debug: { totalCodesInDB: total, tried: [safeNormalized, safeCompact, normalized, compact] },
        }),
        { status: 200, headers: corsHeaders }
      );
    }

    const isUsed = Number(row.is_used) === 1;
    const usedBy = (row.used_by_email || "").toString(); // عندك نفس العمود

    // إذا مستخدم على جهاز ثاني
    if (isUsed && usedBy && usedBy !== deviceId) {
      return new Response(
        JSON.stringify({ ok: false, valid: false, error: "CODE_ALREADY_USED_ON_ANOTHER_DEVICE" }),
        { status: 200, headers: corsHeaders }
      );
    }

    // إذا مستخدم على نفس الجهاز (نسمح)
    if (isUsed && usedBy === deviceId) {
      return new Response(JSON.stringify({ ok: true, valid: true, code: row.code }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    // أول تفعيل: نربط الكود بالجهاز (نحدّث على "code" الحقيقي الموجود بالقاعدة)
    await env.DB.prepare(
      "UPDATE codes SET is_used = 1, used_by_email = ?, used_at = datetime('now') WHERE code = ?"
    )
      .bind(deviceId, row.code)
      .run();

    return new Response(JSON.stringify({ ok: true, valid: true, code: row.code }), {
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
