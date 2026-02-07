export async function onRequest(context) {
  const { request, env } = context;

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "content-type": "application/json; charset=utf-8",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    if (!env?.DB) {
      return new Response(JSON.stringify({ ok: false, error: "DB not bound" }), {
        status: 500,
        headers: corsHeaders,
      });
    }

    // ✅ GET: فحص فقط (بدون قفل) /api/verify?code=...
    // ✅ POST: تفعيل + قفل وربط بالجهاز
    let code = "";
    let deviceId = "";

    if (request.method === "GET") {
      const url = new URL(request.url);
      code = (url.searchParams.get("code") || "").toString();
      deviceId = ""; // GET لا يقفل
    } else if (request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      code = (body.code || "").toString();
      deviceId = (body.deviceId || "").toString();
    } else {
      return new Response(JSON.stringify({ ok: false, error: "Method not allowed" }), {
        status: 405,
        headers: corsHeaders,
      });
    }

    // Normalize
    code = code
      .trim()
      .toUpperCase()
      .replace(/[–—−]/g, "-")
      .replace(/\s+/g, "");

    deviceId = (deviceId || "").trim();

    if (!code) {
      return new Response(JSON.stringify({ ok: false, error: "Missing code" }), {
        status: 400,
        headers: corsHeaders,
      });
    }

    // ✅ اقرأ الكود (مع أعمدة الجهاز الجديدة)
    const row = await env.DB.prepare(
      "SELECT code, is_used, used_by_email, used_by_device_id, used_at FROM codes WHERE code = ? LIMIT 1"
    )
      .bind(code)
      .first();

    if (!row) {
      return new Response(JSON.stringify({ ok: false, valid: false, reason: "NOT_FOUND" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    // ✅ GET: فحص فقط
    if (request.method === "GET") {
      return new Response(
        JSON.stringify({
          ok: true,
          valid: Number(row.is_used) !== 1, // صالح إذا مو مستخدم
          code: row.code,
          is_used: Number(row.is_used) === 1 ? 1 : 0,
          used_by_device_id: row.used_by_device_id || null,
          used_at: row.used_at || null,
        }),
        { status: 200, headers: corsHeaders }
      );
    }

    // ✅ POST لازم deviceId
    if (!deviceId) {
      return new Response(JSON.stringify({ ok: false, valid: false, reason: "MISSING_DEVICE" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    const isUsed = Number(row.is_used) === 1;
    const usedByDevice = (row.used_by_device_id || "").toString();

    // ✅ إذا مستخدم من قبل:
    if (isUsed) {
      // نفس الجهاز → اسمح
      if (usedByDevice && usedByDevice === deviceId) {
        return new Response(JSON.stringify({ ok: true, valid: true, code: row.code, reauth: true }), {
          status: 200,
          headers: corsHeaders,
        });
      }
      // جهاز مختلف → ارفض
      return new Response(JSON.stringify({ ok: false, valid: false, reason: "ALREADY_USED" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    // ✅ غير مستخدم → اقفل وربط بالجهاز
    const now = new Date().toISOString();

    // حماية من سباق التفعيل: نقفل فقط إذا is_used = 0
    const res = await env.DB.prepare(
      "UPDATE codes SET is_used = 1, used_by_device_id = ?, used_at = ? WHERE code = ? AND is_used = 0"
    )
      .bind(deviceId, now, code)
      .run();

    // إذا ما تم تحديث أي صف → يعني أحد سبقك وفعّله
    if (!res || !res.meta || res.meta.changes !== 1) {
      // نعيد قراءة السطر لمعرفة هل هو نفس الجهاز أو جهاز ثاني
      const row2 = await env.DB.prepare(
        "SELECT code, is_used, used_by_device_id, used_at FROM codes WHERE code = ? LIMIT 1"
      )
        .bind(code)
        .first();

      const usedBy2 = (row2?.used_by_device_id || "").toString();
      if (row2 && Number(row2.is_used) === 1 && usedBy2 === deviceId) {
        return new Response(JSON.stringify({ ok: true, valid: true, code, reauth: true }), {
          status: 200,
          headers: corsHeaders,
        });
      }

      return new Response(JSON.stringify({ ok: false, valid: false, reason: "ALREADY_USED" }), {
        status: 200,
        headers: corsHeaders,
      });
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
