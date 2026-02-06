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
    let code = (body.code || "").toString();
    const deviceId = (body.deviceId || "").toString().trim();

    // Normalize code
    code = code
      .trim()
      .toUpperCase()
      .replace(/[–—−]/g, "-")
      .replace(/\s+/g, "");

    if (!code) {
      return new Response(JSON.stringify({ ok: false, error: "Missing code" }), {
        status: 400,
        headers: corsHeaders,
      });
    }

    if (!deviceId) {
      return new Response(JSON.stringify({ ok: false, error: "Missing deviceId" }), {
        status: 400,
        headers: corsHeaders,
      });
    }

    // نستخدم used_by_email لتخزين deviceId مؤقتاً بصيغة dev:xxxx
    const deviceTag = `dev:${deviceId}`;

    const row = await env.DB.prepare(
      "SELECT code, is_used, used_by_email, used_at FROM codes WHERE code = ? LIMIT 1"
    )
      .bind(code)
      .first();

    if (!row) {
      return new Response(JSON.stringify({ ok: false, valid: false, reason: "NOT_FOUND" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    // إذا الكود مستخدم:
    if (Number(row.is_used) === 1) {
      // يسمح فقط لنفس الجهاز
      if ((row.used_by_email || "") === deviceTag) {
        return new Response(
          JSON.stringify({ ok: true, valid: true, code: row.code, alreadyUsed: true }),
          { status: 200, headers: corsHeaders }
        );
      }

      return new Response(
        JSON.stringify({ ok: false, valid: false, reason: "ALREADY_USED_OTHER_DEVICE" }),
        { status: 200, headers: corsHeaders }
      );
    }

    // إذا غير مستخدم -> "نستهلكه الآن" ونربطه بالجهاز
    const res = await env.DB.prepare(
      "UPDATE codes SET is_used = 1, used_by_email = ?, used_at = CURRENT_TIMESTAMP WHERE code = ? AND is_used = 0"
    )
      .bind(deviceTag, code)
      .run();

    // لو حصل Race condition (جهازين بنفس اللحظة)
    if (!res?.meta || res.meta.changes !== 1) {
      const row2 = await env.DB.prepare(
        "SELECT code, is_used, used_by_email, used_at FROM codes WHERE code = ? LIMIT 1"
      )
        .bind(code)
        .first();

      if ((row2?.used_by_email || "") === deviceTag) {
        return new Response(
          JSON.stringify({ ok: true, valid: true, code: row2.code, alreadyUsed: true }),
          { status: 200, headers: corsHeaders }
        );
      }

      return new Response(
        JSON.stringify({ ok: false, valid: false, reason: "ALREADY_USED_OTHER_DEVICE" }),
        { status: 200, headers: corsHeaders }
      );
    }

    return new Response(
      JSON.stringify({ ok: true, valid: true, code: row.code, firstUse: true }),
      { status: 200, headers: corsHeaders }
    );
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: String(e?.message || e) }), {
      status: 500,
      headers: corsHeaders,
    });
  }
}
