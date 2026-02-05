export async function onRequest(context) {
  const { request, env } = context;

  // CORS (إذا صفحتك نفس الدومين غالباً ما تحتاجه، بس نخليه آمن)
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

    // Normalize code (أهم جزء لحل مشكلة الشرطات والمسافات)
    code = code
      .trim()
      .toUpperCase()
      .replace(/[–—−]/g, "-")     // أنواع شرطات ثانية
      .replace(/\s+/g, "");       // إزالة المسافات

    if (!code) {
      return new Response(JSON.stringify({ ok: false, error: "Missing code" }), {
        status: 400,
        headers: corsHeaders,
      });
    }

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

    if (Number(row.is_used) === 1) {
      return new Response(JSON.stringify({ ok: false, valid: false, reason: "ALREADY_USED" }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    // ✅ صالح (بدون ما نستهلكه هنا)
    return new Response(
      JSON.stringify({ ok: true, valid: true, code: row.code }),
      { status: 200, headers: corsHeaders }
    );
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: String(e?.message || e) }), {
      status: 500,
      headers: corsHeaders,
    });
  }
}
