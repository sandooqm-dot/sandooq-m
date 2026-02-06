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

    // ✅ نسمح بـ GET للتجربة من الجوال: /api/verify?code=SNDQ-....
    let code = "";
    if (request.method === "GET") {
      const url = new URL(request.url);
      code = (url.searchParams.get("code") || "").toString();
    } else if (request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      code = (body.code || "").toString();
    } else {
      return new Response(JSON.stringify({ ok: false, error: "Method not allowed" }), {
        status: 405,
        headers: corsHeaders,
      });
    }

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
