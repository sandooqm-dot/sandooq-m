export async function onRequest(context) {
  const { request, env } = context;

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "content-type": "application/json; charset=utf-8",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  if (request.method !== "GET") {
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

    // ✅ حماية بسيطة: لازم مفتاح
    // حط EXPORT_KEY في Cloudflare Pages > Settings > Environment variables
    // وادخل عليه من الرابط: /api/export-codes?key=YOUR_KEY
    const url = new URL(request.url);
    const key = (url.searchParams.get("key") || "").toString().trim();
    const requiredKey = (env.EXPORT_KEY || "").toString().trim();

    if (requiredKey) {
      if (!key || key !== requiredKey) {
        return new Response(JSON.stringify({ ok: false, error: "Unauthorized" }), {
          status: 401,
          headers: corsHeaders,
        });
      }
    } else {
      // لو ما حطيت EXPORT_KEY، بنقفل التصدير بدل ما ينفضح
      return new Response(
        JSON.stringify({ ok: false, error: "EXPORT_KEY is not set in environment variables" }),
        { status: 403, headers: corsHeaders }
      );
    }

    // ✅ اختياري: فلترة حسب حالة الاستخدام
    // ?used=1 أو ?used=0 أو بدونها = الكل
    const usedParam = url.searchParams.get("used");
    const usedFilter =
      usedParam === "1" ? 1 : usedParam === "0" ? 0 : null;

    // ✅ اختياري: فلترة حسب اللعبة
    // ?game=horoof
    const game = (url.searchParams.get("game") || "").toString().trim();

    // ✅ Pagination اختياري
    const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "5000", 10) || 5000, 1), 5000);
    const offset = Math.max(parseInt(url.searchParams.get("offset") || "0", 10) || 0, 0);

    let sql = `
      SELECT
        code,
        is_used,
        used_by_email,
        used_at,
        used_by_device_id,
        device_fingerprint,
        game_slug
      FROM codes
      WHERE 1=1
    `;
    const binds = [];

    if (usedFilter !== null) {
      sql += ` AND is_used = ?`;
      binds.push(usedFilter);
    }

    if (game) {
      sql += ` AND game_slug = ?`;
      binds.push(game);
    }

    sql += `
      ORDER BY is_used ASC, used_at DESC
      LIMIT ? OFFSET ?
    `;
    binds.push(limit, offset);

    const { results } = await env.DB.prepare(sql).bind(...binds).all();

    // ✅ كمان نجيب عدّاد سريع (مستخدم/غير مستخدم)
    const totalRow = await env.DB.prepare(
      `SELECT COUNT(*) as total FROM codes`
    ).first();

    const usedRow = await env.DB.prepare(
      `SELECT COUNT(*) as used FROM codes WHERE is_used = 1`
    ).first();

    const unusedRow = await env.DB.prepare(
      `SELECT COUNT(*) as unused FROM codes WHERE is_used = 0`
    ).first();

    return new Response(
      JSON.stringify({
        ok: true,
        meta: {
          total: Number(totalRow?.total || 0),
          used: Number(usedRow?.used || 0),
          unused: Number(unusedRow?.unused || 0),
          limit,
          offset,
          usedFilter,
          game: game || null,
        },
        rows: (results || []).map(r => ({
          code: r.code,
          is_used: Number(r.is_used || 0),
          used_at: r.used_at || "",
          used_by_email: r.used_by_email || "",
          used_by_device_id: r.used_by_device_id || "",
          device_fingerprint: r.device_fingerprint || "",
          game_slug: r.game_slug || "",
        })),
      }),
      { status: 200, headers: corsHeaders }
    );
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: String(e?.message || e) }), {
      status: 500,
      headers: corsHeaders,
    });
  }
}
