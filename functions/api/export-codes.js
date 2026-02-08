// functions/api/export-codes.js
export async function onRequest(context) {
  const { request, env } = context;

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (request.method !== "GET") {
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

    const url = new URL(request.url);

    // ✅ حماية بالمفتاح
    // ضع EXPORT_KEY في Cloudflare Pages > Settings > Environment variables
    // ثم استخدم: /api/export-codes?key=YOUR_KEY
    const key = (url.searchParams.get("key") || "").toString().trim();
    const requiredKey = (env.EXPORT_KEY || "").toString().trim();

    if (!requiredKey) {
      return new Response(
        JSON.stringify({ ok: false, error: "EXPORT_KEY_NOT_SET" }),
        { status: 403, headers: corsHeaders }
      );
    }
    if (!key || key !== requiredKey) {
      return new Response(JSON.stringify({ ok: false, error: "UNAUTHORIZED" }), {
        status: 401,
        headers: corsHeaders,
      });
    }

    // ✅ Filters
    const usedParam = url.searchParams.get("used"); // "1" | "0" | null
    const usedFilter = usedParam === "1" ? 1 : usedParam === "0" ? 0 : null;

    // ✅ Pagination
    const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "5000", 10) || 5000, 1), 5000);
    const offset = Math.max(parseInt(url.searchParams.get("offset") || "0", 10) || 0, 0);

    // =====================================================
    // ✅ اكتشاف أعمدة جدول codes تلقائياً (حتى ما نصير في HTTP_500)
    // =====================================================
    const colsRes = await env.DB.prepare(`PRAGMA table_info(codes);`).all();
    const cols = (colsRes?.results || []).map(r => String(r.name || "")).filter(Boolean);

    // الأعمدة الأساسية المتوقع وجودها
    const has = (c) => cols.includes(c);

    // ✅ game filter فقط لو العمود موجود
    const game = (url.searchParams.get("game") || "").toString().trim();
    const canFilterGame = !!game && has("game_slug");

    // الأعمدة اللي بنرجّعها حسب الموجود
    const selectCols = [];
    if (has("code")) selectCols.push(`c.code AS code`);
    if (has("is_used")) selectCols.push(`c.is_used AS is_used`);
    if (has("used_by_email")) selectCols.push(`c.used_by_email AS used_by_email`);
    if (has("used_at")) selectCols.push(`c.used_at AS used_at`);
    if (has("game_slug")) selectCols.push(`c.game_slug AS game_slug`);

    // لو لأي سبب ما لقينا حتى code (شي غير منطقي) نوقف
    if (!selectCols.length) {
      return new Response(JSON.stringify({ ok: false, error: "CODES_TABLE_INVALID" }), {
        status: 500,
        headers: corsHeaders,
      });
    }

    // =====================================================
    // ✅ activations: نجيب device_id من جدول activations (لو موجود)
    // =====================================================
    let activationsExists = false;
    try {
      const a = await env.DB.prepare(`PRAGMA table_info(activations);`).all();
      const aCols = (a?.results || []).map(r => String(r.name || "")).filter(Boolean);
      // نعتبره موجود إذا فيه code و device_id
      if (aCols.includes("code") && aCols.includes("device_id")) activationsExists = true;
    } catch (_) {}

    if (activationsExists) {
      selectCols.push(`a.device_id AS activated_device_id`);
      selectCols.push(`a.activated_at AS activated_at`);
    }

    // =====================================================
    // ✅ بناء SQL النهائي
    // =====================================================
    let sql = `
      SELECT ${selectCols.join(", ")}
      FROM codes c
      ${activationsExists ? "LEFT JOIN activations a ON a.code = c.code" : ""}
      WHERE 1=1
    `;
    const binds = [];

    if (usedFilter !== null && has("is_used")) {
      sql += ` AND c.is_used = ?`;
      binds.push(usedFilter);
    }

    if (canFilterGame) {
      sql += ` AND c.game_slug = ?`;
      binds.push(game);
    }

    // ترتيب منطقي بدون الاعتماد على أعمدة غير موجودة
    if (has("is_used") && has("used_at")) {
      sql += ` ORDER BY c.is_used ASC, c.used_at DESC`;
    } else if (has("used_at")) {
      sql += ` ORDER BY c.used_at DESC`;
    } else {
      sql += ` ORDER BY c.code ASC`;
    }

    sql += ` LIMIT ? OFFSET ?`;
    binds.push(limit, offset);

    const rowsRes = await env.DB.prepare(sql).bind(...binds).all();
    const rows = rowsRes?.results || [];

    // =====================================================
    // ✅ Counters (بحسب الأعمدة الموجودة)
    // =====================================================
    const totalRow = await env.DB.prepare(`SELECT COUNT(*) AS total FROM codes;`).first();
    let usedRow = null, unusedRow = null;

    if (has("is_used")) {
      usedRow = await env.DB.prepare(`SELECT COUNT(*) AS used FROM codes WHERE is_used = 1;`).first();
      unusedRow = await env.DB.prepare(`SELECT COUNT(*) AS unused FROM codes WHERE is_used = 0;`).first();
    }

    return new Response(JSON.stringify({
      ok: true,
      meta: {
        total: Number(totalRow?.total || 0),
        used: Number(usedRow?.used || 0),
        unused: Number(unusedRow?.unused || 0),
        limit,
        offset,
        usedFilter,
        game: canFilterGame ? game : null,
        activationsJoined: activationsExists,
        codesColumns: cols, // مفيد للتشخيص لو احتجناه
      },
      rows: rows.map(r => ({
        code: r.code ?? "",
        is_used: r.is_used != null ? Number(r.is_used) : 0,
        used_by_email: r.used_by_email ?? "",
        used_at: r.used_at ?? "",
        game_slug: r.game_slug ?? "",
        activated_device_id: r.activated_device_id ?? "",
        activated_at: r.activated_at ?? "",
      })),
    }), { status: 200, headers: corsHeaders });

  } catch (e) {
    return new Response(JSON.stringify({
      ok: false,
      error: "HTTP_500",
      message: String(e?.message || e),
    }), { status: 500, headers: corsHeaders });
  }
}
