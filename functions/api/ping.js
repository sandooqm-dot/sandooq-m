export async function onRequest(context) {
  const { request, env } = context;

  const headers = {
    "Access-Control-Allow-Origin": "*",
    "content-type": "application/json; charset=utf-8",
  };

  try {
    if (!env?.DB) {
      return new Response(JSON.stringify({ ok: false, error: "DB_NOT_BOUND" }), { status: 500, headers });
    }

    // إجمالي الأكواد
    let total = null;
    try {
      const c = await env.DB.prepare("SELECT COUNT(1) AS n FROM codes").first();
      total = c?.n ?? 0;
    } catch (e) {
      return new Response(
        JSON.stringify({ ok: false, error: "CODES_TABLE_MISSING_OR_SQL_ERROR", details: String(e?.message || e) }),
        { status: 500, headers }
      );
    }

    // عينة من أول كود موجود بالقاعدة
    let sample = null;
    try {
      const s = await env.DB.prepare("SELECT code, is_used, used_by_email, used_at FROM codes ORDER BY ROWID ASC LIMIT 1").first();
      sample = s || null;
    } catch (e) {}

    // اختبار كود لو مررته ?code=
    const url = new URL(request.url);
    const qCode = (url.searchParams.get("code") || "").toString().trim();

    let lookup = null;
    if (qCode) {
      const normalized = qCode
        .toUpperCase()
        .replace(/[–—−]/g, "-")
        .replace(/\s+/g, "")
        .replace(/[^A-Z0-9-]/g, "");

      const compact = normalized.replace(/-/g, "");

      const row = await env.DB.prepare(
        `
        SELECT code, is_used, used_by_email, used_at
        FROM codes
        WHERE code = ?
           OR REPLACE(code, '-', '') = ?
        LIMIT 1
        `
      )
        .bind(normalized, compact)
        .first();

      lookup = {
        input: qCode,
        normalized,
        compact,
        found: !!row,
        row: row || null,
      };
    }

    return new Response(
      JSON.stringify({
        ok: true,
        hasDB: true,
        totalCodesInDB: total,
        sample,
        lookup,
      }),
      { status: 200, headers }
    );
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: String(e?.message || e) }), { status: 500, headers });
  }
}
