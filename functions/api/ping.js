// functions/api/ping.js
export async function onRequest(context) {
  const { request, env } = context;

  const originHeader = request.headers.get("Origin");
  const allowOrigin = originHeader && originHeader !== "null" ? originHeader : "*";

  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Device-Id",
    "Vary": "Origin",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  // نسمح GET فقط عشان تفتحه من المتصفح مباشرة
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ ok: false, error: "METHOD_NOT_ALLOWED" }), {
      status: 405,
      headers,
    });
  }

  try {
    const db = env.DB;

    // هل جدول codes موجود؟ وكم عدد الأكواد؟
    const tables = await db.prepare(`
      SELECT name FROM sqlite_master WHERE type='table'
      ORDER BY name;
    `).all();

    const hasCodesTable = (tables.results || []).some(t => t.name === "codes");
    const hasActivationsTable = (tables.results || []).some(t => t.name === "activations");
    const hasUsersTable = (tables.results || []).some(t => t.name === "users");

    let codesCount = null;
    let usedCount = null;
    let sample = null;

    if (hasCodesTable) {
      const c1 = await db.prepare(`SELECT COUNT(*) as n FROM codes;`).first();
      const c2 = await db.prepare(`SELECT COUNT(*) as n FROM codes WHERE is_used = 1;`).first();
      const s = await db.prepare(`SELECT code, is_used, used_at FROM codes ORDER BY rowid DESC LIMIT 1;`).first();
      codesCount = c1?.n ?? null;
      usedCount = c2?.n ?? null;
      sample = s || null;
    }

    return new Response(JSON.stringify({
      ok: true,
      now: new Date().toISOString(),
      url: request.url,
      origin: originHeader || null,
      db: {
        hasCodesTable,
        hasActivationsTable,
        hasUsersTable,
        codesCount,
        usedCount,
        sampleLastCode: sample,
      }
    }, null, 2), {
      status: 200,
      headers,
    });

  } catch (err) {
    return new Response(JSON.stringify({
      ok: false,
      error: "HTTP_500",
      message: err?.message || "Unknown",
    }, null, 2), {
      status: 500,
      headers,
    });
  }
}
