// functions/api2/admin-usage-export.js
// GET /api2/admin-usage-export
// Returns used codes + email + used_at from D1 (code_usage_v2)
// Protected by ADMIN_API_KEY (header X-Admin-Key) or ?key= for quick testing

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin");
  const h = {
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id, X-Admin-Key",
    "Access-Control-Max-Age": "86400",
    "cache-control": "no-store",
  };
  h["Access-Control-Allow-Origin"] = origin || "*";
  return h;
};

function json(req, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS(req),
      "content-type": "application/json; charset=utf-8",
    },
  });
}

function iso(ts) {
  try {
    return new Date(Number(ts)).toISOString();
  } catch {
    return null;
  }
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS(request) });
  }
  if (request.method !== "GET") {
    return json(request, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env?.DB) return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);

    // 🔒 حماية: لازم مفتاح إداري
    const url = new URL(request.url);
    const keyFromQuery = (url.searchParams.get("key") || "").trim(); // للاختبار السريع
    const keyFromHeader = (request.headers.get("x-admin-key") || "").trim();
    const adminKey = String(env.ADMIN_API_KEY || "").trim();

    if (!adminKey) return json(request, { ok: false, error: "ADMIN_KEY_NOT_SET" }, 500);

    const provided = keyFromHeader || keyFromQuery;
    if (!provided || provided !== adminKey) {
      return json(request, { ok: false, error: "UNAUTHORIZED" }, 401);
    }

    // اختياري: فلترة حسب لعبة
    const game = (url.searchParams.get("game") || "").trim(); // مثال: ?game=horof

    let q = `SELECT code, email, used_at, device_id, game_slug FROM code_usage_v2`;
    let args = [];
    if (game) {
      q += ` WHERE game_slug = ?`;
      args.push(game);
    }
    q += ` ORDER BY used_at DESC LIMIT 10000`;

    const res = await env.DB.prepare(q).bind(...args).all();

    const items = (res?.results || []).map((r) => ({
      code: r.code,
      email: r.email,
      used_at: r.used_at,
      used_at_iso: iso(r.used_at),
      device_id: r.device_id || null,
      game_slug: r.game_slug || null,
    }));

    return json(request, { ok: true, count: items.length, items }, 200);
  } catch (e) {
    console.log("admin_usage_export_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
admin-usage-export.js – api2 – إصدار 1
*/
