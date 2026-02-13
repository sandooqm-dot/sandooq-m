export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  // Helpers
  const json = (status, data, extraHeaders = {}) =>
    new Response(JSON.stringify(data), {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        ...extraHeaders,
      },
    });

  // Allow only same-origin (اختياري قوي ضد الاستخدام الغلط)
  const origin = request.headers.get("Origin");
  if (origin && origin !== url.origin) {
    return json(403, { ok: false, error: "ORIGIN_NOT_ALLOWED" });
  }

  // OPTIONS preflight (لو صار)
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": url.origin,
        "access-control-allow-methods": "POST,DELETE,OPTIONS",
        "access-control-allow-headers": "authorization,content-type",
        "access-control-allow-credentials": "true",
      },
    });
  }

  // DELETE: logout / clear cookie
  if (request.method === "DELETE") {
    const clear = [
      "sandooq_session_v1=;",
      "Path=/;",
      "Max-Age=0;",
      "HttpOnly;",
      "Secure;",
      "SameSite=Lax",
    ].join(" ");
    return json(200, { ok: true }, { "set-cookie": clear });
  }

  if (request.method !== "POST") {
    return json(405, { ok: false, error: "METHOD_NOT_ALLOWED" });
  }

  // Get token from Authorization: Bearer <token>
  const auth = request.headers.get("Authorization") || "";
  let token = "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m) token = (m[1] || "").trim();

  // Fallback: body { token: "..." }
  if (!token) {
    try {
      const body = await request.json();
      token = (body?.token || "").toString().trim();
    } catch {}
  }

  if (!token || token.length < 20) {
    return json(401, { ok: false, error: "MISSING_TOKEN" });
  }

  // Verify session token exists
  const row = await env.DB.prepare(
    "SELECT email FROM sessions WHERE token = ? LIMIT 1"
  ).bind(token).first();

  if (!row?.email) {
    return json(401, { ok: false, error: "INVALID_SESSION" });
  }

  // Issue HttpOnly cookie (1 year)
  const cookie = [
    `sandooq_session_v1=${token};`,
    "Path=/;",
    "Max-Age=31536000;",
    "HttpOnly;",
    "Secure;",
    "SameSite=Lax",
  ].join(" ");

  return json(200, { ok: true }, { "set-cookie": cookie });
}
