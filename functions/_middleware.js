// functions/_middleware.js
// Guard /app: require logged-in + activated, otherwise redirect to /activate
// Uses /api2/me as source of truth + caches per-session for performance.

function getCookie(req, name) {
  const cookie = req.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (k === name) return rest.join("=") || "";
  }
  return "";
}

function redirectToActivate(req) {
  const url = new URL(req.url);
  return Response.redirect(`${url.origin}/activate`, 302);
}

async function fetchMe(origin, token) {
  const r = await fetch(`${origin}/api2/me`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${token}`,
      // device id مو ضروري هنا لأننا نعتمد على تفعيل الإيميل/الكود
    },
    body: JSON.stringify({}),
  });
  const j = await r.json().catch(() => null);
  return j;
}

export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // نحمي فقط /app
  if (!path.startsWith("/app")) return next();

  // token من Cookie أو Authorization
  const auth = request.headers.get("Authorization") || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const cookieTok = getCookie(request, "sandooq_session_v1");
  const token = bearer || cookieTok;

  if (!token) return redirectToActivate(request);

  // Cache (5 دقائق) عشان ما نضغط على D1 مع كل ملف داخل /app
  const cache = caches.default;
  const cacheKey = new Request(`https://auth-cache.local/me/${encodeURIComponent(token)}`, { method: "GET" });
  const cached = await cache.match(cacheKey);
  if (cached) {
    const data = await cached.json().catch(() => null);
    if (data?.ok && data?.activated) return next();
    return redirectToActivate(request);
  }

  const me = await fetchMe(url.origin, token);

  // خزّن بالكااش
  await cache.put(
    cacheKey,
    new Response(JSON.stringify(me || { ok: false }), {
      headers: { "content-type": "application/json", "cache-control": "public, max-age=300" },
    })
  );

  if (me?.ok && me?.activated) return next();
  return redirectToActivate(request);
}

/*
_middleware.js – إصدار 1 (Protect /app via /api2/me + cache)
*/
