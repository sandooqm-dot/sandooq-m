// functions/_middleware.js
// Protect ALL routes except /activate and /api2/*
// Redirect unauth/unalactivated users to /activate

function getCookie(req, name) {
  const cookie = req.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (k === name) return rest.join("=") || "";
  }
  return "";
}

function isPublicPath(pathname) {
  // Allow activation + APIs + minimal public assets
  if (pathname === "/activate" || pathname === "/activate.html") return true;
  if (pathname.startsWith("/api2/")) return true;

  // reset links also hit /activate?reset=1 (same path)
  // Minimal assets for activate page
  const PUBLIC_FILES = new Set([
    "/logo.png",
    "/logo.PNG",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/manifest.json",
    "/apple-touch-icon.png",
  ]);
  if (PUBLIC_FILES.has(pathname)) return true;

  // Let's Encrypt / well-known (safe)
  if (pathname.startsWith("/.well-known/")) return true;

  return false;
}

function redirectToActivate(req) {
  const url = new URL(req.url);
  const next = `${url.pathname}${url.search}`;
  const target = new URL(`${url.origin}/activate`);
  target.searchParams.set("next", next);
  return Response.redirect(target.toString(), 302);
}

async function fetchMe(origin, token) {
  const r = await fetch(`${origin}/api2/me`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${token}`,
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

  // Public allowlist
  if (isPublicPath(path)) return next();

  // Session token from cookie (page requests don't carry Authorization)
  const cookieTok = getCookie(request, "sandooq_session_v1");
  const token = cookieTok ? String(cookieTok).trim() : "";

  if (!token) return redirectToActivate(request);

  // Cache per token (5 minutes) to avoid D1 load
  const cache = caches.default;
  const cacheKey = new Request(`https://auth-cache.local/me/${encodeURIComponent(token)}`, { method: "GET" });

  const cached = await cache.match(cacheKey);
  if (cached) {
    const data = await cached.json().catch(() => null);
    if (data?.ok && data?.activated) return next();
    return redirectToActivate(request);
  }

  const me = await fetchMe(url.origin, token);

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
_middleware.js – إصدار 2 (Protect ALL site except /activate + /api2)
*/
