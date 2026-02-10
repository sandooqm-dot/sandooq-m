// functions/_middleware.js
export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  const VERSION = "mw-v3-debug-root-redirect";
  const TOKEN_COOKIE = "sandooq_token_v1";

  // ✅ صفحة فحص (عشان نتأكد أن الميدلوير شغال فعلاً)
  if (path === "/__mw") {
    return new Response(
      JSON.stringify({ ok: true, version: VERSION, path, time: Date.now() }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
        },
      }
    );
  }

  // ✅ مسارات عامة لا تتقفل
  if (
    path.startsWith("/api/") ||
    path.startsWith("/api2/") ||
    path === "/activate" ||
    path === "/activate/" ||
    path === "/activate.html" ||
    path === "/robots.txt" ||
    path === "/favicon.ico" ||
    path.startsWith("/.well-known/")
  ) {
    return next();
  }

  // ✅ الدومين الرئيسي / (أو /index.html) لا يفتح صفحة اللعبة القديمة
  if (path === "/" || path === "/index.html") {
    return redirect(url, "/activate?next=%2Fapp");
  }

  // ✅ نقفل /app فقط
  if (path === "/app" || path.startsWith("/app/")) {
    const cookieHeader = request.headers.get("Cookie") || "";
    const token = getCookie(cookieHeader, TOKEN_COOKIE);

    if (!token) {
      const nextPath = path + (url.search || "");
      const to = "/activate?next=" + encodeURIComponent(nextPath);
      return redirect(url, to);
    }

    return next();
  }

  return next();
}

function getCookie(cookieHeader, name) {
  const parts = cookieHeader.split(";").map((s) => s.trim());
  for (const p of parts) {
    if (!p) continue;
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    const k = p.slice(0, eq).trim();
    const v = p.slice(eq + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return "";
}

function redirect(currentUrl, toPath) {
  const to = new URL(toPath, currentUrl.origin);
  return new Response(null, {
    status: 302,
    headers: {
      Location: to.toString(),
      "Cache-Control": "no-store",
    },
  });
}

// functions/_middleware.js – إصدار 3 (Debug /__mw + تحويل / إلى /activate + حماية /app)
