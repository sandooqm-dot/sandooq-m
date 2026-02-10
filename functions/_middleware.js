// /functions/_middleware.js
export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // ✅ اسم الكوكي اللي بنستخدمه (بنخليه يتخزن من activate.html بالخطوة الجاية)
  const TOKEN_COOKIE = "sandooq_token_v1";

  // ✅ مسارات عامة (لا تتقفل)
  if (
    path.startsWith("/api/") ||
    path === "/activate" ||
    path === "/activate/" ||
    path === "/activate.html" ||
    path === "/robots.txt" ||
    path === "/favicon.ico" ||
    path.startsWith("/.well-known/")
  ) {
    return next();
  }

  // ✅ الآن (بهذه الخطوة) نقفل /app فقط
  if (path === "/app" || path.startsWith("/app/")) {
    const cookieHeader = request.headers.get("Cookie") || "";
    const token = getCookie(cookieHeader, TOKEN_COOKIE);

    // إذا ما عنده جلسة -> نرجعه لصفحة التفعيل
    if (!token) {
      const nextPath = path + (url.search || "");
      const to = "/activate?next=" + encodeURIComponent(nextPath);
      return redirect(url, to);
    }

    // عنده توكن (مبدئيًا نسمح له) - التحقق النهائي بيكون عبر /api/me بالخطوات الجاية
    return next();
  }

  // باقي الموقع (حالياً) ما نلمسه عشان ما نخرب دخولك الحالي
  return next();
}

function getCookie(cookieHeader, name) {
  // parsing بسيط وآمن
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

// functions/_middleware.js – إصدار 1 (حماية /app فقط)
