// functions/_middleware.js
export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  const VERSION = "mw-v5-lock-html-to-activate";
  const TOKEN_COOKIE = "sandooq_token_v1";

  // ✅ فحص سريع
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

  // ✅ مسارات عامة (لا تتقفل)
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

  // ✅ اسمح للملفات الثابتة (صور/خطوط/JS/CSS/maps...) عشان الواجهات تشتغل
  if (isStaticAsset(path)) {
    return next();
  }

  // ✅ أي زيارة للرابط الرئيسي دايم تروح للتفعيل (مثل نظامكم المطلوب)
  if (path === "/" || path === "/index.html") {
    return redirect(url, "/activate?next=%2Fapp");
  }

  // ✅ أي صفحة HTML ثانية/صفحات اللعبة: لازم يكون فيه جلسة (Cookie)
  // هذا يضمن "أي رابط لأي صفحة يفتح صفحة التفعيل أولاً"
  const cookieHeader = request.headers.get("Cookie") || "";
  const token = getCookie(cookieHeader, TOKEN_COOKIE);

  if (!token) {
    const nextPath = path + (url.search || "");
    return redirect(url, "/activate?next=" + encodeURIComponent(nextPath));
  }

  // عنده جلسة -> يكمل
  return next();
}

/* ---------------- helpers ---------------- */

function isStaticAsset(path) {
  // مجلدات ثابتة عندك
  if (path.startsWith("/maps/")) return true;

  // ملفات ثابتة (صور/خطوط/ستايل/سكربت…)
  return /\.(png|jpe?g|webp|gif|svg|ico|css|js|json|map|txt|xml|woff2?|ttf|otf|eot|mp3|mp4)$/i.test(path);
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

// functions/_middleware.js – إصدار 5
