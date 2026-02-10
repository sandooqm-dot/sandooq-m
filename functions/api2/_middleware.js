// functions/_middleware.js
export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // فحص سريع (تقدر تفتحه: https://domain/__mw )
  if (path === "/__mw") {
    return new Response("mw-ok", {
      status: 200,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
    });
  }

  // اسمح للأصول الثابتة (صور/خطوط/JS/CSS...) بدون أي تحويلات
  if (isStaticAsset(path)) return next();

  // اسمح لصفحة التفعيل
  if (path === "/activate" || path === "/activate.html" || path.startsWith("/activate/")) {
    return next();
  }

  // اسمح للـ APIs
  if (path.startsWith("/api2/") || path.startsWith("/api/")) {
    return next();
  }

  // حماية /app (اللعبة)
  if (path === "/app" || path.startsWith("/app/")) {
    const token = getCookie(request.headers.get("Cookie") || "", "sandooq_token_v1");
    if (!token) {
      return redirectToActivate(url, "/app");
    }

    if (!env?.DB) {
      return new Response("DB_NOT_BOUND", { status: 500 });
    }

    const tokenHash = await sha256Hex(new TextEncoder().encode(token));
    const now = Date.now();

    const s = await env.DB.prepare(
      "SELECT email, expires_at, revoked_at FROM auth_sessions WHERE token_hash = ? LIMIT 1"
    )
      .bind(tokenHash)
      .first();

    if (!s || s.revoked_at || Number(s.expires_at) <= now) {
      return redirectToActivate(url, "/app", true);
    }

    const gameId = String(env?.GAME_ID || "horof").trim();

    const link = await env.DB.prepare(
      "SELECT 1 FROM auth_code_links WHERE game_id = ? AND email = ? LIMIT 1"
    )
      .bind(gameId, String(s.email || ""))
      .first();

    if (!link) {
      return redirectToActivate(url, "/app");
    }

    return next();
  }

  // أي مسار ثاني: نرجعه لصفحة التفعيل (زي horofgame)
  return Response.redirect(new URL("/activate", url.origin), 302);
}

/* ---------------- helpers ---------------- */

function isStaticAsset(path) {
  // أي ملف له امتداد معروف نعتبره asset
  return /\.(png|jpg|jpeg|webp|svg|ico|css|js|mjs|map|json|txt|xml|otf|ttf|woff2?|mp3|mp4)$/i.test(path);
}

function redirectToActivate(url, nextPath, clearCookie = false) {
  const to = new URL("/activate", url.origin);
  if (nextPath) to.searchParams.set("next", nextPath);

  const headers = new Headers({ Location: to.toString(), "Cache-Control": "no-store" });

  if (clearCookie) {
    headers.append(
      "Set-Cookie",
      "sandooq_token_v1=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax"
    );
  }

  return new Response(null, { status: 302, headers });
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

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

// functions/_middleware.js – إصدار 1
