// functions/api2/google/start.js

export async function onRequest(context) {
  const { request, env } = context;

  try {
    const url = new URL(request.url);
    const origin = url.origin;

    // (اختياري) تقييد الدومينات المسموحة لو ALLOWED_ORIGINS موجود
    const allowed = String(env.ALLOWED_ORIGINS || "").trim();
    if (allowed) {
      const list = allowed.split(",").map(s => s.trim()).filter(Boolean);
      if (list.length && !list.includes(origin)) {
        return new Response("Origin غير مسموح", { status: 403 });
      }
    }

    const clientId = String(env.GOOGLE_CLIENT_ID || "").trim();
    if (!clientId) {
      return new Response("GOOGLE_CLIENT_ID غير مضبوط", { status: 500 });
    }

    const redirectUriEnv = String(env.GOOGLE_REDIRECT_URI || "").trim();
    const redirectUri = redirectUriEnv || `${origin}/api2/google/callback`;

    // ===== Helpers
    const b64url = (buf) => {
      const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
      let s = "";
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    };

    const randomB64url = (n) => {
      const a = new Uint8Array(n);
      crypto.getRandomValues(a);
      return b64url(a);
    };

    // ===== PKCE
    const codeVerifier = randomB64url(32); // 43 chars تقريبًا
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(codeVerifier)
    );
    const codeChallenge = b64url(digest);

    // ===== State
    const state = randomB64url(16);

    // ===== Google Auth URL
    const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    auth.searchParams.set("client_id", clientId);
    auth.searchParams.set("redirect_uri", redirectUri);
    auth.searchParams.set("response_type", "code");
    auth.searchParams.set("scope", "openid email profile");
    auth.searchParams.set("access_type", "online");
    auth.searchParams.set("prompt", "select_account");
    auth.searchParams.set("code_challenge", codeChallenge);
    auth.searchParams.set("code_challenge_method", "S256");
    auth.searchParams.set("state", state);

    // ✅ مهم:
    // بدل 302 + Set-Cookie مباشرة،
    // نرجع HTML قصيرة تحفظ الكوكيز أولًا داخل المتصفح ثم تحول إلى Google.
    // هذا يحل مشاكل Safari/WebView في ضياع الكوكيز أثناء redirect السريع.

    const maxAge = 10 * 60; // 10 دقائق
    const cookiePath = "/api2/google/callback";
    const authUrl = auth.toString();

    const html = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>جارٍ التحويل...</title>
  <meta http-equiv="Cache-Control" content="no-store" />
  <meta http-equiv="Pragma" content="no-cache" />
  <meta http-equiv="Expires" content="0" />
  <style>
    body{
      margin:0;
      background:#0b1020;
      color:#fff;
      font-family:Arial,sans-serif;
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:100vh;
      text-align:center;
      padding:24px;
      box-sizing:border-box;
    }
    .box{
      max-width:420px;
      line-height:1.9;
      opacity:.95;
    }
    a{color:#8ab4ff}
  </style>
</head>
<body>
  <div class="box">
    جارٍ تحويلك إلى تسجيل الدخول عبر Google...
    <noscript>
      <div style="margin-top:16px">
        JavaScript غير مفعّل.
        <br>
        <a href="${escapeHtml(authUrl)}">اضغط هنا للمتابعة</a>
      </div>
    </noscript>
  </div>

  <script>
    (function () {
      try {
        var maxAge = ${maxAge};
        var cookiePath = ${JSON.stringify(cookiePath)};
        var state = ${JSON.stringify(state)};
        var verifier = ${JSON.stringify(codeVerifier)};
        var authUrl = ${JSON.stringify(authUrl)};

        var attrs = "; Max-Age=" + maxAge +
                    "; Path=" + cookiePath +
                    "; Secure; SameSite=Lax";

        document.cookie = "sandooq_g_state=" + encodeURIComponent(state) + attrs;
        document.cookie = "sandooq_g_verifier=" + encodeURIComponent(verifier) + attrs;

        // نعطي المتصفح جزءًا من الثانية ليحفظ الكوكيز قبل الخروج إلى Google
        setTimeout(function () {
          location.replace(authUrl);
        }, 60);
      } catch (e) {
        document.body.innerHTML =
          '<div style="padding:24px;font-family:Arial,sans-serif;color:#fff;background:#0b1020;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center">' +
          '<div>تعذر بدء تسجيل الدخول عبر Google.<br><br>' +
          '<a style="color:#8ab4ff" href=' + JSON.stringify(${JSON.stringify(authUrl)}) + '>اضغط هنا للمتابعة</a>' +
          '</div></div>';
      }
    })();
  </script>
</body>
</html>`;

    return new Response(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        "Referrer-Policy": "no-referrer",
      },
    });

  } catch (e) {
    return new Response("start exception: " + String(e?.stack || e), { status: 500 });
  }
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/*
functions/api2/google/start.js – إصدار 2
Fix: use HTML bridge page to persist OAuth state/verifier cookies before redirecting to Google
*/
