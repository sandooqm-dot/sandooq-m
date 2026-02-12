export async function onRequestGet({ request, env }) {
  try {
    const url = new URL(request.url);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const oauthError = url.searchParams.get("error");

    if (oauthError) {
      return html(`رسالة\nخطأ من Google: ${escapeHtml(oauthError)}`);
    }
    if (!code || !state) {
      return html("رسالة\nبيانات الرجوع من Google ناقصة (code/state).");
    }

    // --- Cookies (for PKCE/state) ---
    const cookie = request.headers.get("Cookie") || "";
    const cookieGet = (name) => {
      const m = cookie.match(new RegExp(`(?:^|; )${name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&")}=([^;]*)`));
      return m ? decodeURIComponent(m[1]) : null;
    };

    const expectedState =
      cookieGet("g_state") ||
      cookieGet("google_state") ||
      cookieGet("oauth_state") ||
      cookieGet("state");

    if (expectedState && expectedState !== state) {
      return html("رسالة\nبيانات التحقق غير صحيحة (state mismatch).");
    }

    const codeVerifier =
      cookieGet("g_verifier") ||
      cookieGet("google_verifier") ||
      cookieGet("oauth_verifier") ||
      cookieGet("verifier");

    const redirectUri =
      (env.GOOGLE_REDIRECT_URI && String(env.GOOGLE_REDIRECT_URI).trim()) ||
      `${url.origin}/api2/google/callback`;

    const clientId = String(env.GOOGLE_CLIENT_ID || "").trim();
    const clientSecret = String(env.GOOGLE_CLIENT_SECRET || "").trim();

    if (!clientId || !clientSecret) {
      return html("رسالة\nنقص في إعدادات GOOGLE_CLIENT_ID أو GOOGLE_CLIENT_SECRET داخل Cloudflare.");
    }

    // --- Token exchange ---
    const body = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
    });

    // PKCE is optional depending on start.js
    if (codeVerifier) body.set("code_verifier", codeVerifier);

    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    const tokenJson = await tokenRes.json().catch(() => ({}));

    if (!tokenRes.ok) {
      const msg = [
        "فشل تبادل رمز (token exchange) من Google.",
        "",
        `status: ${tokenRes.status}`,
        `error: ${tokenJson.error || "unknown"}`,
        `desc: ${tokenJson.error_description || "no_desc"}`,
        `redirect_uri_used: ${redirectUri}`,
      ].join("\n");
      return html(escapeHtml(msg));
    }

    const accessToken = tokenJson.access_token;
    if (!accessToken) {
      return html("رسالة\nلم يصل access_token من Google.");
    }

    // --- Get user info ---
    const infoRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const info = await infoRes.json().catch(() => ({}));

    if (!infoRes.ok || !info.email) {
      return html("رسالة\nلم نستطع جلب بيانات البريد من Google.");
    }

    const email = String(info.email).toLowerCase().trim();
    const sub = info.sub ? String(info.sub).trim() : null;
    const now = Date.now();

    // --- Ensure users row (dynamic columns-safe) ---
    // We avoid crashing if your users schema differs.
    try {
      const colsRes = await env.DB.prepare("PRAGMA table_info(users)").all();
      const cols = (colsRes.results || []).map((r) => r.name);

      const insertCols = [];
      const insertVals = [];
      const placeholders = [];

      if (cols.includes("email")) {
        insertCols.push("email");
        insertVals.push(email);
        placeholders.push("?");
      }

      if (sub && cols.includes("google_sub")) {
        insertCols.push("google_sub");
        insertVals.push(sub);
        placeholders.push("?");
      }

      if (cols.includes("created_at")) {
        insertCols.push("created_at");
        insertVals.push(now);
        placeholders.push("?");
      }

      // mark verified if column exists
      if (cols.includes("verified_at")) {
        insertCols.push("verified_at");
        insertVals.push(now);
        placeholders.push("?");
      } else if (cols.includes("is_verified")) {
        insertCols.push("is_verified");
        insertVals.push(1);
        placeholders.push("?");
      }

      if (insertCols.length) {
        const sql =
          `INSERT INTO users (${insertCols.join(",")}) VALUES (${placeholders.join(",")}) ` +
          `ON CONFLICT(email) DO UPDATE SET ` +
          insertCols
            .filter((c) => c !== "email")
            .map((c) => `${c}=excluded.${c}`)
            .join(",");

        // If only email col exists, update set becomes empty -> handle:
        if (sql.includes("DO UPDATE SET ") && sql.endsWith("DO UPDATE SET ")) {
          // do nothing
        } else {
          await env.DB.prepare(sql).bind(...insertVals).run();
        }
      }
    } catch (_) {
      // ignore users upsert errors to not block login
    }

    // --- Create session ---
    const token = crypto.randomUUID();

    try {
      await env.DB.prepare(
        "INSERT INTO sessions (token, email, created_at) VALUES (?, ?, ?)"
      ).bind(token, email, now).run();
    } catch (e) {
      return html("رسالة\nخطأ في إنشاء جلسة الدخول (sessions).");
    }

    // --- Return HTML that stores token then redirects ---
    // IMPORTANT: activate page reads localStorage 'sandooq_token_v1'
    const redirectTo = "/activate";
    const page = `<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <title>تسجيل الدخول...</title>
</head>
<body>
<script>
(function(){
  try{
    localStorage.setItem("sandooq_token_v1", ${JSON.stringify(token)});
    // optional: keep email for UI
    localStorage.setItem("sandooq_email_v1", ${JSON.stringify(email)});
  }catch(e){}
  location.replace(${JSON.stringify(redirectTo)});
})();
</script>
</body>
</html>`;

    // clear oauth cookies if موجودة (اختياري)
    return new Response(page, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Set-Cookie": [
          "g_state=; Path=/; Max-Age=0; Secure; SameSite=Lax",
          "g_verifier=; Path=/; Max-Age=0; Secure; SameSite=Lax",
          "google_state=; Path=/; Max-Age=0; Secure; SameSite=Lax",
          "google_verifier=; Path=/; Max-Age=0; Secure; SameSite=Lax",
          "oauth_state=; Path=/; Max-Age=0; Secure; SameSite=Lax",
          "oauth_verifier=; Path=/; Max-Age=0; Secure; SameSite=Lax",
        ].join(", "),
      },
    });
  } catch (err) {
    return html("رسالة\nحدث خطأ غير متوقع في Google callback.");
  }
}

function html(text) {
  return new Response(`<!doctype html><meta charset="utf-8"><pre>${escapeHtml(String(text))}</pre>`, {
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
