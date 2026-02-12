export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return text("بيانات الرجوع من Google ناقصة (code/state).", 400);
  }

  const cookie = request.headers.get("Cookie") || "";
  const stateCookie = getCookie(cookie, "g_state");
  const verifier = getCookie(cookie, "g_verifier");

  if (!stateCookie || stateCookie !== state) {
    return text("state غير مطابق (قد تكون الكوكي ما وصلت).", 400);
  }
  if (!verifier) {
    return text("Missing code verifier (g_verifier).", 400);
  }

  const clientId = String(env.GOOGLE_CLIENT_ID || "").trim();
  const clientSecret = String(env.GOOGLE_CLIENT_SECRET || "").trim();
  const redirectUri =
    (env.GOOGLE_REDIRECT_URI && String(env.GOOGLE_REDIRECT_URI).trim()) ||
    `${url.origin}/api2/google/callback`;

  if (!clientId || !clientSecret) {
    return text("GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET غير مضبوطين.", 500);
  }

  // 1) Token Exchange (PKCE)
  const form = new URLSearchParams();
  form.set("client_id", clientId);
  form.set("client_secret", clientSecret);
  form.set("code", code);
  form.set("grant_type", "authorization_code");
  form.set("redirect_uri", redirectUri);
  form.set("code_verifier", verifier);

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });

  const tokenJson = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok) {
    return text(
      [
        "Google (token exchange) فشل",
        `status: ${tokenRes.status}`,
        `error: ${tokenJson.error || ""}`,
        `desc: ${tokenJson.error_description || ""}`,
        `redirect_uri_used: ${redirectUri}`,
      ].join("\n"),
      400
    );
  }

  const accessToken = tokenJson.access_token;
  if (!accessToken) {
    return text("Google لم يرجّع access_token.", 400);
  }

  // 2) Userinfo
  const uiRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const profile = await uiRes.json().catch(() => ({}));
  if (!uiRes.ok) {
    return text(
      [
        "Google (userinfo) فشل",
        `status: ${uiRes.status}`,
        JSON.stringify(profile, null, 2),
      ].join("\n"),
      400
    );
  }

  const email = String(profile.email || "").trim().toLowerCase();
  const sub = String(profile.sub || "").trim();

  if (!email || !sub) {
    return text("Google لم يرجّع email/sub.", 400);
  }

  // 3) Upsert user (Google يعتبر Email Verified)
  const now = new Date().toISOString();

  const uInfo = await env.DB.prepare("PRAGMA table_info(users)").all();
  const uCols = new Set((uInfo.results || []).map((r) => r.name));

  const insertCols = [];
  const insertVals = [];
  const params = [];

  const push = (col, val) => {
    insertCols.push(col);
    insertVals.push("?");
    params.push(val);
  };

  if (uCols.has("email")) push("email", email);

  if (uCols.has("google_sub")) push("google_sub", sub);
  if (uCols.has("email_verified")) push("email_verified", 1);
  if (uCols.has("verified_at")) push("verified_at", now);
  if (uCols.has("created_at")) push("created_at", now);
  if (uCols.has("id")) push("id", crypto.randomUUID());

  // إذا جدول users ما فيه email أصلاً، نوقف برسالة واضحة
  if (!uCols.has("email")) {
    return text("جدول users ما فيه عمود email.", 500);
  }

  const updates = [];
  if (uCols.has("google_sub")) updates.push("google_sub=excluded.google_sub");
  if (uCols.has("email_verified")) updates.push("email_verified=1");
  if (uCols.has("verified_at")) updates.push("verified_at=excluded.verified_at");

  const upsertSql =
    `INSERT INTO users (${insertCols.join(",")}) VALUES (${insertVals.join(",")}) ` +
    `ON CONFLICT(email) DO UPDATE SET ${updates.length ? updates.join(",") : "email=email"}`;

  await env.DB.prepare(upsertSql).bind(...params).run();

  // 4) Create session token (مثل login.js)
  const sessionToken = base64urlRandom(32);

  await env.DB
    .prepare("INSERT INTO sessions (token, email, created_at) VALUES (?,?,?)")
    .bind(sessionToken, email, now)
    .run();

  // 5) Clear PKCE cookies + return HTML that stores token in localStorage then redirects
  const headers = new Headers();
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.append("Set-Cookie", clearCookie("g_state"));
  headers.append("Set-Cookie", clearCookie("g_verifier"));

  const activatePath = "/activate"; // عندك /activate شغال
  const html = `<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <title>جاري تسجيل الدخول...</title>
</head>
<body>
  <script>
    (function(){
      try {
        localStorage.setItem("sandooq_token_v1", ${JSON.stringify(sessionToken)});
      } catch(e) {}
      location.replace(${JSON.stringify(activatePath)});
    })();
  </script>
</body>
</html>`;

  return new Response(html, { status: 200, headers });
}

function text(msg, status = 200) {
  return new Response(String(msg), {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function getCookie(cookie, name) {
  const m = cookie.match(new RegExp("(^|;\\s*)" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[2]) : "";
}

function clearCookie(name) {
  return `${name}=; Path=/; Secure; SameSite=Lax; Max-Age=0; HttpOnly`;
}

function base64url(bytes) {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlRandom(nBytes) {
  const bytes = new Uint8Array(nBytes);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}
