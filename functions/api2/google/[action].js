// functions/api2/google/[action].js
export async function onRequest(context) {
  const { request, env, params } = context;
  const action = (params && params.action) ? String(params.action) : "";

  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  if (action === "start") return handleStart({ request, env });
  if (action === "callback") return handleCallback({ request, env });

  return new Response("Not Found", { status: 404 });
}

/* -------------------- Helpers -------------------- */
function b64url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomB64Url(byteLen = 32) {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return b64url(bytes);
}

async function sha256B64Url(str) {
  const data = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return b64url(new Uint8Array(hash));
}

function parseCookies(cookieHeader = "") {
  const map = new Map();
  cookieHeader.split(";").forEach(part => {
    const p = part.trim();
    if (!p) return;
    const eq = p.indexOf("=");
    if (eq === -1) return;
    const k = p.slice(0, eq).trim();
    const v = p.slice(eq + 1).trim();
    map.set(k, decodeURIComponent(v));
  });
  return map;
}

function esc(s) {
  return String(s ?? "").replace(/[<>&"]/g, c => ({
    "<": "&lt;",
    ">": "&gt;",
    "&": "&amp;",
    '"': "&quot;"
  }[c]));
}

function htmlMessage(title, message) {
  return `<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <title>${esc(title)}</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Tahoma,Arial; margin:0; background:#fff; color:#111;}
    .wrap{padding:40px 18px; max-width:760px; margin:0 auto;}
    h1{font-size:22px; margin:0 0 12px;}
    p{font-size:17px; line-height:1.8; margin:0 0 10px;}
    .box{margin-top:14px; padding:14px; border:1px solid #e5e5e5; border-radius:10px; background:#fafafa; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:13px; white-space:pre-wrap;}
    .hint{margin-top:14px; color:#444;}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>${esc(title)}</h1>
    <p>${esc(message)}</p>
  </div>
</body>
</html>`;
}

function setCookieHeadersForOAuth(state, verifier) {
  const common = "Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600";
  return [
    `__Host-g_state=${encodeURIComponent(state)}; ${common}`,
    `__Host-g_verifier=${encodeURIComponent(verifier)}; ${common}`,
  ];
}

function clearCookieHeadersForOAuth() {
  const common = "Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0";
  return [
    `__Host-g_state=; ${common}`,
    `__Host-g_verifier=; ${common}`,
  ];
}

function getRedirectUri(reqUrl, env) {
  // استخدم المتغير إذا موجود (أفضل — وأنت عندك GOOGLE_REDIRECT_URI ✅)
  if (env.GOOGLE_REDIRECT_URI && String(env.GOOGLE_REDIRECT_URI).trim()) {
    return String(env.GOOGLE_REDIRECT_URI).trim();
  }
  const u = new URL(reqUrl);
  return `${u.origin}/api2/google/callback`;
}

async function ensureSessionsInsert(env, token, email) {
  const hasSessions =
    (await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'"
    ).first());

  if (!hasSessions) throw new Error("SESSIONS_TABLE_MISSING");

  const info = await env.DB.prepare("PRAGMA table_info(sessions)").all();
  const cols = (info?.results || []).map(r => r.name);

  const hasToken = cols.includes("token");
  const hasEmail = cols.includes("email");
  const hasCreatedAt = cols.includes("created_at");

  if (!hasToken || !hasEmail) throw new Error("SESSIONS_SCHEMA_MISSING_TOKEN_OR_EMAIL");

  const now = new Date().toISOString();
  if (hasCreatedAt) {
    await env.DB.prepare(
      "INSERT INTO sessions (token, email, created_at) VALUES (?, ?, ?)"
    ).bind(token, email, now).run();
  } else {
    await env.DB.prepare(
      "INSERT INTO sessions (token, email) VALUES (?, ?)"
    ).bind(token, email).run();
  }
}

/* -------------------- /api2/google/start -------------------- */
async function handleStart({ request, env }) {
  if (!env.GOOGLE_CLIENT_ID) {
    return new Response(htmlMessage("رسالة", "نقص إعدادات Google (GOOGLE_CLIENT_ID)."), {
      status: 500,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  const redirectUri = getRedirectUri(request.url, env);

  // PKCE
  const state = randomB64Url(32);
  const verifier = randomB64Url(64);
  const challenge = await sha256B64Url(verifier);

  const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  auth.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
  auth.searchParams.set("redirect_uri", redirectUri);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("scope", "openid email profile");
  auth.searchParams.set("state", state);
  auth.searchParams.set("code_challenge", challenge);
  auth.searchParams.set("code_challenge_method", "S256");
  auth.searchParams.set("prompt", "select_account");

  const headers = new Headers();
  for (const c of setCookieHeadersForOAuth(state, verifier)) headers.append("Set-Cookie", c);
  headers.set("Location", auth.toString());

  return new Response(null, { status: 302, headers });
}

/* -------------------- /api2/google/callback -------------------- */
async function handleCallback({ request, env }) {
  const url = new URL(request.url);

  const error = url.searchParams.get("error");
  if (error) {
    return new Response(htmlMessage("رسالة", `تعذر تسجيل الدخول عبر Google: ${error}`), {
      status: 400,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) {
    return new Response(htmlMessage("رسالة", "بيانات الرجوع من Google ناقصة (code/state)."), {
      status: 400,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const savedState = cookies.get("__Host-g_state");
  const verifier = cookies.get("__Host-g_verifier");

  if (!savedState || !verifier || savedState !== state) {
    const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
    for (const c of clearCookieHeadersForOAuth()) headers.append("Set-Cookie", c);
    return new Response(htmlMessage("رسالة", "تعذر قراءة بيانات التحقق (state/verifier)."), {
      status: 400,
      headers,
    });
  }

  const redirectUri = getRedirectUri(request.url, env);

  // Exchange code -> token
  const tokenBody = new URLSearchParams();
  tokenBody.set("client_id", env.GOOGLE_CLIENT_ID || "");
  tokenBody.set("client_secret", env.GOOGLE_CLIENT_SECRET || ""); // هنا لازم يكون صحيح
  tokenBody.set("code", code);
  tokenBody.set("redirect_uri", redirectUri);
  tokenBody.set("grant_type", "authorization_code");
  tokenBody.set("code_verifier", verifier);

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenBody.toString(),
  });

  const tokenText = await tokenRes.text();
  let tokenJson = {};
  try { tokenJson = JSON.parse(tokenText); } catch {}

  if (!tokenRes.ok || !tokenJson.access_token) {
    const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
    for (const c of clearCookieHeadersForOAuth()) headers.append("Set-Cookie", c);

    const err = tokenJson.error || "UNKNOWN";
    const desc = tokenJson.error_description || tokenText || "";
    const debug = [
      `status: ${tokenRes.status}`,
      `error: ${err}`,
      `desc: ${desc}`,
      `redirect_uri_used: ${redirectUri}`,
      `client_id_tail: ${(env.GOOGLE_CLIENT_ID || "").slice(-10)}`
    ].join("\n");

    const page = `<!doctype html><html lang="ar" dir="rtl"><head>
      <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
      <title>رسالة</title>
      <style>
        body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Tahoma,Arial; margin:0; background:#fff; color:#111;}
        .wrap{padding:40px 18px; max-width:760px; margin:0 auto;}
        h1{font-size:22px; margin:0 0 12px;}
        p{font-size:17px; line-height:1.8; margin:0 0 12px;}
        .box{margin-top:14px; padding:14px; border:1px solid #e5e5e5; border-radius:10px; background:#fafafa; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:13px; white-space:pre-wrap;}
      </style>
    </head><body><div class="wrap">
      <h1>رسالة</h1>
      <p>فشل تبادل رمز Google. (token exchange)</p>
      <div class="box">${esc(debug)}</div>
      <p style="margin-top:14px;color:#444">
        إذا كانت <b>error</b> = <b>invalid_client</b> → مشكلة في GOOGLE_CLIENT_SECRET.<br/>
        إذا كانت <b>error</b> = <b>invalid_grant</b> → غالبًا verifier/redirect_uri غير مطابق أو الكود انتهى.<br/>
        إذا كانت <b>error</b> = <b>redirect_uri_mismatch</b> → تأكد redirect URI مطابق 100% في Google Console.
      </p>
    </div></body></html>`;

    return new Response(page, { status: 400, headers });
  }

  // Get user info
  const userRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${tokenJson.access_token}` },
  });
  const userJson = await userRes.json().catch(() => ({}));
  const email = userJson.email;

  if (!userRes.ok || !email) {
    const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
    for (const c of clearCookieHeadersForOAuth()) headers.append("Set-Cookie", c);
    return new Response(htmlMessage("رسالة", "فشل جلب بيانات المستخدم من Google."), {
      status: 400,
      headers,
    });
  }

  // Create session token
  const sessionToken = randomB64Url(32);

  try {
    await ensureSessionsInsert(env, sessionToken, email);
  } catch (e) {
    const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
    for (const c of clearCookieHeadersForOAuth()) headers.append("Set-Cookie", c);

    const msg =
      (e && e.message === "SESSIONS_TABLE_MISSING") ? "قاعدة البيانات ناقصها جدول sessions."
      : (e && e.message === "SESSIONS_SCHEMA_MISSING_TOKEN_OR_EMAIL") ? "جدول sessions ناقص أعمدة token/email."
      : "خطأ في إنشاء جلسة الدخول (sessions).";

    return new Response(htmlMessage("رسالة", msg), { status: 500, headers });
  }

  // Clear oauth cookies + Store token to localStorage + Redirect to /activate
  const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
  for (const c of clearCookieHeadersForOAuth()) headers.append("Set-Cookie", c);

  const html = `<!doctype html>
<html lang="ar" dir="rtl">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<title>جاري تسجيل الدخول…</title></head>
<body>
<script>
  try {
    localStorage.setItem('sandooq_token_v1', ${JSON.stringify(sessionToken)});
    localStorage.setItem('sandooq_email_v1', ${JSON.stringify(email)});
  } catch (e) {}
  location.replace('/activate');
</script>
</body>
</html>`;

  return new Response(html, { status: 200, headers });
}
