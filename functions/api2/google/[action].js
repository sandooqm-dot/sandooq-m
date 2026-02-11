// functions/api2/google/[action].js
export async function onRequest(context) {
  const { request, env, params } = context;
  const action = (params && params.action) ? String(params.action) : "";

  if (request.method !== "GET") return new Response("Method Not Allowed", { status: 405 });

  if (action === "start") return handleStart({ request, env });
  if (action === "callback") return handleCallback({ request, env });
  if (action === "debug") return handleDebug({ request, env });

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
  return String(s ?? "").replace(/[<>&"]/g, c => ({ "<":"&lt;", ">":"&gt;", "&":"&amp;", '"':"&quot;" }[c]));
}
function htmlPage(title, bodyHtml) {
  return `<!doctype html><html lang="ar" dir="rtl"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<title>${esc(title)}</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Tahoma,Arial;margin:0;background:#fff;color:#111}
.wrap{padding:40px 18px;max-width:820px;margin:0 auto}
h1{font-size:22px;margin:0 0 12px}
p{font-size:17px;line-height:1.8;margin:0 0 10px}
.box{margin-top:14px;padding:14px;border:1px solid #e5e5e5;border-radius:10px;background:#fafafa;
font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;white-space:pre-wrap}
</style></head><body><div class="wrap"><h1>${esc(title)}</h1>${bodyHtml}</div></body></html>`;
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
  if (env.GOOGLE_REDIRECT_URI && String(env.GOOGLE_REDIRECT_URI).trim()) {
    return String(env.GOOGLE_REDIRECT_URI).trim();
  }
  const u = new URL(reqUrl);
  return `${u.origin}/api2/google/callback`;
}
async function ensureSessionsInsert(env, token, email) {
  const hasSessions =
    (await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'").first());
  if (!hasSessions) throw new Error("SESSIONS_TABLE_MISSING");

  const info = await env.DB.prepare("PRAGMA table_info(sessions)").all();
  const cols = (info?.results || []).map(r => r.name);
  if (!cols.includes("token") || !cols.includes("email")) throw new Error("SESSIONS_SCHEMA_MISSING_TOKEN_OR_EMAIL");

  const now = new Date().toISOString();
  if (cols.includes("created_at")) {
    await env.DB.prepare("INSERT INTO sessions (token, email, created_at) VALUES (?, ?, ?)")
      .bind(token, email, now).run();
  } else {
    await env.DB.prepare("INSERT INTO sessions (token, email) VALUES (?, ?)")
      .bind(token, email).run();
  }
}

/* -------------------- /api2/google/debug -------------------- */
async function handleDebug({ request, env }) {
  const redirectUri = getRedirectUri(request.url, env);
  const cid = (env.GOOGLE_CLIENT_ID || "").trim();
  const csec = (env.GOOGLE_CLIENT_SECRET || "").trim();

  const box = [
    `origin: ${new URL(request.url).origin}`,
    `redirect_uri_used: ${redirectUri}`,
    `client_id_tail: ${cid ? cid.slice(-18) : "(EMPTY)"}`,
    `client_id_format_ok: ${cid.endsWith(".apps.googleusercontent.com") ? "YES" : "NO"}`,
    `client_secret_present: ${csec ? "YES" : "NO"}`,
    `client_secret_len: ${csec ? String(csec.length) : "0"}`,
  ].join("\n");

  return new Response(
    htmlPage("Google OAuth Debug", `<p>هذه الصفحة فقط للتأكد أن السيرفر يقرأ القيم الصحيحة (بدون عرض أسرار).</p><div class="box">${esc(box)}</div>`),
    { status: 200, headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

/* -------------------- /api2/google/start -------------------- */
async function handleStart({ request, env }) {
  if (!env.GOOGLE_CLIENT_ID) {
    return new Response(htmlPage("رسالة", `<p>نقص إعدادات Google (GOOGLE_CLIENT_ID).</p>`), {
      status: 500, headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  const redirectUri = getRedirectUri(request.url, env);

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
    return new Response(htmlPage("رسالة", `<p>تعذر تسجيل الدخول عبر Google: ${esc(error)}</p>`), {
      status: 400, headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) {
    return new Response(htmlPage("رسالة", `<p>بيانات الرجوع من Google ناقصة (code/state).</p>`), {
      status: 400, headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const savedState = cookies.get("__Host-g_state");
  const verifier = cookies.get("__Host-g_verifier");

  if (!savedState || !verifier || savedState !== state) {
    const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
    for (const c of clearCookieHeadersForOAuth()) headers.append("Set-Cookie", c);
    return new Response(htmlPage("رسالة", `<p>تعذر قراءة بيانات التحقق (state/verifier).</p>`), {
      status: 400, headers,
    });
  }

  const redirectUri = getRedirectUri(request.url, env);

  const tokenBody = new URLSearchParams();
  tokenBody.set("client_id", (env.GOOGLE_CLIENT_ID || "").trim());
  tokenBody.set("client_secret", (env.GOOGLE_CLIENT_SECRET || "").trim());
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

    const box = [
      `status: ${tokenRes.status}`,
      `error: ${tokenJson.error || "UNKNOWN"}`,
      `desc: ${tokenJson.error_description || tokenText || ""}`,
      `redirect_uri_used: ${redirectUri}`,
      `client_id_tail: ${((env.GOOGLE_CLIENT_ID || "").trim()).slice(-18)}`
    ].join("\n");

    return new Response(
      htmlPage("رسالة", `<p>فشل تبادل رمز Google. (token exchange)</p><div class="box">${esc(box)}</div>`),
      { status: 400, headers }
    );
  }

  const userRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${tokenJson.access_token}` },
  });
  const userJson = await userRes.json().catch(() => ({}));
  const email = userJson.email;

  if (!userRes.ok || !email) {
    const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
    for (const c of clearCookieHeadersForOAuth()) headers.append("Set-Cookie", c);
    return new Response(htmlPage("رسالة", `<p>فشل جلب بيانات المستخدم من Google.</p>`), {
      status: 400, headers,
    });
  }

  const sessionToken = randomB64Url(32);

  try {
    await ensureSessionsInsert(env, sessionToken, email);
  } catch (e) {
    const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
    for (const c of clearCookieHeadersForOAuth()) headers.append("Set-Cookie", c);
    return new Response(htmlPage("رسالة", `<p>خطأ في إنشاء جلسة الدخول (sessions).</p>`), {
      status: 500, headers,
    });
  }

  const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
  for (const c of clearCookieHeadersForOAuth()) headers.append("Set-Cookie", c);

  const html = `<!doctype html><html lang="ar" dir="rtl"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<title>جاري تسجيل الدخول…</title></head><body>
<script>
  try {
    localStorage.setItem('sandooq_token_v1', ${JSON.stringify(sessionToken)});
    localStorage.setItem('sandooq_email_v1', ${JSON.stringify(email)});
  } catch (e) {}
  location.replace('/activate');
</script>
</body></html>`;

  return new Response(html, { status: 200, headers });
}
