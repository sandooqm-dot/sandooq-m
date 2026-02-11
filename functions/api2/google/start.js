// functions/api2/google/start.js

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const clientId = String(env.GOOGLE_CLIENT_ID || "").trim();

  // ✅ sanitize redirect uri (remove spaces/newlines anywhere)
  const redirectUriRaw =
    env.GOOGLE_REDIRECT_URI || "https://horof.sandooq-games.com/api2/google/callback";
  const redirectUri = String(redirectUriRaw).replace(/\s+/g, "");

  if (!clientId) {
    return json({ ok: false, error: "MISSING_GOOGLE_CLIENT_ID" }, 500);
  }

  // PKCE
  const state = randomB64Url(32);
  const codeVerifier = randomB64Url(64);
  const codeChallenge = await sha256B64Url(codeVerifier);

  // Signed cookie using JWT_SECRET (HMAC-SHA256)
  const jwtSecret = String(env.JWT_SECRET || "").trim();
  if (!jwtSecret) {
    return json({ ok: false, error: "MISSING_JWT_SECRET" }, 500);
  }

  const cookieValue = await signCookie(jwtSecret, {
    state,
    codeVerifier,
    iat: Date.now(),
  });

  const scope = encodeURIComponent("openid email profile");
  const authUrl =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    `?client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&scope=${scope}` +
    `&state=${encodeURIComponent(state)}` +
    `&code_challenge=${encodeURIComponent(codeChallenge)}` +
    `&code_challenge_method=S256` +
    `&prompt=select_account`;

  const headers = new Headers();

  // ✅ مهم: نخليها SameSite=None عشان OAuth (أضمن مع سفاري)
  headers.set(
    "Set-Cookie",
    `__Host-sandooq_state_v1=${cookieValue}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=None`
  );

  const url = new URL(request.url);
  const wantsJson = url.searchParams.get("json") === "1";

  // لو تبغى JSON (للاختبار أو fetch)
  if (wantsJson) {
    headers.set("Content-Type", "application/json; charset=utf-8");
    return new Response(JSON.stringify({ ok: true, url: authUrl, redirectUri }), {
      status: 200,
      headers,
    });
  }

  // ✅ بدل 302: نرجّع صفحة 200 تثبت الكوكي ثم تحول
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(
    `<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
<title>توجيه إلى Google…</title>
</head>
<body style="font-family:system-ui,-apple-system;display:flex;min-height:100vh;align-items:center;justify-content:center;background:#fff;">
<div style="text-align:center;line-height:1.8;">
<div style="font-size:18px;">لحظة… نودّيك لتسجيل الدخول عبر Google</div>
<div style="font-size:14px;color:#666;">إذا ما تم التحويل تلقائيًا اضغط الزر</div>
<button id="go" style="margin-top:14px;padding:12px 16px;border:0;border-radius:10px;background:#1a73e8;color:#fff;font-size:16px;cursor:pointer;">
متابعة
</button>
</div>
<script>
  const url = ${JSON.stringify(authUrl)};
  // تحويل مباشر
  location.replace(url);
  // زر احتياطي
  document.getElementById('go').onclick = () => location.href = url;
</script>
</body>
</html>`,
    { status: 200, headers }
  );
}

// ---------- helpers ----------

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function randomB64Url(byteLen) {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return b64urlEncode(bytes);
}

async function sha256B64Url(input) {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return b64urlEncode(new Uint8Array(hash));
}

function b64urlEncode(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function signCookie(secret, payload) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const payloadJson = JSON.stringify(payload);
  const payloadB64 = b64urlEncode(new TextEncoder().encode(payloadJson));
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  const sigB64 = b64urlEncode(new Uint8Array(sig));

  return `${payloadB64}.${sigB64}`;
}
