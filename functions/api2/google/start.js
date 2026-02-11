// functions/api2/google/start.js
export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const clientId = env.GOOGLE_CLIENT_ID;
  const redirectUri =
    env.GOOGLE_REDIRECT_URI || "https://horof.sandooq-games.com/api2/google/callback";

  if (!clientId) {
    return json({ ok: false, error: "MISSING_GOOGLE_CLIENT_ID" }, 500);
  }

  // PKCE
  const state = randomB64Url(32);
  const codeVerifier = randomB64Url(64);
  const codeChallenge = await sha256B64Url(codeVerifier);

  // Signed cookie (state + verifier) using JWT_SECRET (HMAC-SHA256)
  const jwtSecret = env.JWT_SECRET;
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
  headers.set(
    "Set-Cookie",
    `__Host-sandooq_gstate_v1=${cookieValue}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`
  );

  // If user wants JSON, allow ?json=1
  const url = new URL(request.url);
  const wantsJson = url.searchParams.get("json") === "1";

  if (wantsJson) {
    headers.set("Content-Type", "application/json; charset=utf-8");
    return new Response(JSON.stringify({ ok: true, url: authUrl }), { status: 200, headers });
  }

  headers.set("Location", authUrl);
  return new Response(null, { status: 302, headers });
}

// ---------------- helpers ----------------

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function randomB64Url(byteLen) {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

async function sha256B64Url(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return base64Url(new Uint8Array(hash));
}

function base64Url(u8) {
  // btoa expects binary string
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  const b64 = btoa(s);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function signCookie(secret, payloadObj) {
  const payload = JSON.stringify(payloadObj);
  const payloadB64 = base64Url(new TextEncoder().encode(payload));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  const sigB64 = base64Url(new Uint8Array(sigBuf));

  return `${payloadB64}.${sigB64}`;
}
