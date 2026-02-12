export async function onRequestGet({ request, env }) {
  try {
    const url = new URL(request.url);

    const clientId = String(env.GOOGLE_CLIENT_ID || "").trim();
    const redirectUri =
      (env.GOOGLE_REDIRECT_URI && String(env.GOOGLE_REDIRECT_URI).trim()) ||
      `${url.origin}/api2/google/callback`;

    if (!clientId) {
      return text("GOOGLE_CLIENT_ID غير موجود في Cloudflare.", 500);
    }

    // PKCE: generate code_verifier + code_challenge
    const verifier = base64urlRandom(64); // 64 bytes -> safe length
    const challenge = await pkceChallengeS256(verifier);

    // state for CSRF protection
    const state = crypto.randomUUID();

    const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    authUrl.searchParams.set("client_id", clientId);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("scope", "openid email profile");
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("code_challenge", challenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    authUrl.searchParams.set("prompt", "select_account");

    // optional but helpful sometimes
    authUrl.searchParams.set("access_type", "offline");

    // Cookies must be sent back on callback
    const cookie = [
      cookieSet("g_state", state, { httpOnly: true, maxAge: 600 }),
      cookieSet("g_verifier", verifier, { httpOnly: true, maxAge: 600 }),
    ].join(", ");

    return new Response(null, {
      status: 302,
      headers: {
        Location: authUrl.toString(),
        "Cache-Control": "no-store",
        "Set-Cookie": cookie,
      },
    });
  } catch (e) {
    return text("خطأ غير متوقع في /api2/google/start", 500);
  }
}

function text(msg, status = 200) {
  return new Response(String(msg), {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

// ---- helpers ----
function cookieSet(name, value, { httpOnly = true, maxAge = 600 } = {}) {
  // SameSite=Lax يسمح بإرسال الكوكيز عند الرجوع من Google (top-level navigation)
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
  ];
  if (httpOnly) parts.push("HttpOnly");
  return parts.join("; ");
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

async function pkceChallengeS256(verifier) {
  const enc = new TextEncoder();
  const data = enc.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64url(new Uint8Array(digest));
}
