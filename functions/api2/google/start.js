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
    if (!clientId) return new Response("GOOGLE_CLIENT_ID غير مضبوط", { status: 500 });

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
    // verifier لازم يكون 43-128 حرف -> 32 بايت = 43 حرف تقريبًا ✅
    const codeVerifier = randomB64url(32);
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
    const codeChallenge = b64url(digest);

    // ===== State (CSRF)
    const state = randomB64url(16);

    // نخزنهم في كوكيز (تروح مع تحويل Google ثم ترجع للـ callback)
    const maxAge = 10 * 60; // 10 دقائق
    const cookieBase =
      `Max-Age=${maxAge}; Path=/api2/google/callback; HttpOnly; Secure; SameSite=Lax`;

    const headers = new Headers();
    headers.append("Set-Cookie", `sandooq_g_state=${state}; ${cookieBase}`);
    headers.append("Set-Cookie", `sandooq_g_verifier=${codeVerifier}; ${cookieBase}`);
    headers.set("Cache-Control", "no-store");

    // ===== Google Auth URL
    const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    auth.searchParams.set("client_id", clientId);
    auth.searchParams.set("redirect_uri", redirectUri);
    auth.searchParams.set("response_type", "code");
    auth.searchParams.set("scope", "openid email profile");
    auth.searchParams.set("access_type", "online");
    auth.searchParams.set("prompt", "select_account");

    // PKCE params ✅
    auth.searchParams.set("code_challenge", codeChallenge);
    auth.searchParams.set("code_challenge_method", "S256");

    // state ✅
    auth.searchParams.set("state", state);

    headers.set("Location", auth.toString());

    return new Response(null, { status: 302, headers });
  } catch (e) {
    return new Response("start exception: " + String(e?.stack || e), { status: 500 });
  }
}
