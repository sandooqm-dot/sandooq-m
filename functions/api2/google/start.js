export async function onRequest(context) {
  const { request, env } = context;

  try {
    const url = new URL(request.url);
    const origin = url.origin;

    const clientId = String(env.GOOGLE_CLIENT_ID || "").trim();
    if (!clientId) {
      return new Response("GOOGLE_CLIENT_ID غير مضبوط", { status: 500 });
    }

    const redirectUri = `${origin}/api2/google/callback`;

    const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    auth.searchParams.set("client_id", clientId);
    auth.searchParams.set("redirect_uri", redirectUri);
    auth.searchParams.set("response_type", "code");
    auth.searchParams.set("scope", "openid email profile");
    auth.searchParams.set("access_type", "online");
    auth.searchParams.set("prompt", "select_account");

    // ✅ مهم: لا نرسل code_challenge نهائيًا (يعني لا PKCE)
    // وبالتالي callback ما يحتاج code_verifier وبيختفي الخطأ.

    return new Response(null, {
      status: 302,
      headers: {
        Location: auth.toString(),
        "Cache-Control": "no-store",
      },
    });
  } catch (e) {
    return new Response("start exception: " + String(e?.stack || e), { status: 500 });
  }
}
