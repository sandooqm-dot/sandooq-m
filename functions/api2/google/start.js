// functions/api2/google/start.js
// Google OAuth Start (PKCE) - writes cookie reliably for Safari/iOS
export async function onRequestGet({ request, env }) {
  try {
    const url = new URL(request.url);

    const clientId = env.GOOGLE_CLIENT_ID;
    const redirectUri = env.GOOGLE_REDIRECT_URI; // مثال: https://horof.sandooq-games.com/api2/google/callback

    if (!clientId || !redirectUri) {
      return json({ ok: false, error: "MISSING_GOOGLE_ENV" }, 500);
    }

    const state = base64url(randomBytes(24));
    const verifier = base64url(randomBytes(32));
    const challenge = await pkceChallenge(verifier);

    // نخزن state + verifier في كوكي (10 دقائق)
    const payload = base64url(
      new TextEncoder().encode(
        JSON.stringify({ state, verifier, ts: Date.now() })
      )
    );

    const cookieName = "g_oauth_v1";

    // مهم جداً: SameSite=Lax عشان ينرسل في الرجعة من Google على Safari
    // Path=/ عشان يكون متاح للـ callback
    // Max-Age=600 (10 دقائق)
    const setCookie =
      `${cookieName}=${payload}; ` +
      `Max-Age=600; Path=/; HttpOnly; Secure; SameSite=Lax`;

    // بناء رابط جوجل
    const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    authUrl.searchParams.set("client_id", clientId);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("scope", "openid email profile");
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("code_challenge", challenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    authUrl.searchParams.set("prompt", "select_account");

    // إذا طلبت JSON
    const wantJson =
      url.searchParams.get("json") === "1" ||
      (request.headers.get("accept") || "").includes("application/json");

    if (wantJson) {
      return new Response(
        JSON.stringify({
          ok: true,
          url: authUrl.toString(),
          redirectUri,
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
            "set-cookie": setCookie,
          },
        }
      );
    }

    // الأفضل: Redirect مباشر (يضمن حفظ الكوكي)
    return new Response(null, {
      status: 302,
      headers: {
        location: authUrl.toString(),
        "cache-control": "no-store",
        "set-cookie": setCookie,
      },
    });
  } catch (e) {
    return json({ ok: false, error: "START_ERROR", details: String(e) }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function randomBytes(len) {
  const a = new Uint8Array(len);
  crypto.getRandomValues(a);
  return a;
}

function base64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  const b64 = btoa(str);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function pkceChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64url(new Uint8Array(digest));
}
