// functions/api2/google/callback.js
export async function onRequestGet(context) {
  const { request, env } = context;

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const err = url.searchParams.get("error");

  const redirectUri =
    (env.GOOGLE_REDIRECT_URI || "").trim() ||
    "https://horof.sandooq-games.com/api2/google/callback";

  // 1) Basic checks
  if (err) return htmlPage(`فشل تسجيل الدخول عبر Google: ${escapeHtml(err)}`, 400);
  if (!code || !state) return htmlPage("طلب غير صالح (code/state ناقص).", 400);

  if (!env.DB) return htmlPage("DB غير مربوط في Cloudflare (Binding name لازم يكون DB).", 500);

  const clientId = (env.GOOGLE_CLIENT_ID || "").trim();
  const clientSecret = (env.GOOGLE_CLIENT_SECRET || "").trim();
  if (!clientId) return htmlPage("ناقص GOOGLE_CLIENT_ID في Secrets.", 500);
  if (!clientSecret) return htmlPage("ناقص GOOGLE_CLIENT_SECRET في Secrets.", 500);

  const jwtSecret = (env.JWT_SECRET || "").trim();
  if (!jwtSecret) return htmlPage("ناقص JWT_SECRET في Secrets.", 500);

  // 2) Read state cookie (created by /api2/google/start)
  const cookieToken = getCookie(request.headers.get("Cookie") || "", "__Host-sandooq_state_v1");
  if (!cookieToken) return htmlPage("انتهت الجلسة/الكوكي غير موجود. ارجع واضغط دخول بجوجل من جديد.", 400);

  // Try verify HS256 JWT (then fallback to decode payload only if needed)
  let stPayload = verifyJwtHS256(cookieToken, jwtSecret);
  if (!stPayload) stPayload = decodeJwtPayload(cookieToken);

  if (!stPayload || !stPayload.state || !stPayload.codeVerifier) {
    return htmlPage("تعذر قراءة بيانات التحقق (state/verifier).", 400);
  }

  if (stPayload.state !== state) {
    return htmlPage("state غير متطابق. ارجع واضغط دخول بجوجل من جديد.", 400);
  }

  // Optional: expiry 10 minutes
  if (stPayload.iat && Date.now() - Number(stPayload.iat) > 10 * 60 * 1000) {
    return htmlPage("انتهت صلاحية محاولة تسجيل الدخول. ارجع وجرب مرة ثانية.", 400);
  }

  // 3) Exchange code -> tokens
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
      code_verifier: stPayload.codeVerifier,
    }),
  });

  const tokenJson = await tokenRes.json().catch(() => null);
  if (!tokenRes.ok || !tokenJson?.id_token) {
    return htmlPage(
      `فشل تبادل الكود مع Google.<br><pre>${escapeHtml(JSON.stringify(tokenJson || {}, null, 2))}</pre>`,
      400
    );
  }

  const idToken = tokenJson.id_token;

  // 4) Validate id_token via tokeninfo
  const infoRes = await fetch(
    "https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(idToken)
  );
  const info = await infoRes.json().catch(() => null);

  if (!infoRes.ok || !info?.email) {
    return htmlPage(
      `فشل التحقق من Google token.<br><pre>${escapeHtml(JSON.stringify(info || {}, null, 2))}</pre>`,
      400
    );
  }

  if (String(info.aud || "") !== clientId) {
    return htmlPage("aud غير مطابق لِـ GOOGLE_CLIENT_ID. (تأكد تستخدم Client ID الصحيح)", 400);
  }

  const email = String(info.email).trim().toLowerCase();
  const emailVerified = String(info.email_verified || "") === "true" || info.email_verified === true;
  if (!emailVerified) return htmlPage("بريد Google غير موثّق (email_verified=false).", 403);

  // 5) Upsert user + create session
  try {
    await env.DB.prepare(
      `
      INSERT INTO users (email, password_hash, salt_b64, verified, created_at)
      VALUES (?1, '', '', 1, datetime('now'))
      ON CONFLICT(email) DO UPDATE SET verified=1
    `
    )
      .bind(email)
      .run();

    const sessionToken = randomHex(32);

    await env.DB.prepare(
      `INSERT INTO sessions (token, email, created_at) VALUES (?1, ?2, datetime('now'))`
    )
      .bind(sessionToken, email)
      .run();

    // Clear state cookie + set localStorage token then go /activate
    const headers = new Headers();
    headers.set("Cache-Control", "no-store");
    headers.append(
      "Set-Cookie",
      "__Host-sandooq_state_v1=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
    );

    const page = `<!doctype html>
<html lang="ar" dir="rtl">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>تم تسجيل الدخول</title></head>
<body style="font-family:system-ui;text-align:center;padding:32px">
<p>تم تسجيل الدخول عبر Google…</p>
<script>
try { localStorage.setItem('sandooq_token_v1', ${JSON.stringify(sessionToken)}); } catch(e) {}
location.replace('/activate');
</script>
</body></html>`;

    return new Response(page, { status: 200, headers });
  } catch (e) {
    return htmlPage("خطأ قاعدة البيانات: " + escapeHtml(String(e?.message || e)), 500);
  }
}

/* ---------------- helpers ---------------- */

function htmlPage(msg, status = 200) {
  const body = `<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <body style="font-family:system-ui;padding:24px">
  <h3>رسالة</h3><div>${msg}</div></body></html>`;
  return new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
}

function getCookie(cookieHeader, name) {
  const parts = cookieHeader.split(";").map((p) => p.trim());
  for (const p of parts) {
    if (p.startsWith(name + "=")) return p.slice(name.length + 1);
  }
  return "";
}

function base64urlDecodeToString(input) {
  input = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = input.length % 4;
  if (pad) input += "=".repeat(4 - pad);
  const bytes = Uint8Array.from(atob(input), (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function base64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeJwtPayload(token) {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    return JSON.parse(base64urlDecodeToString(parts[1]));
  } catch {
    return null;
  }
}

async function hmacSha256(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return new Uint8Array(sig);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
}

function verifyJwtHS256(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;
    const data = `${h}.${p}`;
    return (async () => {
      const sig = await hmacSha256(secret, data);
      const sigB64u = base64urlEncode(sig);
      if (!timingSafeEqual(sigB64u, s)) return null;
      const payload = JSON.parse(base64urlDecodeToString(p));
      return payload;
    })();
  } catch {
    return null;
  }
}

function randomHex(bytesLen = 32) {
  const bytes = new Uint8Array(bytesLen);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
