// functions/_middleware.js
export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // فحص سريع
  if (path === "/__mw") {
    return new Response("mw-ok", {
      status: 200,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  }

  // اسمح للأصول الثابتة (بدون حماية)
  if (isStaticAsset(path)) return next();

  // اسمح لصفحات التفعيل
  if (path === "/activate" || path === "/activate.html" || path.startsWith("/activate/")) {
    return next();
  }

  // اسمح للـ APIs
  if (path.startsWith("/api2/") || path.startsWith("/api/")) {
    return next();
  }

  // أي شيء غير اللي فوق = محمي (يشمل / و /app و أي صفحة لعبة)
  // لازم: JWT_SECRET + DB
  if (!env?.JWT_SECRET) {
    return new Response("MISSING_JWT_SECRET", { status: 500 });
  }
  if (!env?.DB) {
    return new Response("DB_NOT_BOUND", { status: 500 });
  }

  const cookie = request.headers.get("Cookie") || "";
  const token = getCookie(cookie, "sandooq_token_v1");

  if (!token) {
    return redirectToActivate(url, path);
  }

  const payload = await verifyJwtHS256(env.JWT_SECRET, token);
  const email = String(payload?.email || "").trim().toLowerCase();

  if (!email) {
    return redirectToActivate(url, path, true);
  }

  // لازم يكون مُفعّل (موجود له سجل في activations)
  const act = await env.DB.prepare(
    `SELECT 1 FROM activations WHERE email = ? LIMIT 1`
  ).bind(email).first();

  if (!act) {
    return redirectToActivate(url, path);
  }

  return next();
}

/* ---------------- helpers ---------------- */

function isStaticAsset(path) {
  return /\.(png|jpg|jpeg|webp|svg|ico|css|js|mjs|map|json|txt|xml|otf|ttf|woff2?|mp3|mp4)$/i.test(path);
}

function redirectToActivate(url, nextPath, clearCookie = false) {
  const to = new URL("/activate", url.origin);
  if (nextPath && nextPath !== "/activate" && nextPath !== "/activate.html") {
    to.searchParams.set("next", nextPath);
  }

  const headers = new Headers({
    Location: to.toString(),
    "Cache-Control": "no-store",
  });

  if (clearCookie) {
    headers.append(
      "Set-Cookie",
      "sandooq_token_v1=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax"
    );
  }

  return new Response(null, { status: 302, headers });
}

function getCookie(cookieHeader, name) {
  const parts = cookieHeader.split(";").map((s) => s.trim());
  for (const p of parts) {
    if (!p) continue;
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    const k = p.slice(0, eq).trim();
    const v = p.slice(eq + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return "";
}

/* ---------- JWT verify (HS256) ---------- */

function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64Url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function strToBytes(s) {
  return new TextEncoder().encode(s);
}

function safeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

async function hmacSha256(secret, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    strToBytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return new Uint8Array(sig);
}

async function verifyJwtHS256(secret, token) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 3) return null;

    const [h, p, s] = parts;
    const toSign = `${h}.${p}`;

    const sigBytes = await hmacSha256(secret, strToBytes(toSign));
    const expected = bytesToBase64Url(sigBytes);

    if (!safeEqual(expected, s)) return null;

    const payloadJson = new TextDecoder().decode(base64UrlToBytes(p));
    const payload = JSON.parse(payloadJson);

    const now = Math.floor(Date.now() / 1000);
    if (!payload?.exp || now >= Number(payload.exp)) return null;

    return payload;
  } catch {
    return null;
  }
}

// functions/_middleware.js – إصدار 2 (JWT cookie + activations gate)
