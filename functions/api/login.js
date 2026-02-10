// /functions/api/login.js
export async function onRequest(context) {
  const { request, env } = context;
  const VERSION = "login-v10-rewrite";

  // --- CORS helpers ---
  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json(
      { ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION },
      405,
      cors
    );
  }

  // --- Validate DB binding ---
  if (!env || !env.DB) {
    return json(
      {
        ok: false,
        error: "DB_NOT_BOUND",
        version: VERSION,
        message:
          "env.DB is missing. Check Pages -> Settings -> Bindings -> D1 database name must be DB.",
      },
      500,
      cors
    );
  }

  // --- Parse body safely ---
  let body;
  try {
    body = await request.json();
  } catch {
    return json(
      { ok: false, error: "BAD_JSON", version: VERSION },
      400,
      cors
    );
  }

  const email = String(body?.email || "").trim().toLowerCase();
  const password = String(body?.password || "");
  const deviceId = String(body?.deviceId || "").trim();

  if (!email || !password) {
    return json(
      { ok: false, error: "MISSING_FIELDS", version: VERSION },
      400,
      cors
    );
  }

  // --- Fetch user ---
  let user;
  try {
    user = await env.DB.prepare(
      "SELECT email, provider, password_hash, salt_b64 FROM users WHERE email = ? LIMIT 1"
    )
      .bind(email)
      .first();
  } catch (e) {
    return json(
      { ok: false, error: "DB_QUERY_FAILED", version: VERSION, message: String(e?.message || e) },
      500,
      cors
    );
  }

  if (!user) {
    return json(
      { ok: false, error: "INVALID_CREDENTIALS", version: VERSION },
      401,
      cors
    );
  }

  if (user.provider && user.provider !== "email") {
    return json(
      { ok: false, error: "USE_PROVIDER_LOGIN", version: VERSION, provider: user.provider },
      401,
      cors
    );
  }

  const storedHash = String(user.password_hash || "");
  const saltB64 = String(user.salt_b64 || "");
  if (!storedHash || !saltB64) {
    return json(
      { ok: false, error: "BROKEN_USER_RECORD", version: VERSION },
      500,
      cors
    );
  }

  // --- Verify password (try both salt+pw and pw+salt, with base64/base64url normalization) ---
  const saltBytes = base64ToBytesFlexible(saltB64);
  const pwBytes = new TextEncoder().encode(password);

  const cand1 = await sha256Base64(concatBytes(saltBytes, pwBytes)); // salt + pw
  const cand2 = await sha256Base64(concatBytes(pwBytes, saltBytes)); // pw + salt
  const ok =
    normalizeHash(cand1) === normalizeHash(storedHash) ||
    normalizeHash(cand2) === normalizeHash(storedHash) ||
    normalizeHash(toBase64UrlNoPad(cand1)) === normalizeHash(storedHash) ||
    normalizeHash(toBase64UrlNoPad(cand2)) === normalizeHash(storedHash);

  if (!ok) {
    return json(
      { ok: false, error: "INVALID_CREDENTIALS", version: VERSION },
      401,
      cors
    );
  }

  // --- Upsert device (optional) ---
  const now = new Date().toISOString();
  if (deviceId) {
    try {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO user_devices (email, device_id, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?)"
      )
        .bind(email, deviceId, now, now)
        .run();

      await env.DB.prepare(
        "UPDATE user_devices SET last_seen_at = ? WHERE email = ? AND device_id = ?"
      )
        .bind(now, email, deviceId)
        .run();
    } catch {
      // device logging is non-blocking
    }
  }

  // --- Create session ---
  const token = randomToken();
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(); // 30 days

  try {
    await env.DB.prepare(
      "INSERT INTO sessions (token, email, created_at, expires_at) VALUES (?, ?, ?, ?)"
    )
      .bind(token, email, now, expiresAt)
      .run();
  } catch (e) {
    return json(
      { ok: false, error: "SESSION_CREATE_FAILED", version: VERSION, message: String(e?.message || e) },
      500,
      cors
    );
  }

  // Cookie (useful for browser)
  const cookie = buildCookie("session", token, {
    maxAge: 60 * 60 * 24 * 30,
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
  });

  const headers = new Headers(cors);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.append("Set-Cookie", cookie);

  return new Response(
    JSON.stringify({ ok: true, version: VERSION, email, token, expiresAt }),
    { status: 200, headers }
  );
}

/* ---------------- helpers ---------------- */

function json(obj, status, corsHeaders) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(obj), { status, headers });
}

function makeCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowedRaw = (env?.ALLOWED_ORIGINS || "").trim();
  let allowOrigin = "*";

  if (allowedRaw) {
    const allowed = allowedRaw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    if (allowed.includes("*")) {
      allowOrigin = "*";
    } else if (origin && allowed.includes(origin)) {
      allowOrigin = origin;
    } else {
      // fallback: first allowed origin (prevents wild access)
      allowOrigin = allowed[0] || "*";
    }
  } else if (origin) {
    // dev-friendly default if not configured
    allowOrigin = origin;
  }

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Vary": "Origin",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

function bytesToBase64Url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function toBase64UrlNoPad(b64) {
  return String(b64)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function normalizeHash(h) {
  return toBase64UrlNoPad(String(h || "").trim());
}

function base64ToBytesFlexible(b64) {
  let s = String(b64 || "").trim();
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function sha256Base64(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(digest);
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin); // standard base64 with padding
}

function buildCookie(name, value, opts = {}) {
  const parts = [`${name}=${value}`];
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.path) parts.push(`Path=${opts.path}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  return parts.join("; ");
}
