// functions/api/login.js
export async function onRequest(context) {
  const { request, env } = context;

  // ---------- CORS ----------
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  const allowOrigin = allowed.length
    ? (allowed.includes(origin) ? origin : allowed[0])
    : "*";

  const corsHeaders = {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
  };

  const json = (obj, status = 200) =>
    new Response(JSON.stringify(obj), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders },
    });

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  if (request.method === "GET") return json({ ok: true, version: "login-v9-jwt" });

  if (request.method !== "POST") return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  if (!env.DB) return json({ ok: false, error: "DB_NOT_BOUND" }, 500);
  if (!env.JWT_SECRET) return json({ ok: false, error: "JWT_SECRET_MISSING" }, 500);

  const db = env.DB;

  // ---------- Helpers ----------
  const PBKDF2_ITER = 100000;
  const enc = new TextEncoder();

  const toB64 = (bytesLike) => {
    const u8 = bytesLike instanceof ArrayBuffer ? new Uint8Array(bytesLike) : new Uint8Array(bytesLike);
    let s = "";
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  };

  const fromB64 = (b64) => {
    const bin = atob(b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  };

  const b64url = (bytesLike) =>
    toB64(bytesLike).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

  const ensureUsersTable = async () => {
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt_b64 TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);
  };

  const pbkdf2Hash = async (password, saltB64) => {
    const salt = fromB64(saltB64);
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
      keyMaterial,
      256
    );

    return toB64(bits);
  };

  const hmacSign = async (data, secret) => {
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
    return new Uint8Array(sig);
  };

  const signJWT = async (payloadObj) => {
    const header = { alg: "HS256", typ: "JWT" };
    const headerB64 = b64url(enc.encode(JSON.stringify(header)));
    const payloadB64 = b64url(enc.encode(JSON.stringify(payloadObj)));
    const toSign = `${headerB64}.${payloadB64}`;
    const sig = await hmacSign(toSign, env.JWT_SECRET);
    return `${toSign}.${b64url(sig)}`;
  };

  // ---------- Main ----------
  try {
    await ensureUsersTable();

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON", version: "login-v9-jwt" }, 400);

    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const deviceId =
      String(body.deviceId || "").trim() ||
      String(request.headers.get("X-Device-Id") || "").trim() ||
      null;

    if (!email || !password) {
      return json({ ok: false, error: "MISSING_FIELDS", version: "login-v9-jwt" }, 400);
    }

    const user = await db
      .prepare(`SELECT email, password_hash, salt_b64 FROM users WHERE email = ?`)
      .bind(email)
      .first();

    if (!user) {
      return json({ ok: false, error: "INVALID_CREDENTIALS", version: "login-v9-jwt" }, 401);
    }

    const computed = await pbkdf2Hash(password, user.salt_b64);
    if (computed !== user.password_hash) {
      return json({ ok: false, error: "INVALID_CREDENTIALS", version: "login-v9-jwt" }, 401);
    }

    const now = Math.floor(Date.now() / 1000);
    const exp = now + 60 * 60 * 24 * 30; // 30 days

    const token = await signJWT({
      sub: email,
      email,
      deviceId,
      iat: now,
      exp,
    });

    return json(
      {
        ok: true,
        version: "login-v9-jwt",
        email,
        token,
        expiresAt: new Date(exp * 1000).toISOString(),
        pbkdf2Iterations: PBKDF2_ITER,
      },
      200
    );
  } catch (e) {
    return json(
      {
        ok: false,
        error: "LOGIN_FAILED",
        version: "login-v9-jwt",
        message: String(e?.message || e),
      },
      500
    );
  }
}
