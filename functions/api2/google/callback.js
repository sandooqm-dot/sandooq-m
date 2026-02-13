// functions/api2/google/callback.js

export async function onRequest(context) {
  const { request, env } = context;

  try {
    if (!env?.DB) {
      return new Response("DB_NOT_BOUND", { status: 500 });
    }

    const url = new URL(request.url);
    const origin = url.origin;

    const err = url.searchParams.get("error");
    if (err) {
      const desc = url.searchParams.get("error_description") || "";
      return new Response(`Google error: ${err}\n${desc}`, { status: 400 });
    }

    const code = url.searchParams.get("code");
    const stateQ = url.searchParams.get("state") || "";
    if (!code) {
      return new Response("بيانات الرجوع من Google ناقصة (code).", { status: 400 });
    }

    const clientId = String(env.GOOGLE_CLIENT_ID || "").trim();
    const clientSecret = String(env.GOOGLE_CLIENT_SECRET || "").trim();
    if (!clientId || !clientSecret) {
      return new Response("GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET غير مضبوطين.", { status: 500 });
    }

    // ✅ نفس منطق start.js (لو عندك GOOGLE_REDIRECT_URI استخدمه)
    const redirectUriEnv = String(env.GOOGLE_REDIRECT_URI || "").trim();
    const redirectUri = redirectUriEnv || `${origin}/api2/google/callback`;

    // ====== PKCE: اقرأ من الكوكيز
    const stateC = getCookie(request, "sandooq_g_state");
    const verifier = getCookie(request, "sandooq_g_verifier");

    // لازم state يطابق (حماية) + verifier موجود (عشان PKCE)
    if (!stateQ || !stateC || stateQ !== stateC) {
      return new Response(
        "Google callback: state غير صحيح/مفقود. ارجع وسوّ تسجيل الدخول من جديد.",
        { status: 400 }
      );
    }
    if (!verifier) {
      return new Response(
        "Google callback: Missing code verifier. ارجع وابدأ تسجيل الدخول من جديد.",
        { status: 400 }
      );
    }

    // 1) Exchange code -> tokens (PKCE ✅)
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
        code_verifier: verifier, // ✅ PKCE verifier
      }),
    });

    const tokenJson = await tokenRes.json().catch(() => ({}));

    if (!tokenRes.ok) {
      const msg =
        `فشل تبادل رمز (token exchange) من Google.\n` +
        `status: ${tokenRes.status}\n` +
        `error: ${tokenJson.error || "unknown"}\n` +
        `desc: ${tokenJson.error_description || ""}\n` +
        `redirect_uri_used: ${redirectUri}`;
      return new Response(msg, { status: 400 });
    }

    const idToken = tokenJson.id_token || "";
    const accessToken = tokenJson.access_token || "";

    // 2) Extract email
    let email = "";
    let emailVerified = true; // Google login = verified عملياً
    let googleSub = "";

    // Try decode id_token payload (بدون تحقق توقيع)
    if (idToken && idToken.split(".").length >= 2) {
      const payload = safeJsonParse(b64urlDecode(idToken.split(".")[1]));
      email = String(payload?.email || "");
      googleSub = String(payload?.sub || "");
      if (typeof payload?.email_verified === "boolean") emailVerified = payload.email_verified;
    }

    // Fallback to userinfo
    if (!email && accessToken) {
      const uiRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const ui = await uiRes.json().catch(() => ({}));
      email = String(ui?.email || "");
      googleSub = String(ui?.sub || googleSub || "");
      if (typeof ui?.email_verified === "boolean") emailVerified = ui.email_verified;
      if (typeof ui?.verified_email === "boolean") emailVerified = ui.verified_email;
    }

    email = (email || "").trim().toLowerCase();
    if (!email) {
      return new Response("لم نتمكن من استخراج البريد من Google.", { status: 400 });
    }

    // 3) Upsert user safely حسب أعمدة جدول users عندك
    await upsertUser(env.DB, {
      email,
      verified: emailVerified ? 1 : 1,
      provider: "google",
      google_sub: googleSub || "",
    });

    // 4) Create session token in sessions table
    const sessionToken = makeToken(32);
    await insertSession(env.DB, sessionToken, email);

    // 5) Redirect back to activate (مثل ما هو عندك عشان ما نكسر activate.html)
    const dest = `${origin}/activate?token=${encodeURIComponent(sessionToken)}`;

    // ✅ امسح كوكيز PKCE بعد الاستخدام + زرع كوكيز الجلسة
    const headers = new Headers();
    headers.set("Location", dest);
    headers.set("Cache-Control", "no-store");

    const maxAge = 30 * 24 * 60 * 60; // 30 يوم
    headers.append(
      "Set-Cookie",
      `sandooq_token_v1=${encodeURIComponent(sessionToken)}; Max-Age=${maxAge}; Path=/; Secure; SameSite=Lax; HttpOnly`
    );
    headers.append(
      "Set-Cookie",
      `sandooq_session_v1=${encodeURIComponent(sessionToken)}; Max-Age=${maxAge}; Path=/; Secure; SameSite=Lax; HttpOnly`
    );

    headers.append(
      "Set-Cookie",
      `sandooq_g_state=; Max-Age=0; Path=/api2/google/callback; HttpOnly; Secure; SameSite=Lax`
    );
    headers.append(
      "Set-Cookie",
      `sandooq_g_verifier=; Max-Age=0; Path=/api2/google/callback; HttpOnly; Secure; SameSite=Lax`
    );

    return new Response(null, { status: 302, headers });

  } catch (e) {
    const msg = `Worker exception in google/callback\n${String(e?.stack || e)}`;
    return new Response(msg, { status: 500 });
  }
}

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  const parts = raw.split(";").map(s => s.trim()).filter(Boolean);
  for (const p of parts) {
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    const k = p.slice(0, eq).trim();
    const v = p.slice(eq + 1);
    if (k === name) return decodeURIComponent(v);
  }
  return "";
}

function safeJsonParse(s) {
  try { return JSON.parse(s); } catch { return null; }
}

function b64urlDecode(s) {
  s = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  let out = "";
  for (let i = 0; i < bin.length; i++) out += bin.charCodeAt(i) < 128 ? bin[i] : String.fromCharCode(bin.charCodeAt(i));
  return out;
}

function makeToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  let s = btoa(String.fromCharCode(...arr)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return s;
}

async function getTableInfo(db, table) {
  const r = await db.prepare(`PRAGMA table_info(${table})`).all();
  return (r?.results || []);
}

function defaultForType(type) {
  const t = String(type || "").toUpperCase();
  if (t.includes("INT")) return 0;
  if (t.includes("REAL") || t.includes("FLOAT") || t.includes("DOUBLE")) return 0;
  return "";
}

async function upsertUser(db, data) {
  const info = await getTableInfo(db, "users");
  const cols = new Map(info.map(x => [x.name, x]));
  if (!cols.has("email")) {
    throw new Error("users table must have email column");
  }

  const now = new Date().toISOString();

  const values = new Map();
  values.set("email", data.email);

  if (cols.has("verified")) values.set("verified", data.verified ?? 1);
  if (cols.has("provider")) values.set("provider", data.provider || "google");
  if (cols.has("google_sub")) values.set("google_sub", data.google_sub || "");
  if (cols.has("created_at")) values.set("created_at", now);
  if (cols.has("updated_at")) values.set("updated_at", now);
  if (cols.has("last_login_at")) values.set("last_login_at", now);

  const pwCandidates = ["password_hash", "pass_hash", "pw_hash", "hash"];
  for (const c of pwCandidates) {
    if (cols.has(c) && !values.has(c)) values.set(c, "GOOGLE");
  }
  if (cols.has("salt_b64") && !values.has("salt_b64")) values.set("salt_b64", "");

  for (const [name, meta] of cols.entries()) {
    if (meta.pk === 1) continue;
    if (values.has(name)) continue;
    if (meta.notnull === 1 && meta.dflt_value == null) {
      values.set(name, defaultForType(meta.type));
    }
  }

  const insertCols = Array.from(values.keys());
  const insertQs = insertCols.map(() => "?").join(",");
  const insertSql = `INSERT OR IGNORE INTO users (${insertCols.join(",")}) VALUES (${insertQs})`;
  await db.prepare(insertSql).bind(...insertCols.map(c => values.get(c))).run();

  const set = [];
  const bind = [];
  if (cols.has("verified")) { set.push("verified=?"); bind.push(data.verified ?? 1); }
  if (cols.has("provider")) { set.push("provider=?"); bind.push(data.provider || "google"); }
  if (cols.has("google_sub")) { set.push("google_sub=?"); bind.push(data.google_sub || ""); }
  if (cols.has("updated_at")) { set.push("updated_at=?"); bind.push(now); }
  if (cols.has("last_login_at")) { set.push("last_login_at=?"); bind.push(now); }

  if (set.length) {
    const updSql = `UPDATE users SET ${set.join(",")} WHERE email=?`;
    bind.push(data.email);
    await db.prepare(updSql).bind(...bind).run();
  }
}

async function insertSession(db, token, email) {
  const info = await getTableInfo(db, "sessions");
  const colNames = new Set(info.map(x => x.name));

  const now = new Date().toISOString();

  const cols = [];
  const vals = [];
  const bind = [];

  function add(name, value) {
    if (colNames.has(name)) {
      cols.push(name);
      vals.push("?");
      bind.push(value);
    }
  }

  add("token", token);

  // ✅✅ FIX: خزّن الإيميل في العمود الموجود فعلاً
  if (colNames.has("email")) add("email", email);
  else if (colNames.has("user_email")) add("user_email", email);
  else if (colNames.has("used_by_email")) add("used_by_email", email);

  add("created_at", now);

  for (const c of info) {
    if (c.pk === 1) continue;
    if (cols.includes(c.name)) continue;
    if (c.notnull === 1 && c.dflt_value == null) {
      cols.push(c.name);
      vals.push("?");
      bind.push(defaultForType(c.type));
    }
  }

  const sql = `INSERT INTO sessions (${cols.join(",")}) VALUES (${vals.join(",")})`;
  await db.prepare(sql).bind(...bind).run();
}

/*
google/callback.js – إصدار 3 (fix sessions email column + sets sandooq_token_v1 & sandooq_session_v1 cookies)
*/
