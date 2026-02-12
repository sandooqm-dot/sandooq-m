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
    if (!code) {
      return new Response("بيانات الرجوع من Google ناقصة (code).", { status: 400 });
    }

    const clientId = String(env.GOOGLE_CLIENT_ID || "").trim();
    const clientSecret = String(env.GOOGLE_CLIENT_SECRET || "").trim();
    if (!clientId || !clientSecret) {
      return new Response("GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET غير مضبوطين.", { status: 500 });
    }

    const redirectUri = `${origin}/api2/google/callback`;

    // 1) Exchange code -> tokens (Server-side, no PKCE assumption here)
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
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

    // Try decode id_token payload (without signature verify – acceptable for our use here)
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

    // 5) Redirect back to activate with token in URL (front will capture & store)
    const dest = `${origin}/activate?token=${encodeURIComponent(sessionToken)}`;
    return Response.redirect(dest, 302);

  } catch (e) {
    const msg = `Worker exception in google/callback\n${String(e?.stack || e)}`;
    return new Response(msg, { status: 500 });
  }
}

function safeJsonParse(s) {
  try { return JSON.parse(s); } catch { return null; }
}

function b64urlDecode(s) {
  // base64url -> base64
  s = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  // atob
  const bin = atob(s);
  let out = "";
  for (let i = 0; i < bin.length; i++) out += bin.charCodeAt(i) < 128 ? bin[i] : String.fromCharCode(bin.charCodeAt(i));
  return out;
}

function makeToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  // base64url
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
  // TEXT, BLOB, etc
  return "";
}

async function upsertUser(db, data) {
  const info = await getTableInfo(db, "users");
  const cols = new Map(info.map(x => [x.name, x]));
  if (!cols.has("email")) {
    throw new Error("users table must have email column");
  }

  const now = new Date().toISOString();

  // Build insert values with required NOT NULL cols
  const values = new Map();
  values.set("email", data.email);

  // Common optional columns
  if (cols.has("verified")) values.set("verified", data.verified ?? 1);
  if (cols.has("provider")) values.set("provider", data.provider || "google");
  if (cols.has("google_sub")) values.set("google_sub", data.google_sub || "");
  if (cols.has("created_at")) values.set("created_at", now);
  if (cols.has("updated_at")) values.set("updated_at", now);
  if (cols.has("last_login_at")) values.set("last_login_at", now);

  // If password columns exist & may be NOT NULL, set safe dummy values
  const pwCandidates = ["password_hash", "pass_hash", "pw_hash", "hash"];
  for (const c of pwCandidates) {
    if (cols.has(c) && !values.has(c)) values.set(c, "GOOGLE");
  }
  if (cols.has("salt_b64") && !values.has("salt_b64")) values.set("salt_b64", "");

  // Satisfy any NOT NULL cols without default (excluding PK)
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

  // Update existing row with key fields (if columns exist)
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

  // default minimal
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
  add("email", email);
  add("created_at", now);

  // satisfy required NOT NULL cols without default if any
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
