// functions/api2/google/callback.js
export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const qp = url.searchParams;

  const errorFromGoogle = qp.get("error");
  const code = qp.get("code");
  const state = qp.get("state");

  // Helpers
  const html = (title, body) =>
    new Response(
      `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <title>${escapeHtml(title)}</title>
      <style>
        body{font-family:system-ui,-apple-system,Segoe UI,Roboto; padding:24px; line-height:1.7}
        .box{border:1px solid #ddd;border-radius:12px;padding:16px;max-width:720px}
        code,pre{background:#f7f7f7;border-radius:10px;padding:10px;display:block;overflow:auto}
        a{color:#1565c0}
      </style></head><body><div class="box">${body}</div></body></html>`,
      { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } }
    );

  const jsonBody = async (res) => {
    try { return await res.json(); } catch { return null; }
  };

  const getCookie = (name) => {
    const raw = request.headers.get("Cookie") || "";
    const parts = raw.split(";").map(s => s.trim());
    for (const p of parts) {
      if (!p) continue;
      const eq = p.indexOf("=");
      if (eq === -1) continue;
      const k = p.slice(0, eq).trim();
      const v = p.slice(eq + 1).trim();
      if (k === name) return decodeURIComponent(v);
    }
    return null;
  };

  const appendClearCookie = (headers, name) => {
    headers.append(
      "Set-Cookie",
      `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
    );
  };

  const tokenHex = (bytes = 32) => {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return [...arr].map(b => b.toString(16).padStart(2, "0")).join("");
  };

  const now = Math.floor(Date.now() / 1000);

  // ---- Basic validation ----
  if (errorFromGoogle) {
    return html("Google OAuth", `رجع Google بخطأ: <b>${escapeHtml(errorFromGoogle)}</b><br><br>
    ارجع وجرّب مرة ثانية من:<br>
    <a href="/api2/google/start">/api2/google/start</a>`);
  }

  if (!code || !state) {
    return html("Google OAuth", `بيانات الرجوع من Google ناقصة (<b>code/state</b>).<br><br>
    جرّب تبدأ من جديد من:<br>
    <a href="/api2/google/start">/api2/google/start</a>`);
  }

  // ---- Read PKCE verifier from cookies (multiple possible names) ----
  const verifier =
    getCookie("g_verifier") ||
    getCookie("pkce_verifier") ||
    getCookie("google_verifier") ||
    getCookie("oauth_verifier");

  const stateCookie =
    getCookie("g_state") ||
    getCookie("pkce_state") ||
    getCookie("google_state") ||
    getCookie("oauth_state");

  // ---- Client vars (trim to kill whitespace problems) ----
  const rawClientId = env.GOOGLE_CLIENT_ID || "";
  const rawClientSecret = env.GOOGLE_CLIENT_SECRET || "";
  const rawRedirect = env.GOOGLE_REDIRECT_URI || "";

  const client_id = rawClientId.trim();
  const client_secret = rawClientSecret.trim();
  const redirect_uri = rawRedirect.trim() || `${url.origin}/api2/google/callback`;

  const client_id_has_whitespace = rawClientId !== client_id;

  // ---- State check (if we have a state cookie) ----
  if (stateCookie && stateCookie !== state) {
    const h = new Headers({ "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    appendClearCookie(h, "g_state"); appendClearCookie(h, "pkce_state"); appendClearCookie(h, "google_state"); appendClearCookie(h, "oauth_state");
    appendClearCookie(h, "g_verifier"); appendClearCookie(h, "pkce_verifier"); appendClearCookie(h, "google_verifier"); appendClearCookie(h, "oauth_verifier");

    return new Response(
      `<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
       <body style="font-family:system-ui;padding:24px;line-height:1.7">
       <div style="border:1px solid #ddd;border-radius:12px;padding:16px;max-width:720px">
       <b>خطأ:</b> state غير مطابق (حماية).<br><br>
       ابدأ من جديد من: <a href="/api2/google/start">/api2/google/start</a>
       </div></body></html>`,
      { headers: h }
    );
  }

  // If verifier missing → explain clearly (this is your current error)
  if (!verifier) {
    return html("Google OAuth", `
      <b>فشل تبادل الرمز (token exchange)</b><br>
      السبب: <b>Missing code verifier</b> (PKCE).<br><br>
      هذا يعني أن ملف <b>/api2/google/start</b> لا يرسل/يحفظ verifier في كوكيز (أو باسم مختلف).<br><br>
      <b>حلّك:</b> بعد ما ترفع هذا الملف، أعطني "تم" وبعطيك ملف:
      <br><code>functions/api2/google/start.js</code>
      ليولّد ويحفظ <b>state/verifier</b> بشكل صحيح. ✅
      <hr>
      <pre>
redirect_uri_used: ${escapeHtml(redirect_uri)}
client_id_has_whitespace: ${client_id_has_whitespace ? "YES" : "NO"}
      </pre>
    `);
  }

  // ---- Exchange code for tokens ----
  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id,
        client_secret,
        redirect_uri,
        grant_type: "authorization_code",
        code_verifier: verifier,
      }).toString(),
    });

    const tokenJson = await jsonBody(tokenRes);

    if (!tokenRes.ok) {
      return html("Google OAuth", `
        <b>فشل تبادل الرمز (token exchange)</b><br><br>
        <pre>status: ${tokenRes.status}
error: ${escapeHtml(tokenJson?.error || "unknown")}
desc: ${escapeHtml(tokenJson?.error_description || "No description")}
redirect_uri_used: ${escapeHtml(redirect_uri)}
client_id_has_whitespace: ${client_id_has_whitespace ? "YES" : "NO"}</pre>
        <br>
        إذا كان <b>invalid_client</b> → تأكد أن:
        <ul>
          <li>GOOGLE_CLIENT_ID = Client ID الصحيح</li>
          <li>GOOGLE_CLIENT_SECRET = Secret الصحيح (مو الـ ID)</li>
          <li>بدون أي مسافة/سطر جديد</li>
        </ul>
      `);
    }

    const access_token = tokenJson.access_token;
    if (!access_token) {
      return html("Google OAuth", `تمت الاستجابة بدون access_token.<br><pre>${escapeHtml(JSON.stringify(tokenJson, null, 2))}</pre>`);
    }

    // ---- Get user profile ----
    const uiRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const ui = await jsonBody(uiRes);

    if (!uiRes.ok || !ui?.email) {
      return html("Google OAuth", `
        فشل جلب بيانات المستخدم من Google.<br>
        <pre>status: ${uiRes.status}
body: ${escapeHtml(JSON.stringify(ui, null, 2))}</pre>
      `);
    }

    const email = String(ui.email).toLowerCase();
    const sub = ui.sub ? String(ui.sub) : null;
    const name = ui.name ? String(ui.name) : null;

    // ---- Create session token ----
    const sessionToken = tokenHex(32);

    // ---- Persist session (required by your /api2/me flow غالبًا) ----
    if (env.DB) {
      // sessions table (token,email,created_at) is expected
      try {
        await env.DB.prepare(
          "INSERT INTO sessions (token, email, created_at) VALUES (?, ?, ?)"
        ).bind(sessionToken, email, now).run();
      } catch (e) {
        // If schema differs, show a clear message instead of 1101
        return html("Google OAuth", `
          تم تسجيل Google بنجاح لكن حصل خطأ في إنشاء جلسة الدخول (sessions).<br><br>
          <pre>${escapeHtml(String(e))}</pre>
        `);
      }

      // users upsert (best-effort + mark verified)
      try {
        const colsRes = await env.DB.prepare("PRAGMA table_info(users)").all();
        const cols = new Set((colsRes.results || []).map(r => r.name));

        const hasEmail = cols.has("email");
        if (hasEmail) {
          const existing = await env.DB.prepare(
            cols.has("google_sub")
              ? "SELECT email FROM users WHERE email = ? OR google_sub = ? LIMIT 1"
              : "SELECT email FROM users WHERE email = ? LIMIT 1"
          ).bind(email, sub).first();

          if (existing) {
            // Update verified + google_sub if available
            if (cols.has("email_verified_at")) {
              await env.DB.prepare("UPDATE users SET email_verified_at = COALESCE(email_verified_at, ?) WHERE email = ?")
                .bind(now, email).run();
            } else if (cols.has("verified_at")) {
              await env.DB.prepare("UPDATE users SET verified_at = COALESCE(verified_at, ?) WHERE email = ?")
                .bind(now, email).run();
            } else if (cols.has("is_verified")) {
              await env.DB.prepare("UPDATE users SET is_verified = 1 WHERE email = ?")
                .bind(email).run();
            }

            if (sub && cols.has("google_sub")) {
              await env.DB.prepare("UPDATE users SET google_sub = ? WHERE email = ?")
                .bind(sub, email).run();
            }

            if (name) {
              const nameCol = cols.has("display_name") ? "display_name" : (cols.has("name") ? "name" : null);
              if (nameCol) {
                await env.DB.prepare(`UPDATE users SET ${nameCol} = COALESCE(${nameCol}, ?) WHERE email = ?`)
                  .bind(name, email).run();
              }
            }
          } else {
            // Insert new user with whatever columns exist
            const fields = [];
            const vals = [];
            const qs = [];

            fields.push("email"); vals.push(email); qs.push("?");
            if (cols.has("created_at")) { fields.push("created_at"); vals.push(now); qs.push("?"); }
            if (sub && cols.has("google_sub")) { fields.push("google_sub"); vals.push(sub); qs.push("?"); }
            if (name) {
              const nameCol = cols.has("display_name") ? "display_name" : (cols.has("name") ? "name" : null);
              if (nameCol) { fields.push(nameCol); vals.push(name); qs.push("?"); }
            }
            if (cols.has("email_verified_at")) { fields.push("email_verified_at"); vals.push(now); qs.push("?"); }
            else if (cols.has("verified_at")) { fields.push("verified_at"); vals.push(now); qs.push("?"); }
            else if (cols.has("is_verified")) { fields.push("is_verified"); vals.push(1); qs.push("?"); }

            await env.DB.prepare(
              `INSERT INTO users (${fields.join(",")}) VALUES (${qs.join(",")})`
            ).bind(...vals).run();
          }
        }
      } catch {
        // ignore users upsert if schema differs
      }
    }

    // ---- Clear cookies to avoid reuse ----
    const headers = new Headers({
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    appendClearCookie(headers, "g_state");
    appendClearCookie(headers, "pkce_state");
    appendClearCookie(headers, "google_state");
    appendClearCookie(headers, "oauth_state");
    appendClearCookie(headers, "g_verifier");
    appendClearCookie(headers, "pkce_verifier");
    appendClearCookie(headers, "google_verifier");
    appendClearCookie(headers, "oauth_verifier");

    // ---- IMPORTANT: Store token in localStorage then go to /activate ----
    const redirectTo = "/activate"; // نفس دومينك
    const page = `<!doctype html><html lang="ar" dir="rtl"><head>
      <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <title>جاري تسجيل الدخول...</title></head>
      <body style="font-family:system-ui;padding:24px;line-height:1.7">
      جاري تحويلك...<script>
        try{
          localStorage.setItem('sandooq_token_v1', ${JSON.stringify(sessionToken)});
          localStorage.setItem('sandooq_email_v1', ${JSON.stringify(email)});
        }catch(e){}
        location.replace(${JSON.stringify(redirectTo)});
      </script>
      <noscript>فعّل JavaScript ثم حدّث الصفحة.</noscript>
      </body></html>`;

    return new Response(page, { headers });
  } catch (e) {
    return html("Google OAuth", `خطأ غير متوقع داخل السيرفر.<br><pre>${escapeHtml(String(e))}</pre>`);
  }
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
