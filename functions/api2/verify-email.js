// functions/api2/verify-email.js
// Cloudflare Pages Function: POST /api2/verify-email

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
  "Access-Control-Max-Age": "86400",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS,
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isIntegerType(t) {
  const s = String(t || "").toUpperCase();
  return s.includes("INT");
}

function defaultForType(t, now) {
  const s = String(t || "").toUpperCase();
  if (s.includes("INT")) return now;
  if (s.includes("REAL") || s.includes("FLOA") || s.includes("DOUB")) return 0;
  if (s.includes("CHAR") || s.includes("TEXT") || s.includes("CLOB")) return "";
  // آخر حل: نص فاضي (أفضل من null مع NOT NULL)
  return "";
}

export async function onRequestOptions() {
  return new Response(null, { headers: CORS_HEADERS });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const otp = String(body.otp ?? "").trim();

    if (!email || !otp) {
      return json({ ok: false, error: "MISSING_FIELDS" }, 400);
    }

    // 1) نجيب بيانات التسجيل المؤقت من pending_users (هو اللي عندك فيه otp فعليًا)
    const pending = await env.DB
      .prepare("SELECT email, password_hash, otp FROM pending_users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    if (!pending) {
      return json({ ok: false, error: "OTP_NOT_FOUND" }, 404);
    }

    // لو ما تطابق
    if (String(pending.otp).trim() !== otp) {
      return json({ ok: false, error: "OTP_NOT_FOUND" }, 404);
    }

    // 2) نبني INSERT متوافق مع سكيمة users (بدون ما نكسر لو فيه أعمدة NOT NULL)
    const info = await env.DB.prepare("PRAGMA table_info(users)").all();
    const colsInfo = info?.results || [];
    const colsByName = new Map(colsInfo.map((r) => [r.name, r]));

    // لازم يوجد email + password_hash في users
    if (!colsByName.has("email") || !colsByName.has("password_hash")) {
      return json({ ok: false, error: "USERS_SCHEMA_MISSING_FIELDS" }, 500);
    }

    const now = Date.now();

    // هل المستخدم موجود؟
    const existing = await env.DB
      .prepare("SELECT 1 FROM users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    if (!existing) {
      const cols = [];
      const ph = [];
      const vals = [];

      // أساسيات
      cols.push("email"); ph.push("?"); vals.push(email);
      cols.push("password_hash"); ph.push("?"); vals.push(pending.password_hash);

      // قيم تحقق اختيارية لو الأعمدة موجودة
      if (colsByName.has("is_verified")) {
        cols.push("is_verified"); ph.push("?"); vals.push(1);
      }
      if (colsByName.has("email_verified_at")) {
        cols.push("email_verified_at"); ph.push("?"); vals.push(now);
      }
      if (colsByName.has("verified_at")) {
        cols.push("verified_at"); ph.push("?"); vals.push(now);
      }
      if (colsByName.has("created_at")) {
        cols.push("created_at"); ph.push("?"); vals.push(now);
      }
      if (colsByName.has("updated_at")) {
        cols.push("updated_at"); ph.push("?"); vals.push(now);
      }

      // لو عندك id نصّي (مو INTEGER PK) نعبيه UUID
      if (colsByName.has("id")) {
        const r = colsByName.get("id");
        const isPk = Number(r.pk) === 1;
        const isInt = isIntegerType(r.type);

        // إذا id INTEGER PRIMARY KEY: لا ندخله وخله يتولد تلقائيًا
        // إذا id TEXT أو غيره: نعبيه UUID (خصوصًا لو NOT NULL)
        if (!(isPk && isInt)) {
          cols.push("id"); ph.push("?"); vals.push(crypto.randomUUID());
        }
      }

      // 🔥 أكمل أي عمود NOT NULL بدون default (عشان ما يطيح INSERT)
      for (const r of colsInfo) {
        const name = r.name;
        const notNull = Number(r.notnull) === 1;
        const hasDefault = r.dflt_value !== null && r.dflt_value !== undefined;

        if (!notNull || hasDefault) continue;
        if (cols.includes(name)) continue;

        const isPk = Number(r.pk) === 1;
        const isInt = isIntegerType(r.type);

        // PK رقم (rowid) خلّه يتولد
        if (isPk && isInt) continue;

        // PK نصّي نعطيه UUID
        if (isPk && !isInt) {
          cols.push(name); ph.push("?"); vals.push(crypto.randomUUID());
          continue;
        }

        // غير ذلك: نعطي قيمة افتراضية حسب النوع
        cols.push(name);
        ph.push("?");
        vals.push(defaultForType(r.type, now));
      }

      try {
        await env.DB
          .prepare(`INSERT INTO users (${cols.join(",")}) VALUES (${ph.join(",")})`)
          .bind(...vals)
          .run();
      } catch (e) {
        // إذا موجود مسبقًا (UNIQUE) نتجاهل ونكمل
        const msg = String(e?.message || "");
        if (!msg.includes("UNIQUE") && !msg.includes("constraint")) throw e;
      }
    } else {
      // لو موجود، حدّث حالة التحقق لو الأعمدة موجودة
      const sets = [];
      const vals = [];

      if (colsByName.has("is_verified")) { sets.push("is_verified = ?"); vals.push(1); }
      if (colsByName.has("email_verified_at")) { sets.push("email_verified_at = ?"); vals.push(now); }
      if (colsByName.has("verified_at")) { sets.push("verified_at = ?"); vals.push(now); }
      if (colsByName.has("updated_at")) { sets.push("updated_at = ?"); vals.push(now); }

      if (sets.length) {
        await env.DB
          .prepare(`UPDATE users SET ${sets.join(", ")} WHERE email = ?`)
          .bind(...vals, email)
          .run();
      }
    }

    // 3) نحذف التسجيل المؤقت
    await env.DB.prepare("DELETE FROM pending_users WHERE email = ?").bind(email).run();

    // (اختياري) تنظيف أي OTP قديم إن كان فيه جدول email_otps
    try {
      await env.DB.prepare("DELETE FROM email_otps WHERE email = ?").bind(email).run();
    } catch (_) {}

    return json({ ok: true, email, verified: true });
  } catch (err) {
    console.log("verify_email_error", String(err?.message || err));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
verify-email.js – api2 – إصدار 2 (Schema-safe users insert)
*/
