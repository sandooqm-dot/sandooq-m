// functions/api2/verify-email.js
// ✅ Fix: verify OTP from pending_users (not email_otps) to stop OTP_NOT_FOUND

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS },
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function toOtpString(x) {
  // نخلي المقارنة ثابتة حتى لو DB مخزنها رقم أو نص
  const s = String(x ?? "").trim();
  return s;
}

let _colsCache = new Map();
async function getTableCols(db, table) {
  if (_colsCache.has(table)) return _colsCache.get(table);
  const res = await db.prepare(`PRAGMA table_info(${table});`).all();
  const cols = new Set((res?.results || []).map((r) => r.name));
  _colsCache.set(table, cols);
  return cols;
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env?.DB) return json({ ok: false, error: "NO_DB_BINDING" }, 500);

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const otp = toOtpString(body.otp);

    if (!email) return json({ ok: false, error: "MISSING_EMAIL" }, 400);
    if (!otp) return json({ ok: false, error: "MISSING_OTP" }, 400);

    // 1) اقرأ الـ OTP من pending_users (هذا الموجود فعليًا عندك)
    const pending = await env.DB
      .prepare(`SELECT email, password_hash, otp FROM pending_users WHERE email = ? LIMIT 1;`)
      .bind(email)
      .first();

    if (!pending) {
      // ما فيه تسجيل معلّق لهذا الإيميل
      return json({ ok: false, error: "OTP_NOT_FOUND" }, 404);
    }

    const dbOtp = toOtpString(pending.otp);

    if (dbOtp !== otp) {
      // موجود تسجيل معلّق لكن الرمز غلط
      return json({ ok: false, error: "OTP_INVALID" }, 400);
    }

    // 2) ثبّت المستخدم في users (بدون افتراض أعمدة غير موجودة)
    const now = new Date().toISOString();
    const usersCols = await getTableCols(env.DB, "users");

    // أقل شيء لازم email + password_hash
    if (!usersCols.has("email") || !usersCols.has("password_hash")) {
      return json({ ok: false, error: "USERS_SCHEMA_INVALID" }, 500);
    }

    // جرّب Insert ثم لو كان موجود سو Update
    try {
      const insertCols = ["email", "password_hash"];
      const insertVals = [email, pending.password_hash];

      if (usersCols.has("email_verified_at")) {
        insertCols.push("email_verified_at");
        insertVals.push(now);
      }
      if (usersCols.has("email_verified")) {
        insertCols.push("email_verified");
        insertVals.push(1);
      }
      if (usersCols.has("created_at")) {
        insertCols.push("created_at");
        insertVals.push(now);
      }

      const q = `INSERT INTO users (${insertCols.join(",")}) VALUES (${insertCols.map(() => "?").join(",")});`;
      await env.DB.prepare(q).bind(...insertVals).run();
    } catch (e) {
      // غالبًا الإيميل موجود → Update
      const updates = ["password_hash = ?"];
      const vals = [pending.password_hash];

      if (usersCols.has("email_verified_at")) {
        updates.push("email_verified_at = ?");
        vals.push(now);
      }
      if (usersCols.has("email_verified")) {
        updates.push("email_verified = ?");
        vals.push(1);
      }

      vals.push(email);
      await env.DB
        .prepare(`UPDATE users SET ${updates.join(", ")} WHERE email = ?;`)
        .bind(...vals)
        .run();
    }

    // 3) احذف السجل المعلّق من pending_users عشان ما يصير "الإيميل مسجل" بدون فائدة
    await env.DB.prepare(`DELETE FROM pending_users WHERE email = ?;`).bind(email).run();

    // 4) (اختياري) أنشئ Session لو جدول sessions يدعم token/email
    let token = null;
    try {
      const sessCols = await getTableCols(env.DB, "sessions");
      if (sessCols.has("token") && (sessCols.has("email") || sessCols.has("user_email"))) {
        token = crypto.randomUUID() + crypto.randomUUID();
        const exp = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(); // 30 يوم

        const colEmail = sessCols.has("email") ? "email" : "user_email";
        const cols = ["token", colEmail];
        const vals = [token, email];

        if (sessCols.has("created_at")) {
          cols.push("created_at");
          vals.push(now);
        }
        if (sessCols.has("expires_at")) {
          cols.push("expires_at");
          vals.push(exp);
        }

        await env.DB
          .prepare(`INSERT INTO sessions (${cols.join(",")}) VALUES (${cols.map(() => "?").join(",")});`)
          .bind(...vals)
          .run();
      }
    } catch (_) {
      // ما نوقف التحقق لو الجلسة ما انكتبت
    }

    return json({ ok: true, email, token });
  } catch (err) {
    console.log("verify_email_error", String(err?.message || err));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}

// اسم النسخة: verify-email.js – إصدار 1 (Fix OTP_NOT_FOUND from pending_users)
