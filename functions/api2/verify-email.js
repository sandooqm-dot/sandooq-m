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

async function tableInfo(db, tableName) {
  try {
    const res = await db.prepare(`PRAGMA table_info(${tableName});`).all();
    const rows = res?.results || [];
    return rows.map(r => ({
      name: r.name,
      notnull: Number(r.notnull || 0),
      dflt_value: r.dflt_value,
      pk: Number(r.pk || 0),
      type: r.type,
    }));
  } catch {
    return [];
  }
}

function hasCol(cols, name) {
  return cols.some(c => c.name === name);
}

function nowMs() {
  return Date.now();
}

function safeUUID() {
  // crypto.randomUUID موجودة على Cloudflare Workers
  return (crypto && crypto.randomUUID) ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`;
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

    // --- 1) نجيب الـ OTP من أي مكان موجود (pending_users أولاً ثم email_otps) ---
    const pendingCols = await tableInfo(env.DB, "pending_users");
    const emailOtpsCols = await tableInfo(env.DB, "email_otps");

    let pending = null;

    if (pendingCols.length) {
      // لو جدول pending_users موجود
      const selCols = ["email"];
      if (hasCol(pendingCols, "password_hash")) selCols.push("password_hash");
      if (hasCol(pendingCols, "otp")) selCols.push("otp");

      // (مستقبلاً لو أضفت password_salt)
      if (hasCol(pendingCols, "password_salt")) selCols.push("password_salt");

      pending = await env.DB
        .prepare(`SELECT ${selCols.join(", ")} FROM pending_users WHERE email = ? LIMIT 1`)
        .bind(email)
        .first();
    }

    // لو ما لقى في pending_users، جرّب email_otps
    // (بعض النسخ كانت تكتب OTP هناك)
    let otpRecord = null;
    if (!pending && emailOtpsCols.length) {
      const selCols = ["email"];
      if (hasCol(emailOtpsCols, "otp")) selCols.push("otp");
      if (hasCol(emailOtpsCols, "code")) selCols.push("code");
      if (hasCol(emailOtpsCols, "otp_code")) selCols.push("otp_code");

      otpRecord = await env.DB
        .prepare(`SELECT ${selCols.join(", ")} FROM email_otps WHERE email = ? ORDER BY rowid DESC LIMIT 1`)
        .bind(email)
        .first();
    }

    // --- 2) تحقق من تطابق OTP ---
    const pendingOtp = pending?.otp != null ? String(pending.otp).trim() : "";
    const otpFromEmailOtps =
      otpRecord?.otp != null ? String(otpRecord.otp).trim() :
      otpRecord?.otp_code != null ? String(otpRecord.otp_code).trim() :
      otpRecord?.code != null ? String(otpRecord.code).trim() : "";

    const effectiveOtp = pendingOtp || otpFromEmailOtps;

    if (!effectiveOtp) {
      return json({ ok: false, error: "OTP_NOT_FOUND" }, 404);
    }
    if (effectiveOtp !== otp) {
      return json({ ok: false, error: "OTP_NOT_FOUND" }, 404);
    }

    // لازم يكون عندنا password_hash من pending_users عشان نقدر نسوي Login بعدين
    if (!pending || !pending.password_hash) {
      // OTP صحيح (من email_otps) لكن ما عندنا password_hash لأن التسجيل المؤقت مو موجود/انحذف
      // هنا نوقف ونرجّع خطأ واضح بدل ما نكمل ونسبب INVALID_CREDENTIALS
      return json({ ok: false, error: "PENDING_USER_NOT_FOUND" }, 409);
    }

    // --- 3) إدخال/تحديث المستخدم في users بشكل آمن ---
    const usersCols = await tableInfo(env.DB, "users");
    if (!usersCols.length) {
      return json({ ok: false, error: "USERS_TABLE_NOT_FOUND" }, 500);
    }

    const existing = await env.DB
      .prepare("SELECT email FROM users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    const colSet = new Set(usersCols.map(c => c.name));

    // تجهيز قيم افتراضية لأكثر الأعمدة شيوعًا
    const valuesMap = {
      email,
      password_hash: pending.password_hash,
      password_salt: pending.password_salt ?? null,
      created_at: nowMs(),
      updated_at: nowMs(),
      verified_at: nowMs(),
      email_verified: 1,
      verified: 1,
      is_verified: 1,
      provider: "email",
      status: "active",
      role: "user",
      id: safeUUID(),
      user_id: safeUUID(),
    };

    // ساعدنا: إذا عنده أعمدة NOT NULL بدون default ولا نعرف نعبيها → نوقف بخطأ واضح في اللوق
    const missingRequired = usersCols
      .filter(c => c.notnull === 1 && (c.dflt_value === null || c.dflt_value === undefined))
      .filter(c => !["email"].includes(c.name)) // email بنعبيه دائمًا
      .filter(c => !Object.prototype.hasOwnProperty.call(valuesMap, c.name) && colSet.has(c.name));

    if (missingRequired.length) {
      console.log("verify_email_schema_missing_required", email, missingRequired.map(c => c.name));
      return json({ ok: false, error: "USERS_SCHEMA_MISSING_REQUIRED_COLS" }, 500);
    }

    if (!existing) {
      // INSERT
      const insertCols = [];
      const insertVals = [];

      // نضيف فقط الأعمدة الموجودة فعليًا في الجدول
      for (const [k, v] of Object.entries(valuesMap)) {
        if (colSet.has(k)) {
          insertCols.push(k);
          insertVals.push(v);
        }
      }

      const placeholders = insertCols.map(() => "?").join(", ");
      const sql = `INSERT INTO users (${insertCols.join(", ")}) VALUES (${placeholders})`;

      try {
        await env.DB.prepare(sql).bind(...insertVals).run();
      } catch (e) {
        const msg = String(e?.message || e);
        // فقط نتجاهل UNIQUE الحقيقي… أي شيء ثاني نوقف
        if (msg.includes("UNIQUE") || msg.includes("unique")) {
          // موجود مسبقًا
        } else {
          console.log("verify_email_user_insert_failed", email, msg);
          return json({ ok: false, error: "USER_INSERT_FAILED" }, 500);
        }
      }
    } else {
      // UPDATE (لو المستخدم موجود، نحدّث hash لتوحيد الحالة)
      if (colSet.has("password_hash")) {
        await env.DB
          .prepare("UPDATE users SET password_hash = ? WHERE email = ?")
          .bind(pending.password_hash, email)
          .run();
      }
      if (colSet.has("email_verified")) {
        await env.DB
          .prepare("UPDATE users SET email_verified = 1 WHERE email = ?")
          .bind(email)
          .run();
      }
      if (colSet.has("verified")) {
        await env.DB
          .prepare("UPDATE users SET verified = 1 WHERE email = ?")
          .bind(email)
          .run();
      }
    }

    // --- 4) تأكد 100% أن المستخدم صار موجود في users ---
    const ensured = await env.DB
      .prepare("SELECT email FROM users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    if (!ensured) {
      console.log("verify_email_user_not_created", email);
      return json({ ok: false, error: "USER_NOT_CREATED" }, 500);
    }

    // --- 5) الآن فقط نحذف pending_users + ننظف email_otps ---
    await env.DB.prepare("DELETE FROM pending_users WHERE email = ?").bind(email).run();
    try {
      await env.DB.prepare("DELETE FROM email_otps WHERE email = ?").bind(email).run();
    } catch (_) {}

    return json({ ok: true, email, verified: true }, 200);
  } catch (err) {
    console.log("verify_email_error", String(err?.message || err));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
verify-email.js – api2 – إصدار 2 (Fix Users insert + No delete pending until ensured)
*/
