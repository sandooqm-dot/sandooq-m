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
  return (crypto && crypto.randomUUID) ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`;
}

function isIntegerPk(col) {
  if (!col) return false;
  const t = String(col.type || "").toUpperCase();
  return col.pk === 1 && t.includes("INT"); // INTEGER PRIMARY KEY
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
      const selCols = ["email"];

      // أهم شي: hash + salt لازم يوصلون هنا
      if (hasCol(pendingCols, "password_hash")) selCols.push("password_hash");
      if (hasCol(pendingCols, "salt_b64")) selCols.push("salt_b64");
      if (hasCol(pendingCols, "salt")) selCols.push("salt");

      // بعض النسخ القديمة تسميه password_salt
      if (hasCol(pendingCols, "password_salt")) selCols.push("password_salt");

      // OTP قد يكون باسم مختلف
      if (hasCol(pendingCols, "otp")) selCols.push("otp");
      if (hasCol(pendingCols, "code")) selCols.push("code");
      if (hasCol(pendingCols, "otp_code")) selCols.push("otp_code");

      pending = await env.DB
        .prepare(`SELECT ${selCols.join(", ")} FROM pending_users WHERE email = ? LIMIT 1`)
        .bind(email)
        .first();
    }

    // لو ما لقى في pending_users، جرّب email_otps
    let otpRecord = null;
    if ((!pending || (!pending.otp && !pending.code && !pending.otp_code)) && emailOtpsCols.length) {
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
    const pendingOtp =
      pending?.otp != null ? String(pending.otp).trim() :
      pending?.otp_code != null ? String(pending.otp_code).trim() :
      pending?.code != null ? String(pending.code).trim() : "";

    const otpFromEmailOtps =
      otpRecord?.otp != null ? String(otpRecord.otp).trim() :
      otpRecord?.otp_code != null ? String(otpRecord.otp_code).trim() :
      otpRecord?.code != null ? String(otpRecord.code).trim() : "";

    const effectiveOtp = pendingOtp || otpFromEmailOtps;

    if (!effectiveOtp) return json({ ok: false, error: "OTP_NOT_FOUND" }, 404);
    if (effectiveOtp !== otp) return json({ ok: false, error: "OTP_NOT_FOUND" }, 404);

    // لازم يكون عندنا password_hash من pending_users عشان نسوي Login بعدين
    if (!pending || !pending.password_hash) {
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
    const idCol = usersCols.find(c => c.name === "id");
    const idIsAutoInt = isIntegerPk(idCol);

    // salt_b64: لازم نجيبها من pending_users (لأن جدول users يطلبها NOT NULL)
    const pendingSaltB64 =
      (pending?.salt_b64 != null ? String(pending.salt_b64) : "") ||
      (pending?.password_salt != null ? String(pending.password_salt) : "") ||
      (pending?.salt != null ? String(pending.salt) : "");

    // إذا جدول users يتطلب salt_b64 وما عندنا قيمة له → نوقف بخطأ واضح
    const usersNeedsSaltB64 = usersCols.some(c => c.name === "salt_b64" && c.notnull === 1 && (c.dflt_value == null));
    if (usersNeedsSaltB64 && !pendingSaltB64) {
      console.log("verify_email_pending_salt_missing", email);
      return json({ ok: false, error: "PENDING_SALT_MISSING" }, 409);
    }

    const valuesMap = {
      email,
      provider: "email",

      password_hash: pending.password_hash,

      // توافق: نخزن salt_b64 إذا العمود موجود
      salt_b64: pendingSaltB64 || null,
      salt: pendingSaltB64 || null, // بعض الجداول/الأكواد تتوقع salt بدل salt_b64

      created_at: nowMs(),
      updated_at: nowMs(),

      email_verified: 1,
      is_email_verified: 1,
      email_verified_at: String(nowMs()),

      verified: 1,
      is_verified: 1,
      verified_at: nowMs(),

      status: "active",
      role: "user",

      // ملاحظة: id إذا كان INTEGER AUTOINCREMENT ما نرسله نهائيًا
      id: idIsAutoInt ? undefined : safeUUID(),
      user_id: safeUUID(),
      google_sub: null,
    };

    // الأعمدة NOT NULL بدون default ولا نقدر نعبيها → نوقف بخطأ واضح
    const missingRequired = usersCols
      .filter(c => c.notnull === 1 && (c.dflt_value === null || c.dflt_value === undefined))
      .filter(c => !["email"].includes(c.name))
      .filter(c => {
        // لا نعتبر id مطلوب إذا كان INTEGER PK (بيتعبي تلقائي)
        if (c.name === "id" && idIsAutoInt) return false;
        return !Object.prototype.hasOwnProperty.call(valuesMap, c.name) || valuesMap[c.name] === undefined;
      })
      .filter(c => colSet.has(c.name));

    if (missingRequired.length) {
      console.log("verify_email_schema_missing_required", email, missingRequired.map(c => c.name));
      return json({ ok: false, error: "USERS_SCHEMA_MISSING_REQUIRED_COLS" }, 500);
    }

    if (!existing) {
      // INSERT
      const insertCols = [];
      const insertVals = [];

      for (const [k, v] of Object.entries(valuesMap)) {
        if (!colSet.has(k)) continue;
        if (v === undefined) continue;
        // لو id INTEGER AUTOINCREMENT لا نرسله
        if (k === "id" && idIsAutoInt) continue;

        insertCols.push(k);
        insertVals.push(v);
      }

      const placeholders = insertCols.map(() => "?").join(", ");
      const sql = `INSERT INTO users (${insertCols.join(", ")}) VALUES (${placeholders})`;

      try {
        await env.DB.prepare(sql).bind(...insertVals).run();
      } catch (e) {
        const msg = String(e?.message || e);
        if (msg.includes("UNIQUE") || msg.includes("unique")) {
          // موجود مسبقًا
        } else {
          console.log("verify_email_user_insert_failed", email, msg);
          return json({ ok: false, error: "USER_INSERT_FAILED" }, 500);
        }
      }
    } else {
      // UPDATE
      if (colSet.has("password_hash")) {
        await env.DB
          .prepare("UPDATE users SET password_hash = ? WHERE email = ?")
          .bind(pending.password_hash, email)
          .run();
      }
      if (colSet.has("salt_b64") && pendingSaltB64) {
        await env.DB
          .prepare("UPDATE users SET salt_b64 = ? WHERE email = ?")
          .bind(pendingSaltB64, email)
          .run();
      }
      if (colSet.has("salt") && pendingSaltB64) {
        await env.DB
          .prepare("UPDATE users SET salt = ? WHERE email = ?")
          .bind(pendingSaltB64, email)
          .run();
      }
      if (colSet.has("email_verified")) {
        await env.DB.prepare("UPDATE users SET email_verified = 1 WHERE email = ?").bind(email).run();
      }
      if (colSet.has("is_email_verified")) {
        await env.DB.prepare("UPDATE users SET is_email_verified = 1 WHERE email = ?").bind(email).run();
      }
      if (colSet.has("email_verified_at")) {
        await env.DB.prepare("UPDATE users SET email_verified_at = ? WHERE email = ?").bind(String(nowMs()), email).run();
      }
      if (colSet.has("updated_at")) {
        await env.DB.prepare("UPDATE users SET updated_at = ? WHERE email = ?").bind(nowMs(), email).run();
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
    try { await env.DB.prepare("DELETE FROM email_otps WHERE email = ?").bind(email).run(); } catch (_) {}

    return json({ ok: true, email, verified: true }, 200);
  } catch (err) {
    console.log("verify_email_error", String(err?.message || err));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
verify-email.js – api2 – إصدار 3 (Fix salt_b64 required + don't insert autoincrement id)
*/
