// functions/api2/verify-email.js

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "POST, OPTIONS",
      "access-control-allow-headers": "content-type, authorization, x-device-id",
      "access-control-max-age": "86400",
    },
  });
}

export async function onRequestPost({ request, env }) {
  try {
    const db = env.DB;
    if (!db) return json({ ok: false, error: "NO_DB_BINDING" }, 500);

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const otp = String(body.otp ?? body.code ?? "").trim();

    if (!email || !otp) return json({ ok: false, error: "BAD_REQUEST" }, 400);

    // 1) نجيب المستخدم المعلّق من pending_users (هو اللي عندك فيه otp فعليًا)
    const pending = await db
      .prepare("SELECT email, password_hash, otp FROM pending_users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    if (!pending) {
      return json({ ok: false, error: "OTP_NOT_FOUND" }, 404);
    }

    const savedOtp = String(pending.otp ?? "").trim();
    if (!savedOtp || savedOtp !== otp) {
      return json({ ok: false, error: "OTP_INVALID" }, 400);
    }

    // 2) نعرف أعمدة users عشان ندخل بشكل متوافق مع سكيمتك الحالية
    const usersInfo = await db.prepare("PRAGMA table_info(users)").all();
    const userCols = new Set((usersInfo.results || []).map((r) => r.name));

    const now = Date.now();

    // هل المستخدم موجود مسبقًا في users؟
    let user = await db.prepare("SELECT rowid AS _rowid, * FROM users WHERE email = ? LIMIT 1").bind(email).first();

    if (!user) {
      const cols = [];
      const ph = [];
      const vals = [];

      if (userCols.has("email")) { cols.push("email"); ph.push("?"); vals.push(email); }
      if (userCols.has("password_hash")) { cols.push("password_hash"); ph.push("?"); vals.push(pending.password_hash); }

      // أعمدة اختيارية (لو موجودة عندك)
      if (userCols.has("email_verified_at")) { cols.push("email_verified_at"); ph.push("?"); vals.push(now); }
      if (userCols.has("verified_at")) { cols.push("verified_at"); ph.push("?"); vals.push(now); }
      if (userCols.has("is_verified")) { cols.push("is_verified"); ph.push("?"); vals.push(1); }
      if (userCols.has("created_at")) { cols.push("created_at"); ph.push("?"); vals.push(now); }

      if (cols.length < 2) {
        // لازم أقل شيء email + password_hash
        return json({ ok: false, error: "USERS_SCHEMA_MISSING_COLUMNS" }, 500);
      }

      await db
        .prepare(`INSERT INTO users (${cols.join(",")}) VALUES (${ph.join(",")})`)
        .bind(...vals)
        .run();

      user = await db.prepare("SELECT rowid AS _rowid, * FROM users WHERE email = ? LIMIT 1").bind(email).first();
    } else {
      // تحديث حالة التحقق لو الأعمدة موجودة
      const sets = [];
      const vals = [];
      if (userCols.has("email_verified_at")) { sets.push("email_verified_at = ?"); vals.push(now); }
      if (userCols.has("verified_at")) { sets.push("verified_at = ?"); vals.push(now); }
      if (userCols.has("is_verified")) { sets.push("is_verified = ?"); vals.push(1); }

      if (sets.length) {
        await db.prepare(`UPDATE users SET ${sets.join(", ")} WHERE email = ?`).bind(...vals, email).run();
      }
    }

    // 3) حذف السجل من pending_users (عشان ما يصير الإيميل “محجوز” بدون فايدة)
    await db.prepare("DELETE FROM pending_users WHERE email = ?").bind(email).run();

    // تنظيف احتياطي لو كنت تستخدم email_otps سابقًا
    await db.prepare("DELETE FROM email_otps WHERE email = ?").bind(email).run();

    // 4) إنشاء Session Token (إذا جدول sessions يدعمه)
    let token = null;
    try {
      const sessInfo = await db.prepare("PRAGMA table_info(sessions)").all();
      const sessCols = new Set((sessInfo.results || []).map((r) => r.name));

      if (sessCols.size) {
        const rand = crypto.getRandomValues(new Uint8Array(16));
        const hex = [...rand].map((b) => b.toString(16).padStart(2, "0")).join("");
        token = `${crypto.randomUUID()}-${hex}`;

        const userId =
          user?.id ??
          user?.user_id ??
          user?._rowid ??
          null;

        const deviceId = request.headers.get("x-device-id") || null;
        const expiresAt = now + 1000 * 60 * 60 * 24 * 30; // 30 يوم

        const cols = [];
        const ph = [];
        const vals = [];

        if (sessCols.has("token")) { cols.push("token"); ph.push("?"); vals.push(token); }
        if (sessCols.has("user_id") && userId != null) { cols.push("user_id"); ph.push("?"); vals.push(userId); }
        if (sessCols.has("email")) { cols.push("email"); ph.push("?"); vals.push(email); }
        if (sessCols.has("device_id") && deviceId) { cols.push("device_id"); ph.push("?"); vals.push(deviceId); }
        if (sessCols.has("created_at")) { cols.push("created_at"); ph.push("?"); vals.push(now); }
        if (sessCols.has("expires_at")) { cols.push("expires_at"); ph.push("?"); vals.push(expiresAt); }

        if (cols.length) {
          await db.prepare(`INSERT INTO sessions (${cols.join(",")}) VALUES (${ph.join(",")})`).bind(...vals).run();
        } else {
          token = null;
        }
      }
    } catch (_) {
      token = null;
    }

    return json({ ok: true, email, token }, 200);
  } catch (e) {
    console.log("verify_email_error", e?.message || String(e));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}
