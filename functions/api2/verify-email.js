function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
    },
  });
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function guessDefaultValue(sqlType, now) {
  const t = String(sqlType || "").toUpperCase();
  if (t.includes("INT")) return now;
  if (t.includes("CHAR") || t.includes("TEXT") || t.includes("CLOB")) return "";
  if (t.includes("REAL") || t.includes("FLOA") || t.includes("DOUB")) return 0;
  return ""; // fallback
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

    // ✅ الـ OTP عندك ينحفظ في pending_users (حسب استعلاماتك)
    const pending = await db
      .prepare("SELECT email, password_hash, otp FROM pending_users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    if (!pending) return json({ ok: false, error: "OTP_NOT_FOUND" }, 404);

    const savedOtp = String(pending.otp ?? "").trim();
    if (!savedOtp || savedOtp !== otp) return json({ ok: false, error: "OTP_INVALID" }, 400);

    const now = Date.now();

    // نجيب سكيمة users عشان ندخل بشكل متوافق 100%
    const info = await db.prepare("PRAGMA table_info(users)").all();
    const colsInfo = info?.results || [];
    const colsByName = new Map(colsInfo.map(r => [r.name, r]));

    // هل المستخدم موجود أصلًا؟
    const existing = await db
      .prepare("SELECT rowid AS _rowid, * FROM users WHERE email = ? LIMIT 1")
      .bind(email)
      .first();

    if (!existing) {
      const cols = [];
      const ph = [];
      const vals = [];

      // قيم أساسية
      if (colsByName.has("id")) {
        cols.push("id"); ph.push("?"); vals.push(crypto.randomUUID());
      }
      if (colsByName.has("email")) {
        cols.push("email"); ph.push("?"); vals.push(email);
      }
      if (colsByName.has("password_hash")) {
        cols.push("password_hash"); ph.push("?"); vals.push(pending.password_hash);
      }

      // قيم تحقق اختيارية
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

      // 🔥 أهم جزء: أي عمود NOT NULL بدون default لازم نعطيه قيمة
      for (const r of colsInfo) {
        const name = r.name;
        const notNull = Number(r.notnull) === 1;
        const hasDefault = r.dflt_value !== null && r.dflt_value !== undefined;
        const already = cols.includes(name);

        // تجاهل rowid/PK integer
        if (already) continue;
        if (!notNull) continue;
        if (hasDefault) continue;

        // إذا PK نصي وما عطيناه قيمة
        if (Number(r.pk) === 1) {
          cols.push(name); ph.push("?"); vals.push(crypto.randomUUID());
          continue;
        }

        // أعط قيمة افتراضية حسب النوع
        cols.push(name);
        ph.push("?");
        vals.push(guessDefaultValue(r.type, now));
      }

      // لازم على الأقل email + password_hash موجودين
      if (!cols.includes("email") || !cols.includes("password_hash")) {
        return json({ ok: false, error: "USERS_SCHEMA_MISSING_EMAIL_OR_PASSWORD" }, 500);
      }

      await db
        .prepare(`INSERT INTO users (${cols.join(",")}) VALUES (${ph.join(",")})`)
        .bind(...vals)
        .run();
    } else {
      // لو موجود، نحدّث حالة التحقق إذا الأعمدة موجودة
      const sets = [];
      const vals = [];

      if (colsByName.has("is_verified")) { sets.push("is_verified = ?"); vals.push(1); }
      if (colsByName.has("email_verified_at")) { sets.push("email_verified_at = ?"); vals.push(now); }
      if (colsByName.has("verified_at")) { sets.push("verified_at = ?"); vals.push(now); }
      if (colsByName.has("updated_at")) { sets.push("updated_at = ?"); vals.push(now); }

      if (sets.length) {
        await db.prepare(`UPDATE users SET ${sets.join(", ")} WHERE email = ?`).bind(...vals, email).run();
      }
    }

    // ننظف الـ pending (عشان ما ينحجز الإيميل)
    await db.prepare("DELETE FROM pending_users WHERE email = ?").bind(email).run();

    // تنظيف احتياطي لو فيه جدول قديم
    await db.prepare("DELETE FROM email_otps WHERE email = ?").bind(email).run();

    return json({ ok: true, email }, 200);
  } catch (e) {
    console.log("verify_email_error", e?.message || String(e));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}
