// functions/api2/verify-email.js
// Cloudflare Pages Function: POST /api2/verify-email

const VERSION = "api2-verify-email-v4-schema-guard";

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin") || req.headers.get("Origin");
  const h = {
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "cache-control": "no-store",
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

function json(req, data, status = 200) {
  return new Response(JSON.stringify({ ...data, version: VERSION }), {
    status,
    headers: {
      ...CORS_HEADERS(req),
      "content-type": "application/json; charset=utf-8",
    },
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

async function tableInfo(DB, table) {
  try {
    const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
    const rows = res?.results || [];
    return rows.map((r) => ({
      name: String(r.name),
      notnull: Number(r.notnull || 0),
      dflt_value: r.dflt_value,
      pk: Number(r.pk || 0),
      type: String(r.type || ""),
    }));
  } catch {
    return [];
  }
}

async function tableExists(DB, table) {
  try {
    const r = await DB.prepare(
      `SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1`
    ).bind(table).first();
    return !!r?.name;
  } catch {
    return false;
  }
}

function hasCol(cols, name) {
  return cols.some((c) => c.name === name);
}

function nowMs() {
  return Date.now();
}

function isIntegerPk(col) {
  if (!col) return false;
  const t = String(col.type || "").toUpperCase();
  return col.pk === 1 && t.includes("INT"); // INTEGER PRIMARY KEY
}

async function ensureBaseTables(DB) {
  // ✅ إنشاء الجداول الأساسية لو ما كانت موجودة (حل جذري للجداول المفقودة)
  try {
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS pending_users (
        email TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        otp TEXT NOT NULL,
        otp_expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `).run();

    // نخلي users واسع للتوافق (بعض النسخ تستخدم salt_b64 وبعضها password_salt)
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        provider TEXT DEFAULT 'email',
        password_hash TEXT,
        salt_b64 TEXT,
        password_salt TEXT,
        salt TEXT,
        is_email_verified INTEGER DEFAULT 0,
        email_verified INTEGER DEFAULT 0,
        created_at INTEGER,
        updated_at INTEGER
      );
    `).run();

    return { ok: true };
  } catch (e) {
    console.log("verify_email_schema_create_failed", String(e?.message || e));
    return { ok: false, error: "SCHEMA_CREATE_FAILED" };
  }
}

function buildMissingRequired(cols, valuesMap) {
  const colSet = new Set(cols.map((c) => c.name));
  const idCol = cols.find((c) => c.name === "id");
  const idIsAutoInt = isIntegerPk(idCol);

  const missing = cols
    .filter((c) => c.notnull === 1 && (c.dflt_value === null || c.dflt_value === undefined))
    .filter((c) => !["email"].includes(c.name))
    .filter((c) => {
      // لو id INTEGER PK -> يتعبى تلقائي
      if (c.name === "id" && idIsAutoInt) return false;
      if (!colSet.has(c.name)) return false;
      return !Object.prototype.hasOwnProperty.call(valuesMap, c.name) || valuesMap[c.name] === undefined;
    })
    .map((c) => c.name);

  return { missing, idIsAutoInt, colSet };
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS(request) });
  }
  if (request.method !== "POST") {
    return json(request, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env?.DB) {
      return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);
    }

    // ✅ تأكد من وجود الجداول الأساسية
    const schema = await ensureBaseTables(env.DB);
    if (!schema.ok) {
      return json(request, { ok: false, error: schema.error }, 500);
    }

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const otpIn = String(body.otp ?? "").trim();

    if (!email || !otpIn) {
      return json(request, { ok: false, error: "MISSING_FIELDS" }, 400);
    }

    // ✅ لازم pending_users موجود وفيه بيانات التسجيل المؤقتة
    if (!(await tableExists(env.DB, "pending_users"))) {
      return json(request, { ok: false, error: "PENDING_USERS_TABLE_NOT_FOUND" }, 500);
    }

    const pendingCols = await tableInfo(env.DB, "pending_users");
    if (!pendingCols.length || !hasCol(pendingCols, "email")) {
      return json(request, { ok: false, error: "PENDING_USERS_SCHEMA_INVALID" }, 500);
    }

    // أعمدة مطلوبة للتدفق (حسب register.js v5)
    const must = ["password_hash", "password_salt", "otp", "otp_expires_at"];
    const missingPending = must.filter((c) => !hasCol(pendingCols, c));
    if (missingPending.length) {
      return json(request, { ok: false, error: "PENDING_USERS_SCHEMA_MISSING_COLS", missing: missingPending }, 500);
    }

    const pending = await env.DB.prepare(
      `SELECT email, password_hash, password_salt, otp, otp_expires_at
       FROM pending_users WHERE email = ? LIMIT 1`
    ).bind(email).first();

    if (!pending) {
      return json(request, { ok: false, error: "PENDING_USER_NOT_FOUND" }, 404);
    }

    const otpDb = String(pending.otp || "").trim();
    const exp = Number(pending.otp_expires_at || 0);

    if (!otpDb) return json(request, { ok: false, error: "OTP_NOT_FOUND" }, 404);
    if (otpDb !== otpIn) return json(request, { ok: false, error: "OTP_INVALID" }, 401);

    if (exp && nowMs() > exp) {
      return json(request, { ok: false, error: "OTP_EXPIRED" }, 410);
    }

    // ✅ جهز بيانات user حسب أعمدة users الموجودة فعليًا
    const usersCols = await tableInfo(env.DB, "users");
    if (!usersCols.length || !hasCol(usersCols, "email")) {
      return json(request, { ok: false, error: "USERS_SCHEMA_INVALID" }, 500);
    }

    const saltB64 = String(pending.password_salt || "").trim(); // هذا هو salt b64 من register
    const t = nowMs();

    // نجهز قيم عامة، وبنحط اللي موجود فقط بالأعمدة
    const valuesMap = {
      email,
      provider: "email",
      password_hash: pending.password_hash,

      // توافق: لو عندك salt_b64 أو password_salt أو salt
      salt_b64: saltB64 || null,
      password_salt: saltB64 || null,
      salt: saltB64 || null,

      // توثيق
      is_email_verified: 1,
      email_verified: 1,

      created_at: t,
      updated_at: t,
    };

    const { missing: missingUsersRequired, idIsAutoInt, colSet } = buildMissingRequired(usersCols, valuesMap);

    // لو عندك جدول users قديم فيه أعمدة NOT NULL غريبة بدون default → نطلعها لك واضح
    if (missingUsersRequired.length) {
      console.log("verify_email_users_missing_required", email, missingUsersRequired);
      return json(request, {
        ok: false,
        error: "USERS_SCHEMA_MISSING_REQUIRED_COLS",
        missing: missingUsersRequired
      }, 500);
    }

    const existing = await env.DB.prepare(
      "SELECT email FROM users WHERE email = ? LIMIT 1"
    ).bind(email).first();

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

      await env.DB.prepare(sql).bind(...insertVals).run();
    } else {
      // UPDATE (نثبت كلمة المرور + الملح + التوثيق)
      if (colSet.has("password_hash")) {
        await env.DB.prepare("UPDATE users SET password_hash=? WHERE email=?")
          .bind(pending.password_hash, email).run();
      }

      if (saltB64) {
        if (colSet.has("salt_b64")) {
          await env.DB.prepare("UPDATE users SET salt_b64=? WHERE email=?")
            .bind(saltB64, email).run();
        }
        if (colSet.has("password_salt")) {
          await env.DB.prepare("UPDATE users SET password_salt=? WHERE email=?")
            .bind(saltB64, email).run();
        }
        if (colSet.has("salt")) {
          await env.DB.prepare("UPDATE users SET salt=? WHERE email=?")
            .bind(saltB64, email).run();
        }
      }

      if (colSet.has("is_email_verified")) {
        await env.DB.prepare("UPDATE users SET is_email_verified=1 WHERE email=?")
          .bind(email).run();
      }
      if (colSet.has("email_verified")) {
        await env.DB.prepare("UPDATE users SET email_verified=1 WHERE email=?")
          .bind(email).run();
      }
      if (colSet.has("updated_at")) {
        await env.DB.prepare("UPDATE users SET updated_at=? WHERE email=?")
          .bind(t, email).run();
      }
    }

    // ✅ تأكد أنه صار موجود
    const ensured = await env.DB.prepare(
      "SELECT email FROM users WHERE email = ? LIMIT 1"
    ).bind(email).first();

    if (!ensured) {
      return json(request, { ok: false, error: "USER_NOT_CREATED" }, 500);
    }

    // ✅ نظافة: احذف pending
    await env.DB.prepare("DELETE FROM pending_users WHERE email=?").bind(email).run();

    return json(request, { ok: true, email, verified: true }, 200);

  } catch (e) {
    console.log("verify_email_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
verify-email.js – api2 – إصدار 4 (Schema Guard + OTP expiry + salt compatibility)
*/
