// functions/api2/verify-email.js
// Cloudflare Pages Function: POST /api2/verify-email

const VERSION = "api2-verify-email-v5-compat";

export async function onRequest(context) {
  const { request, env } = context;

  const cors = makeCorsHeaders(request, env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }
  if (request.method !== "POST") {
    return json(cors, { ok: false, error: "METHOD_NOT_ALLOWED", version: VERSION }, 405);
  }

  try {
    if (!env?.DB) {
      return json(cors, { ok: false, error: "DB_NOT_BOUND", version: VERSION }, 500);
    }

    // ✅ تأكد من وجود الجداول + الأعمدة الأساسية (مرن ومتوافق)
    const schema = await ensureSchema(env.DB);
    if (!schema.ok) {
      return json(cors, { ok: false, ...schema, version: VERSION }, 500);
    }

    const body = await request.json().catch(() => ({}));
    const email = normalizeEmail(body.email);
    const otpIn = String(body.otp ?? "").trim();

    if (!email || !otpIn) {
      return json(cors, { ok: false, error: "MISSING_FIELDS", version: VERSION }, 400);
    }

    // ✅ اقرأ من pending_users
    const pending = await env.DB.prepare(
      `SELECT * FROM pending_users WHERE email = ? LIMIT 1`
    ).bind(email).first();

    if (!pending) {
      return json(cors, { ok: false, error: "PENDING_USER_NOT_FOUND", version: VERSION }, 404);
    }

    const otpDb = String(pending.otp || "").trim();
    const exp = Number(pending.otp_expires_at || 0);

    if (!otpDb) {
      return json(cors, { ok: false, error: "OTP_NOT_FOUND", version: VERSION }, 404);
    }
    if (otpDb !== otpIn) {
      return json(cors, { ok: false, error: "OTP_INVALID", version: VERSION }, 401);
    }
    if (exp && Date.now() > exp) {
      return json(cors, { ok: false, error: "OTP_EXPIRED", version: VERSION }, 410);
    }

    // ✅ جهز بيانات users حسب الأعمدة الموجودة فعليًا
    const usersInfo = await tableInfo(env.DB, "users");
    const usersCols = new Map(usersInfo.map(c => [c.name, c]));
    if (!usersCols.has("email")) {
      return json(cors, { ok: false, error: "USERS_SCHEMA_INVALID", version: VERSION }, 500);
    }

    const saltB64 = String(pending.password_salt || pending.salt_b64 || pending.salt || "").trim();
    const passHash = String(pending.password_hash || "").trim();

    const nowIso = new Date().toISOString();
    const nowMs = Date.now();

    // helper يختار نوع التاريخ حسب نوع العمود
    const tsFor = (colName) => {
      const meta = usersCols.get(colName);
      const t = String(meta?.type || "").toUpperCase();
      return t.includes("INT") ? nowMs : nowIso;
    };

    // ✅ هل المستخدم موجود؟
    const existing = await env.DB.prepare(
      `SELECT email FROM users WHERE email = ? LIMIT 1`
    ).bind(email).first();

    if (!existing) {
      // INSERT ديناميكي: نحط فقط الأعمدة الموجودة
      const values = new Map();
      values.set("email", email);

      if (usersCols.has("provider")) values.set("provider", "email");

      if (usersCols.has("password_hash")) values.set("password_hash", passHash);

      // توافق الملح: نخزن نفس القيمة في أكثر من عمود إذا موجود
      if (saltB64) {
        if (usersCols.has("password_salt")) values.set("password_salt", saltB64);
        if (usersCols.has("salt_b64")) values.set("salt_b64", saltB64);
        if (usersCols.has("salt")) values.set("salt", saltB64);
      }

      // توثيق البريد: نخزن كل الأعمدة الشائعة إذا موجودة
      if (usersCols.has("is_email_verified")) values.set("is_email_verified", 1);
      if (usersCols.has("email_verified")) values.set("email_verified", 1);
      if (usersCols.has("verified")) values.set("verified", 1);
      if (usersCols.has("is_verified")) values.set("is_verified", 1);

      if (usersCols.has("created_at")) values.set("created_at", tsFor("created_at"));
      if (usersCols.has("updated_at")) values.set("updated_at", tsFor("updated_at"));
      if (usersCols.has("last_login_at")) values.set("last_login_at", tsFor("last_login_at"));

      // ✅ سد أي أعمدة NOT NULL بدون default (لو موجودة) بقيم آمنة
      const missRequired = missingRequired(usersInfo, Object.fromEntries(values));
      if (missRequired.length) {
        return json(cors, {
          ok: false,
          error: "USERS_SCHEMA_MISSING_REQUIRED_COLS",
          missing: missRequired,
          version: VERSION
        }, 500);
      }

      const cols = Array.from(values.keys());
      const qs = cols.map(() => "?").join(",");
      const sql = `INSERT INTO users (${cols.join(",")}) VALUES (${qs})`;

      await env.DB.prepare(sql).bind(...cols.map(k => values.get(k))).run();

    } else {
      // UPDATE: ثبّت التوثيق + hash + salt
      if (usersCols.has("password_hash") && passHash) {
        await env.DB.prepare(`UPDATE users SET password_hash=? WHERE email=?`)
          .bind(passHash, email).run();
      }

      if (saltB64) {
        if (usersCols.has("password_salt")) {
          await env.DB.prepare(`UPDATE users SET password_salt=? WHERE email=?`)
            .bind(saltB64, email).run();
        }
        if (usersCols.has("salt_b64")) {
          await env.DB.prepare(`UPDATE users SET salt_b64=? WHERE email=?`)
            .bind(saltB64, email).run();
        }
        if (usersCols.has("salt")) {
          await env.DB.prepare(`UPDATE users SET salt=? WHERE email=?`)
            .bind(saltB64, email).run();
        }
      }

      if (usersCols.has("provider")) {
        await env.DB.prepare(`UPDATE users SET provider='email' WHERE email=?`)
          .bind(email).run();
      }

      if (usersCols.has("is_email_verified")) {
        await env.DB.prepare(`UPDATE users SET is_email_verified=1 WHERE email=?`)
          .bind(email).run();
      }
      if (usersCols.has("email_verified")) {
        await env.DB.prepare(`UPDATE users SET email_verified=1 WHERE email=?`)
          .bind(email).run();
      }
      if (usersCols.has("verified")) {
        await env.DB.prepare(`UPDATE users SET verified=1 WHERE email=?`)
          .bind(email).run();
      }
      if (usersCols.has("is_verified")) {
        await env.DB.prepare(`UPDATE users SET is_verified=1 WHERE email=?`)
          .bind(email).run();
      }
      if (usersCols.has("updated_at")) {
        await env.DB.prepare(`UPDATE users SET updated_at=? WHERE email=?`)
          .bind(tsFor("updated_at"), email).run();
      }
    }

    // ✅ نظافة: احذف pending بعد نجاح التوثيق
    await env.DB.prepare(`DELETE FROM pending_users WHERE email=?`).bind(email).run();

    return json(cors, { ok: true, email, verified: true, version: VERSION }, 200);

  } catch (e) {
    console.log("verify_email_error", String(e?.message || e));
    return json(cors, { ok: false, error: "SERVER_ERROR", version: VERSION }, 500);
  }
}

/* ---------- helpers ---------- */

function json(corsHeaders, obj, status = 200) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(obj), { status, headers });
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function makeCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || request.headers.get("origin") || "";
  const allowedRaw = String(env?.ALLOWED_ORIGINS || "").trim();

  let allowOrigin = origin || "*";
  if (allowedRaw) {
    const allowed = allowedRaw.split(",").map(s => s.trim()).filter(Boolean);
    if (allowed.includes("*")) allowOrigin = origin || "*";
    else if (origin && allowed.includes(origin)) allowOrigin = origin;
    else allowOrigin = allowed[0] || (origin || "*");
  }

  const h = {
    "Access-Control-Allow-Origin": allowOrigin,
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
  };

  // credentials ممنوع مع "*"
  if (allowOrigin !== "*") {
    h["Access-Control-Allow-Credentials"] = "true";
  }

  return h;
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

async function tableCols(DB, table) {
  const info = await tableInfo(DB, table);
  return new Set(info.map(x => x.name));
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

async function addColIfMissing(DB, table, colsSet, colName, colDef) {
  if (colsSet.has(colName)) return;
  try {
    await DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${colName} ${colDef};`).run();
    colsSet.add(colName);
  } catch {
    // ignore
  }
}

function missingRequired(tableInfoArr, valuesObj) {
  const cols = tableInfoArr || [];
  const missing = [];

  for (const c of cols) {
    if (c.pk === 1) continue;
    if (c.notnull !== 1) continue;
    if (!(c.dflt_value === null || c.dflt_value === undefined)) continue;

    if (c.name === "email") continue;

    if (!Object.prototype.hasOwnProperty.call(valuesObj, c.name) || valuesObj[c.name] === undefined) {
      missing.push(c.name);
    }
  }
  return missing;
}

async function ensureSchema(DB) {
  try {
    // جداول أساسية (توافق)
    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS pending_users (
        email TEXT PRIMARY KEY,
        password_hash TEXT,
        password_salt TEXT,
        salt_b64 TEXT,
        otp TEXT,
        otp_expires_at INTEGER,
        created_at INTEGER,
        updated_at INTEGER
      );
    `).run();

    await DB.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        provider TEXT DEFAULT 'email',
        password_hash TEXT,
        password_salt TEXT,
        salt_b64 TEXT,
        salt TEXT,
        verified INTEGER DEFAULT 0,
        is_verified INTEGER DEFAULT 0,
        is_email_verified INTEGER DEFAULT 0,
        email_verified INTEGER DEFAULT 0,
        created_at TEXT,
        updated_at TEXT,
        last_login_at TEXT,
        google_sub TEXT
      );
    `).run();

  } catch (e) {
    console.log("verify_email_schema_create_failed", String(e?.message || e));
    return { ok: false, error: "SCHEMA_CREATE_FAILED" };
  }

  // ✅ تأكد من الأعمدة الأساسية + أضف أعمدة ناقصة للتوافق
  try {
    if (!(await tableExists(DB, "pending_users"))) return { ok: false, error: "PENDING_USERS_TABLE_NOT_FOUND" };
    if (!(await tableExists(DB, "users"))) return { ok: false, error: "USERS_TABLE_NOT_FOUND" };

    const pCols = await tableCols(DB, "pending_users");
    if (!pCols.has("email")) return { ok: false, error: "PENDING_USERS_SCHEMA_INVALID" };

    await addColIfMissing(DB, "pending_users", pCols, "password_hash", "TEXT");
    await addColIfMissing(DB, "pending_users", pCols, "password_salt", "TEXT");
    await addColIfMissing(DB, "pending_users", pCols, "salt_b64", "TEXT");
    await addColIfMissing(DB, "pending_users", pCols, "otp", "TEXT");
    await addColIfMissing(DB, "pending_users", pCols, "otp_expires_at", "INTEGER");
    await addColIfMissing(DB, "pending_users", pCols, "created_at", "INTEGER");
    await addColIfMissing(DB, "pending_users", pCols, "updated_at", "INTEGER");

    const mustP = ["email","password_hash","password_salt","otp","otp_expires_at"];
    const missingP = mustP.filter(x => !pCols.has(x));
    if (missingP.length) {
      return { ok: false, error: "PENDING_USERS_SCHEMA_MISSING_COLS", missing: missingP };
    }

    const uCols = await tableCols(DB, "users");
    if (!uCols.has("email")) return { ok: false, error: "USERS_SCHEMA_INVALID" };

    await addColIfMissing(DB, "users", uCols, "provider", "TEXT DEFAULT 'email'");
    await addColIfMissing(DB, "users", uCols, "password_hash", "TEXT");
    await addColIfMissing(DB, "users", uCols, "password_salt", "TEXT");
    await addColIfMissing(DB, "users", uCols, "salt_b64", "TEXT");
    await addColIfMissing(DB, "users", uCols, "salt", "TEXT");
    await addColIfMissing(DB, "users", uCols, "verified", "INTEGER DEFAULT 0");
    await addColIfMissing(DB, "users", uCols, "is_verified", "INTEGER DEFAULT 0");
    await addColIfMissing(DB, "users", uCols, "is_email_verified", "INTEGER DEFAULT 0");
    await addColIfMissing(DB, "users", uCols, "email_verified", "INTEGER DEFAULT 0");
    await addColIfMissing(DB, "users", uCols, "created_at", "TEXT");
    await addColIfMissing(DB, "users", uCols, "updated_at", "TEXT");
    await addColIfMissing(DB, "users", uCols, "last_login_at", "TEXT");
    await addColIfMissing(DB, "users", uCols, "google_sub", "TEXT");

    return { ok: true };
  } catch (e) {
    console.log("verify_email_schema_guard_failed", String(e?.message || e));
    return { ok: false, error: "SCHEMA_GUARD_FAILED" };
  }
}

/*
verify-email.js – api2 – إصدار 5 (CORS مضبوط + schema compat + salt_b64/password_salt mirror)
*/
