// functions/api2/reset.js
// POST /api2/reset
// Reset password using token stored in D1 password_resets (created by /api2/forgot)

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin");
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
  return new Response(JSON.stringify(data), {
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

function isStrongEnough(pw) {
  return String(pw || "").length >= 8;
}

async function tableCols(DB, table) {
  const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
  return new Set((res?.results || []).map((r) => String(r.name)));
}

async function tableExists(DB, table) {
  const r = await DB.prepare(
    `SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1`
  ).bind(table).first();
  return !!r?.name;
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(String(str));
  const digest = await crypto.subtle.digest("SHA-256", data);
  const b = new Uint8Array(digest);
  let hex = "";
  for (const x of b) hex += x.toString(16).padStart(2, "0");
  return hex;
}

function b64FromBytes(arr) {
  // arr صغير (16/32) فـ String.fromCharCode آمنة هنا
  return btoa(String.fromCharCode(...arr));
}

async function pbkdf2Base64(password, saltBytes, iterations = 210000, length = 32) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(String(password)),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    key,
    length * 8
  );

  return b64FromBytes(new Uint8Array(bits));
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS(request) });
  }
  if (request.method !== "POST") {
    return json(request, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env?.DB) return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);

    // نقرأ body
    const body = await request.json().catch(() => ({}));

    // token ممكن يجي بعدة أسماء + احتياط من Authorization (لو الفرونت خزّنه بالغلط)
    const auth = request.headers.get("Authorization") || "";
    const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

    const token =
      String(body?.token || body?.reset_token || body?.resetToken || bearer || "").trim();

    // كلمة المرور ممكن تجي بأسماء مختلفة
    const password =
      String(body?.password || body?.new_password || body?.newPassword || "").trim();

    // email اختياري (ما نعتمد عليه) لكن إذا جاء نطابقه مع اللي في التوكن
    const maybeEmail = body?.email ? normalizeEmail(body.email) : "";

    if (!token) return json(request, { ok: false, error: "RESET_TOKEN_NOT_FOUND" }, 400);
    if (!password) return json(request, { ok: false, error: "MISSING_PASSWORD" }, 400);
    if (!isStrongEnough(password)) return json(request, { ok: false, error: "WEAK_PASSWORD" }, 400);

    // لازم جدول password_resets موجود (forgot.js يسويه، لكن هنا احتياط)
    if (!(await tableExists(env.DB, "password_resets"))) {
      return json(request, { ok: false, error: "RESET_TOKEN_NOT_FOUND" }, 400);
    }

    const now = Date.now();
    const tokenHash = await sha256Hex(token);

    const row = await env.DB.prepare(
      `SELECT email, expires_at, used_at
         FROM password_resets
        WHERE token_hash = ?
        LIMIT 1`
    ).bind(tokenHash).first();

    if (!row) {
      return json(request, { ok: false, error: "RESET_TOKEN_NOT_FOUND" }, 400);
    }

    if (row.used_at) {
      return json(request, { ok: false, error: "RESET_TOKEN_USED" }, 400);
    }

    if (Number(row.expires_at || 0) < now) {
      return json(request, { ok: false, error: "RESET_TOKEN_EXPIRED" }, 400);
    }

    const email = normalizeEmail(row.email);

    // لو الفرونت مرر email، لازم يطابق (اختياري)
    if (maybeEmail && maybeEmail !== email) {
      return json(request, { ok: false, error: "EMAIL_MISMATCH" }, 400);
    }

    // تحديث كلمة المرور في users
    const uCols = await tableCols(env.DB, "users");

    // نحدد أعمدة الباسورد المتاحة
    const hashCol =
      (uCols.has("password_hash") && "password_hash") ||
      (uCols.has("pass_hash") && "pass_hash") ||
      (uCols.has("pw_hash") && "pw_hash") ||
      (uCols.has("hash") && "hash") ||
      "";

    if (!hashCol) {
      return json(request, { ok: false, error: "USERS_SCHEMA_MISSING_PASSWORD_COL" }, 500);
    }

    // إذا فيه salt_b64 نستخدم PBKDF2، وإلا نحط SHA256 legacy
    let newHash = "";
    let newSaltB64 = "";

    if (uCols.has("salt_b64")) {
      const salt = new Uint8Array(16);
      crypto.getRandomValues(salt);
      newSaltB64 = b64FromBytes(salt);
      newHash = await pbkdf2Base64(password, salt, 210000, 32);
    } else {
      newHash = await sha256Hex(password);
    }

    // UPDATE users
    const sets = [];
    const binds = [];

    sets.push(`${hashCol} = ?`);
    binds.push(newHash);

    if (uCols.has("salt_b64")) {
      sets.push(`salt_b64 = ?`);
      binds.push(newSaltB64);
    }

    if (uCols.has("updated_at")) {
      sets.push(`updated_at = ?`);
      binds.push(new Date().toISOString());
    }

    binds.push(email);

    const upd = await env.DB.prepare(
      `UPDATE users SET ${sets.join(", ")} WHERE email = ?`
    ).bind(...binds).run();

    // لو ما فيه مستخدم فعليًا (احتياط)
    if (!upd?.success) {
      // D1 أحيانًا ما يعطي affected_rows بشكل ثابت، فنسوي تحقق سريع
      const u = await env.DB.prepare(`SELECT email FROM users WHERE email=? LIMIT 1`).bind(email).first();
      if (!u?.email) return json(request, { ok: false, error: "USER_NOT_FOUND" }, 400);
    }

    // نعلّم التوكن كمستخدم
    await env.DB.prepare(
      `UPDATE password_resets SET used_at = ? WHERE token_hash = ?`
    ).bind(now, tokenHash).run();

    return json(request, { ok: true }, 200);

  } catch (e) {
    console.log("reset_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
reset.js – api2 – إصدار 1 (robust token+password, derive email from token, PBKDF2 if salt_b64 exists)
*/
