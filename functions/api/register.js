// functions/api/register.js
export async function onRequest(context) {
  const { request, env } = context;

  // ===== CORS =====
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  const corsHeaders = {
    "Access-Control-Allow-Origin": allowed.includes(origin) ? origin : (allowed[0] || "*"),
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };

  function json(obj, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        ...corsHeaders,
        ...extraHeaders,
      },
    });
  }

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  if (request.method !== "POST") return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);

  if (!env.DB) return json({ ok: false, error: "DB_NOT_BOUND" }, 500);
  const db = env.DB;

  // ===== Helpers =====
  const nowISO = () => new Date().toISOString();

  function headerDeviceId(req) {
    return req.headers.get("X-Device-Id") || "";
  }

  function readDeviceId(req) {
    const u = new URL(req.url);
    const q = (u.searchParams.get("deviceId") || "").toString().trim();
    return q || headerDeviceId(req);
  }

  // PBKDF2 settings (Cloudflare cap: 100000)
  const PBKDF2_ITER = 100000;

  function toB64(bytes) {
    const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : new Uint8Array(bytes);
    let s = "";
    for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
  }

  function fromB64(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function pbkdf2Hash(password, saltB64) {
    const enc = new TextEncoder();
    const salt = fromB64(saltB64);

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
      keyMaterial,
      256
    );

    return toB64(bits);
  }

  function randomSaltB64() {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    return toB64(salt);
  }

  async function run(sql, binds = []) {
    // نستخدم prepare().run() بدل exec عشان الثبات
    const stmt = db.prepare(sql);
    const bound = binds.length ? stmt.bind(...binds) : stmt;
    return await bound.run();
  }

  async function all(sql, binds = []) {
    const stmt = db.prepare(sql);
    const bound = binds.length ? stmt.bind(...binds) : stmt;
    return await bound.all();
  }

  async function tableColumns(table) {
    // PRAGMA table_info(users) → يرجع rows فيها name
    let r = await all(`PRAGMA table_info(${table});`).catch(() => null);
    let rows = r?.results || [];

    // fallback
    if (!rows.length) {
      r = await all(`SELECT name FROM pragma_table_info(?)`, [table]).catch(() => null);
      rows = r?.results || [];
    }

    return new Set(rows.map(x => x.name));
  }

  async function ensureTablesAndMigrate() {
    // 1) Create tables if not exists (أحدث مخطط)
    await run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        provider TEXT NOT NULL DEFAULT 'email',
        password_hash TEXT NOT NULL,
        salt_b64 TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);

    await run(`
      CREATE TABLE IF NOT EXISTS activations (
        code TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        activated_at TEXT NOT NULL
      );
    `);

    await run(`
      CREATE TABLE IF NOT EXISTS code_ownership (
        code TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        linked_at TEXT NOT NULL
      );
    `);

    // 2) Migrate users table if old schema موجود
    const cols = await tableColumns("users");

    // لو كان جدول قديم وما فيه بعض الأعمدة، نضيفها بدون ما نكسر شيء
    if (!cols.has("provider")) {
      await run(`ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'email';`).catch(() => {});
    }
    if (!cols.has("password_hash")) {
      await run(`ALTER TABLE users ADD COLUMN password_hash TEXT;`).catch(() => {});
    }
    if (!cols.has("salt_b64")) {
      await run(`ALTER TABLE users ADD COLUMN salt_b64 TEXT NOT NULL DEFAULT '';`).catch(() => {});
    }
    if (!cols.has("created_at")) {
      await run(`ALTER TABLE users ADD COLUMN created_at TEXT NOT NULL DEFAULT '';`).catch(() => {});
    }
  }

  // ===== Main =====
  try {
    await ensureTablesAndMigrate();

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON" }, 400);

    const email = (body.email || "").toString().trim().toLowerCase();
    const password = (body.password || "").toString();
    const code = (body.code || "").toString().trim();
    const deviceId = (body.deviceId || "").toString().trim() || readDeviceId(request);

    if (!email || !password) return json({ ok: false, error: "MISSING_FIELDS" }, 400);

    // لو أرسل كود، لازم يكون مُفعل أولاً على نفس الجهاز
    if (code) {
      if (!deviceId) return json({ ok: false, error: "MISSING_DEVICE" }, 400);

      const act = await db.prepare(`SELECT code, device_id FROM activations WHERE code = ?`)
        .bind(code)
        .first();

      if (!act) return json({ ok: false, error: "ACTIVATE_FIRST" }, 409);

      if (act.device_id !== deviceId) {
        return json({ ok: false, error: "CODE_BOUND_TO_OTHER_DEVICE" }, 409);
      }
    }

    // هل المستخدم موجود؟
    const existing = await db.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
    if (existing) return json({ ok: false, error: "EMAIL_EXISTS" }, 409);

    const saltB64 = randomSaltB64();
    const passwordHash = await pbkdf2Hash(password, saltB64);

    // نقرأ أعمدة users الفعلية ونبني INSERT على الموجود (عشان أي مخطط قديم ما يكسرنا)
    const cols = await tableColumns("users");

    const insertCols = ["email"];
    const vals = [email];
    const qs = ["?"];

    // provider لو موجود
    if (cols.has("provider")) {
      insertCols.push("provider");
      vals.push("email"); // provider = email/password
      qs.push("?");
    }

    // password_hash لو موجود وإلا نحاول password (احتياط قديم)
    if (cols.has("password_hash")) {
      insertCols.push("password_hash");
      vals.push(passwordHash);
      qs.push("?");
    } else if (cols.has("password")) {
      insertCols.push("password");
      vals.push(passwordHash);
      qs.push("?");
    } else {
      // لو شيء غريب جدًا
      return json({ ok: false, error: "USERS_SCHEMA_INVALID" }, 500);
    }

    // salt_b64 لو موجود
    if (cols.has("salt_b64")) {
      insertCols.push("salt_b64");
      vals.push(saltB64);
      qs.push("?");
    }

    // created_at لو موجود
    if (cols.has("created_at")) {
      insertCols.push("created_at");
      vals.push(nowISO());
      qs.push("?");
    }

    await run(
      `INSERT INTO users (${insertCols.join(", ")}) VALUES (${qs.join(", ")})`,
      vals
    );

    // لو فيه كود، اربطه بالإيميل
    if (code) {
      await run(
        `INSERT OR REPLACE INTO code_ownership (code, email, linked_at) VALUES (?, ?, ?)`,
        [code, email, nowISO()]
      );
    }

    return json(
      {
        ok: true,
        email,
        pbkdf2Iterations: PBKDF2_ITER,
        linkedCode: code || null,
      },
      200
    );
  } catch (e) {
    return json(
      {
        ok: false,
        error: "REGISTER_FAILED",
        message: String(e?.message || e),
      },
      500
    );
  }
}

// register.js – إصدار 3
