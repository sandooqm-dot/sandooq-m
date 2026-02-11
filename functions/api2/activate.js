// functions/api2/activate.js
// POST /api2/activate
// v4: Fix NOT NULL activations.activated_at by inserting required cols dynamically.

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

export async function onRequestOptions() {
  return new Response(null, { headers: CORS_HEADERS });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeCode(code) {
  return String(code || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "")
    .replace(/[–—−]/g, "-");
}

function nowIso() {
  return new Date().toISOString();
}

function parseCookies(cookieHeader) {
  const out = {};
  const s = String(cookieHeader || "");
  s.split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i === -1) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function bearerToken(req) {
  const h = req.headers.get("authorization") || req.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

async function dbAll(DB, label, sql, binds = []) {
  try {
    return await DB.prepare(sql).bind(...binds).all();
  } catch (e) {
    throw new Error(`${label}: ${String(e?.message || e)}`);
  }
}
async function dbFirst(DB, label, sql, binds = []) {
  try {
    return await DB.prepare(sql).bind(...binds).first();
  } catch (e) {
    throw new Error(`${label}: ${String(e?.message || e)}`);
  }
}
async function dbRun(DB, label, sql, binds = []) {
  try {
    return await DB.prepare(sql).bind(...binds).run();
  } catch (e) {
    throw new Error(`${label}: ${String(e?.message || e)}`);
  }
}

async function tableInfo(DB, tableName) {
  const r = await dbAll(DB, `PRAGMA table_info(${tableName})`, `PRAGMA table_info(${tableName});`);
  // كل عنصر: { cid, name, type, notnull, dflt_value, pk }
  return (r?.results || []).map((x) => ({
    name: String(x.name),
    type: String(x.type || ""),
    notnull: Number(x.notnull || 0),
    dflt: x.dflt_value,
  }));
}

function valueForAtColumn(colType) {
  // إذا كان العمود INT نخزن timestamp (ms)
  const t = String(colType || "").toUpperCase();
  if (t.includes("INT")) return Date.now();
  return nowIso();
}

function autoValueForRequiredCol(colName, colType) {
  const n = String(colName || "").toLowerCase();

  // أي عمود ينتهي بـ _at (مثل activated_at / created_at / updated_at)
  if (n.endsWith("_at")) return valueForAtColumn(colType);

  // أعمدة منطقية/حالة شائعة
  if (n === "activated" || n === "is_activated" || n === "is_active" || n === "used" || n === "is_used") return 1;

  // status
  if (n === "status") return "used";

  // fallback
  return null;
}

async function ensureActivationsTable(DB) {
  // إنشاء جدول لو ما كان موجود (بشكل متسامح)
  await dbRun(
    DB,
    "ensureActivationsTable:CREATE",
    `
    CREATE TABLE IF NOT EXISTS activations (
      code TEXT NOT NULL,
      email TEXT,
      device_id TEXT NOT NULL,
      activated_at TEXT NOT NULL,
      created_at TEXT,
      PRIMARY KEY (code, device_id)
    );
  `
  );

  // لو الجدول قديم، نحاول نضيف أعمدة ناقصة (بدون كسر)
  const info = await tableInfo(DB, "activations");
  const cols = new Set(info.map((x) => x.name));

  async function addCol(sqlLabel, sql) {
    try { await dbRun(DB, sqlLabel, sql); } catch {}
  }

  if (!cols.has("code")) await addCol("ADD code", `ALTER TABLE activations ADD COLUMN code TEXT;`);
  if (!cols.has("email")) await addCol("ADD email", `ALTER TABLE activations ADD COLUMN email TEXT;`);
  if (!cols.has("device_id")) await addCol("ADD device_id", `ALTER TABLE activations ADD COLUMN device_id TEXT;`);
  if (!cols.has("created_at")) await addCol("ADD created_at", `ALTER TABLE activations ADD COLUMN created_at TEXT;`);

  // الأهم: activated_at
  if (!cols.has("activated_at")) {
    // نضيفه (قد يكون NOT NULL عندك، بس لو أضفناه هنا بيكون NULL افتراضياً للصفوف القديمة)
    // ومع ذلك إحنا الآن وقت الإدخال بنعطيه قيمة دائماً.
    await addCol("ADD activated_at", `ALTER TABLE activations ADD COLUMN activated_at TEXT;`);
  }
}

async function getSessionEmail(DB, req) {
  let token = bearerToken(req);

  if (!token) {
    const cookies = parseCookies(req.headers.get("Cookie") || "");
    token =
      cookies["sandooq_session_v1"] ||
      cookies["sandooq_session"] ||
      cookies["sandooq_token_v1"] ||
      cookies["token"] ||
      "";
  }

  token = String(token || "").trim();
  if (!token) return { ok: false, error: "UNAUTHORIZED" };

  let row = await dbFirst(DB, "getSessionEmail:email", `SELECT email FROM sessions WHERE token = ? LIMIT 1`, [token]);
  let email = normalizeEmail(row?.email);

  if (!email) {
    row = await dbFirst(DB, "getSessionEmail:user_email", `SELECT user_email FROM sessions WHERE token = ? LIMIT 1`, [token]);
    email = normalizeEmail(row?.user_email);
  }

  if (!email) return { ok: false, error: "SESSION_NOT_FOUND" };
  return { ok: true, email, token };
}

async function listTables(DB) {
  const r = await dbAll(
    DB,
    "listTables",
    `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;`
  );
  return (r?.results || []).map((x) => String(x.name));
}

function pickFirst(cols, names) {
  for (const n of names) if (cols.includes(n)) return n;
  return null;
}

async function detectCodesTable(DB) {
  const tables = await listTables(DB);
  const codeColCandidates = ["code", "activation_code", "license", "key"];

  let best = null;

  for (const t of tables) {
    if (t === "sessions" || t === "users" || t === "pending_users" || t === "activations") continue;

    let info = [];
    try { info = await tableInfo(DB, t); } catch { continue; }
    const cols = info.map((x) => x.name);

    const codeCol = pickFirst(cols, codeColCandidates);
    if (!codeCol) continue;

    const ownerCol = pickFirst(cols, ["used_by_email", "bound_email", "owner_email", "used_email", "email"]);
    const isUsedCol = pickFirst(cols, ["is_used", "used", "activated", "is_activated"]);
    const usedAtCol = pickFirst(cols, ["used_at", "activated_at"]);
    const statusCol = pickFirst(cols, ["status"]);
    const limitCol = pickFirst(cols, ["device_limit", "max_devices", "devices_limit"]);

    let score = 10;
    if (ownerCol) score += 5;
    if (isUsedCol) score += 3;
    if (usedAtCol) score += 2;
    if (statusCol) score += 2;
    if (limitCol) score += 1;

    if (!best || score > best.score) {
      best = { table: t, cols, codeCol, ownerCol, isUsedCol, usedAtCol, statusCol, limitCol, score };
    }
  }

  return { best, tables };
}

async function insertActivationSmart(DB, { code, email, deviceId }) {
  const info = await tableInfo(DB, "activations");

  const cols = info.map((x) => x.name);
  const meta = Object.fromEntries(info.map((x) => [x.name, x]));

  // نبني INSERT حسب الأعمدة الموجودة + نعبي أي NOT NULL بدون default بقيم تلقائية
  const fields = [];
  const placeholders = [];
  const binds = [];

  function addField(name, value) {
    if (!cols.includes(name)) return;
    fields.push(name);
    placeholders.push("?");
    binds.push(value);
  }

  addField("code", code);
  addField("email", email);
  addField("device_id", deviceId);

  // الأهم: activated_at / created_at إن وجدت
  if (cols.includes("activated_at")) addField("activated_at", valueForAtColumn(meta["activated_at"]?.type));
  if (cols.includes("created_at")) addField("created_at", valueForAtColumn(meta["created_at"]?.type));

  // أي أعمدة NOT NULL بدون default وما انضافت = نعبيها تلقائي
  for (const c of info) {
    if (!c.notnull) continue;
    if (c.dflt != null) continue;
    if (fields.includes(c.name)) continue;

    const v = autoValueForRequiredCol(c.name, c.type);
    if (v === null) {
      // ما نقدر نخمن قيمة آمنة
      throw new Error(`REQUIRED_COL_MISSING:${c.name}`);
    }
    addField(c.name, v);
  }

  await dbRun(
    DB,
    "insertActivation",
    `INSERT INTO activations (${fields.join(",")}) VALUES (${placeholders.join(",")})`,
    binds
  );
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    if (!env.DB) return json({ ok: false, error: "DB_NOT_BOUND" }, 500);

    const deviceId = String(request.headers.get("X-Device-Id") || "").trim();
    if (!deviceId) return json({ ok: false, error: "MISSING_DEVICE_ID" }, 400);

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "BAD_JSON" }, 400);

    const code = normalizeCode(body.code);
    if (!code) return json({ ok: false, error: "MISSING_FIELDS" }, 400);

    // auth -> email
    const ses = await getSessionEmail(env.DB, request);
    if (!ses.ok) return json({ ok: false, error: ses.error }, 401);
    const email = ses.email;

    // ensure activations table exists / columns
    await ensureActivationsTable(env.DB);

    // detect codes table
    const { best, tables } = await detectCodesTable(env.DB);
    if (!best) {
      return json(
        { ok: false, error: `CODES_TABLE_NOT_FOUND|tables=${tables.join(",")}` },
        500
      );
    }

    const {
      table: codesTable,
      codeCol,
      ownerCol,
      isUsedCol,
      usedAtCol,
      statusCol,
      limitCol,
    } = best;

    const codeRow = await dbFirst(
      env.DB,
      "loadCodeRow",
      `SELECT * FROM ${codesTable} WHERE ${codeCol} = ? LIMIT 1`,
      [code]
    );

    if (!codeRow) return json({ ok: false, error: "CODE_NOT_FOUND" }, 404);

    const boundEmail = ownerCol ? normalizeEmail(codeRow[ownerCol]) : "";

    if (boundEmail && boundEmail !== email) {
      return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    if (!boundEmail && isUsedCol && Number(codeRow[isUsedCol] || 0) === 1) {
      return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
    }
    if (!boundEmail && statusCol && String(codeRow[statusCol] || "").toLowerCase() === "used") {
      return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    // device limit
    let limit = 2;
    if (limitCol) {
      const v = Number(codeRow[limitCol]);
      if (Number.isFinite(v) && v >= 1) limit = v;
    }

    // already on same device?
    const existing = await dbFirst(
      env.DB,
      "checkExistingActivation",
      `SELECT device_id FROM activations WHERE code = ? AND device_id = ? LIMIT 1`,
      [code, deviceId]
    );

    if (!existing) {
      const cntRow = await dbFirst(
        env.DB,
        "countActivations",
        `SELECT COUNT(*) AS n FROM activations WHERE code = ? AND email = ?`,
        [code, email]
      );

      const n = Number(cntRow?.n || 0);
      if (n >= limit) return json({ ok: false, error: "DEVICE_LIMIT_REACHED" }, 409);

      await insertActivationSmart(env.DB, { code, email, deviceId });
    }

    // bind to email (first time)
    if (ownerCol && !boundEmail) {
      const sets = [];
      const binds = [];

      sets.push(`${ownerCol} = ?`);
      binds.push(email);

      if (isUsedCol) sets.push(`${isUsedCol} = 1`);
      if (usedAtCol) {
        sets.push(`${usedAtCol} = ?`);
        binds.push(Date.now());
      }
      if (statusCol) {
        sets.push(`${statusCol} = ?`);
        binds.push("used");
      }

      await dbRun(
        env.DB,
        "bindCodeToEmail",
        `UPDATE ${codesTable} SET ${sets.join(", ")} WHERE ${codeCol} = ?`,
        [...binds, code]
      );
    }

    return json({ ok: true, activated: true, email, code, deviceId }, 200);
  } catch (e) {
    const msg = String(e?.message || e || "unknown");
    return json({ ok: false, error: `SERVER_ERROR|${msg}` }, 500);
  }
}

/*
functions/api2/activate.js – v4
*/
