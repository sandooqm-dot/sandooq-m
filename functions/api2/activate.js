// functions/api2/activate.js
// POST /api2/activate
// v2: fixes SERVER_ERROR by auto-migrating activations table (missing columns)

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

function normalizeCode(code) {
  return String(code || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "")
    .replace(/[–—−]/g, "-");
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

async function tableInfo(db, tableName) {
  const res = await db.prepare(`PRAGMA table_info(${tableName});`).all();
  return (res?.results || []).map((r) => String(r.name));
}

function nowIso() {
  return new Date().toISOString();
}

function nowMs() {
  return Date.now();
}

async function ensureActivationsTable(db) {
  // 1) Create if missing (new schema)
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS activations (
      code TEXT NOT NULL,
      email TEXT,
      device_id TEXT NOT NULL,
      created_at TEXT,
      PRIMARY KEY (code, device_id)
    );
  `).run();

  // 2) If table existed old/partial -> add missing cols safely
  const cols = await tableInfo(db, "activations");

  // add email if missing
  if (!cols.includes("email")) {
    try {
      await db.prepare(`ALTER TABLE activations ADD COLUMN email TEXT;`).run();
    } catch (e) {
      // ignore if not supported / already exists race
      console.log("activations_add_email_skip", String(e?.message || e));
    }
  }

  // add created_at if missing
  if (!cols.includes("created_at")) {
    try {
      await db.prepare(`ALTER TABLE activations ADD COLUMN created_at TEXT;`).run();
    } catch (e) {
      console.log("activations_add_created_at_skip", String(e?.message || e));
    }
  }

  // add device_id if somehow missing (rare)
  if (!cols.includes("device_id")) {
    try {
      await db.prepare(`ALTER TABLE activations ADD COLUMN device_id TEXT;`).run();
    } catch (e) {
      console.log("activations_add_device_skip", String(e?.message || e));
    }
  }

  // add code if somehow missing (rare)
  if (!cols.includes("code")) {
    try {
      await db.prepare(`ALTER TABLE activations ADD COLUMN code TEXT;`).run();
    } catch (e) {
      console.log("activations_add_code_skip", String(e?.message || e));
    }
  }
}

async function getSessionEmail(db, req) {
  // 1) Authorization Bearer
  let token = bearerToken(req);

  // 2) Cookie fallback (أسماء محتملة)
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

  const row = await db
    .prepare(`SELECT email FROM sessions WHERE token = ? LIMIT 1`)
    .bind(token)
    .first();

  const email = normalizeEmail(row?.email);
  if (!email) return { ok: false, error: "SESSION_NOT_FOUND" };

  return { ok: true, email, token };
}

async function findCodesTable(db) {
  const candidates = ["codes", "activation_codes", "license_codes", "game_codes"];
  for (const t of candidates) {
    try {
      const cols = await tableInfo(db, t);
      if (cols.length) return { table: t, cols };
    } catch {}
  }
  return { table: null, cols: [] };
}

function firstExistingCol(cols, names) {
  for (const n of names) if (cols.includes(n)) return n;
  return null;
}

export async function onRequestOptions() {
  return new Response(null, { headers: CORS_HEADERS });
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

    // session -> email
    const ses = await getSessionEmail(env.DB, request);
    if (!ses.ok) return json({ ok: false, error: ses.error }, 401);
    const email = ses.email;

    // ✅ IMPORTANT: fix most common SERVER_ERROR cause
    await ensureActivationsTable(env.DB);

    // locate codes table
    const { table: codesTable, cols: codesCols } = await findCodesTable(env.DB);
    if (!codesTable) return json({ ok: false, error: "CODES_TABLE_NOT_FOUND" }, 500);

    const codeCol = firstExistingCol(codesCols, ["code", "activation_code", "license", "key"]);
    if (!codeCol) return json({ ok: false, error: "CODES_SCHEMA_MISSING_CODE_COL" }, 500);

    const ownerCol = firstExistingCol(codesCols, [
      "used_by_email",
      "bound_email",
      "owner_email",
      "used_email",
      "email",
    ]);

    const isUsedCol = firstExistingCol(codesCols, ["is_used", "used", "activated", "is_activated"]);
    const usedAtCol = firstExistingCol(codesCols, ["used_at", "activated_at"]);
    const statusCol = firstExistingCol(codesCols, ["status"]);
    const limitCol = firstExistingCol(codesCols, ["device_limit", "max_devices", "devices_limit"]);

    // load code row
    const codeRow = await env.DB
      .prepare(`SELECT * FROM ${codesTable} WHERE ${codeCol} = ? LIMIT 1`)
      .bind(code)
      .first();

    if (!codeRow) return json({ ok: false, error: "CODE_NOT_FOUND" }, 404);

    const boundEmail = ownerCol ? normalizeEmail(codeRow[ownerCol]) : "";

    // already used by another account
    if (boundEmail && boundEmail !== email) {
      return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    // if code marks used (even if email col missing)
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

    // already activated on same device?
    const existing = await env.DB
      .prepare(`SELECT device_id FROM activations WHERE code = ? AND device_id = ? LIMIT 1`)
      .bind(code, deviceId)
      .first();

    if (!existing) {
      // count activations for this code+email (email may exist now by migration)
      const cntRow = await env.DB
        .prepare(`SELECT COUNT(*) AS n FROM activations WHERE code = ? AND email = ?`)
        .bind(code, email)
        .first();

      const n = Number(cntRow?.n || 0);
      if (n >= limit) return json({ ok: false, error: "DEVICE_LIMIT_REACHED" }, 409);

      // insert activation (after migration columns exist)
      await env.DB
        .prepare(
          `INSERT INTO activations (code, email, device_id, created_at)
           VALUES (?, ?, ?, ?)`
        )
        .bind(code, email, deviceId, nowIso())
        .run();
    }

    // bind code to email (first time only)
    if (ownerCol && !boundEmail) {
      const sets = [];
      const binds = [];

      sets.push(`${ownerCol} = ?`);
      binds.push(email);

      if (isUsedCol) sets.push(`${isUsedCol} = 1`);
      if (usedAtCol) {
        sets.push(`${usedAtCol} = ?`);
        binds.push(nowMs());
      }
      if (statusCol) {
        sets.push(`${statusCol} = ?`);
        binds.push("used");
      }

      await env.DB
        .prepare(`UPDATE ${codesTable} SET ${sets.join(", ")} WHERE ${codeCol} = ?`)
        .bind(...binds, code)
        .run();
    }

    return json(
      {
        ok: true,
        activated: true,
        email,
        code,
        deviceId,
      },
      200
    );
  } catch (e) {
    // بدل SERVER_ERROR المبهم: نطبع السبب في اللوق (والواجهة تبقى SERVER_ERROR)
    console.log("activate_error_v2", String(e?.message || e));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
activate.js – api2 – v2 (Auto-migrate activations columns to kill SERVER_ERROR)
*/
