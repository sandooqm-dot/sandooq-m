// functions/api2/activate.js
// Cloudflare Pages Function: POST /api2/activate

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
  try {
    const res = await db.prepare(`PRAGMA table_info(${tableName});`).all();
    return (res?.results || []).map((r) => ({
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

function hasCol(cols, name) {
  return cols.some((c) => c.name === name);
}

function firstExistingCol(cols, names) {
  for (const n of names) if (hasCol(cols, n)) return n;
  return null;
}

async function findFirstTable(db, candidates) {
  for (const t of candidates) {
    const cols = await tableInfo(db, t);
    if (cols.length) return { table: t, cols };
  }
  return { table: null, cols: [] };
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

  // sessions schema: (token,email,created_at,expires_at...) حسب جدولك
  try {
    const row = await db
      .prepare(`SELECT email FROM sessions WHERE token = ? LIMIT 1`)
      .bind(token)
      .first();

    const email = normalizeEmail(row?.email);
    if (!email) return { ok: false, error: "SESSION_NOT_FOUND" };

    return { ok: true, email, token };
  } catch (e) {
    console.log("activate_session_lookup_failed", String(e?.message || e));
    return { ok: false, error: "SESSION_LOOKUP_FAILED" };
  }
}

function nowIso() {
  return new Date().toISOString();
}

function nowMs() {
  return Date.now();
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

    const body = await request.json().catch(() => ({}));
    const codeRaw = body.code ?? body.activationCode ?? body.key ?? "";
    const code = normalizeCode(codeRaw);

    if (!code) return json({ ok: false, error: "MISSING_FIELDS" }, 400);

    // --- Auth (session -> email) ---
    const ses = await getSessionEmail(env.DB, request);
    if (!ses.ok) return json({ ok: false, error: ses.error }, 401);

    const email = ses.email;

    // --- Ensure activations table exists (عشان ما يطيح SERVER_ERROR) ---
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS activations (
        code TEXT NOT NULL,
        email TEXT NOT NULL,
        device_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (code, device_id)
      );
    `).run();

    // --- Find codes table (اسم الجدول يختلف عند بعض النسخ) ---
    const { table: codesTable, cols: codesCols } = await findFirstTable(env.DB, [
      "codes",
      "activation_codes",
      "license_codes",
      "game_codes",
    ]);

    if (!codesTable) {
      console.log("activate_codes_table_not_found");
      return json({ ok: false, error: "CODES_TABLE_NOT_FOUND" }, 500);
    }

    const codeCol = firstExistingCol(codesCols, ["code", "activation_code", "license", "key"]);
    if (!codeCol) {
      console.log("activate_codes_table_missing_code_col", codesTable);
      return json({ ok: false, error: "CODES_SCHEMA_MISSING_CODE_COL" }, 500);
    }

    // --- Load code row ---
    const codeRow = await env.DB
      .prepare(`SELECT * FROM ${codesTable} WHERE ${codeCol} = ? LIMIT 1`)
      .bind(code)
      .first();

    if (!codeRow) return json({ ok: false, error: "CODE_NOT_FOUND" }, 404);

    // --- Determine “bound/owner email” column (الأكثر شيوعًا) ---
    const ownerCol = firstExistingCol(codesCols, [
      "used_by_email",
      "bound_email",
      "owner_email",
      "used_email",
      "email", // بعض الجداول تستخدم email لمالك الكود
    ]);

    const isUsedCol = firstExistingCol(codesCols, ["is_used", "used", "activated", "is_activated"]);
    const usedAtCol = firstExistingCol(codesCols, ["used_at", "activated_at"]);
    const statusCol = firstExistingCol(codesCols, ["status"]);

    const boundEmail = ownerCol ? normalizeEmail(codeRow[ownerCol]) : "";

    // إذا الكود مربوط بحساب ثاني → مرفوض
    if (boundEmail && boundEmail !== email) {
      return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    // بعض الجداول تميّز الاستخدام بدون إيميل
    if (!boundEmail && isUsedCol && Number(codeRow[isUsedCol] || 0) === 1) {
      return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    if (!boundEmail && statusCol && String(codeRow[statusCol] || "").toLowerCase() === "used") {
      return json({ ok: false, error: "CODE_ALREADY_USED" }, 409);
    }

    // --- Device limit (افتراضي جهازين) ---
    const limitCol = firstExistingCol(codesCols, ["device_limit", "max_devices", "devices_limit"]);
    let limit = 2;
    if (limitCol) {
      const v = Number(codeRow[limitCol]);
      if (Number.isFinite(v) && v >= 1) limit = v;
    }

    // هل هذا الجهاز مفعّل مسبقًا لنفس الكود؟
    const existingActivation = await env.DB
      .prepare(`SELECT device_id FROM activations WHERE code = ? AND device_id = ? LIMIT 1`)
      .bind(code, deviceId)
      .first();

    if (!existingActivation) {
      const cntRow = await env.DB
        .prepare(`SELECT COUNT(*) AS n FROM activations WHERE code = ? AND email = ?`)
        .bind(code, email)
        .first();

      const n = Number(cntRow?.n || 0);
      if (n >= limit) {
        return json({ ok: false, error: "DEVICE_LIMIT_REACHED" }, 409);
      }

      // Insert activation
      try {
        await env.DB
          .prepare(
            `INSERT INTO activations (code, email, device_id, created_at)
             VALUES (?, ?, ?, ?)`
          )
          .bind(code, email, deviceId, nowIso())
          .run();
      } catch (e) {
        const msg = String(e?.message || e);
        // لو صار Duplicate بسبب سباق، اعتبره OK
        if (!msg.toLowerCase().includes("unique") && !msg.toLowerCase().includes("constraint")) {
          console.log("activate_insert_failed", code, email, deviceId, msg);
          return json({ ok: false, error: "ACTIVATION_WRITE_FAILED" }, 500);
        }
      }
    }

    // --- Bind code to this email (أول مرة فقط) + mark used fields إن وجدت ---
    // نحدّث فقط إذا كان غير مربوط
    if (ownerCol && !boundEmail) {
      const sets = [];
      const binds = [];

      sets.push(`${ownerCol} = ?`);
      binds.push(email);

      if (isUsedCol) {
        sets.push(`${isUsedCol} = 1`);
      }
      if (usedAtCol) {
        sets.push(`${usedAtCol} = ?`);
        binds.push(nowMs());
      }
      if (statusCol) {
        sets.push(`${statusCol} = ?`);
        binds.push("used");
      }

      try {
        await env.DB
          .prepare(`UPDATE ${codesTable} SET ${sets.join(", ")} WHERE ${codeCol} = ?`)
          .bind(...binds, code)
          .run();
      } catch (e) {
        console.log("activate_bind_code_failed", String(e?.message || e));
        // ما نوقف التفعيل إذا ربط الكود فشل (لكن نرجع تحذير واضح)
        return json({ ok: false, error: "CODE_BIND_FAILED" }, 500);
      }
    }

    return json(
      {
        ok: true,
        email,
        code,
        activated: true,
        deviceId,
      },
      200
    );
  } catch (err) {
    console.log("activate_error", String(err?.message || err));
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
activate.js – api2 – إصدار 1 (Robust activate + device limit + schema-safe)
*/
