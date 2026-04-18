// functions/api2/export-links.js
// GET /api2/export-links
// v1: export linked codes from D1 for Google Sheets monitoring only

const VERSION = "api2-export-links-v1";

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin") || req.headers.get("Origin");
  const h = {
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Key",
    "Access-Control-Max-Age": "86400",
    "cache-control": "no-store",
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
    h["Vary"] = "Origin";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

function json(req, data, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    ...CORS_HEADERS(req),
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });

  for (const [k, v] of Object.entries(extraHeaders || {})) {
    if (Array.isArray(v)) {
      for (const vv of v) headers.append(k, vv);
    } else if (v !== undefined && v !== null && v !== "") {
      headers.set(k, String(v));
    }
  }

  return new Response(JSON.stringify({ ...data, version: VERSION }), {
    status,
    headers,
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function safeIdent(name) {
  const s = String(name || "");
  if (!/^[A-Za-z0-9_]+$/.test(s)) return null;
  return s;
}

function bearerToken(req) {
  const h = req.headers.get("authorization") || req.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

async function dbAll(DB, sql, binds = []) {
  return await DB.prepare(sql).bind(...binds).all();
}

async function tableInfo(DB, tableName) {
  const t = safeIdent(tableName);
  if (!t) return [];
  const r = await dbAll(DB, `PRAGMA table_info(${t});`);
  return (r?.results || []).map((x) => ({
    name: String(x.name),
    type: String(x.type || ""),
  }));
}

async function listTables(DB) {
  const r = await dbAll(
    DB,
    `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;`
  );
  return (r?.results || []).map((x) => String(x.name));
}

function pickFirst(cols, names) {
  for (const n of names) {
    if (cols.includes(n)) return n;
  }
  return null;
}

async function detectCodesTable(DB) {
  const tables = await listTables(DB);

  if (tables.includes("codes")) {
    const info = await tableInfo(DB, "codes");
    const cols = info.map((x) => x.name);
    const codeCol = pickFirst(cols, ["code", "activation_code", "license", "key"]);
    if (codeCol) {
      return {
        table: "codes",
        cols,
        codeCol,
        ownerCol: pickFirst(cols, [
          "used_by_email",
          "bound_email",
          "owner_email",
          "used_email",
          "email",
          "user_email",
        ]),
        usedAtCol: pickFirst(cols, ["used_at", "activated_at"]),
        statusCol: pickFirst(cols, ["status"]),
      };
    }
  }

  return null;
}

function toIsoOrBlank(v) {
  if (v === null || v === undefined || v === "") return "";

  if (typeof v === "number" && Number.isFinite(v)) {
    // milliseconds
    if (v > 100000000000) {
      const d = new Date(v);
      return isNaN(d.getTime()) ? "" : d.toISOString();
    }
    // seconds
    if (v > 1000000000) {
      const d = new Date(v * 1000);
      return isNaN(d.getTime()) ? "" : d.toISOString();
    }
  }

  const s = String(v).trim();
  if (!s) return "";

  if (/^\d+$/.test(s)) {
    const n = Number(s);
    if (Number.isFinite(n)) {
      if (n > 100000000000) {
        const d = new Date(n);
        return isNaN(d.getTime()) ? s : d.toISOString();
      }
      if (n > 1000000000) {
        const d = new Date(n * 1000);
        return isNaN(d.getTime()) ? s : d.toISOString();
      }
    }
  }

  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toISOString();
}

function getAdminToken(req, url) {
  return (
    bearerToken(req) ||
    String(req.headers.get("X-Admin-Key") || "").trim() ||
    String(url.searchParams.get("token") || "").trim()
  );
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS(request) });
  }

  if (request.method !== "GET") {
    return json(request, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env?.DB) {
      return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);
    }

    const url = new URL(request.url);

    const expectedToken = String(env.EXPORT_LINKS_TOKEN || "").trim();
    if (!expectedToken) {
      return json(request, { ok: false, error: "EXPORT_LINKS_TOKEN_NOT_SET" }, 500);
    }

    const providedToken = getAdminToken(request, url);
    if (!providedToken || providedToken !== expectedToken) {
      return json(request, { ok: false, error: "UNAUTHORIZED" }, 401);
    }

    const includeAll = url.searchParams.get("all") === "1";

    const hasActivations = (await listTables(env.DB)).includes("activations");
    const codesMeta = await detectCodesTable(env.DB);

    let rows = [];

    if (codesMeta?.table) {
      const codesTable = safeIdent(codesMeta.table);
      const codeCol = safeIdent(codesMeta.codeCol);
      const ownerCol = codesMeta.ownerCol ? safeIdent(codesMeta.ownerCol) : null;
      const usedAtCol = codesMeta.usedAtCol ? safeIdent(codesMeta.usedAtCol) : null;
      const statusCol = codesMeta.statusCol ? safeIdent(codesMeta.statusCol) : null;

      if (!codesTable || !codeCol) {
        return json(request, { ok: false, error: "BAD_CODES_SCHEMA" }, 500);
      }

      let sql = "";
      if (hasActivations) {
        sql = `
          WITH act AS (
            SELECT
              code,
              MAX(CASE
                WHEN email IS NOT NULL AND TRIM(email) <> '' THEN LOWER(TRIM(email))
                ELSE NULL
              END) AS act_email,
              MIN(activated_at) AS first_activated_at,
              COUNT(DISTINCT device_id) AS devices_count
            FROM activations
            GROUP BY code
          )
          SELECT
            c.${codeCol} AS code
            ${ownerCol ? `, c.${ownerCol} AS owner_email` : `, NULL AS owner_email`}
            ${usedAtCol ? `, c.${usedAtCol} AS code_used_at` : `, NULL AS code_used_at`}
            ${statusCol ? `, c.${statusCol} AS code_status` : `, NULL AS code_status`}
            , act.act_email
            , act.first_activated_at
            , COALESCE(act.devices_count, 0) AS devices_count
          FROM ${codesTable} c
          LEFT JOIN act ON act.code = c.${codeCol}
          ORDER BY c.rowid ASC
        `;
      } else {
        sql = `
          SELECT
            c.${codeCol} AS code
            ${ownerCol ? `, c.${ownerCol} AS owner_email` : `, NULL AS owner_email`}
            ${usedAtCol ? `, c.${usedAtCol} AS code_used_at` : `, NULL AS code_used_at`}
            ${statusCol ? `, c.${statusCol} AS code_status` : `, NULL AS code_status`}
            , NULL AS act_email
            , NULL AS first_activated_at
            , 0 AS devices_count
          FROM ${codesTable} c
          ORDER BY c.rowid ASC
        `;
      }

      const res = await dbAll(env.DB, sql);
      rows = (res?.results || []).map((r) => {
        const linkedEmail = normalizeEmail(r.owner_email || r.act_email || "");
        const linkedAtRaw = r.code_used_at ?? r.first_activated_at ?? "";
        const linkedAt = toIsoOrBlank(linkedAtRaw);

        return {
          code: String(r.code || "").trim().toUpperCase(),
          linked_email: linkedEmail,
          linked_at: linkedAt,
          devices_count: Number(r.devices_count || 0),
          status: String(r.code_status || "").trim(),
        };
      });
    } else if (hasActivations) {
      // fallback لو ما لقينا codes table
      const res = await dbAll(
        env.DB,
        `
        SELECT
          code,
          MAX(CASE
            WHEN email IS NOT NULL AND TRIM(email) <> '' THEN LOWER(TRIM(email))
            ELSE NULL
          END) AS linked_email,
          MIN(activated_at) AS linked_at_raw,
          COUNT(DISTINCT device_id) AS devices_count
        FROM activations
        GROUP BY code
        ORDER BY code ASC
        `
      );

      rows = (res?.results || []).map((r) => ({
        code: String(r.code || "").trim().toUpperCase(),
        linked_email: normalizeEmail(r.linked_email || ""),
        linked_at: toIsoOrBlank(r.linked_at_raw),
        devices_count: Number(r.devices_count || 0),
        status: r.linked_email ? "used" : "",
      }));
    } else {
      return json(request, { ok: false, error: "NO_CODES_OR_ACTIVATIONS_FOUND" }, 500);
    }

    if (!includeAll) {
      rows = rows.filter((r) => r.linked_email || r.linked_at || r.status.toLowerCase() === "used");
    }

    return json(request, {
      ok: true,
      total: rows.length,
      rows,
    });
  } catch (e) {
    const msg = String(e?.message || e || "unknown");
    return json(request, { ok: false, error: `SERVER_ERROR|${msg}` }, 500);
  }
}

/*
اسم الملف:
functions/api2/export-links.js

مهم:
هذا الملف يقرأ فقط من D1 ويرجع البيانات للمراقبة.
لا يغيّر التفعيل ولا يكتب في الشيت.
*/
