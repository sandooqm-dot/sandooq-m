// functions/api2/admin-usage-export.js
// GET /api2/admin-usage-export?key=XXXX&format=json|csv
// يرجّع: قائمة الأكواد + حالة الاستخدام + تاريخ الاستخدام + الإيميل (بدون أي Redirect للعبة)

function text(status, msg) {
  return new Response(msg, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

async function tableInfo(DB, table) {
  try {
    const r = await DB.prepare(`PRAGMA table_info(${table});`).all();
    return r?.results || [];
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

function pickFirst(colsSet, candidates) {
  for (const c of candidates) if (colsSet.has(c)) return c;
  return "";
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function normalizeCode(v) {
  return String(v || "").trim().toUpperCase().replace(/\s+/g, "").replace(/[–—−]/g, "-");
}

function toISO(v) {
  if (v === null || v === undefined || v === "") return "";
  // رقم (ms أو sec)
  if (typeof v === "number") {
    const ms = v > 10_000_000_000 ? v : v * 1000;
    try { return new Date(ms).toISOString(); } catch { return String(v); }
  }
  const s = String(v).trim();
  // رقم كنص
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    const ms = n > 10_000_000_000 ? n : n * 1000;
    try { return new Date(ms).toISOString(); } catch { return s; }
  }
  // ISO أو نص
  return s;
}

function toCSV(items) {
  const esc = (x) => {
    const s = String(x ?? "");
    if (/[,"\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };

  const head = ["code", "used", "used_at", "email"];
  const rows = [head.join(",")];

  for (const it of items) {
    rows.push([esc(it.code), esc(it.used ? 1 : 0), esc(it.used_at), esc(it.email)].join(","));
  }
  return rows.join("\n");
}

export async function onRequest(context) {
  const { request, env } = context;

  try {
    if (!env?.DB) return text(500, "DB_NOT_BOUND");

    const url = new URL(request.url);

    // ✅ admin key من env (ندعم أكثر من اسم عشان ما نتوه)
    const ADMIN_KEY =
      String(env.ADMIN_USAGE_EXPORT_KEY || env.ADMIN_EXPORT_KEY || env.ADMIN_KEY || "").trim();

    if (!ADMIN_KEY) return text(500, "ADMIN_KEY_NOT_SET");

    const key = String(url.searchParams.get("key") || "").trim();
    if (!key || key !== ADMIN_KEY) {
      // ❌ لا Redirect للعبة — يرجّع 401 واضح
      return text(401, "UNAUTHORIZED");
    }

    const format = String(url.searchParams.get("format") || "json").toLowerCase();

    // 1) الأفضل: جدول codes لأنه يحتوي كل الأكواد (مستخدم/غير مستخدم)
    let items = [];

    if (await tableExists(env.DB, "codes")) {
      const info = await tableInfo(env.DB, "codes");
      const cols = new Set(info.map((x) => String(x.name)));

      const codeCol = pickFirst(cols, ["code", "activation_code"]);
      if (!codeCol) return text(500, "CODES_TABLE_MISSING_CODE_COL");

      const emailCol = pickFirst(cols, ["used_by_email", "email", "user_email", "used_email"]);
      const usedAtCol = pickFirst(cols, ["used_at", "activated_at", "updated_at", "created_at"]);
      const isUsedCol = pickFirst(cols, ["is_used", "used", "activated"]);

      const sql = `SELECT * FROM codes`;
      const r = await env.DB.prepare(sql).all();

      for (const row of (r?.results || [])) {
        const code = normalizeCode(row[codeCol]);
        const email = emailCol ? normalizeEmail(row[emailCol]) : "";
        const usedAt = usedAtCol ? toISO(row[usedAtCol]) : "";

        let used = false;
        if (isUsedCol) used = Number(row[isUsedCol]) === 1;
        // fallback
        if (!used) used = !!email || !!usedAt;

        items.push({
          code,
          used,
          used_at: usedAt,
          email,
        });
      }

      // ترتيب ثابت: الأكواد تبقى بمكانها
      items.sort((a, b) => (a.code > b.code ? 1 : a.code < b.code ? -1 : 0));
    } else if (await tableExists(env.DB, "activations")) {
      // fallback: لو ما عندك codes
      const r = await env.DB.prepare(`SELECT * FROM activations`).all();
      const sample = (r?.results || [])[0] || {};
      const cols = new Set(Object.keys(sample).map(String));

      const codeCol = pickFirst(cols, ["code", "activation_code"]);
      const emailCol = pickFirst(cols, ["used_by_email", "email", "user_email"]);
      const usedAtCol = pickFirst(cols, ["used_at", "activated_at", "created_at"]);

      items = (r?.results || []).map((row) => ({
        code: normalizeCode(codeCol ? row[codeCol] : ""),
        used: true,
        used_at: toISO(usedAtCol ? row[usedAtCol] : ""),
        email: normalizeEmail(emailCol ? row[emailCol] : ""),
      })).filter((x) => x.code);

      items.sort((a, b) => (a.code > b.code ? 1 : a.code < b.code ? -1 : 0));
    } else {
      return text(500, "NO_CODES_OR_ACTIVATIONS_TABLE");
    }

    // ✅ Output
    if (format === "csv") {
      const csv = toCSV(items);
      return new Response(csv, {
        status: 200,
        headers: {
          "content-type": "text/csv; charset=utf-8",
          "content-disposition": "attachment; filename=code_usage.csv",
          "cache-control": "no-store",
        },
      });
    }

    return json({
      ok: true,
      count: items.length,
      items,
    }, 200);

  } catch (e) {
    return text(500, "SERVER_ERROR: " + String(e?.message || e));
  }
}

/*
functions/api2/admin-usage-export.js – إصدار 1 (No redirect, JSON/CSV export)
*/
