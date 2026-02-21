// functions/api2/custom-questions.js
// GET/POST /api2/custom-questions
// ✅ حفظ/قراءة الأسئلة الخاصة بشكل دائم مرتبط بالإيميل (D1)
// - GET  : يرجّع الأسئلة المحفوظة + updatedAt
// - POST : يحفظ (استبدال كامل) أو تحديث حرف واحد
//
// ملاحظة: هذا الملف لا يعتمد على Firebase نهائياً.

const VERSION = "api2-custom-questions-v1";

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function getCookie(req, name) {
  const cookie = req.headers.get("cookie") || req.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (k === name) {
      const raw = (rest.join("=") || "").trim();
      if (!raw) return "";
      try { return decodeURIComponent(raw); } catch { return raw; }
    }
  }
  return "";
}

function CORS_HEADERS(req) {
  const origin = req.headers.get("origin") || req.headers.get("Origin") || "";
  const h = {
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Vary": "Origin",
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
}

function json(req, data, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    ...CORS_HEADERS(req),
    "Content-Type": "application/json; charset=utf-8",
  });
  for (const [k, v] of Object.entries(extraHeaders || {})) {
    if (Array.isArray(v)) {
      for (const vv of v) headers.append(k, vv);
    } else if (v !== undefined && v !== null && v !== "") {
      headers.set(k, String(v));
    }
  }
  return new Response(JSON.stringify({ ...data, version: VERSION }), { status, headers });
}

// ✅ Cookie للجلسة (للـ Middleware) — 30 يوم
function setAuthCookie(token) {
  return `sandooq_token_v1=${encodeURIComponent(token)}; Path=/; Max-Age=2592000; Secure; SameSite=Lax; HttpOnly`;
}
function setLegacyCookie(token) {
  return `sandooq_session_v1=${encodeURIComponent(token)}; Path=/; Max-Age=2592000; Secure; SameSite=Lax; HttpOnly`;
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

async function tableCols(DB, table) {
  try {
    const res = await DB.prepare(`PRAGMA table_info(${table});`).all();
    return new Set((res?.results || []).map((r) => String(r.name)));
  } catch {
    return new Set();
  }
}

async function findSessionEmail(DB, token) {
  if (!token) return null;
  if (!(await tableExists(DB, "sessions"))) return null;

  const cols = await tableCols(DB, "sessions");
  if (!cols.size || !cols.has("token")) return null;

  if (cols.has("email")) {
    const row = await DB.prepare(
      `SELECT email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    ).bind(token).first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  if (cols.has("user_email")) {
    const row = await DB.prepare(
      `SELECT user_email AS email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    ).bind(token).first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  return null;
}

function isVerifiedFromUserRow(u) {
  return (
    u?.is_email_verified === 1 ||
    u?.email_verified === 1 ||
    u?.verified === 1 ||
    u?.is_verified === 1
  );
}

// ---------- Custom Questions shape helpers ----------
function safeStr(x, max = 260) {
  const s = String(x ?? "").replace(/\s+/g, " ").trim();
  if (!s) return "";
  return s.length > max ? s.slice(0, max).trim() : s;
}

function sanitizeCustomQuestions(input) {
  // نتوقع شكل:
  // { "أ": [ {q:"",a:""}, ... ], "ب": [...] , ... }
  // أو ممكن { letters: {...} } أو { customQuestions: {...} }
  let obj = input;

  if (obj && typeof obj === "object") {
    if (obj.customQuestions && typeof obj.customQuestions === "object") obj = obj.customQuestions;
    else if (obj.letters && typeof obj.letters === "object") obj = obj.letters;
  }

  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return {};

  const out = {};
  const keys = Object.keys(obj);

  // حد حماية بسيط
  if (keys.length > 60) return {};

  for (const letter of keys) {
    const L = safeStr(letter, 6);
    const arr = obj[letter];

    if (!L) continue;
    if (!Array.isArray(arr)) continue;

    // عندك 7 أسئلة لكل حرف — نخليها مرنة لكن نحدها 20 احتياط
    const items = [];
    for (const it of arr.slice(0, 20)) {
      const q = safeStr(it?.q ?? it?.question ?? "", 300);
      const a = safeStr(it?.a ?? it?.answer ?? "", 140);
      if (!q && !a) continue;
      items.push({ q, a });
    }
    out[L] = items;
  }

  return out;
}

function sanitizeOneLetter(letter, items) {
  const L = safeStr(letter, 6);
  if (!L) return { letter: "", items: [] };

  const arr = Array.isArray(items) ? items : [];
  const out = [];
  for (const it of arr.slice(0, 20)) {
    const q = safeStr(it?.q ?? it?.question ?? "", 300);
    const a = safeStr(it?.a ?? it?.answer ?? "", 140);
    if (!q && !a) continue;
    out.push({ q, a });
  }
  return { letter: L, items: out };
}

function jsonSizeOk(obj, maxBytes = 60_000) {
  try {
    const s = JSON.stringify(obj || {});
    return s.length <= maxBytes;
  } catch {
    return false;
  }
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS(request) });
  }

  if (request.method !== "GET" && request.method !== "POST") {
    return json(request, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env?.DB) {
      return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);
    }

    // token من:
    // 1) Authorization: Bearer
    // 2) Cookie: sandooq_token_v1
    // 3) Cookie: sandooq_session_v1
    const auth = request.headers.get("Authorization") || "";
    const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    const cookieTokNew = getCookie(request, "sandooq_token_v1");
    const cookieTokOld = getCookie(request, "sandooq_session_v1");

    const token = bearer || cookieTokNew || cookieTokOld;
    if (!token) {
      return json(request, { ok: false, error: "NO_SESSION" }, 401);
    }

    const email = await findSessionEmail(env.DB, token);
    if (!email) {
      return json(request, { ok: false, error: "INVALID_SESSION" }, 401);
    }

    // لازم user موجود (وأفضل يكون verified)
    if (!(await tableExists(env.DB, "users"))) {
      return json(request, { ok: false, error: "USERS_TABLE_MISSING" }, 500);
    }

    const userRow = await env.DB.prepare(
      `SELECT * FROM users WHERE email = ? LIMIT 1`
    ).bind(email).first();

    if (!userRow) {
      return json(request, { ok: false, error: "USER_NOT_FOUND" }, 401);
    }

    const verified = isVerifiedFromUserRow(userRow);
    if (!verified) {
      // لأننا نبي حفظ دائم مرتبط بحساب مؤكد
      return json(request, { ok: false, error: "EMAIL_NOT_VERIFIED" }, 403);
    }

    // تأكد جدول التخزين
    if (!(await tableExists(env.DB, "custom_questions"))) {
      // نحاول إنشاءه (لو صلاحيات D1 تسمح)
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS custom_questions (
          email TEXT PRIMARY KEY,
          data_json TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        );
      `).run();
    }

    if (request.method === "GET") {
      const row = await env.DB.prepare(
        `SELECT data_json, updated_at FROM custom_questions WHERE email=? LIMIT 1`
      ).bind(email).first();

      const customQuestions = row?.data_json ? (JSON.parse(row.data_json) || {}) : {};
      const updatedAt = Number(row?.updated_at || 0);

      return json(
        request,
        { ok: true, email, customQuestions, updatedAt },
        200,
        { "Set-Cookie": [setAuthCookie(token), setLegacyCookie(token)] }
      );
    }

    // POST
    const body = await request.json().catch(() => ({}));

    // 1) clear
    if (body?.clear === true) {
      const now = Date.now();
      await env.DB.prepare(
        `INSERT INTO custom_questions(email,data_json,updated_at)
         VALUES(?,?,?)
         ON CONFLICT(email) DO UPDATE SET data_json=excluded.data_json, updated_at=excluded.updated_at`
      ).bind(email, "{}", now).run();

      return json(
        request,
        { ok: true, email, customQuestions: {}, updatedAt: now },
        200,
        { "Set-Cookie": [setAuthCookie(token), setLegacyCookie(token)] }
      );
    }

    // 2) letter update: { letter:"ف", items:[{q,a}...] }
    if (body && (body.letter || body.items)) {
      const { letter, items } = sanitizeOneLetter(body.letter, body.items);

      if (!letter) {
        return json(request, { ok: false, error: "BAD_LETTER" }, 400);
      }

      const row = await env.DB.prepare(
        `SELECT data_json FROM custom_questions WHERE email=? LIMIT 1`
      ).bind(email).first();

      let current = {};
      try { current = row?.data_json ? (JSON.parse(row.data_json) || {}) : {}; } catch { current = {}; }

      current[letter] = items;

      if (!jsonSizeOk(current)) {
        return json(request, { ok: false, error: "TOO_LARGE" }, 413);
      }

      const now = Date.now();
      await env.DB.prepare(
        `INSERT INTO custom_questions(email,data_json,updated_at)
         VALUES(?,?,?)
         ON CONFLICT(email) DO UPDATE SET data_json=excluded.data_json, updated_at=excluded.updated_at`
      ).bind(email, JSON.stringify(current), now).run();

      return json(
        request,
        { ok: true, email, customQuestions: current, updatedAt: now },
        200,
        { "Set-Cookie": [setAuthCookie(token), setLegacyCookie(token)] }
      );
    }

    // 3) full replace: { customQuestions:{...} } أو { letters:{...} } أو object مباشر
    const full = sanitizeCustomQuestions(body);

    if (!jsonSizeOk(full)) {
      return json(request, { ok: false, error: "TOO_LARGE" }, 413);
    }

    const now = Date.now();
    await env.DB.prepare(
      `INSERT INTO custom_questions(email,data_json,updated_at)
       VALUES(?,?,?)
       ON CONFLICT(email) DO UPDATE SET data_json=excluded.data_json, updated_at=excluded.updated_at`
    ).bind(email, JSON.stringify(full), now).run();

    return json(
      request,
      { ok: true, email, customQuestions: full, updatedAt: now },
      200,
      { "Set-Cookie": [setAuthCookie(token), setLegacyCookie(token)] }
    );

  } catch (e) {
    console.log("custom_questions_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
custom-questions.js – api2 – v1
*/
