// functions/api2/custom-questions.js
// Cloudflare Pages Function: GET/POST /api2/custom-questions

const CORS_HEADERS = (req) => {
  const origin = req.headers.get("origin");
  const h = {
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
  };
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    h["Access-Control-Allow-Origin"] = "*";
  }
  return h;
};

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

  return new Response(JSON.stringify(data), { status, headers });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function getCookie(req, name) {
  const cookie = req.headers.get("cookie") || req.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (k === name) {
      const raw = rest.join("=") || "";
      try {
        return decodeURIComponent(raw);
      } catch {
        return raw;
      }
    }
  }
  return "";
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

  const cols = await tableCols(DB, "sessions");
  if (!cols.size || !cols.has("token")) return null;

  if (cols.has("email")) {
    const row = await DB.prepare(
      `SELECT email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    )
      .bind(token)
      .first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  if (cols.has("user_email")) {
    const row = await DB.prepare(
      `SELECT user_email AS email FROM sessions WHERE token = ? ORDER BY rowid DESC LIMIT 1`
    )
      .bind(token)
      .first();
    return row?.email ? normalizeEmail(row.email) : null;
  }

  return null;
}

async function ensureTable(DB) {
  await DB.exec(`
    CREATE TABLE IF NOT EXISTS custom_questions (
      email TEXT NOT NULL,
      game TEXT NOT NULL DEFAULT 'horof',
      payload_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (email, game)
    );

    CREATE INDEX IF NOT EXISTS idx_custom_questions_game ON custom_questions(game);
    CREATE INDEX IF NOT EXISTS idx_custom_questions_updated_at ON custom_questions(updated_at);
  `);
}

function getTokenFromRequest(request, body = null) {
  const auth = request.headers.get("Authorization") || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const cookieTokNew = getCookie(request, "sandooq_token_v1");
  const cookieTokOld = getCookie(request, "sandooq_session_v1");
  const bodyTok = body?.token ? String(body.token).trim() : "";
  return bearer || cookieTokNew || cookieTokOld || bodyTok || "";
}

function readPayloadFromBody(body) {
  if (!body || typeof body !== "object") return undefined;

  if (Object.prototype.hasOwnProperty.call(body, "questions")) return body.questions;
  if (Object.prototype.hasOwnProperty.call(body, "payload")) return body.payload;
  if (Object.prototype.hasOwnProperty.call(body, "data")) return body.data;
  if (Object.prototype.hasOwnProperty.call(body, "customQuestions")) return body.customQuestions;

  return undefined;
}

function safeParseJSON(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS(request) });
  }

  if (request.method !== "GET" && request.method !== "POST") {
    return json(request, { ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  try {
    if (!env.DB) {
      return json(request, { ok: false, error: "DB_NOT_BOUND" }, 500);
    }

    await ensureTable(env.DB);

    let body = null;
    if (request.method === "POST") {
      body = await request.json().catch(() => ({}));
    }

    const token = getTokenFromRequest(request, body);
    if (!token) {
      return json(request, { ok: false, error: "NO_SESSION" }, 401);
    }

    const email = await findSessionEmail(env.DB, token);
    if (!email) {
      return json(request, { ok: false, error: "SESSION_NOT_FOUND" }, 401);
    }

    const url = new URL(request.url);
    const game = String(
      url.searchParams.get("game") || body?.game || "horof"
    ).trim().toLowerCase() || "horof";

    if (request.method === "GET") {
      const row = await env.DB.prepare(
        `SELECT payload_json, created_at, updated_at
         FROM custom_questions
         WHERE email = ? AND game = ?
         LIMIT 1`
      )
        .bind(email, game)
        .first();

      const payload = safeParseJSON(row?.payload_json || "{}", {});

      return json(request, {
        ok: true,
        email,
        game,
        questions: payload,
        created_at: row?.created_at || null,
        updated_at: row?.updated_at || null,
      });
    }

    const payload = readPayloadFromBody(body);
    if (payload === undefined) {
      return json(request, { ok: false, error: "MISSING_QUESTIONS" }, 400);
    }

    const payloadJson = JSON.stringify(payload);
    const bytes = new TextEncoder().encode(payloadJson).length;
    if (bytes > 250000) {
      return json(request, { ok: false, error: "PAYLOAD_TOO_LARGE" }, 413);
    }

    await env.DB.prepare(
      `INSERT INTO custom_questions (email, game, payload_json, created_at, updated_at)
       VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))
       ON CONFLICT(email, game) DO UPDATE SET
         payload_json = excluded.payload_json,
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')`
    )
      .bind(email, game, payloadJson)
      .run();

    const row = await env.DB.prepare(
      `SELECT created_at, updated_at
       FROM custom_questions
       WHERE email = ? AND game = ?
       LIMIT 1`
    )
      .bind(email, game)
      .first();

    return json(request, {
      ok: true,
      saved: true,
      email,
      game,
      created_at: row?.created_at || null,
      updated_at: row?.updated_at || null,
    });
  } catch (e) {
    console.log("custom_questions_error", String(e?.message || e));
    return json(request, { ok: false, error: "SERVER_ERROR" }, 500);
  }
}

/*
custom-questions.js – api2 – إصدار 1
- حفظ دائم للأسئلة الخاصة لكل حساب
- جلب الأسئلة الخاصة حسب الجلسة الحالية
- إنشاء الجدول تلقائيًا أول مرة داخل D1
*/
