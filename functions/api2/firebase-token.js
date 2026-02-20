// functions/api2/firebase-token.js
// GET/POST /api2/firebase-token
// ✅ Firebase تم إلغاؤه نهائياً من المشروع (Endpoint مُعطّل)

// ملاحظة: نتركه موجود عشان لو فيه أي كود قديم يناديه ما يصير كراش غريب.
// بيرجع رسالة واضحة إن Firebase مُلغى.

const VERSION = "api2-firebase-token-disabled-v1";

function parseAllowedOrigins(env) {
  const raw = String(env?.ALLOWED_ORIGINS || "").trim();
  if (!raw) return null;
  return new Set(raw.split(",").map(s => s.trim()).filter(Boolean));
}

function corsHeaders(req, env) {
  const origin = req.headers.get("origin") || req.headers.get("Origin") || "";
  const allowed = parseAllowedOrigins(env);

  const h = {
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Vary": "Origin",
  };

  if (origin) {
    // ✅ لو حاط ALLOWED_ORIGINS نقيّد المصدر
    if (allowed && !allowed.has(origin)) {
      return h; // بدون Allow-Origin (المتصفح بيرفض تلقائياً)
    }
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Credentials"] = "true";
  } else {
    // فتح مباشر من المتصفح (بدون Origin)
    h["Access-Control-Allow-Origin"] = "*";
  }

  return h;
}

function json(req, env, data, status = 200) {
  return new Response(JSON.stringify({ ...data, version: VERSION }), {
    status,
    headers: {
      ...corsHeaders(req, env),
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(request, env) });
  }

  if (request.method !== "GET" && request.method !== "POST") {
    return json(request, env, {
      ok: false,
      error: "METHOD_NOT_ALLOWED",
      message: "الطريقة غير مسموحة",
    }, 405);
  }

  // ✅ Firebase مُلغى نهائياً
  return json(request, env, {
    ok: false,
    error: "FIREBASE_DISABLED",
    message: "تم إلغاء Firebase نهائيًا. النظام الآن يعمل عبر Pusher + Durable Objects.",
  }, 410);
}

/*
firebase-token.js – api2 – Disabled (Firebase removed)
*/
