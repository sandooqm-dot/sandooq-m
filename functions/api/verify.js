export async function onRequest(context) {
  const { request, env } = context;

  // ✅ CORS ذكي (يرجع نفس Origin إذا موجود)
  const origin = request.headers.get("Origin") || "*";
  const corsHeaders = {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Credentials": "true",
    "Content-Type": "application/json; charset=utf-8",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  // ✅ لازم DB
  if (!env?.DB) {
    return new Response(JSON.stringify({ ok: false, error: "DB_NOT_BOUND" }), {
      status: 200,
      headers: corsHeaders,
    });
  }

  // Helpers
  const normalizeCode = (x) =>
    (x || "")
      .toString()
      .trim()
      .toUpperCase()
      .replace(/[–—−]/g, "-")
      .replace(/\s+/g, "");

  const json = (obj) =>
    new Response(JSON.stringify(obj), { status: 200, headers: corsHeaders });

  // ✅ قراءة Body (JSON أو Form)
  async function readBody() {
    const ct = (request.headers.get("content-type") || "").toLowerCase();

    // JSON
    if (ct.includes("application/json")) {
      return await request.json().catch(() => ({}));
    }

    // Form
    if (ct.includes("application/x-www-form-urlencoded") || ct.includes("multipart/form-data")) {
      const form = await request.formData().catch(() => null);
      if (!form) return {};
      const obj = {};
      for (const [k, v] of form.entries()) obj[k] = v;
      return obj;
    }

    // محاولة JSON كاحتياط
    return await request.json().catch(() => ({}));
  }

  // ✅ GET = فحص فقط (يفيد للتشخيص)
  if (request.method === "GET") {
    const url = new URL(request.url);
    const input = url.searchParams.get("code") || "";
    const code = normalizeCode(input);

    if (!code) return json({ ok: false, error: "MISSING_CODE" });

    const row = await env.DB.prepare(
      "SELECT code, is_used, used_by_email, used_at FROM codes WHERE code = ? LIMIT 1"
    ).bind(code).first();

    return json({
      ok: true,
      lookup: {
        input,
        normalized: code,
        found: !!row,
        row: row || null,
      },
    });
  }

  // ✅ POST = تفعيل/تحقق
  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" });
  }

  try {
    const body = await readBody();

    let code = normalizeCode(body.code || body.activationCode || body.c || "");
    // ✅ deviceId قد يجي بأسماء مختلفة
    let deviceId = (body.deviceId || body.device_id || body.did || "").toString().trim();
    // ✅ email اختياري (لو تبي تربطه لاحقًا)
    let email = (body.email || body.userEmail || "").toString().trim().toLowerCase();

    if (!code) return json({ ok: false, error: "MISSING_CODE" });

    // ✅ لو deviceId ناقص: رجّع سبب واضح (بدل INVALID_CODE)
    if (!deviceId) {
      return json({
        ok: false,
        error: "MISSING_DEVICE",
        hint: "activate.html لازم يرسل deviceId (ويفضّل تخزينه في localStorage مرة واحدة).",
      });
    }

    // ✅ جلب الكود
    const row = await env.DB.prepare(
      "SELECT code, is_used, used_by_email, used_at FROM codes WHERE code = ? LIMIT 1"
    ).bind(code).first();

    if (!row) {
      return json({ ok: false, valid: false, error: "CODE_NOT_FOUND", code });
    }

    const isUsed = Number(row.is_used) === 1;
    const usedBy = (row.used_by_email || "").toString();

    // ✅ إذا مستخدم على “هوية مختلفة”
    // ملاحظة: currently نخزن deviceId داخل used_by_email (حل مؤقت)
    if (isUsed && usedBy && usedBy !== deviceId) {
      return json({
        ok: false,
        valid: false,
        error: "CODE_ALREADY_USED_ON_ANOTHER_DEVICE",
        code,
      });
    }

    // ✅ مستخدم لنفس الجهاز = ممتاز
    if (isUsed && usedBy === deviceId) {
      return json({ ok: true, valid: true, activated: true, code, sameDevice: true });
    }

    // ✅ أول تفعيل: اربط بالجهاز
    await env.DB.prepare(
      "UPDATE codes SET is_used = 1, used_by_email = ?, used_at = datetime('now') WHERE code = ?"
    ).bind(deviceId, code).run();

    return json({
      ok: true,
      valid: true,
      activated: true,
      code,
      // نخليها للمراجعة
      debug: { stored: "used_by_email=deviceId", emailCaptured: !!email },
    });
  } catch (e) {
    return json({ ok: false, error: "SERVER_ERROR", message: String(e?.message || e) });
  }
}
