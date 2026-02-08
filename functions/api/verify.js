// functions/api/verify.js
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
    "Access-Control-Allow-Headers": "Content-Type, X-Device-Id",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
    "Cache-Control": "no-store",
  };

  function j(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders },
    });
  }

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  if (request.method !== "POST") return j({ ok: false, valid: false, error: "METHOD_NOT_ALLOWED" }, 405);
  if (!env?.DB) return j({ ok: false, valid: false, error: "DB_NOT_BOUND" }, 500);

  // ===== Helpers =====
  function normCodeFull(code) {
    return (code || "")
      .toString()
      .trim()
      .toUpperCase()
      .replace(/[–—−]/g, "-")
      .replace(/\s+/g, "")
      .replace(/[^A-Z0-9-]/g, "");
  }
  function compactCode(code) {
    return (code || "").replace(/-/g, "");
  }

  try {
    const body = await request.json().catch(() => ({}));

    const rawCode = body?.code ?? "";
    const headerDevice = request.headers.get("X-Device-Id") || "";
    const rawDeviceId = body?.deviceId ?? headerDevice;

    const codeNorm = normCodeFull(rawCode);
    const codeCompact = compactCode(codeNorm);
    const deviceId = (rawDeviceId || "").toString().trim();

    if (!codeNorm) return j({ ok: false, valid: false, error: "MISSING_CODE" }, 400);
    if (!deviceId) return j({ ok: false, valid: false, error: "DEVICE_REQUIRED" }, 400);

    const db = env.DB;

    // 1) Ensure activations table exists
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS activations (
        code TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        activated_at TEXT NOT NULL
      );
    `).run();

    // 2) Ensure code exists in codes (match by code or compact)
    const codeRow = await db.prepare(`
      SELECT code, is_used, used_at
      FROM codes
      WHERE code = ?
         OR REPLACE(code,'-','') = ?
      LIMIT 1;
    `).bind(codeNorm, codeCompact).first();

    if (!codeRow?.code) {
      return j({ ok: false, valid: false, error: "CODE_NOT_FOUND" }, 404);
    }

    const realCode = codeRow.code;              // الكود الحقيقي كما هو مخزن
    const realCodeCompact = compactCode(realCode);

    // 3) Check existing activation by real code (or compact)
    const act = await db.prepare(`
      SELECT code, device_id, activated_at
      FROM activations
      WHERE code = ?
         OR REPLACE(code,'-','') = ?
      LIMIT 1;
    `).bind(realCode, realCodeCompact).first();

    // إذا متفعل سابقًا
    if (act?.code) {
      if ((act.device_id || "") === deviceId) {
        // Same device => OK
        // نضمن codes.is_used = 1
        if (Number(codeRow.is_used) !== 1) {
          const nowFix = new Date().toISOString();
          await db.prepare(`
            UPDATE codes
            SET is_used = 1, used_at = COALESCE(used_at, ?)
            WHERE code = ?;
          `).bind(nowFix, realCode).run();
        }

        return j({
          ok: true,
          valid: true,
          status: "ALREADY_ACTIVATED",
          code: realCode,
          deviceId,
          activatedAt: act.activated_at,
        }, 200);
      }

      // Different device
      return j({
        ok: false,
        valid: false,
        error: "CODE_USED_OTHER_DEVICE",
        code: realCode,
      }, 409);
    }

    // 4) First activation: insert activation (unique lock)
    const now = new Date().toISOString();

    try {
      await db.prepare(`
        INSERT INTO activations (code, device_id, activated_at)
        VALUES (?, ?, ?);
      `).bind(realCode, deviceId, now).run();
    } catch (e) {
      // لو صار سباق: نقرأ ونحكم
      const act2 = await db.prepare(`
        SELECT code, device_id, activated_at
        FROM activations
        WHERE code = ?
           OR REPLACE(code,'-','') = ?
        LIMIT 1;
      `).bind(realCode, realCodeCompact).first();

      if (act2?.device_id === deviceId) {
        return j({
          ok: true,
          valid: true,
          status: "ALREADY_ACTIVATED",
          code: realCode,
          deviceId,
          activatedAt: act2.activated_at,
        }, 200);
      }

      return j({
        ok: false,
        valid: false,
        error: "CODE_USED_OTHER_DEVICE",
        code: realCode,
      }, 409);
    }

    // 5) Mark used (بعد ما صار Lock)
    await db.prepare(`
      UPDATE codes
      SET is_used = 1, used_at = COALESCE(used_at, ?)
      WHERE code = ?;
    `).bind(now, realCode).run();

    return j({
      ok: true,
      valid: true,
      status: "ACTIVATED",
      code: realCode,
      deviceId,
      activatedAt: now,
    }, 200);

  } catch (err) {
    return j({
      ok: false,
      valid: false,
      error: "HTTP_500",
      message: err?.message || "Unknown error",
    }, 500);
  }
}
