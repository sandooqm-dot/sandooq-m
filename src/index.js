function corsHeaders(req) {
  const origin = req.headers.get("Origin") || "*";
  return {
    "Access-Control-Allow-Origin": origin,
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Device-Id",
    "Access-Control-Max-Age": "86400",
  };
}

function withCors(req, res) {
  const h = new Headers(res.headers);
  const ch = corsHeaders(req);
  for (const [k, v] of Object.entries(ch)) h.set(k, v);
  return new Response(res.body, { status: res.status, headers: h });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return withCors(request, new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);
    const room = url.searchParams.get("room") || "default";

    // ping
    if (url.pathname === "/health") {
      return withCors(request, json({ ok: true, room }));
    }

    const id = env.ROOMS.idFromName(room);
    const stub = env.ROOMS.get(id);

    if (url.pathname === "/state" && request.method === "GET") {
      const r = await stub.fetch("https://do/state");
      return withCors(request, r);
    }

    if (url.pathname === "/action" && request.method === "POST") {
      const r = await stub.fetch("https://do/action", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: await request.text(),
      });
      return withCors(request, r);
    }

    return withCors(request, json({ ok: false, msg: "Not found" }, 404));
  },
};

// ✅ خمول الغرفة (افتراضي ساعتين)
const DEFAULT_IDLE_MS = 2 * 60 * 60 * 1000;

export class RoomDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;

    // اختياري للاختبار: تقدر تحط Variable اسمها ROOM_IDLE_MS
    const ms = Number(env?.ROOM_IDLE_MS || DEFAULT_IDLE_MS);
    this.IDLE_MS = Number.isFinite(ms) ? ms : DEFAULT_IDLE_MS;

    // حماية: لا تقل عن دقيقة (حتى ما يصير حذف بالغلط لو أحد حط رقم صغير)
    this.IDLE_MS = Math.max(60 * 1000, this.IDLE_MS);
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/state") {
      const s = (await this.state.storage.get("state")) || {};
      return json({ ok: true, state: s });
    }

    if (url.pathname === "/action") {
      let body = {};
      try {
        body = await request.json();
      } catch {}

      const current = (await this.state.storage.get("state")) || {};
      const next =
        body && typeof body === "object" && !Array.isArray(body)
          ? { ...current, ...body }
          : current;

      const now = Date.now();

      // ✅ حفظ الحالة
      await this.state.storage.put("state", next);

      // ✅ تحديث آخر تفاعل (لا نعتبر /state تفاعل — فقط /action)
      await this.state.storage.put("lastActiveAt", now);

      // ✅ اضبط Alarm بعد ساعتين من آخر تفاعل
      try {
        await this.state.storage.setAlarm(now + this.IDLE_MS);
      } catch (e) {
        // ما نوقف اللعب لو فشل alarm (نكتفي باللوج)
        console.log("setAlarm_failed", String(e?.message || e));
      }

      return json({ ok: true, state: next });
    }

    return json({ ok: false, msg: "DO Not found" }, 404);
  }

  // ✅ يُستدعى تلقائياً عند alarm
  async alarm() {
    const now = Date.now();
    const last = Number((await this.state.storage.get("lastActiveAt")) || 0);

    // إذا فيه تفاعل حديث: نعيد جدولة الإنذار للوقت الصحيح
    if (last && now - last < this.IDLE_MS) {
      try {
        await this.state.storage.setAlarm(last + this.IDLE_MS);
      } catch (e) {
        console.log("reschedule_failed", String(e?.message || e));
      }
      return;
    }

    // ✅ انتهت صلاحية الغرفة: حذف نهائي
    try {
      // يحذف كل شيء مرتبط بالغرفة
      if (typeof this.state.storage.deleteAll === "function") {
        await this.state.storage.deleteAll();
      } else {
        await this.state.storage.delete("state");
        await this.state.storage.delete("lastActiveAt");
      }
    } catch (e) {
      console.log("expire_delete_failed", String(e?.message || e));
    }
  }
}
