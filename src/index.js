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

// ✅ التعديل هنا فقط: بدون extends DurableObject وبدون super()
export class RoomDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
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
      const next = (body && typeof body === "object") ? { ...current, ...body } : current;

      await this.state.storage.put("state", next);
      return json({ ok: true, state: next });
    }

    return json({ ok: false, msg: "DO Not found" }, 404);
  }
}
