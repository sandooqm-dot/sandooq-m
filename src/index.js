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

const te = new TextEncoder();

function toHex(buf) {
  const u8 = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < u8.length; i++) out += u8[i].toString(16).padStart(2, "0");
  return out;
}

async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    te.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, te.encode(message));
  return toHex(sig);
}

// ✅ MD5 "مضمون" على Cloudflare (لو مدعوم)، وإلا fallback للـ md5 القديمة
async function md5HexSafe(str) {
  try {
    // Cloudflare Workers تدعم MD5 في أغلب البيئات
    const dig = await crypto.subtle.digest("MD5", te.encode(str));
    return toHex(dig);
  } catch (e) {
    return md5HexFallback(str);
  }
}

// Fallback MD5 (لو لم يُدعم MD5)
function md5HexFallback(str) {
  function cmn(q, a, b, x, s, t) {
    a = (a + q + x + t) | 0;
    return (((a << s) | (a >>> (32 - s))) + b) | 0;
  }
  function ff(a, b, c, d, x, s, t) {
    return cmn((b & c) | (~b & d), a, b, x, s, t);
  }
  function gg(a, b, c, d, x, s, t) {
    return cmn((b & d) | (c & ~d), a, b, x, s, t);
  }
  function hh(a, b, c, d, x, s, t) {
    return cmn(b ^ c ^ d, a, b, x, s, t);
  }
  function ii(a, b, c, d, x, s, t) {
    return cmn(c ^ (b | ~d), a, b, x, s, t);
  }
  function md5cycle(state, k) {
    let [a, b, c, d] = state;

    a = ff(a, b, c, d, k[0], 7, -680876936);
    d = ff(d, a, b, c, k[1], 12, -389564586);
    c = ff(c, d, a, b, k[2], 17, 606105819);
    b = ff(b, c, d, a, k[3], 22, -1044525330);
    a = ff(a, b, c, d, k[4], 7, -176418897);
    d = ff(d, a, b, c, k[5], 12, 1200080426);
    c = ff(c, d, a, b, k[6], 17, -1473231341);
    b = ff(b, c, d, a, k[7], 22, -45705983);
    a = ff(a, b, c, d, k[8], 7, 1770035416);
    d = ff(d, a, b, c, k[9], 12, -1958414417);
    c = ff(c, d, a, b, k[10], 17, -42063);
    b = ff(b, c, d, a, k[11], 22, -1990404162);
    a = ff(a, b, c, d, k[12], 7, 1804603682);
    d = ff(d, a, b, c, k[13], 12, -40341101);
    c = ff(c, d, a, b, k[14], 17, -1502002290);
    b = ff(b, c, d, a, k[15], 22, 1236535329);

    a = gg(a, b, c, d, k[1], 5, -165796510);
    d = gg(d, a, b, c, k[6], 9, -1069501632);
    c = gg(c, d, a, b, k[11], 14, 643717713);
    b = gg(b, c, d, a, k[0], 20, -373897302);
    a = gg(a, b, c, d, k[5], 5, -701558691);
    d = gg(d, a, b, c, k[10], 9, 38016083);
    c = gg(c, d, a, b, k[15], 14, -660478335);
    b = gg(b, c, d, a, k[4], 20, -405537848);
    a = gg(a, b, c, d, k[9], 5, 568446438);
    d = gg(d, a, b, c, k[14], 9, -1019803690);
    c = gg(c, d, a, b, k[3], 14, -187363961);
    b = gg(b, c, d, a, k[8], 20, 1163531501);
    a = gg(a, b, c, d, k[13], 5, -1444681467);
    d = gg(d, a, b, c, k[2], 9, -51403784);
    c = gg(c, d, a, b, k[7], 14, 1735328473);
    b = gg(b, c, d, a, k[12], 20, -1926607734);

    a = hh(a, b, c, d, k[5], 4, -378558);
    d = hh(d, a, b, c, k[8], 11, -2022574463);
    c = hh(c, d, a, b, k[11], 16, 1839030562);
    b = hh(b, c, d, a, k[14], 23, -35309556);
    a = hh(a, b, c, d, k[1], 4, -1530992060);
    d = hh(d, a, b, c, k[4], 11, 1272893353);
    c = hh(c, d, a, b, k[7], 16, -155497632);
    b = hh(b, c, d, a, k[10], 23, -1094730640);
    a = hh(a, b, c, d, k[13], 4, 681279174);
    d = hh(d, a, b, c, k[0], 11, -358537222);
    c = hh(c, d, a, b, k[3], 16, -722521979);
    b = hh(b, c, d, a, k[6], 23, 76029189);
    a = hh(a, b, c, d, k[9], 4, -640364487);
    d = hh(d, a, b, c, k[12], 11, -421815835);
    c = hh(c, d, a, b, k[15], 16, 530742520);
    b = hh(b, c, d, a, k[2], 23, -995338651);

    a = ii(a, b, c, d, k[0], 6, -198630844);
    d = ii(d, a, b, c, k[7], 10, 1126891415);
    c = ii(c, d, a, b, k[14], 15, -1416354905);
    b = ii(b, c, d, a, k[5], 21, -57434055);
    a = ii(a, b, c, d, k[12], 6, 1700485571);
    d = ii(d, a, b, c, k[3], 10, -1894986606);
    c = ii(c, d, a, b, k[10], 15, -1051523);
    b = ii(b, c, d, a, k[1], 21, -2054922799);
    a = ii(a, b, c, d, k[8], 6, 1873313359);
    d = ii(d, a, b, c, k[15], 10, -30611744);
    c = ii(c, d, a, b, k[6], 15, -1560198380);
    b = ii(b, c, d, a, k[13], 21, 1309151649);
    a = ii(a, b, c, d, k[4], 6, -145523070);
    d = ii(d, a, b, c, k[11], 10, -1120210379);
    c = ii(c, d, a, b, k[2], 15, 718787259);
    b = ii(b, c, d, a, k[9], 21, -343485551);

    state[0] = (state[0] + a) | 0;
    state[1] = (state[1] + b) | 0;
    state[2] = (state[2] + c) | 0;
    state[3] = (state[3] + d) | 0;
  }

  function md5blk(s) {
    const md5blks = [];
    for (let i = 0; i < 64; i += 4) {
      md5blks[i >> 2] =
        s.charCodeAt(i) +
        (s.charCodeAt(i + 1) << 8) +
        (s.charCodeAt(i + 2) << 16) +
        (s.charCodeAt(i + 3) << 24);
    }
    return md5blks;
  }

  function md51(s) {
    let n = s.length;
    const state = [1732584193, -271733879, -1732584194, 271733878];
    let i;
    for (i = 64; i <= n; i += 64) {
      md5cycle(state, md5blk(s.substring(i - 64, i)));
    }
    s = s.substring(i - 64);
    const tail = new Array(16).fill(0);
    for (i = 0; i < s.length; i++)
      tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
    tail[i >> 2] |= 0x80 << ((i % 4) << 3);
    if (i > 55) {
      md5cycle(state, tail);
      for (i = 0; i < 16; i++) tail[i] = 0;
    }
    tail[14] = n * 8;
    md5cycle(state, tail);
    return state;
  }

  function rhex(n) {
    let s = "";
    for (let j = 0; j < 4; j++)
      s += ((n >> (j * 8 + 4)) & 0x0f).toString(16) + ((n >> (j * 8)) & 0x0f).toString(16);
    return s;
  }

  const out = md51(str);
  return rhex(out[0]) + rhex(out[1]) + rhex(out[2]) + rhex(out[3]);
}

function needPusher(env) {
  return env.PUSHER_APP_ID && env.PUSHER_KEY && env.PUSHER_SECRET && env.PUSHER_CLUSTER;
}

function channelForRoom(room) {
  return `private-room-${room}`;
}

async function pusherAuth(env, socketId, channelName) {
  const toSign = `${socketId}:${channelName}`;
  const sig = await hmacSha256Hex(env.PUSHER_SECRET, toSign);
  return { auth: `${env.PUSHER_KEY}:${sig}` };
}

async function pusherTrigger(env, room, payloadObj) {
  if (!needPusher(env)) {
    return { ok: false, status: 0, text: "PUSHER_NOT_CONFIGURED" };
  }

  const appId = String(env.PUSHER_APP_ID);
  const key = String(env.PUSHER_KEY);
  const secret = String(env.PUSHER_SECRET);
  const cluster = String(env.PUSHER_CLUSTER);

  const channel = channelForRoom(room);

  const bodyObj = {
    name: "room-update",
    channels: [channel],
    data: JSON.stringify(payloadObj || {}),
  };
  const bodyStr = JSON.stringify(bodyObj);
  const bodyMd5 = await md5HexSafe(bodyStr);

  const ts = Math.floor(Date.now() / 1000);
  const params = {
    auth_key: key,
    auth_timestamp: String(ts),
    auth_version: "1.0",
    body_md5: bodyMd5,
  };

  const query = Object.keys(params)
    .sort()
    .map((k) => `${k}=${encodeURIComponent(params[k])}`)
    .join("&");

  const path = `/apps/${encodeURIComponent(appId)}/events`;
  const stringToSign = `POST\n${path}\n${query}`;
  const signature = await hmacSha256Hex(secret, stringToSign);

  const url = `https://api-${cluster}.pusher.com${path}?${query}&auth_signature=${signature}`;

  const resp = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: bodyStr,
  });

  const text = await resp.text().catch(() => "");
  return { ok: resp.ok, status: resp.status, text };
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return withCors(request, new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);
    const room = url.searchParams.get("room") || "default";

    if (url.pathname === "/health") {
      return withCors(request, json({ ok: true, room }));
    }

    // ✅ اختبار مباشر: يرجّع لنا نتيجة Pusher (بدون ما نعتمد على Debug Console)
    if (url.pathname === "/pusher/ping" && request.method === "GET") {
      const payload = { ping: Date.now(), room };
      const out = await pusherTrigger(env, room, payload);
      return withCors(request, json({ ok: true, sent: out.ok, pusher: out }));
    }

    if (url.pathname === "/pusher/auth" && request.method === "POST") {
      try {
        const ct = (request.headers.get("content-type") || "").toLowerCase();
        let socketId = "";
        let channelName = "";

        if (ct.includes("application/json")) {
          const b = await request.json().catch(() => ({}));
          socketId = String(b.socket_id || "");
          channelName = String(b.channel_name || "");
        } else {
          const t = await request.text();
          const p = new URLSearchParams(t);
          socketId = String(p.get("socket_id") || "");
          channelName = String(p.get("channel_name") || "");
        }

        if (!socketId || !channelName) {
          return withCors(request, json({ ok: false, error: "MISSING_FIELDS" }, 400));
        }
        if (!channelName.startsWith("private-room-")) {
          return withCors(request, json({ ok: false, error: "BAD_CHANNEL" }, 403));
        }
        if (!needPusher(env)) {
          return withCors(request, json({ ok: false, error: "PUSHER_NOT_CONFIGURED" }, 500));
        }

        const out = await pusherAuth(env, socketId, channelName);
        return withCors(request, json(out));
      } catch (e) {
        return withCors(request, json({ ok: false, error: "AUTH_FAILED" }, 500));
      }
    }

    const id = env.ROOMS.idFromName(room);
    const stub = env.ROOMS.get(id);

    if (url.pathname === "/state" && request.method === "GET") {
      const r = await stub.fetch("https://do/state");
      return withCors(request, r);
    }

    if (url.pathname === "/action" && request.method === "POST") {
      const bodyText = await request.text();

      const r = await stub.fetch("https://do/action", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: bodyText,
      });

      // ✅ إرسال Pusher (خلفية)
      if (needPusher(env)) {
        let patch = null;
        try { patch = JSON.parse(bodyText); } catch { patch = { raw: bodyText }; }

        const payload = { room, t: Date.now(), patch };

        // إذا debug=1 نخليه ينتظر ويرجع لنا النتيجة داخل header
        if (url.searchParams.get("debug") === "1") {
          const out = await pusherTrigger(env, room, payload);
          const rr = new Response(r.body, r);
          rr.headers.set("x-pusher-ok", String(out.ok));
          rr.headers.set("x-pusher-status", String(out.status));
          rr.headers.set("x-pusher-text", (out.text || "").slice(0, 200));
          return withCors(request, rr);
        }

        try { ctx.waitUntil(pusherTrigger(env, room, payload)); } catch {}
      }

      return withCors(request, r);
    }

    return withCors(request, json({ ok: false, msg: "Not found" }, 404));
  },
};

// Durable Object
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
      try { body = await request.json(); } catch {}

      const current = (await this.state.storage.get("state")) || {};
      const next = (body && typeof body === "object") ? { ...current, ...body } : current;

      await this.state.storage.put("state", next);
      return json({ ok: true, state: next });
    }

    return json({ ok: false, msg: "DO Not found" }, 404);
  }
}

/* VERSION: src/index.js — vPusher-2-debug */
