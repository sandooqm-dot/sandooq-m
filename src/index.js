// src/index.js
// Horof Sync Worker (Durable Objects) + Pusher fan-out + /stats + /pusher/auth
//
// ✅ Backward compatible: clients that still poll /state will keep working.
// ✅ To enable Pusher, set these environment variables (Secrets) in Cloudflare:
//    PUSHER_APP_ID, PUSHER_KEY, PUSHER_SECRET, PUSHER_CLUSTER
//
// Endpoints (same origin as the worker):
//   GET  /health?room=ROOM
//   GET  /state?room=ROOM&pid=PID
//   POST /action?room=ROOM           (JSON patch/object)
//   GET  /stats?room=ROOM
//   POST /pusher/auth?room=ROOM      (Pusher private-channel auth)

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

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

function utcDayKey(ts = Date.now()) {
  return new Date(ts).toISOString().slice(0, 10); // YYYY-MM-DD (UTC)
}

function clampMin(n, min) {
  n = Number(n);
  return Number.isFinite(n) ? Math.max(min, n) : min;
}

// ---------- MD5 (small, pure JS) ----------
/* eslint-disable */
function md5cycle(x, k) {
  let a = x[0], b = x[1], c = x[2], d = x[3];

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

  x[0] = add32(a, x[0]);
  x[1] = add32(b, x[1]);
  x[2] = add32(c, x[2]);
  x[3] = add32(d, x[3]);
}

function cmn(q, a, b, x, s, t) {
  a = add32(add32(a, q), add32(x, t));
  return add32((a << s) | (a >>> (32 - s)), b);
}
function ff(a, b, c, d, x, s, t) { return cmn((b & c) | (~b & d), a, b, x, s, t); }
function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & ~d), a, b, x, s, t); }
function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | ~d), a, b, x, s, t); }

function md51(s) {
  const n = s.length;
  const state = [1732584193, -271733879, -1732584194, 271733878];
  let i;
  for (i = 64; i <= n; i += 64) {
    md5cycle(state, md5blk(s.substring(i - 64, i)));
  }
  s = s.substring(i - 64);
  const tail = new Array(16).fill(0);
  for (i = 0; i < s.length; i++) tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
  tail[i >> 2] |= 0x80 << ((i % 4) << 3);
  if (i > 55) { md5cycle(state, tail); for (i = 0; i < 16; i++) tail[i] = 0; }
  tail[14] = n * 8;
  md5cycle(state, tail);
  return state;
}

function md5blk(s) {
  const md5blks = [];
  for (let i = 0; i < 64; i += 4) {
    md5blks[i >> 2] = s.charCodeAt(i) +
      (s.charCodeAt(i + 1) << 8) +
      (s.charCodeAt(i + 2) << 16) +
      (s.charCodeAt(i + 3) << 24);
  }
  return md5blks;
}

function rhex(n) {
  let s = "", j = 0;
  for (; j < 4; j++) s += hex_chr[(n >> (j * 8 + 4)) & 0x0F] + hex_chr[(n >> (j * 8)) & 0x0F];
  return s;
}
const hex_chr = "0123456789abcdef".split("");

function md5hex(s) {
  const out = md51(s);
  return rhex(out[0]) + rhex(out[1]) + rhex(out[2]) + rhex(out[3]);
}

function add32(a, b) { return (a + b) & 0xFFFFFFFF; }
/* eslint-enable */

// ---------- Pusher helpers ----------
async function hmacSHA256Hex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function pusherEnabled(env) {
  return Boolean(env?.PUSHER_APP_ID && env?.PUSHER_KEY && env?.PUSHER_SECRET && env?.PUSHER_CLUSTER);
}

async function pusherTrigger(env, channel, event, payloadObj) {
  if (!pusherEnabled(env)) return { ok: false, skipped: true };

  const body = JSON.stringify({
    name: event,
    channels: [channel],
    data: JSON.stringify(payloadObj ?? {}),
  });

  const body_md5 = md5hex(body);
  const auth_timestamp = Math.floor(Date.now() / 1000);
  const baseQS = `auth_key=${encodeURIComponent(env.PUSHER_KEY)}&auth_timestamp=${auth_timestamp}&auth_version=1.0&body_md5=${body_md5}`;
  const path = `/apps/${env.PUSHER_APP_ID}/events`;
  const stringToSign = `POST\n${path}\n${baseQS}`;
  const auth_signature = await hmacSHA256Hex(env.PUSHER_SECRET, stringToSign);

  const url = `https://api-${env.PUSHER_CLUSTER}.pusher.com${path}?${baseQS}&auth_signature=${auth_signature}`;

  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });

  return { ok: r.ok, status: r.status };
}

async function parseBodyAsObject(request) {
  const ct = (request.headers.get("content-type") || "").toLowerCase();
  if (ct.includes("application/json")) {
    try { return await request.json(); } catch { return {}; }
  }
  const txt = await request.text();
  const params = new URLSearchParams(txt);
  const obj = {};
  for (const [k, v] of params.entries()) obj[k] = v;
  return obj;
}

// ---------- Worker (router) ----------
export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return withCors(request, new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);
    const room = url.searchParams.get("room") || "default";
    const pid = url.searchParams.get("pid") || ""; // optional
    const id = env.ROOMS.idFromName(room);
    const stub = env.ROOMS.get(id);

    if (url.pathname === "/health") {
      return withCors(request, json({
        ok: true,
        room,
        pusher: pusherEnabled(env) ? "enabled" : "disabled",
      }));
    }

    if (url.pathname === "/state" && request.method === "GET") {
      const r = await stub.fetch(`https://do/state?pid=${encodeURIComponent(pid)}`, {
        headers: { "x-room-name": room },
      });
      return withCors(request, r);
    }

    if (url.pathname === "/action" && request.method === "POST") {
      const r = await stub.fetch("https://do/action", {
        method: "POST",
        headers: { "content-type": "application/json", "x-room-name": room },
        body: await request.text(),
      });
      return withCors(request, r);
    }

    if (url.pathname === "/stats" && request.method === "GET") {
      const r = await stub.fetch("https://do/stats", { headers: { "x-room-name": room } });
      return withCors(request, r);
    }

    if (url.pathname === "/pusher/auth" && request.method === "POST") {
      if (!pusherEnabled(env)) {
        return withCors(request, json({ ok: false, msg: "Pusher not configured" }, 503));
      }
      const body = await parseBodyAsObject(request);
      const socket_id = String(body.socket_id || "");
      const channel_name = String(body.channel_name || "");

      const expected = `private-room-${room}`;
      if (!socket_id || !channel_name || channel_name !== expected) {
        return withCors(request, json({ ok: false, msg: "Forbidden" }, 403));
      }

      const stringToSign = `${socket_id}:${channel_name}`;
      const signature = await hmacSHA256Hex(env.PUSHER_SECRET, stringToSign);
      const auth = `${env.PUSHER_KEY}:${signature}`;
      return withCors(request, json({ auth }));
    }

    return withCors(request, json({ ok: false, msg: "Not found" }, 404));
  },
};

// ---------- Durable Object ----------
const DEFAULT_IDLE_MS = 2 * 60 * 60 * 1000; // ساعتين
const SEEN_TTL_MS = 90 * 1000; // آخر 90 ثانية نحسبها "متصل"
const SEEN_GC_MAX = 200; // حماية من التضخم

export class Room {
  constructor(state, env) {
    this.state = state;
    this.env = env;

    const ms = Number(env?.ROOM_IDLE_MS || DEFAULT_IDLE_MS);
    this.IDLE_MS = clampMin(ms, 60 * 1000);

    this.roomName = null;
  }

  _setRoomFromReq(request) {
    if (this.roomName) return;
    const rn = request.headers.get("x-room-name");
    if (rn) this.roomName = rn;
  }

  async _loadMetrics(now = Date.now()) {
    const day = utcDayKey(now);
    const m = (await this.state.storage.get("metrics")) || {
      day,
      actionsToday: 0,
      pusherMsgsToday: 0,
      peakClientsToday: 0,
      seen: {}, // pid -> lastSeenTs
    };
    if (m.day !== day) {
      return { day, actionsToday: 0, pusherMsgsToday: 0, peakClientsToday: 0, seen: {} };
    }
    if (!m.seen || typeof m.seen !== "object") m.seen = {};
    return m;
  }

  _gcSeen(seen, now) {
    const out = {};
    let count = 0;
    for (const [pid, ts] of Object.entries(seen || {})) {
      if (now - Number(ts || 0) <= SEEN_TTL_MS) {
        out[pid] = Number(ts || 0);
        count++;
        if (count >= SEEN_GC_MAX) break;
      }
    }
    return out;
  }

  _clientsNow(seen, now) {
    let n = 0;
    for (const ts of Object.values(seen || {})) {
      if (now - Number(ts || 0) <= SEEN_TTL_MS) n++;
    }
    return n;
  }

  async fetch(request) {
    this._setRoomFromReq(request);

    const url = new URL(request.url);

    if (url.pathname === "/state") {
      const s = (await this.state.storage.get("state")) || {};

      const pid = url.searchParams.get("pid") || "";
      if (pid) {
        const now = Date.now();
        const m = await this._loadMetrics(now);
        m.seen = this._gcSeen(m.seen, now);
        m.seen[String(pid).slice(0, 80)] = now;
        const clientsNow = this._clientsNow(m.seen, now);
        m.peakClientsToday = Math.max(Number(m.peakClientsToday || 0), clientsNow);
        await this.state.storage.put("metrics", m);
      }

      return json({ ok: true, state: s });
    }

    if (url.pathname === "/stats") {
      const now = Date.now();
      const m = await this._loadMetrics(now);
      m.seen = this._gcSeen(m.seen, now);
      const clientsNow = this._clientsNow(m.seen, now);
      m.peakClientsToday = Math.max(Number(m.peakClientsToday || 0), clientsNow);
      await this.state.storage.put("metrics", m);

      const lastActiveAt = Number((await this.state.storage.get("lastActiveAt")) || 0);

      return json({
        ok: true,
        room: this.roomName || "unknown",
        day: m.day,
        actionsToday: Number(m.actionsToday || 0),
        pusherMessagesToday: Number(m.pusherMsgsToday || 0),
        clientsNow,
        peakClientsToday: Number(m.peakClientsToday || 0),
        lastActiveAt,
        pusherConfigured: pusherEnabled(this.env),
      });
    }

    if (url.pathname === "/action") {
      let body = {};
      try { body = await request.json(); } catch {}

      const current = (await this.state.storage.get("state")) || {};
      const patch = (body && typeof body === "object" && !Array.isArray(body)) ? body : {};
      const next = { ...current, ...patch };

      const now = Date.now();

      await this.state.storage.put("state", next);
      await this.state.storage.put("lastActiveAt", now);

      try {
        await this.state.storage.setAlarm(now + this.IDLE_MS);
      } catch (e) {
        console.log("setAlarm_failed", String(e?.message || e));
      }

      const m = await this._loadMetrics(now);
      m.actionsToday = Number(m.actionsToday || 0) + 1;
      m.seen = this._gcSeen(m.seen, now);
      const clientsNow = this._clientsNow(m.seen, now);
      m.peakClientsToday = Math.max(Number(m.peakClientsToday || 0), clientsNow);

      if (pusherEnabled(this.env) && this.roomName) {
        const ch = `private-room-${this.roomName}`;
        const trig = await pusherTrigger(this.env, ch, "patch", { patch, ts: now });
        if (trig?.ok) m.pusherMsgsToday = Number(m.pusherMsgsToday || 0) + 1;
      }

      await this.state.storage.put("metrics", m);

      return json({ ok: true, state: next });
    }

    return json({ ok: false, msg: "DO Not found" }, 404);
  }

  async alarm() {
    const now = Date.now();
    const last = Number((await this.state.storage.get("lastActiveAt")) || 0);

    if (last && now - last < this.IDLE_MS) {
      try {
        await this.state.storage.setAlarm(last + this.IDLE_MS);
      } catch (e) {
        console.log("reschedule_failed", String(e?.message || e));
      }
      return;
    }

    try {
      if (typeof this.state.storage.deleteAll === "function") {
        await this.state.storage.deleteAll();
      } else {
        await this.state.storage.delete("state");
        await this.state.storage.delete("lastActiveAt");
        await this.state.storage.delete("metrics");
      }
    } catch (e) {
      console.log("expire_delete_failed", String(e?.message || e));
    }
  }
}
