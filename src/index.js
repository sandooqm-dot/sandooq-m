// src/index.js
// Horof Sync Worker (Durable Objects) + Pusher fan-out + /stats + /pusher/auth + /pusher/config + /monitor
//
// ✅ Backward compatible: clients that still poll /state will keep working.
// ✅ Pusher secrets stay in Cloudflare Worker Secrets:
//    PUSHER_APP_ID, PUSHER_KEY, PUSHER_SECRET, PUSHER_CLUSTER
// ✅ Optional monitor env:
//    PUSHER_PLAN_MESSAGES=4000000
//
// Endpoints:
//   GET  /health?room=ROOM
//   GET  /state?room=ROOM&pid=PID
//   POST /action?room=ROOM
//   GET  /stats?room=ROOM
//   POST /pusher/auth?room=ROOM
//   GET  /pusher/config?room=ROOM
//   GET  /monitor
//   GET  /monitor/summary

function parseAllowedOrigins(env) {
  const raw = String(env?.ALLOWED_ORIGINS || "*").trim();
  if (!raw) return ["*"];
  return raw.split(",").map(s => s.trim()).filter(Boolean);
}

function isOriginAllowed(req, env) {
  const origin = (req.headers.get("Origin") || "").trim();
  if (!origin) return true;
  const allowed = parseAllowedOrigins(env);
  return allowed.includes("*") || allowed.includes(origin);
}

function resolveAllowOrigin(req, env) {
  const origin = (req.headers.get("Origin") || "").trim();
  const allowed = parseAllowedOrigins(env);

  if (allowed.includes("*")) return origin || "*";
  if (origin && allowed.includes(origin)) return origin;
  return allowed[0] || "*";
}

function corsHeaders(req, env) {
  const allowOrigin = resolveAllowOrigin(req, env);
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Device-Id",
    "Access-Control-Max-Age": "86400",
  };
}

function withCors(req, res, env) {
  const h = new Headers(res.headers);
  const ch = corsHeaders(req, env);
  for (const [k, v] of Object.entries(ch)) h.set(k, v);
  return new Response(res.body, { status: res.status, headers: h });
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

function html(page, status = 200, extraHeaders = {}) {
  return new Response(page, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

function utcDayKey(ts = Date.now()) {
  return new Date(ts).toISOString().slice(0, 10);
}

function utcMonthKey(ts = Date.now()) {
  return new Date(ts).toISOString().slice(0, 7);
}

function nextUtcDayResetTs(ts = Date.now()) {
  const d = new Date(ts);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1, 0, 0, 0, 0);
}

function utcResetCountdown(ts = Date.now()) {
  const resetAt = nextUtcDayResetTs(ts);
  const remainingMs = Math.max(0, resetAt - ts);
  return {
    resetAt,
    remainingMs,
    hoursRemaining: Math.max(1, Math.ceil(remainingMs / (60 * 60 * 1000))),
    minutesRemaining: Math.max(1, Math.ceil(remainingMs / (60 * 1000))),
  };
}

function clampMin(n, min) {
  n = Number(n);
  return Number.isFinite(n) ? Math.max(min, n) : min;
}

function normalizeRoom(v) {
  const s = String(v || "").trim();
  return (s || "default").slice(0, 120);
}

function normalizePid(v) {
  return String(v || "").trim().slice(0, 80);
}

function toFiniteNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function roomMetricsPathKey(pathname) {
  switch (pathname) {
    case "/state": return "state";
    case "/action": return "action";
    case "/stats": return "stats";
    case "/health": return "health";
    case "/pusher/auth": return "pusherAuth";
    case "/pusher/config": return "pusherConfig";
    case "/monitor": return "monitorUI";
    case "/monitor/summary": return "monitorSummary";
    default: return pathname.replace(/^\//, "") || "unknown";
  }
}

function isKnownGamePath(pathname) {
  switch (String(pathname || "")) {
    case "/state":
    case "/action":
    case "/stats":
    case "/health":
    case "/pusher/auth":
    case "/pusher/config":
    case "/pusher/trigger":
      return true;
    default:
      return false;
  }
}

function isIgnorableExternal404(pathname, status) {
  return Number(status || 0) === 404 && !isKnownGamePath(pathname);
}

function isImportantRequestError(pathname, status) {
  const s = Number(status || 0);
  if (s >= 500) return true;
  if (s < 400) return false;
  if (isIgnorableExternal404(pathname, s)) return false;
  return true;
}

/* eslint-disable */
// ---------- MD5 (small, pure JS) ----------
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

function roomChannel(room) {
  return `private-room-${room}`;
}

function publicPusherConfig(env, room) {
  if (!pusherEnabled(env)) {
    return {
      enabled: false,
      key: null,
      cluster: null,
      channel: roomChannel(room),
      authEndpoint: `/pusher/auth?room=${encodeURIComponent(room)}`,
    };
  }

  return {
    enabled: true,
    key: env.PUSHER_KEY,
    cluster: env.PUSHER_CLUSTER,
    channel: roomChannel(room),
    authEndpoint: `/pusher/auth?room=${encodeURIComponent(room)}`,
  };
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

// ---------- Monitor helpers ----------
const MONITOR_ROOM = "__monitor__";
const MONITOR_ACTIVE_ROOM_MS = 2 * 60 * 1000;
const MONITOR_ROOM_STALE_MS = 6 * 60 * 60 * 1000;
const DEFAULT_PUSHER_PLAN_MESSAGES = 4_000_000;
const DEFAULT_CF_MONTHLY_REQUESTS = 10_000_000;
const DEFAULT_CF_FREE_DAILY_REQUESTS = 100_000;
const DEFAULT_CF_PLAN_NAME = "Workers Paid ($5)";

function monitorStub(env) {
  const id = env.ROOMS.idFromName(MONITOR_ROOM);
  return env.ROOMS.get(id);
}

function queueMonitorEvent(ctx, env, payload) {
  if (!ctx?.waitUntil || !env?.ROOMS) return;
  const body = JSON.stringify(payload || {});
  ctx.waitUntil(
    monitorStub(env)
      .fetch("https://do/monitor-event", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-room-name": MONITOR_ROOM,
        },
        body,
      })
      .catch(() => null)
  );
}

function queueMonitorRequest(ctx, env, data) {
  queueMonitorEvent(ctx, env, { type: "request", ...(data || {}) });
}

function queueMonitorPusher(ctx, env, data) {
  queueMonitorEvent(ctx, env, { type: "pusher_sent", ...(data || {}) });
}

function monitorPageHtml() {
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  <title>مراقبة سباق الحروف</title>
  <style>
    :root{
      --bg:#0a1020;
      --bg2:#101a31;
      --panel:#111b2f;
      --panel2:#0d1628;
      --panel3:#15213a;
      --line:rgba(148,163,184,.18);
      --text:#f8fbff;
      --text2:#d7e1f0;
      --muted:#8ea0bd;
      --blue:#4f8cff;
      --cyan:#28c7fa;
      --green:#19c37d;
      --yellow:#f7b538;
      --red:#ff5d73;
      --shadow:0 18px 40px rgba(2,8,23,.28);
      --radius:22px;
    }
    *{box-sizing:border-box}
    html,body{margin:0}
    body{
      color:var(--text);
      font-family:Arial,sans-serif;
      background:
        radial-gradient(1200px 520px at 100% -10%, rgba(79,140,255,.16), transparent 55%),
        radial-gradient(800px 420px at 0% 0%, rgba(40,199,250,.10), transparent 50%),
        linear-gradient(180deg, #060b16 0%, #0a1020 36%, #0f1830 100%);
      min-height:100vh;
    }
    body::before{
      content:"";
      position:fixed; inset:0;
      background-image:
        linear-gradient(rgba(255,255,255,.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px);
      background-size:32px 32px;
      pointer-events:none;
      opacity:.22;
    }
    .wrap{position:relative; width:min(1440px,100%); margin:0 auto; padding:18px}
    .hero{
      display:flex; align-items:center; justify-content:space-between; gap:14px; flex-wrap:wrap;
      padding:18px 18px 16px;
      border:1px solid var(--line);
      background:linear-gradient(180deg, rgba(17,27,47,.92), rgba(12,20,38,.92));
      border-radius:28px;
      box-shadow:var(--shadow);
      margin-bottom:14px;
      backdrop-filter: blur(8px);
    }
    .heroTitle{font-size:30px; font-weight:900; line-height:1.15; letter-spacing:-.2px}
    .heroSub{margin-top:8px; color:var(--muted); font-size:14px; line-height:1.9}
    .heroMeta{display:flex; gap:10px; flex-wrap:wrap; margin-top:12px}
    .ghostTag{
      display:inline-flex; align-items:center; gap:8px;
      padding:8px 12px; border-radius:999px;
      background:rgba(255,255,255,.05); border:1px solid var(--line);
      color:var(--text2); font-size:12px; font-weight:700;
    }
    .controls{display:flex; gap:10px; flex-wrap:wrap}
    button{
      border:0; border-radius:16px; padding:13px 18px;
      font-weight:800; font-size:15px; cursor:pointer; color:#fff;
      background:linear-gradient(135deg, var(--blue), #355dff);
      box-shadow:0 12px 26px rgba(53,93,255,.24);
    }
    button.secondary{
      background:rgba(255,255,255,.05);
      border:1px solid var(--line);
      box-shadow:none;
      color:var(--text);
    }

    .quickRow{
      display:grid;
      grid-template-columns:repeat(4, minmax(0,1fr));
      gap:10px;
      margin-bottom:14px;
    }
    .quickCard{
      min-height:88px;
      padding:12px 12px 10px;
      border-radius:22px;
      border:1px solid var(--line);
      background:linear-gradient(180deg, rgba(16,26,49,.95), rgba(10,16,32,.95));
      box-shadow:var(--shadow);
      display:flex; flex-direction:column; justify-content:space-between;
    }
    .quickLabel{font-size:11px; color:var(--muted); font-weight:700; line-height:1.4}
    .quickValue{font-size:22px; font-weight:900; line-height:1.15}
    .quickValue.good{color:var(--green)}
    .quickValue.warnTxt{color:var(--yellow)}
    .quickValue.badTxt{color:var(--red)}

    .mainGrid{
      display:grid;
      grid-template-columns:repeat(12, minmax(0,1fr));
      gap:14px;
    }
    .card{
      grid-column:span 12;
      border:1px solid var(--line);
      border-radius:28px;
      background:linear-gradient(180deg, rgba(17,27,47,.94), rgba(10,16,32,.96));
      box-shadow:var(--shadow);
      padding:16px;
      overflow:hidden;
    }
    .card.third{grid-column:span 4}
    .card.half{grid-column:span 6}
    .cardHead{
      display:flex; align-items:flex-start; justify-content:space-between; gap:12px;
      margin-bottom:14px;
    }
    .headSide{display:flex; align-items:center; gap:12px; min-width:0}
    .accent{
      width:12px; height:48px; border-radius:999px;
      background:linear-gradient(180deg, var(--cyan), var(--blue));
      box-shadow:0 8px 24px rgba(40,199,250,.26);
      flex:none;
    }
    .cardTitle{font-size:17px; font-weight:900; display:flex; align-items:center; gap:10px; flex-wrap:wrap}
    .cardDesc{color:var(--muted); font-size:12px; line-height:1.8; margin-top:4px}
    .help{position:relative}
    .helpBtn{
      width:30px; height:30px; border-radius:999px; padding:0;
      background:rgba(255,255,255,.06); border:1px solid var(--line);
      box-shadow:none; color:#fff; font-size:14px;
    }
    .helpBox{
      display:none;
      position:fixed;
      left:14px; right:14px; bottom:14px;
      z-index:9999;
      width:auto; max-width:620px; margin:0 auto;
      padding:14px 15px;
      border-radius:18px;
      border:1px solid var(--line);
      background:#0a1120;
      color:#ecf4ff; font-size:13px; line-height:1.9;
      box-shadow:0 18px 38px rgba(0,0,0,.48);
      white-space:pre-line;
      max-height:62vh;
      overflow:auto;
    }
    .help.open .helpBox{display:block}

    .tag{
      display:inline-flex; align-items:center; justify-content:center;
      min-height:34px;
      padding:8px 12px; border-radius:999px;
      font-size:12px; font-weight:800;
      border:1px solid var(--line);
      background:rgba(255,255,255,.05); color:var(--text2);
      white-space:nowrap;
    }
    .ok{background:rgba(25,195,125,.16); border-color:rgba(25,195,125,.45); color:#cbffe8}
    .warn{background:rgba(247,181,56,.16); border-color:rgba(247,181,56,.45); color:#fff0c9}
    .bad{background:rgba(255,93,115,.16); border-color:rgba(255,93,115,.45); color:#ffd7dd}
    .info{background:rgba(40,199,250,.12); border-color:rgba(40,199,250,.38); color:#d6f6ff}

    .heroNumber{
      font-size:40px; font-weight:900; line-height:1.05; letter-spacing:-.6px;
      margin:8px 0 6px;
    }
    .heroNumber.ltr{direction:ltr; unicode-bidi:embed; text-align:right}
    .subLine{color:var(--muted); font-size:14px}
    .progressShell{
      margin:16px 0 12px;
      height:12px; border-radius:999px; overflow:hidden;
      background:#0b1324; border:1px solid var(--line);
    }
    .bar{
      width:0%; height:100%;
      background:linear-gradient(90deg, var(--green) 0%, var(--cyan) 38%, var(--yellow) 72%, var(--red) 100%);
      transition:width .25s ease;
      border-radius:999px;
    }

    .metricGrid{display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:10px}
    .metric{
      padding:13px 14px;
      border-radius:20px;
      background:linear-gradient(180deg, rgba(255,255,255,.03), rgba(255,255,255,.02));
      border:1px solid var(--line);
      min-height:88px;
    }
    .metricLabel{color:var(--muted); font-size:12px; line-height:1.6}
    .metricValue{margin-top:6px; font-size:28px; font-weight:900}
    .metricValue.small{font-size:24px}
    .metaRow{display:flex; gap:8px; flex-wrap:wrap; margin-top:10px}

    .sectionTitle{
      font-size:15px; font-weight:900; margin-bottom:10px;
      color:var(--text2);
    }

    .tableWrap{
      overflow:auto;
      border-radius:22px;
      border:1px solid var(--line);
      background:rgba(8,14,28,.5);
    }
    table{width:100%; border-collapse:collapse; min-width:760px}
    th,td{
      padding:12px 10px; text-align:right; border-bottom:1px solid rgba(148,163,184,.12);
      font-size:13px; vertical-align:top;
    }
    th{
      position:sticky; top:0; z-index:1;
      background:#0d1628; color:#cfe0fb; font-size:12px;
    }

    .alerts{display:grid; gap:10px}
    .alert{
      padding:14px 14px;
      border-radius:18px;
      background:rgba(255,255,255,.04);
      border:1px solid var(--line);
      line-height:1.85;
    }
    .alert strong{display:block; margin-bottom:4px}

    .rowEnded td{
      background:rgba(255,93,115,.06);
    }

    .empty{
      text-align:center; padding:18px;
      color:var(--muted);
      border-radius:18px;
      border:1px dashed rgba(148,163,184,.18);
      background:rgba(255,255,255,.02);
    }
    .footerNote{margin-top:12px; color:var(--muted); font-size:12px; line-height:1.95}

    @media (max-width:1150px){
      .card.third{grid-column:span 6}
    }
    @media (max-width:860px){
      .wrap{padding:12px}
      .hero{padding:14px}
      .heroTitle{font-size:26px}
      .card.third,.card.half{grid-column:span 12}
    }
    @media (max-width:680px){
      .hero{border-radius:24px}
      .quickRow{gap:8px}
      .quickCard{padding:10px 9px; min-height:80px; border-radius:18px}
      .quickLabel{font-size:10px}
      .quickValue{font-size:16px}
      .controls{width:100%}
      .controls button{flex:1}
      .card{padding:14px; border-radius:24px}
      .cardHead{align-items:flex-start}
      .accent{width:10px; height:40px}
      .cardTitle{font-size:16px}
      .cardDesc{font-size:11px}
      .heroNumber{font-size:34px}
      .metricGrid{grid-template-columns:repeat(2, minmax(0,1fr))}
      .metric{min-height:78px; padding:12px}
      .metricValue{font-size:24px}
      .metricValue.small{font-size:20px}
      .footerNote{font-size:11px}
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div>
        <div class="heroTitle">لوحة مراقبة سباق الحروف</div>
        <div class="heroSub"></div>
        <div class="heroMeta">
          <div class="ghostTag">رابط واحد للمتابعة من الجوال</div>
          <div class="ghostTag">تحديث تلقائي كل 5 ثوانٍ</div>
          <div class="ghostTag">لا تؤثر على اللاعبين</div>
          <div id="dailyResetChip" class="ghostTag">تصفير اليوم بعد: —</div>
        </div>
      </div>
      <div class="controls">
        <button id="refreshBtn">تحديث الآن</button>
        <button id="autoBtn" class="secondary">إيقاف التحديث</button>
      </div>
    </section>

    <section class="quickRow">
      <div class="quickCard">
        <div class="quickLabel">آخر تحديث</div>
        <div id="lastUpdated" class="quickValue">—</div>
      </div>
      <div class="quickCard">
        <div class="quickLabel">حالة الـ Worker</div>
        <div id="workerStatus" class="quickValue">—</div>
      </div>
      <div class="quickCard">
        <div class="quickLabel">حالة Pusher</div>
        <div id="pusherStatus" class="quickValue">—</div>
      </div>
      <div class="quickCard">
        <div class="quickLabel">التقييم العام</div>
        <div id="overallStatus" class="quickValue">—</div>
      </div>
    </section>

    <div class="mainGrid">
      <section class="card third">
        <div class="cardHead">
          <div class="headSide">
            <div class="accent"></div>
            <div>
              <div class="cardTitle">استهلاك رسائل Pusher
                <span class="help" data-help>
                  <button class="helpBtn" type="button">؟</button>
                  <div class="helpBox">تعرض هذه اللوحة عدد الرسائل التي أرسلها هذا الـ Worker إلى Pusher خلال الشهر الحالي، مقارنة بحد الخطة المحدد عندك.

الحدود المقترحة:
- طبيعي: أقل من 50%
- متوسط: من 50% إلى 80%
- قلق: أكثر من 80%</div>
                </span>
              </div>
              <div class="cardDesc">مفيدة لمعرفة الاستهلاك الحالي من اشتراكك الشهري بشكل سريع.</div>
            </div>
          </div>
          <div id="pusherUsageBadge" class="tag info">بانتظار البيانات</div>
        </div>
        <div id="pusherMain" class="heroNumber ltr">—</div>
        <div id="pusherSub" class="subLine">—</div>
        <div class="progressShell"><div id="pusherBar" class="bar"></div></div>
        <div class="metaRow">
          <div id="pusherTodayTag" class="tag info">اليوم: —</div>
          <div id="pusherRemainingTag" class="tag info">المتبقي: —</div>
          <div id="pusherResetTag" class="tag info">يتصفّر بعد: —</div>
        </div>
      </section>

      <section class="card third">
        <div class="cardHead">
          <div class="headSide">
            <div class="accent"></div>
            <div>
              <div class="cardTitle">التزامن الحالي المباشر
                <span class="help" data-help>
                  <button class="helpBtn" type="button">؟</button>
                  <div class="helpBox">تعرض هذه اللوحة الصورة الحالية للعبة: عدد الاتصالات المباشرة الآن، وعدد الغرف النشطة الآن، وعدد الغرف التي ظهرت اليوم.

الحدود المقترحة:
- طبيعي: حمل مريح
- متوسط: زيادة ملحوظة لكن مستقرة
- قلق: زيادة قوية أو غرف كثيرة مع أخطاء</div>
                </span>
              </div>
              <div class="cardDesc">أهم أرقام اللعب الحي الآن في مكان واحد.</div>
            </div>
          </div>
          <div id="liveBadge" class="tag info">بانتظار البيانات</div>
        </div>
        <div class="metricGrid">
          <div class="metric"><div class="metricLabel">الاتصالات الحالية الآن</div><div id="liveConnections" class="metricValue">—</div></div>
          <div class="metric"><div class="metricLabel">الغرف النشطة الآن</div><div id="liveRooms" class="metricValue">—</div></div>
          <div class="metric"><div class="metricLabel">الغرف التي ظهرت اليوم</div><div id="liveRoomsToday" class="metricValue small">—</div></div>
          <div class="metric"><div class="metricLabel">غرف منتهية ظاهرة</div><div id="liveRoomsTracked" class="metricValue small">—</div></div>
        </div>
      </section>

      <section class="card third">
        <div class="cardHead">
          <div class="headSide">
            <div class="accent"></div>
            <div>
              <div class="cardTitle">مؤشرات واستهلاك Cloudflare
                <span class="help" data-help>
                  <button class="helpBtn" type="button">؟</button>
                  <div class="helpBox">هذه اللوحة تعرض مؤشرات Cloudflare التشغيلية + استهلاك الخطة الحالية بشكل واضح.

المعروض هنا:
- طلبات اليوم
- نسبة الأخطاء
- متوسط الاستجابة
- استخدام الشهر الحالي من الخطة المدفوعة
- مقارنة بالحد المجاني القديم 100,000 طلب يوميًا
- تفصيل طلبات اللعب مقابل طلبات الحالة والمراقبة وPusher

الحدود المقترحة:
- نسبة أخطاء اللعبة المهمة: طبيعي أقل من 0.5% — متوسط حتى 2% — قلق فوق 2%
- متوسط الاستجابة: طبيعي أقل من 300ms — متوسط حتى 800ms — قلق فوق 800ms
- طلبات 404 الخارجية تُعرض منفصلة ولا تدخل ضمن أخطاء اللعبة المهمة</div>
                </span>
              </div>
              <div class="cardDesc">يوضح الخطة الحالية، استهلاك الشهر، والفرق بين أنواع الطلبات داخل الـ Worker.</div>
            </div>
          </div>
          <div id="cfBadge" class="tag info">بانتظار البيانات</div>
        </div>
        <div class="metricGrid">
          <div class="metric"><div class="metricLabel">الخطة الحالية</div><div id="cfPlanName" class="metricValue small">—</div></div>
          <div class="metric"><div class="metricLabel">استخدام الشهر الحالي</div><div id="cfMonthMain" class="metricValue small">—</div></div>
          <div class="metric"><div class="metricLabel">المتبقي من الخطة</div><div id="cfMonthRemaining" class="metricValue small">—</div></div>
          <div class="metric"><div class="metricLabel">الحد المجاني السابق</div><div id="cfFreeLimit" class="metricValue small">—</div></div>
        </div>
        <div class="metaRow">
          <div id="cfMonthUsageTag" class="tag info">استهلاك الشهر: —</div>
          <div id="cfRequests" class="tag info">طلبات اليوم: —</div>
          <div id="cfErrors" class="tag warn">أخطاء اللعبة اليوم: —</div>
          <div id="cfLatency" class="tag info">متوسط الاستجابة: —</div>
          <div id="cfErrorRate" class="tag info">نسبة الأخطاء المهمة: —</div>
          <div id="cfResetTag" class="tag info">يتصفّر بعد: —</div>
        </div>
        <div class="metaRow">
          <div id="cf2xx" class="tag info">2xx: —</div>
          <div id="cf4xx" class="tag warn">4xx مهم: —</div>
          <div id="cfExt404" class="tag info">404 خارجية: —</div>
          <div id="cf5xx" class="tag bad">5xx: —</div>
        </div>
        <div class="sectionTitle">تفصيل طلبات الـ Worker</div>
        <div class="metricGrid">
          <div class="metric"><div class="metricLabel">طلبات اللعب /action</div><div id="cfReqAction" class="metricValue small">—</div></div>
          <div class="metric"><div class="metricLabel">طلبات الحالة /state</div><div id="cfReqState" class="metricValue small">—</div></div>
          <div class="metric"><div class="metricLabel">طلبات Pusher auth/config</div><div id="cfReqPusher" class="metricValue small">—</div></div>
          <div class="metric"><div class="metricLabel">طلبات المراقبة</div><div id="cfReqMonitor" class="metricValue small">—</div></div>
        </div>
        <div class="metaRow">
          <div id="cfReqOther" class="tag info">طلبات خارجية/أخرى: —</div>
        </div>
      </section>

      <section class="card half">
        <div class="cardHead">
          <div class="headSide">
            <div class="accent"></div>
            <div>
              <div class="cardTitle">الحالة العامة والتنبيهات
                <span class="help" data-help>
                  <button class="helpBtn" type="button">؟</button>
                  <div class="helpBox">هذه اللوحة تجمع أهم التنبيهات التي تحتاج تراقبها بسرعة: اقتراب حد رسائل Pusher، ارتفاع الأخطاء، بطء الاستجابة، أو غرفة عليها نشاط غير طبيعي.</div>
                </span>
              </div>
              <div class="cardDesc">مختصر سريع للأشياء التي تحتاج انتباهك الآن.</div>
            </div>
          </div>
          <div id="alertsBadge" class="tag info">بانتظار البيانات</div>
        </div>
        <div id="alertsBox" class="alerts">
          <div class="empty">بانتظار أول تحديث…</div>
        </div>
      </section>

      <section class="card half">
        <div class="cardHead">
          <div class="headSide">
            <div class="accent"></div>
            <div>
              <div class="cardTitle">الغرف الحالية والمنتهية</div>
              <div class="cardDesc">يعرض الغرف النشطة والهادئة، ويُظهر الغرف التي انتهت بالخمول باللون الأحمر بدون احتسابها ضمن الحالي.</div>
            </div>
          </div>
          <div id="roomsBadge" class="tag info">بانتظار البيانات</div>
        </div>
        <div class="tableWrap">
          <table>
            <thead>
              <tr>
                <th>الغرفة</th>
                <th>الحالة</th>
                <th>المتصلون</th>
                <th>آخر ظهور</th>
                <th>آخر Pusher</th>
                <th>طلبات اليوم</th>
                <th>رسائل اليوم</th>
                <th>آخر مسار</th>
                <th>Rev</th>
              </tr>
            </thead>
            <tbody id="roomsBody">
              <tr><td colspan="9" class="empty">لا توجد غرف متتبعة بعد</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <div class="cardHead">
          <div class="headSide">
            <div class="accent"></div>
            <div>
              <div class="cardTitle">آخر الأخطاء المهمة</div>
              <div class="cardDesc">آخر الأخطاء أو الاستجابات غير الطبيعية داخل الـ Worker.</div>
            </div>
          </div>
          <div id="errorsBadge" class="tag info">بانتظار البيانات</div>
        </div>
        <div class="tableWrap">
          <table>
            <thead>
              <tr>
                <th>الوقت</th>
                <th>الحالة</th>
                <th>المسار</th>
                <th>الغرفة</th>
                <th>التفصيل</th>
              </tr>
            </thead>
            <tbody id="errorsBody">
              <tr><td colspan="5" class="empty">لا توجد أخطاء بعد</td></tr>
            </tbody>
          </table>
        </div>
        <div class="footerNote">
          ملاحظة: رقم رسائل Pusher هنا هو عداد داخلي مبني على الرسائل التي يرسلها هذا الـ Worker إلى Pusher، وهو ممتاز للمراقبة اليومية، لكنه ليس بديلًا رسميًا عن صفحة الفوترة داخل Pusher.
          <br>
          أما مؤشرات Cloudflare هنا فهي مؤشرات تشغيلية داخلية من نفس الـ Worker، هدفها تعطيك نظرة عربية سريعة من رابط واحد بدون تنقل بين عدة لوحات.
        </div>
      </section>
    </div>
  </div>

  <script>
    const $ = (id) => document.getElementById(id);
    const fmt = (n) => Number(n || 0).toLocaleString('en-US');
    const pct = (n) => (Number(n || 0)).toFixed(1) + '%';
    const ms = (n) => Math.round(Number(n || 0)) + 'ms';

    function ago(ts){
      const n = Number(ts || 0);
      if (!n) return '—';
      const diff = Math.max(0, Date.now() - n);
      const s = Math.floor(diff / 1000);
      if (s < 60) return 'الآن';
      const m = Math.floor(s / 60);
      if (m < 60) return 'قبل ' + m + ' د';
      const h = Math.floor(m / 60);
      if (h < 24) return 'قبل ' + h + ' س';
      const d = Math.floor(h / 24);
      return 'قبل ' + d + ' ي';
    }

    function setBadge(el, text, kind){
      el.className = 'tag ' + kind;
      el.textContent = text;
    }

    function usageLevel(p){
      const x = Number(p || 0);
      if (x >= 80) return ['قلق','bad'];
      if (x >= 50) return ['متوسط','warn'];
      return ['طبيعي','ok'];
    }

    function errorLevel(rate){
      const x = Number(rate || 0);
      if (x > 2) return ['قلق','bad'];
      if (x >= 0.5) return ['متوسط','warn'];
      return ['طبيعي','ok'];
    }

    function latencyLevel(v){
      const x = Number(v || 0);
      if (x > 800) return ['قلق','bad'];
      if (x >= 300) return ['متوسط','warn'];
      return ['طبيعي','ok'];
    }

    function liveLevel(connections, rooms, errRate){
      const c = Number(connections || 0);
      const r = Number(rooms || 0);
      const e = Number(errRate || 0);
      if (e > 2 || c >= 120 || r >= 15) return ['قلق','bad'];
      if (e >= 0.5 || c >= 60 || r >= 8) return ['متوسط','warn'];
      return ['طبيعي','ok'];
    }

    function overallLevel(sum){
      const p = Number(sum?.pusher?.usagePercentMonth || 0);
      const e = Number(sum?.cloudflare?.errorRatePercent || 0);
      const l = Number(sum?.cloudflare?.avgLatencyMs || 0);
      if (p >= 80 || e > 2 || l > 800) return ['يحتاج انتباه','bad'];
      if (p >= 50 || e >= 0.5 || l >= 300) return ['مستقر مع متابعة','warn'];
      return ['ممتاز','ok'];
    }

    function colorQuickValue(el, kind){
      el.classList.remove('good','warnTxt','badTxt');
      if (kind === 'ok') el.classList.add('good');
      else if (kind === 'warn') el.classList.add('warnTxt');
      else if (kind === 'bad') el.classList.add('badTxt');
    }

    function renderAlerts(alerts){
      const box = $('alertsBox');
      if (!alerts || !alerts.length) {
        box.innerHTML = '<div class="empty">لا توجد تنبيهات مقلقة الآن — الوضع يبدو طبيعيًا.</div>';
        setBadge($('alertsBadge'),'لا توجد تنبيهات','ok');
        return;
      }
      setBadge($('alertsBadge'),'عدد التنبيهات: ' + alerts.length, alerts.some(a => a.level === 'bad') ? 'bad' : 'warn');
      box.innerHTML = alerts.map(a => {
        const cls = a.level === 'bad' ? 'bad' : (a.level === 'warn' ? 'warn' : 'info');
        return '<div class="alert '+ cls +'">' +
          '<strong>' + a.title + '</strong>' +
          '<div>' + a.text + '</div>' +
          '</div>';
      }).join('');
    }

    function renderRooms(rooms){
      const body = $('roomsBody');
      if (!rooms || !rooms.length) {
        body.innerHTML = '<tr><td colspan="9" class="empty">لا توجد غرف متتبعة حتى الآن</td></tr>';
        setBadge($('roomsBadge'),'0 غرفة','info');
        return;
      }
      const endedCount = rooms.filter(r => r.isEnded).length;
      const currentCount = rooms.filter(r => !r.isEnded).length;
      setBadge($('roomsBadge'),'الحالية: ' + currentCount + ' | المنتهية: ' + endedCount, endedCount ? 'warn' : 'info');
      body.innerHTML = rooms.map(r => {
        const statusText = r.isEnded ? 'انتهت' : (r.isActive ? 'نشطة' : 'هادئة');
        const cls = r.isEnded ? 'bad' : (r.isActive ? 'ok' : 'info');
        const rowCls = r.isEnded ? ' class="rowEnded"' : '';
        return '<tr' + rowCls + '>' +
          '<td>' + r.room + '</td>' +
          '<td><span class="tag ' + cls + '">' + statusText + '</span></td>' +
          '<td>' + fmt(r.clientsNow) + '</td>' +
          '<td>' + ago(r.lastSeenAt) + '</td>' +
          '<td>' + ago(r.lastPusherAt) + '</td>' +
          '<td>' + fmt(r.requestsToday) + '</td>' +
          '<td>' + fmt(r.pusherMsgsToday) + '</td>' +
          '<td>' + (r.lastPath || '—') + '</td>' +
          '<td>' + fmt(r.rev) + '</td>' +
          '</tr>';
      }).join('');
    }

    function renderErrors(errors){
      const body = $('errorsBody');
      if (!errors || !errors.length) {
        body.innerHTML = '<tr><td colspan="5" class="empty">لا توجد أخطاء مهمة الآن</td></tr>';
        setBadge($('errorsBadge'),'لا توجد أخطاء','ok');
        return;
      }
      setBadge($('errorsBadge'),'عدد السجلات: ' + errors.length, errors.some(e => Number(e.status || 0) >= 500) ? 'bad' : 'warn');
      body.innerHTML = errors.map(e => {
        const s = Number(e.status || 0);
        const cls = s >= 500 ? 'bad' : (s >= 400 ? 'warn' : 'info');
        return '<tr>' +
          '<td>' + ago(e.ts) + '</td>' +
          '<td><span class="tag ' + cls + '">' + s + '</span></td>' +
          '<td>' + (e.path || '—') + '</td>' +
          '<td>' + (e.room || '—') + '</td>' +
          '<td>' + (e.msg || '—') + '</td>' +
          '</tr>';
      }).join('');
    }

    function render(summary){
      $('lastUpdated').textContent = ago(summary.generatedAt);
      const reset = summary.dailyReset || {};
      $('dailyResetChip').textContent = 'تصفير اليوم بعد: ' + (reset.hoursLabel || '—');

      const workerOk = summary.system?.worker ? 'شغال' : 'غير واضح';
      $('workerStatus').textContent = workerOk;
      colorQuickValue($('workerStatus'), summary.system?.worker ? 'ok' : 'warn');

      const pusherOk = summary.system?.pusherConfigured ? 'مربوط' : 'غير مضبوط';
      $('pusherStatus').textContent = pusherOk;
      colorQuickValue($('pusherStatus'), summary.system?.pusherConfigured ? 'ok' : 'warn');

      const [overallText, overallKind] = overallLevel(summary);
      $('overallStatus').textContent = overallText;
      colorQuickValue($('overallStatus'), overallKind);

      const pusher = summary.pusher || {};
      $('pusherMain').textContent = fmt(pusher.messagesMonth) + ' / ' + fmt(pusher.planMessages);
      $('pusherSub').textContent = 'نسبة الاستخدام الشهرية الحالية: ' + pct(pusher.usagePercentMonth);
      $('pusherBar').style.width = Math.min(100, Number(pusher.usagePercentMonth || 0)) + '%';
      $('pusherTodayTag').textContent = 'اليوم: ' + fmt(pusher.messagesToday);
      $('pusherRemainingTag').textContent = 'المتبقي: ' + fmt(pusher.remainingMessages);
      $('pusherResetTag').textContent = 'يتصفّر بعد: ' + ((summary.dailyReset && summary.dailyReset.hoursLabel) || '—');
      const [puText, puKind] = usageLevel(pusher.usagePercentMonth);
      setBadge($('pusherUsageBadge'), puText, puKind);

      const live = summary.live || {};
      $('liveConnections').textContent = fmt(live.connectionsNow);
      $('liveRooms').textContent = fmt(live.roomsActiveNow);
      $('liveRoomsToday').textContent = fmt(live.roomsSeenToday);
      $('liveRoomsTracked').textContent = fmt(live.roomsEndedVisible);
      const [lvText, lvKind] = liveLevel(live.connectionsNow, live.roomsActiveNow, summary.cloudflare?.errorRatePercent);
      setBadge($('liveBadge'), lvText, lvKind);

      const cf = summary.cloudflare || {};
      $('cfPlanName').textContent = String(cf.planName || '—');
      $('cfMonthMain').textContent = fmt(cf.requestsMonth) + ' / ' + fmt(cf.planRequestsMonth);
      $('cfMonthRemaining').textContent = fmt(cf.remainingRequestsMonth);
      $('cfFreeLimit').textContent = fmt(cf.freeDailyRequests) + ' / يوم';
      $('cfMonthUsageTag').textContent = 'استهلاك الشهر: ' + pct(cf.usagePercentMonth);
      $('cfRequests').textContent = 'طلبات اليوم: ' + fmt(cf.requestsToday);
      $('cfErrors').textContent = 'أخطاء اللعبة اليوم: ' + fmt(cf.errorsToday);
      $('cfErrorRate').textContent = 'نسبة الأخطاء المهمة: ' + pct(cf.errorRatePercent);
      $('cfLatency').textContent = 'متوسط الاستجابة: ' + ms(cf.avgLatencyMs);
      $('cfResetTag').textContent = 'يتصفّر بعد: ' + ((summary.dailyReset && summary.dailyReset.hoursLabel) || '—');
      $('cf2xx').textContent = '2xx: ' + fmt(cf.status2xx);
      $('cf4xx').textContent = '4xx مهم: ' + fmt(cf.status4xx);
      $('cfExt404').textContent = '404 خارجية: ' + fmt(cf.external404Today);
      $('cf5xx').textContent = '5xx: ' + fmt(cf.status5xx);
      const wb = summary.requestBreakdown || {};
      $('cfReqAction').textContent = fmt(wb.action);
      $('cfReqState').textContent = fmt(wb.state);
      $('cfReqPusher').textContent = fmt(wb.pusher);
      $('cfReqMonitor').textContent = fmt(wb.monitor);
      $('cfReqOther').textContent = 'طلبات خارجية/أخرى: ' + fmt(wb.other);
      const er = errorLevel(cf.errorRatePercent);
      const lt = latencyLevel(cf.avgLatencyMs);
      const cu = usageLevel(cf.usagePercentMonth);
      const cfKind = (er[1] === 'bad' || lt[1] === 'bad' || cu[1] === 'bad') ? 'bad' : ((er[1] === 'warn' || lt[1] === 'warn' || cu[1] === 'warn') ? 'warn' : 'ok');
      setBadge($('cfBadge'), cfKind === 'bad' ? 'قلق' : (cfKind === 'warn' ? 'متوسط' : 'طبيعي'), cfKind);

      renderAlerts(summary.alerts || []);
      renderRooms(summary.rooms || []);
      renderErrors(summary.lastErrors || []);
    }

    let timer = null;
    let paused = false;

    async function refresh(){
      try{
        const res = await fetch('/monitor/summary', { cache:'no-store' });
        const data = await res.json();
        if (!res.ok || !data?.ok) throw new Error(data?.msg || 'MONITOR_FAILED');
        render(data);
      }catch(err){
        setBadge($('alertsBadge'),'تعذر قراءة البيانات','bad');
        $('alertsBox').innerHTML = '<div class="alert bad"><strong>تعذر جلب البيانات</strong><div>' + String(err?.message || err) + '</div></div>';
      }
    }

    function start(){
      if (timer) clearInterval(timer);
      timer = setInterval(() => { if (!paused) refresh(); }, 5000);
    }

    document.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-help] .helpBtn');
      if (btn) {
        const wrap = btn.parentElement;
        document.querySelectorAll('[data-help].open').forEach(x => { if (x !== wrap) x.classList.remove('open'); });
        wrap.classList.toggle('open');
        return;
      }
      if (!e.target.closest('[data-help]')) {
        document.querySelectorAll('[data-help].open').forEach(x => x.classList.remove('open'));
      }
    });

    $('refreshBtn').addEventListener('click', refresh);
    $('autoBtn').addEventListener('click', () => {
      paused = !paused;
      $('autoBtn').textContent = paused ? 'استئناف التحديث' : 'إيقاف التحديث';
    });

    refresh();
    start();
  </script>
</body>
</html>`;
}

// ---------- Worker (router) ----------
export default {
  async fetch(request, env, ctx) {
    const startedAt = Date.now();

    if (request.method === "OPTIONS") {
      return withCors(request, new Response(null, { status: 204 }), env);
    }

    if (!isOriginAllowed(request, env)) {
      return withCors(request, json({ ok: false, msg: "Origin not allowed" }, 403), env);
    }

    const url = new URL(request.url);

    if (url.pathname === "/monitor" && request.method === "GET") {
      const res = html(monitorPageHtml());
      queueMonitorRequest(ctx, env, {
        ts: Date.now(),
        path: url.pathname,
        pathKey: roomMetricsPathKey(url.pathname),
        method: request.method,
        status: 200,
        room: MONITOR_ROOM,
        pid: "",
        ms: Date.now() - startedAt,
      });
      return withCors(request, res, env);
    }

    if (url.pathname === "/monitor/summary" && request.method === "GET") {
      const r = await monitorStub(env).fetch("https://do/monitor-summary", {
        headers: { "x-room-name": MONITOR_ROOM },
      });
      queueMonitorRequest(ctx, env, {
        ts: Date.now(),
        path: url.pathname,
        pathKey: roomMetricsPathKey(url.pathname),
        method: request.method,
        status: r.status || 200,
        room: MONITOR_ROOM,
        pid: "",
        ms: Date.now() - startedAt,
      });
      return withCors(request, r, env);
    }

    const room = normalizeRoom(url.searchParams.get("room") || "default");
    const pid = normalizePid(url.searchParams.get("pid") || "");
    const id = env.ROOMS.idFromName(room);
    const stub = env.ROOMS.get(id);

    if (url.pathname === "/health") {
      const res = json({
        ok: true,
        room,
        pusher: publicPusherConfig(env, room),
      });
      queueMonitorRequest(ctx, env, {
        ts: Date.now(),
        path: url.pathname,
        pathKey: roomMetricsPathKey(url.pathname),
        method: request.method,
        status: 200,
        room,
        pid,
        ms: Date.now() - startedAt,
      });
      return withCors(request, res, env);
    }

    if (url.pathname === "/pusher/config" && request.method === "GET") {
      const res = json({
        ok: true,
        room,
        pusher: publicPusherConfig(env, room),
      });
      queueMonitorRequest(ctx, env, {
        ts: Date.now(),
        path: url.pathname,
        pathKey: roomMetricsPathKey(url.pathname),
        method: request.method,
        status: 200,
        room,
        pid,
        ms: Date.now() - startedAt,
      });
      return withCors(request, res, env);
    }

    if (url.pathname === "/state" && request.method === "GET") {
      const r = await stub.fetch(`https://do/state?pid=${encodeURIComponent(pid)}`, {
        headers: { "x-room-name": room },
      });
      queueMonitorRequest(ctx, env, {
        ts: Date.now(),
        path: url.pathname,
        pathKey: roomMetricsPathKey(url.pathname),
        method: request.method,
        status: r.status || 200,
        room,
        pid,
        ms: Date.now() - startedAt,
      });
      return withCors(request, r, env);
    }

    if (url.pathname === "/action" && request.method === "POST") {
      const raw = await request.text();

      const doRes = await stub.fetch("https://do/action", {
        method: "POST",
        headers: { "content-type": "application/json", "x-room-name": room },
        body: raw,
      });

      const doStatus = doRes.status || 200;
      const payload = await doRes.json().catch(() => null);

      if (!payload || typeof payload !== "object") {
        queueMonitorRequest(ctx, env, {
          ts: Date.now(),
          path: url.pathname,
          pathKey: roomMetricsPathKey(url.pathname),
          method: request.method,
          status: 502,
          room,
          pid,
          ms: Date.now() - startedAt,
          msg: "ACTION_BAD_RESPONSE",
        });
        return withCors(request, json({ ok: false, msg: "ACTION_BAD_RESPONSE" }, 502), env);
      }

      if (payload.ok && pusherEnabled(env)) {
        const evt = {
          patch: (payload.patch && typeof payload.patch === "object") ? payload.patch : {},
          ts: Number(payload.ts || Date.now()),
          rev: Number(payload.rev || 0),
        };

        ctx.waitUntil((async () => {
          try {
            const trig = await pusherTrigger(env, roomChannel(room), "patch", evt);
            if (trig?.ok) {
              await stub.fetch("https://do/mark-pusher-sent", {
                method: "POST",
                headers: { "x-room-name": room },
              });
              await monitorStub(env).fetch("https://do/monitor-event", {
                method: "POST",
                headers: {
                  "content-type": "application/json",
                  "x-room-name": MONITOR_ROOM,
                },
                body: JSON.stringify({
                  type: "pusher_sent",
                  ts: Date.now(),
                  room,
                  rev: Number(payload.rev || 0),
                }),
              }).catch(() => null);
            }
          } catch (e) {
            console.log("pusher_trigger_bg_failed", String(e?.message || e));
            await monitorStub(env).fetch("https://do/monitor-event", {
              method: "POST",
              headers: {
                "content-type": "application/json",
                "x-room-name": MONITOR_ROOM,
              },
              body: JSON.stringify({
                type: "request",
                ts: Date.now(),
                path: "/pusher/trigger",
                pathKey: "pusherTrigger",
                method: "POST",
                status: 500,
                room,
                pid,
                ms: 0,
                msg: String(e?.message || e || "PUSHER_TRIGGER_FAILED"),
              }),
            }).catch(() => null);
          }
        })());
      }

      queueMonitorRequest(ctx, env, {
        ts: Date.now(),
        path: url.pathname,
        pathKey: roomMetricsPathKey(url.pathname),
        method: request.method,
        status: doStatus,
        room,
        pid,
        ms: Date.now() - startedAt,
        rev: Number(payload.rev || 0),
      });
      return withCors(request, json(payload, doStatus), env);
    }

    if (url.pathname === "/stats" && request.method === "GET") {
      const r = await stub.fetch("https://do/stats", {
        headers: { "x-room-name": room },
      });
      queueMonitorRequest(ctx, env, {
        ts: Date.now(),
        path: url.pathname,
        pathKey: roomMetricsPathKey(url.pathname),
        method: request.method,
        status: r.status || 200,
        room,
        pid,
        ms: Date.now() - startedAt,
      });
      return withCors(request, r, env);
    }

    if (url.pathname === "/pusher/auth" && request.method === "POST") {
      if (!pusherEnabled(env)) {
        queueMonitorRequest(ctx, env, {
          ts: Date.now(),
          path: url.pathname,
          pathKey: roomMetricsPathKey(url.pathname),
          method: request.method,
          status: 503,
          room,
          pid,
          ms: Date.now() - startedAt,
          msg: "PUSHER_NOT_CONFIGURED",
        });
        return withCors(request, json({ ok: false, msg: "Pusher not configured" }, 503), env);
      }

      const body = await parseBodyAsObject(request);
      const socket_id = String(body.socket_id || "");
      const channel_name = String(body.channel_name || "");
      const expected = roomChannel(room);

      if (!socket_id || !channel_name || channel_name !== expected) {
        queueMonitorRequest(ctx, env, {
          ts: Date.now(),
          path: url.pathname,
          pathKey: roomMetricsPathKey(url.pathname),
          method: request.method,
          status: 403,
          room,
          pid,
          ms: Date.now() - startedAt,
          msg: "FORBIDDEN_PUSHER_AUTH",
        });
        return withCors(request, json({ ok: false, msg: "Forbidden" }, 403), env);
      }

      const stringToSign = `${socket_id}:${channel_name}`;
      const signature = await hmacSHA256Hex(env.PUSHER_SECRET, stringToSign);
      const auth = `${env.PUSHER_KEY}:${signature}`;

      queueMonitorRequest(ctx, env, {
        ts: Date.now(),
        path: url.pathname,
        pathKey: roomMetricsPathKey(url.pathname),
        method: request.method,
        status: 200,
        room,
        pid,
        ms: Date.now() - startedAt,
      });
      return withCors(request, json({ auth }), env);
    }

    queueMonitorRequest(ctx, env, {
      ts: Date.now(),
      path: url.pathname,
      pathKey: roomMetricsPathKey(url.pathname),
      method: request.method,
      status: 404,
      room,
      pid,
      ms: Date.now() - startedAt,
      msg: "NOT_FOUND",
    });
    return withCors(request, json({ ok: false, msg: "Not found" }, 404), env);
  },
};

// ---------- Durable Object ----------
const DEFAULT_IDLE_MS = 2 * 60 * 60 * 1000; // ساعتين
const SEEN_TTL_MS = 90 * 1000; // آخر 90 ثانية نحسبها "متصل"
const SEEN_GC_MAX = 200; // حماية من التضخم

function normalizeBuzzerPayload(raw, now, currentSeq = 0) {
  raw = (raw && typeof raw === "object") ? raw : {};
  return {
    pid: normalizePid(raw.pid || ""),
    name: String(raw.name || "").trim().slice(0, 80),
    team: String(raw.team || "").trim().slice(0, 30),
    ts: toFiniteNumber(raw.ts, now) || now,
    serverTs: now,
    seq: toFiniteNumber(currentSeq, 0) + 1,
  };
}

export class RoomDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;

    const ms = Number(env?.ROOM_IDLE_MS || DEFAULT_IDLE_MS);
    this.IDLE_MS = clampMin(ms, 60 * 1000);

    this.roomName = null;
  }

  _setRoomFromReq(request) {
    const rn = request.headers.get("x-room-name");
    if (rn) this.roomName = rn;
  }

  async _rememberRoomName(request) {
    const rn = request.headers.get("x-room-name");
    if (!rn) return;
    this.roomName = rn;
    try {
      await this.state.storage.put("roomName", rn);
    } catch {}
  }

  async _loadMetrics(now = Date.now()) {
    const day = utcDayKey(now);
    const m = (await this.state.storage.get("metrics")) || {
      day,
      actionsToday: 0,
      pusherMsgsToday: 0,
      peakClientsToday: 0,
      seen: {},
    };
    if (m.day !== day) {
      return { day, actionsToday: 0, pusherMsgsToday: 0, peakClientsToday: 0, seen: {} };
    }
    if (!m.seen || typeof m.seen !== "object") m.seen = {};
    return m;
  }

  async _loadMonitor(now = Date.now()) {
    const day = utcDayKey(now);
    const month = utcMonthKey(now);
    let m = (await this.state.storage.get("monitor")) || {};
    const prevDay = String(m.day || "");
    const prevMonth = String(m.month || "");

    if (!m || typeof m !== "object") m = {};
    if (!m.rooms || typeof m.rooms !== "object") m.rooms = {};
    if (!m.routes || typeof m.routes !== "object") m.routes = {};
    if (!Array.isArray(m.lastErrors)) m.lastErrors = [];

    if (prevDay !== day) {
      m.requestsToday = 0;
      m.errorsToday = 0;
      m.rawErrorsToday = 0;
      m.notFoundToday = 0;
      m.external404Today = 0;
      m.important4xxToday = 0;
      m.status2xx = 0;
      m.status4xx = 0;
      m.status5xx = 0;
      m.totalLatencyMsToday = 0;
      m.routes = {};
      m.lastErrors = [];
      m.pusherMsgsToday = 0;

      for (const roomInfo of Object.values(m.rooms)) {
        if (!roomInfo || typeof roomInfo !== "object") continue;
        roomInfo.requestsToday = 0;
        roomInfo.pusherMsgsToday = 0;
      }
    }

    if (prevMonth !== month) {
      m.pusherMsgsMonth = 0;
      m.requestsMonth = 0;
    }

    m.day = day;
    m.month = month;
    m.requestsToday = toFiniteNumber(m.requestsToday, 0);
    m.errorsToday = toFiniteNumber(m.errorsToday, 0);
    m.rawErrorsToday = toFiniteNumber(m.rawErrorsToday, m.errorsToday);
    m.notFoundToday = toFiniteNumber(m.notFoundToday, 0);
    m.external404Today = toFiniteNumber(m.external404Today, m.notFoundToday);
    m.important4xxToday = toFiniteNumber(m.important4xxToday, Math.max(0, toFiniteNumber(m.status4xx, 0) - toFiniteNumber(m.external404Today, m.notFoundToday)));
    m.status2xx = toFiniteNumber(m.status2xx, 0);
    m.status4xx = toFiniteNumber(m.status4xx, 0);
    m.status5xx = toFiniteNumber(m.status5xx, 0);
    m.totalLatencyMsToday = toFiniteNumber(m.totalLatencyMsToday, 0);
    m.pusherMsgsToday = toFiniteNumber(m.pusherMsgsToday, 0);
    m.pusherMsgsMonth = toFiniteNumber(m.pusherMsgsMonth, 0);
    m.requestsMonth = toFiniteNumber(m.requestsMonth, 0);

    m.rooms = this._gcMonitorRooms(m.rooms, now);
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

  _gcMonitorRooms(rooms, now) {
    const out = {};
    for (const [room, raw] of Object.entries(rooms || {})) {
      if (!raw || typeof raw !== "object") continue;
      const info = { ...raw };
      info.pids = this._gcSeen(info.pids || {}, now);
      info.firstSeenAt = toFiniteNumber(info.firstSeenAt, 0);
      info.lastSeenAt = toFiniteNumber(info.lastSeenAt, 0);
      info.lastActionAt = toFiniteNumber(info.lastActionAt, 0);
      info.lastStateAt = toFiniteNumber(info.lastStateAt, 0);
      info.lastStatsAt = toFiniteNumber(info.lastStatsAt, 0);
      info.lastPusherAt = toFiniteNumber(info.lastPusherAt, 0);
      info.requestsToday = toFiniteNumber(info.requestsToday, 0);
      info.pusherMsgsToday = toFiniteNumber(info.pusherMsgsToday, 0);
      info.lastStatus = toFiniteNumber(info.lastStatus, 0);
      info.rev = toFiniteNumber(info.rev, 0);
      info.expiredAt = toFiniteNumber(info.expiredAt, 0);
      info.endedReason = String(info.endedReason || "");
      const recent = Math.max(info.lastSeenAt, info.lastActionAt, info.lastStateAt, info.lastStatsAt, info.lastPusherAt, info.firstSeenAt, info.expiredAt);
      if (recent && now - recent > MONITOR_ROOM_STALE_MS) continue;
      out[room] = info;
    }
    return out;
  }

  _pushLastError(list, item) {
    const arr = Array.isArray(list) ? list.slice(0) : [];
    arr.unshift(item);
    return arr.slice(0, 25);
  }

  _buildAlerts(summary) {
    const alerts = [];
    const usage = Number(summary?.pusher?.usagePercentMonth || 0);
    const errorRate = Number(summary?.cloudflare?.errorRatePercent || 0);
    const avgLatencyMs = Number(summary?.cloudflare?.avgLatencyMs || 0);
    const activeRooms = Number(summary?.live?.roomsActiveNow || 0);
    const endedRooms = Number(summary?.live?.roomsEndedVisible || 0);
    const cfUsage = Number(summary?.cloudflare?.usagePercentMonth || 0);
    const external404Today = Number(summary?.cloudflare?.external404Today || 0);

    if (usage >= 80) {
      alerts.push({
        level: "bad",
        title: "استهلاك رسائل Pusher اقترب من الحد",
        text: `الاستهلاك الحالي وصل إلى ${usage.toFixed(1)}% من الحد الشهري المحدد.`
      });
    } else if (usage >= 50) {
      alerts.push({
        level: "warn",
        title: "استهلاك رسائل Pusher في المنطقة المتوسطة",
        text: `الاستهلاك الحالي عند ${usage.toFixed(1)}% ويستحسن متابعته.`
      });
    }

    if (errorRate > 2) {
      alerts.push({
        level: "bad",
        title: "نسبة الأخطاء مرتفعة",
        text: `نسبة الأخطاء اليوم ${errorRate.toFixed(2)}% وهي أعلى من الحد المريح.`
      });
    } else if (errorRate >= 0.5) {
      alerts.push({
        level: "warn",
        title: "نسبة الأخطاء تحتاج متابعة",
        text: `نسبة الأخطاء اليوم ${errorRate.toFixed(2)}% وهي أعلى من الطبيعي.`
      });
    }

    if (cfUsage >= 85) {
      alerts.push({
        level: "bad",
        title: "استهلاك Cloudflare الشهري اقترب من الحد",
        text: `استهلاك الطلبات الشهري وصل إلى ${cfUsage.toFixed(1)}% من الخطة الحالية.`
      });
    } else if (cfUsage >= 60) {
      alerts.push({
        level: "warn",
        title: "استهلاك Cloudflare الشهري يحتاج متابعة",
        text: `استهلاك الطلبات الشهري الآن ${cfUsage.toFixed(1)}% من الخطة الحالية.`
      });
    }

    if (avgLatencyMs > 800) {
      alerts.push({
        level: "bad",
        title: "متوسط الاستجابة بطيء",
        text: `متوسط الاستجابة الحالي ${Math.round(avgLatencyMs)}ms.`
      });
    } else if (avgLatencyMs >= 300) {
      alerts.push({
        level: "warn",
        title: "الاستجابة متوسطة",
        text: `متوسط الاستجابة الحالي ${Math.round(avgLatencyMs)}ms.`
      });
    }

    const hotRoom = (summary.rooms || []).find(r => Number(r.clientsNow || 0) >= 10);
    if (hotRoom) {
      alerts.push({
        level: "warn",
        title: "غرفة عليها ضغط مباشر",
        text: `الغرفة ${hotRoom.room} فيها الآن ${hotRoom.clientsNow} متصلين تقريبًا.`
      });
    }

    if (external404Today > 0 && !alerts.some(a => a.level === "bad" || a.level === "warn")) {
      alerts.push({
        level: "info",
        title: "تم رصد طلبات خارجية غير مهمة",
        text: `تم استبعاد ${external404Today} من طلبات 404 الخارجية من تنبيهات اللعبة حتى لا تظهر كمشكلة داخلية.`
      });
    }

    if (endedRooms > 0) {
      alerts.push({
        level: "info",
        title: "يوجد جلسات انتهت بالخمول",
        text: `تم تمييز ${endedRooms} غرف منتهية باللون الأحمر، وهي غير محسوبة ضمن الحالي.`
      });
    }

    if (!alerts.length) {
      alerts.push({
        level: "info",
        title: "الوضع الحالي طبيعي",
        text: activeRooms > 0 ? `يوجد الآن ${activeRooms} غرف نشطة بدون مؤشرات مقلقة واضحة.` : "لا توجد مؤشرات مقلقة واضحة الآن."
      });
    }

    return alerts;
  }

  async _applyMonitorEvent(evt, now = Date.now()) {
    const m = await this._loadMonitor(now);
    const type = String(evt?.type || "");
    const room = normalizeRoom(evt?.room || "");
    const pid = normalizePid(evt?.pid || "");

    if (type === "request") {
      const status = toFiniteNumber(evt?.status, 0);
      const ms = Math.max(0, toFiniteNumber(evt?.ms, 0));
      const path = String(evt?.path || "unknown").slice(0, 120);
      const pathKey = String(evt?.pathKey || roomMetricsPathKey(path)).slice(0, 60);
      const msg = String(evt?.msg || "").slice(0, 220);
      const ts = toFiniteNumber(evt?.ts, now);

      m.requestsToday += 1;
      m.requestsMonth += 1;
      m.totalLatencyMsToday += ms;

      if (status >= 500) m.status5xx += 1;
      else if (status >= 400) m.status4xx += 1;
      else if (status >= 200) m.status2xx += 1;

      const ignorable404 = isIgnorableExternal404(path, status);
      const importantError = isImportantRequestError(path, status);

      if (status >= 400) m.rawErrorsToday += 1;
      if (importantError) m.errorsToday += 1;
      if (status === 404) m.notFoundToday += 1;
      if (ignorable404) m.external404Today += 1;
      if (status >= 400 && status < 500 && importantError) m.important4xxToday += 1;

      const route = (m.routes[pathKey] && typeof m.routes[pathKey] === "object") ? m.routes[pathKey] : {
        count: 0,
        errors: 0,
        totalLatencyMs: 0,
      };
      route.count += 1;
      route.totalLatencyMs += ms;
      if (status >= 400) route.errors += 1;
      m.routes[pathKey] = route;

      if (room && room !== MONITOR_ROOM) {
        const info = (m.rooms[room] && typeof m.rooms[room] === "object") ? m.rooms[room] : {
          firstSeenAt: ts,
          pids: {},
          requestsToday: 0,
          pusherMsgsToday: 0,
        };
        info.firstSeenAt = toFiniteNumber(info.firstSeenAt, ts) || ts;
        info.expiredAt = 0;
        info.endedReason = "";
        info.lastSeenAt = ts;
        info.lastPath = path;
        info.lastStatus = status;
        info.requestsToday = toFiniteNumber(info.requestsToday, 0) + 1;
        info.rev = toFiniteNumber(evt?.rev, toFiniteNumber(info.rev, 0));

        if (path === "/state") info.lastStateAt = ts;
        if (path === "/action") info.lastActionAt = ts;
        if (path === "/stats") info.lastStatsAt = ts;
        if (pid) {
          info.pids = this._gcSeen(info.pids || {}, ts);
          info.pids[pid] = ts;
        } else {
          info.pids = this._gcSeen(info.pids || {}, ts);
        }

        m.rooms[room] = info;
      }

      if (importantError) {
        m.lastErrors = this._pushLastError(m.lastErrors, {
          ts,
          status,
          path,
          room: room || null,
          msg: msg || (status === 404 ? "NOT_FOUND" : "REQUEST_ERROR"),
        });
      }
    }

    if (type === "pusher_sent") {
      const ts = toFiniteNumber(evt?.ts, now);
      m.pusherMsgsToday += 1;
      m.pusherMsgsMonth += 1;

      if (room && room !== MONITOR_ROOM) {
        const info = (m.rooms[room] && typeof m.rooms[room] === "object") ? m.rooms[room] : {
          firstSeenAt: ts,
          pids: {},
          requestsToday: 0,
          pusherMsgsToday: 0,
        };
        info.firstSeenAt = toFiniteNumber(info.firstSeenAt, ts) || ts;
        info.expiredAt = 0;
        info.endedReason = "";
        info.lastSeenAt = Math.max(toFiniteNumber(info.lastSeenAt, 0), ts);
        info.lastPusherAt = ts;
        info.pusherMsgsToday = toFiniteNumber(info.pusherMsgsToday, 0) + 1;
        info.rev = toFiniteNumber(evt?.rev, toFiniteNumber(info.rev, 0));
        info.pids = this._gcSeen(info.pids || {}, ts);
        m.rooms[room] = info;
      }
    }

    if (type === "room_expired") {
      const ts = toFiniteNumber(evt?.ts, now);
      if (room && room !== MONITOR_ROOM) {
        const info = (m.rooms[room] && typeof m.rooms[room] === "object") ? m.rooms[room] : {
          firstSeenAt: ts,
          pids: {},
          requestsToday: 0,
          pusherMsgsToday: 0,
        };
        info.firstSeenAt = toFiniteNumber(info.firstSeenAt, ts) || ts;
        info.expiredAt = ts;
        info.endedReason = String(evt?.reason || "idle_timeout");
        info.lastSeenAt = Math.max(toFiniteNumber(info.lastSeenAt, 0), ts);
        info.pids = {};
        m.rooms[room] = info;
      }
    }

    await this.state.storage.put("monitor", m);
    return m;
  }

  async fetch(request) {
    this._setRoomFromReq(request);
    await this._rememberRoomName(request);
    const url = new URL(request.url);

    if (url.pathname === "/monitor-event" && request.method === "POST") {
      let body = {};
      try { body = await request.json(); } catch {}
      await this._applyMonitorEvent(body, Date.now());
      return json({ ok: true });
    }

    if (url.pathname === "/monitor-summary" && request.method === "GET") {
      const now = Date.now();
      const m = await this._loadMonitor(now);
      await this.state.storage.put("monitor", m);

      const planMessages = clampMin(Number(this.env?.PUSHER_PLAN_MESSAGES || this.env?.PUSHER_MESSAGES_LIMIT || DEFAULT_PUSHER_PLAN_MESSAGES), 1);
      const rooms = [];
      let connectionsNow = 0;
      let roomsActiveNow = 0;
      let roomsSeenToday = 0;
      let roomsEndedVisible = 0;
      let roomsTrackedCurrent = 0;

      for (const [room, raw] of Object.entries(m.rooms || {})) {
        const info = raw || {};
        const pids = this._gcSeen(info.pids || {}, now);
        const clientsNow = this._clientsNow(pids, now);
        const lastSeenAt = toFiniteNumber(info.lastSeenAt, 0);
        const lastActionAt = toFiniteNumber(info.lastActionAt, 0);
        const lastPusherAt = toFiniteNumber(info.lastPusherAt, 0);
        const expiredAt = toFiniteNumber(info.expiredAt, 0);
        const isEnded = expiredAt > 0;
        const isActive = !isEnded && (clientsNow > 0 || (now - Math.max(lastActionAt, lastPusherAt, lastSeenAt) <= MONITOR_ACTIVE_ROOM_MS));

        if (isEnded) roomsEndedVisible += 1;
        else {
          roomsTrackedCurrent += 1;
          if (isActive) roomsActiveNow += 1;
          connectionsNow += clientsNow;
          if (toFiniteNumber(info.requestsToday, 0) > 0 || toFiniteNumber(info.pusherMsgsToday, 0) > 0) roomsSeenToday += 1;
        }

        rooms.push({
          room,
          clientsNow,
          isActive,
          isEnded,
          expiredAt,
          endedReason: String(info.endedReason || ""),
          lastSeenAt,
          lastActionAt,
          lastPusherAt,
          requestsToday: toFiniteNumber(info.requestsToday, 0),
          pusherMsgsToday: toFiniteNumber(info.pusherMsgsToday, 0),
          lastPath: String(info.lastPath || ""),
          lastStatus: toFiniteNumber(info.lastStatus, 0),
          rev: toFiniteNumber(info.rev, 0),
        });
      }

      rooms.sort((a, b) => {
        if (Number(a.isEnded) !== Number(b.isEnded)) return Number(a.isEnded) - Number(b.isEnded);
        if (Number(b.isActive) !== Number(a.isActive)) return Number(b.isActive) - Number(a.isActive);
        if (b.clientsNow !== a.clientsNow) return b.clientsNow - a.clientsNow;
        return Math.max(toFiniteNumber(b.lastSeenAt, 0), toFiniteNumber(b.expiredAt, 0)) - Math.max(toFiniteNumber(a.lastSeenAt, 0), toFiniteNumber(a.expiredAt, 0));
      });

      const requestsToday = toFiniteNumber(m.requestsToday, 0);
      const requestsMonth = toFiniteNumber(m.requestsMonth, 0);
      const rawErrorsToday = toFiniteNumber(m.rawErrorsToday, toFiniteNumber(m.errorsToday, 0));
      const external404Today = toFiniteNumber(m.external404Today, toFiniteNumber(m.notFoundToday, 0));
      const important4xxToday = toFiniteNumber(m.important4xxToday, Math.max(0, toFiniteNumber(m.status4xx, 0) - external404Today));
      const errorsToday = Math.max(0, toFiniteNumber(m.errorsToday, rawErrorsToday - external404Today));
      const avgLatencyMs = requestsToday > 0 ? (toFiniteNumber(m.totalLatencyMsToday, 0) / requestsToday) : 0;
      const errorRatePercent = requestsToday > 0 ? (errorsToday / requestsToday) * 100 : 0;
      const messagesMonth = toFiniteNumber(m.pusherMsgsMonth, 0);
      const usagePercentMonth = Math.min(100, (messagesMonth / planMessages) * 100);
      const cfPlanRequestsMonth = clampMin(Number(this.env?.CF_PLAN_REQUESTS_MONTH || DEFAULT_CF_MONTHLY_REQUESTS), 1);
      const cfFreeDailyRequests = clampMin(Number(this.env?.CF_FREE_DAILY_REQUESTS || DEFAULT_CF_FREE_DAILY_REQUESTS), 1);
      const cfPlanName = String(this.env?.CF_PLAN_NAME || DEFAULT_CF_PLAN_NAME);
      const cfUsagePercentMonth = Math.min(100, (requestsMonth / cfPlanRequestsMonth) * 100);
      const routes = m.routes || {};
      const routeCount = (k) => toFiniteNumber((routes[k] && routes[k].count) || 0, 0);
      const breakdownAction = routeCount("action");
      const breakdownState = routeCount("state");
      const breakdownPusher = routeCount("pusherAuth") + routeCount("pusherConfig") + routeCount("pusherTrigger");
      const breakdownMonitor = routeCount("monitorUI") + routeCount("monitorSummary");
      const knownBreakdown = breakdownAction + breakdownState + breakdownPusher + breakdownMonitor;
      const breakdownOther = Math.max(0, requestsToday - knownBreakdown);

      const resetInfo = utcResetCountdown(now);

      const summary = {
        ok: true,
        generatedAt: now,
        system: {
          worker: true,
          pusherConfigured: pusherEnabled(this.env),
          monitor: true,
        },
        pusher: {
          messagesToday: toFiniteNumber(m.pusherMsgsToday, 0),
          messagesMonth,
          planMessages,
          remainingMessages: Math.max(0, planMessages - messagesMonth),
          usagePercentMonth,
        },
        dailyReset: {
          resetAt: resetInfo.resetAt,
          hoursRemaining: resetInfo.hoursRemaining,
          minutesRemaining: resetInfo.minutesRemaining,
          hoursLabel: `${resetInfo.hoursRemaining}س`,
        },
        live: {
          connectionsNow,
          roomsActiveNow,
          roomsSeenToday,
          roomsTracked: rooms.length,
          roomsTrackedCurrent,
          roomsEndedVisible,
        },
        cloudflare: {
          requestsToday,
          requestsMonth,
          errorsToday,
          rawErrorsToday,
          external404Today,
          errorRatePercent,
          avgLatencyMs,
          status2xx: toFiniteNumber(m.status2xx, 0),
          status4xx: important4xxToday,
          rawStatus4xx: toFiniteNumber(m.status4xx, 0),
          status5xx: toFiniteNumber(m.status5xx, 0),
          planName: cfPlanName,
          planRequestsMonth: cfPlanRequestsMonth,
          freeDailyRequests: cfFreeDailyRequests,
          remainingRequestsMonth: Math.max(0, cfPlanRequestsMonth - requestsMonth),
          usagePercentMonth: cfUsagePercentMonth,
        },
        requestBreakdown: {
          action: breakdownAction,
          state: breakdownState,
          pusher: breakdownPusher,
          monitor: breakdownMonitor,
          other: breakdownOther,
        },
        rooms: rooms.slice(0, 100),
        lastErrors: Array.isArray(m.lastErrors) ? m.lastErrors.slice(0, 25) : [],
        sources: {
          pusher: "عداد داخلي مبني على الرسائل التي يرسلها Worker إلى Pusher",
          cloudflare: "مؤشرات تشغيلية داخلية من نفس Worker",
        },
      };

      summary.alerts = this._buildAlerts(summary);
      return json(summary);
    }

    if (url.pathname === "/state") {
      const s = (await this.state.storage.get("state")) || {};
      const rev = Number((await this.state.storage.get("rev")) || 0);

      const pid = normalizePid(url.searchParams.get("pid") || "");
      if (pid) {
        const now = Date.now();
        const m = await this._loadMetrics(now);
        m.seen = this._gcSeen(m.seen, now);
        m.seen[pid] = now;
        const clientsNow = this._clientsNow(m.seen, now);
        m.peakClientsToday = Math.max(Number(m.peakClientsToday || 0), clientsNow);
        await this.state.storage.put("metrics", m);
      }

      return json({ ok: true, state: s, rev });
    }

    if (url.pathname === "/stats") {
      const now = Date.now();
      const m = await this._loadMetrics(now);
      m.seen = this._gcSeen(m.seen, now);
      const clientsNow = this._clientsNow(m.seen, now);
      m.peakClientsToday = Math.max(Number(m.peakClientsToday || 0), clientsNow);
      await this.state.storage.put("metrics", m);

      const lastActiveAt = Number((await this.state.storage.get("lastActiveAt")) || 0);
      const rev = Number((await this.state.storage.get("rev")) || 0);

      return json({
        ok: true,
        room: this.roomName || "unknown",
        day: m.day,
        actionsToday: Number(m.actionsToday || 0),
        pusherMessagesToday: Number(m.pusherMsgsToday || 0),
        clientsNow,
        peakClientsToday: Number(m.peakClientsToday || 0),
        lastActiveAt,
        rev,
        pusherConfigured: pusherEnabled(this.env),
      });
    }

    if (url.pathname === "/mark-pusher-sent" && request.method === "POST") {
      const now = Date.now();
      const m = await this._loadMetrics(now);
      m.pusherMsgsToday = Number(m.pusherMsgsToday || 0) + 1;
      await this.state.storage.put("metrics", m);
      return json({ ok: true });
    }

    if (url.pathname === "/action") {
      let body = {};
      try { body = await request.json(); } catch {}

      const current = (await this.state.storage.get("state")) || {};
      const now = Date.now();
      const currentRev = Number((await this.state.storage.get("rev")) || 0);

      let nextRev = currentRev;
      let next = current;
      let patch = (body && typeof body === "object" && !Array.isArray(body)) ? { ...body } : {};

      let accepted = true;
      const actionType = String(body?.type || "");

      // ✅ مسار رسمي خاص بالجرس
      if (actionType === "buzz") {
        const existingBuzzer = current?.buzzer ?? null;

        if (current?.status !== "started") {
          return json({
            ok: true,
            accepted: false,
            reason: "GAME_NOT_STARTED",
            winner: existingBuzzer,
            state: current,
            rev: currentRev,
            ts: now
          });
        }

        if (current?.freeze) {
          return json({
            ok: true,
            accepted: false,
            reason: "BUZZER_FROZEN",
            winner: existingBuzzer,
            state: current,
            rev: currentRev,
            ts: now
          });
        }

        if (existingBuzzer) {
          return json({
            ok: true,
            accepted: false,
            reason: "LOCKED",
            winner: existingBuzzer,
            state: current,
            rev: currentRev,
            ts: now
          });
        }

        const nextBuzzer = normalizeBuzzerPayload({
          pid: body.pid,
          name: body.name,
          team: body.team,
          ts: body.ts
        }, now, Number(current?.buzzerSeq || 0));

        next = {
          ...current,
          buzzer: nextBuzzer,
          buzzerSeq: nextBuzzer.seq
        };

        patch = {
          buzzer: nextBuzzer,
          buzzerSeq: nextBuzzer.seq
        };

        nextRev = currentRev + 1;

        await this.state.storage.put("state", next);
        await this.state.storage.put("rev", nextRev);
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
        await this.state.storage.put("metrics", m);

        return json({
          ok: true,
          accepted: true,
          action: "buzz",
          winner: nextBuzzer,
          state: next,
          rev: nextRev,
          patch,
          ts: now
        });
      }

      // ✅ حماية إضافية لأي كود قديم يحاول يكتب buzzer مباشرة
      const existingBuzzer = current?.buzzer ?? null;
      if (Object.prototype.hasOwnProperty.call(patch, "buzzer")) {
        const incomingBuzzer = patch.buzzer;

        if (incomingBuzzer === null) {
          const safePatch = { ...patch };
          // إذا انمسح الجرس يدويًا، لا نزيد seq إلا إذا جاء صريح
          next = { ...current, ...safePatch };
        } else if (!existingBuzzer) {
          const normalized = normalizeBuzzerPayload(incomingBuzzer, now, Number(current?.buzzerSeq || 0));
          patch.buzzer = normalized;
          patch.buzzerSeq = normalized.seq;
          next = { ...current, ...patch };
        } else {
          const safePatch = { ...patch };
          delete safePatch.buzzer;
          delete safePatch.buzzerSeq;
          next = { ...current, ...safePatch };
          accepted = false;
        }
      } else {
        next = { ...current, ...patch };
      }

      nextRev = currentRev + 1;

      await this.state.storage.put("state", next);
      await this.state.storage.put("rev", nextRev);
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
      await this.state.storage.put("metrics", m);

      return json({
        ok: true,
        accepted,
        state: next,
        rev: nextRev,
        patch,
        ts: now
      });
    }

    return json({ ok: false, msg: "DO Not found" }, 404);
  }

  async alarm() {
    const now = Date.now();
    const last = Number((await this.state.storage.get("lastActiveAt")) || 0);
    const storedRoomName = String((await this.state.storage.get("roomName")) || this.roomName || "");

    if (last && now - last < this.IDLE_MS) {
      try {
        await this.state.storage.setAlarm(last + this.IDLE_MS);
      } catch (e) {
        console.log("reschedule_failed", String(e?.message || e));
      }
      return;
    }

    try {
      if (storedRoomName && storedRoomName !== MONITOR_ROOM) {
        await monitorStub(this.env).fetch("https://do/monitor-event", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-room-name": MONITOR_ROOM,
          },
          body: JSON.stringify({
            type: "room_expired",
            ts: now,
            room: storedRoomName,
            reason: "idle_timeout",
          }),
        }).catch(() => null);
      }

      if (typeof this.state.storage.deleteAll === "function") {
        await this.state.storage.deleteAll();
      } else {
        await this.state.storage.delete("state");
        await this.state.storage.delete("rev");
        await this.state.storage.delete("lastActiveAt");
        await this.state.storage.delete("metrics");
      }
    } catch (e) {
      console.log("expire_delete_failed", String(e?.message || e));
    }
  }
}
