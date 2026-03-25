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

function clampProbability(n, fallback = 1) {
  n = Number(n);
  if (!Number.isFinite(n)) return fallback;
  if (n <= 0) return 0;
  if (n >= 1) return 1;
  return n;
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
const DEFAULT_PUSHER_PLAN_CONNECTIONS = 2_000;
const DEFAULT_CF_MONTHLY_REQUESTS = 10_000_000;
const DEFAULT_CF_FREE_DAILY_REQUESTS = 100_000;
const DEFAULT_CF_PLAN_NAME = "Workers Paid ($5)";
const DEFAULT_PUSHER_BILLING_START = "2026-03-19T22:14:00+03:00";

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

function monitorRequestSampleRate(evt, env) {
  const data = (evt && typeof evt === "object") ? evt : {};
  const pathKey = String(data.pathKey || roomMetricsPathKey(data.path || "")).trim();
  const status = Number(data.status || 0);

  if (!Number.isFinite(status) || status >= 400) return 1;
  if (pathKey === "monitorUI" || pathKey === "monitorSummary" || pathKey === "monitorDetailsUI") return 1;

  const envKey = {
    state: "MONITOR_SAMPLE_STATE_OK",
    action: "MONITOR_SAMPLE_ACTION_OK",
    stats: "MONITOR_SAMPLE_STATS_OK",
    health: "MONITOR_SAMPLE_HEALTH_OK",
    pusherAuth: "MONITOR_SAMPLE_PUSHER_AUTH_OK",
    pusherConfig: "MONITOR_SAMPLE_PUSHER_CONFIG_OK",
    pusherTrigger: "MONITOR_SAMPLE_PUSHER_TRIGGER_OK",
  }[pathKey];

  if (envKey && env && Object.prototype.hasOwnProperty.call(env, envKey)) {
    return clampProbability(env[envKey], 1);
  }

  switch (pathKey) {
    case "state": return 0.05;
    case "action": return 0.35;
    case "stats": return 0.15;
    case "health": return 0.10;
    case "pusherAuth": return 0.25;
    case "pusherConfig": return 0.15;
    case "pusherTrigger": return 1;
    default: return 1;
  }
}

function shouldQueueMonitorRequest(evt, env) {
  const rate = monitorRequestSampleRate(evt, env);
  if (rate >= 1) return true;
  if (rate <= 0) return false;
  return Math.random() < rate;
}

function queueMonitorRequest(ctx, env, data) {
  const payload = { type: "request", ...(data || {}) };
  if (!shouldQueueMonitorRequest(payload, env)) return;
  queueMonitorEvent(ctx, env, payload);
}

function parseDateMs(value, fallback = Date.now()) {
  const n = Date.parse(String(value || "").trim());
  return Number.isFinite(n) ? n : fallback;
}

function addUtcMonths(baseTs, monthOffset) {
  const d = new Date(baseTs);
  d.setUTCMonth(d.getUTCMonth() + Number(monthOffset || 0));
  return d.getTime();
}

function pusherBillingCycleInfo(now = Date.now(), anchorValue = DEFAULT_PUSHER_BILLING_START) {
  const fallbackAnchor = parseDateMs(DEFAULT_PUSHER_BILLING_START, now);
  const anchorTs = parseDateMs(anchorValue, fallbackAnchor);

  let startTs = anchorTs;

  if (now >= anchorTs) {
    const a = new Date(anchorTs);
    const n = new Date(now);
    let diffMonths =
      ((n.getUTCFullYear() - a.getUTCFullYear()) * 12) +
      (n.getUTCMonth() - a.getUTCMonth());

    startTs = addUtcMonths(anchorTs, diffMonths);
    if (startTs > now) startTs = addUtcMonths(anchorTs, diffMonths - 1);

    while (addUtcMonths(startTs, 1) <= now) {
      startTs = addUtcMonths(startTs, 1);
    }
  } else {
    while (startTs > now) {
      startTs = addUtcMonths(startTs, -1);
    }
  }

  const nextResetTs = addUtcMonths(startTs, 1);
  const remainingMs = Math.max(0, nextResetTs - now);

  return {
    anchorTs,
    startTs,
    nextResetTs,
    remainingMs,
    label: humanRemainingLabel(remainingMs),
    cycleKey: "pusher:" + String(startTs),
  };
}

function humanRemainingLabel(ms) {
  const totalMinutes = Math.max(1, Math.ceil(Math.max(0, Number(ms || 0)) / (60 * 1000)));
  const days = Math.floor(totalMinutes / (60 * 24));
  const hours = Math.floor((totalMinutes - (days * 24 * 60)) / 60);
  const minutes = totalMinutes % 60;

  if (days > 0) return hours > 0 ? (days + "ي " + hours + "س") : (days + "ي");
  if (hours > 0) return minutes > 0 ? (hours + "س " + minutes + "د") : (hours + "س");
  return Math.max(1, minutes) + "د";
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
  --bg:#08101f;
  --panel:#0e1930;
  --panel2:#101f3d;
  --panel3:#15284a;
  --line:rgba(148,163,184,.16);
  --text:#f8fbff;
  --muted:#9db0d1;
  --blue:#4f8cff;
  --cyan:#27c7f8;
  --green:#19c37d;
  --yellow:#f6b93b;
  --red:#ff5d73;
  --shadow:0 18px 40px rgba(2,8,23,.32);
}
*{box-sizing:border-box}
html,body{margin:0}
body{
  color:var(--text);
  font-family:Arial,sans-serif;
  background:
    radial-gradient(1200px 500px at 100% -10%, rgba(79,140,255,.16), transparent 55%),
    radial-gradient(900px 420px at 0% 0%, rgba(39,199,248,.10), transparent 50%),
    linear-gradient(180deg,#050b16 0%,#0a1121 38%,#0f1a32 100%);
  min-height:100vh;
}
.wrap{width:min(1450px,100%); margin:0 auto; padding:16px}
.top{
  display:flex; justify-content:space-between; gap:12px; align-items:flex-start; flex-wrap:wrap;
  background:linear-gradient(180deg, rgba(17,27,47,.94), rgba(12,20,38,.96));
  border:1px solid var(--line);
  border-radius:26px;
  padding:18px;
  box-shadow:var(--shadow);
}
.title{font-size:30px; font-weight:900}
.sub{margin-top:8px; color:var(--muted); font-size:14px}
.topTags{display:flex; gap:8px; flex-wrap:wrap; margin-top:12px}
.tag{
  display:inline-flex; align-items:center; justify-content:center;
  min-height:34px; padding:8px 12px; border-radius:999px;
  font-size:12px; font-weight:800; border:1px solid var(--line);
  background:rgba(255,255,255,.05); color:#d7e6ff;
}
.ok{background:rgba(25,195,125,.16); border-color:rgba(25,195,125,.45); color:#cbffe8}
.warn{background:rgba(246,185,59,.16); border-color:rgba(246,185,59,.45); color:#fff3cd}
.bad{background:rgba(255,93,115,.16); border-color:rgba(255,93,115,.45); color:#ffd7dd}
.info{background:rgba(39,199,248,.12); border-color:rgba(39,199,248,.38); color:#d6f8ff}
.controls{display:flex; gap:10px; flex-wrap:wrap}
button,a.btn{
  border:0; border-radius:16px; padding:13px 18px;
  font-weight:800; font-size:15px; cursor:pointer; color:#fff;
  background:linear-gradient(135deg,var(--blue),#355dff);
  box-shadow:0 12px 26px rgba(53,93,255,.22);
  text-decoration:none;
}
button.secondary,a.btn.secondary{
  background:rgba(255,255,255,.05); border:1px solid var(--line); box-shadow:none; color:#fff;
}
.section{margin-top:14px; border:1px solid var(--line); border-radius:26px; background:linear-gradient(180deg, rgba(16,26,49,.95), rgba(10,16,32,.96)); box-shadow:var(--shadow); padding:16px}
.sectionHead{display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; margin-bottom:12px}
.sectionTitle{font-size:18px; font-weight:900}
.sectionDesc{margin-top:4px; color:var(--muted); font-size:12px}
.priorityGrid{display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:10px}
.grid4{display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px}
.grid3{display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px}
.card{
  border:1px solid var(--line); border-radius:20px; padding:14px;
  background:linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02));
}
.label{font-size:12px; color:var(--muted); line-height:1.6}
.value{margin-top:6px; font-size:28px; font-weight:900}
.value.small{font-size:22px}
.textGood{color:var(--green)}
.textWarn{color:var(--yellow)}
.textBad{color:var(--red)}
.alerts{display:grid; gap:10px}
.alert{padding:14px; border-radius:18px; border:1px solid var(--line); background:rgba(255,255,255,.04); line-height:1.9}
.alert strong{display:block; margin-bottom:4px}
.tableWrap{overflow:auto; border:1px solid var(--line); border-radius:18px; background:rgba(8,14,28,.42)}
table{width:100%; border-collapse:collapse; min-width:720px}
th,td{padding:12px 10px; text-align:right; border-bottom:1px solid rgba(148,163,184,.12); font-size:13px; vertical-align:top}
th{position:sticky; top:0; background:#0d1628; color:#d6e7ff; font-size:12px}
.empty{padding:18px; text-align:center; color:var(--muted)}
.rooms{display:grid; gap:10px}
.roomItem{
  border:1px solid var(--line); border-radius:18px; background:rgba(255,255,255,.03); overflow:hidden;
}
.roomItem summary{
  list-style:none; cursor:pointer; padding:14px; display:flex; justify-content:space-between; gap:10px; align-items:center;
}
.roomItem summary::-webkit-details-marker{display:none}
.roomMain{display:flex; gap:8px; align-items:center; flex-wrap:wrap}
.roomName{font-size:15px; font-weight:900}
.roomMeta{display:flex; gap:8px; flex-wrap:wrap}
.roomBody{padding:0 14px 14px}
.roomGrid{display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px}
.mini{border:1px solid var(--line); border-radius:16px; padding:12px; background:rgba(255,255,255,.02)}
.mini .label{font-size:11px}
.mini .value{font-size:20px}
.foot{margin-top:12px; color:var(--muted); font-size:12px; line-height:1.9}
@media (max-width:1200px){
  .priorityGrid{grid-template-columns:repeat(3,minmax(0,1fr))}
  .grid4{grid-template-columns:repeat(2,minmax(0,1fr))}
  .grid3{grid-template-columns:repeat(2,minmax(0,1fr))}
  .roomGrid{grid-template-columns:repeat(2,minmax(0,1fr))}
}
@media (max-width:760px){
  .wrap{padding:12px}
  .title{font-size:25px}
  .priorityGrid,.grid4,.grid3,.roomGrid{grid-template-columns:repeat(1,minmax(0,1fr))}
  .value{font-size:22px}
}
</style>
</head>
<body>
<div class="wrap">
  <section class="top">
    <div>
      <div class="title">لوحة مراقبة سباق الحروف</div>
      <div class="sub">صفحة سريعة للمهم فقط: الأخطاء الفعلية، الضغط الحالي، الغرف، بوشر، وكلاودفلير.</div>
      <div class="topTags">
        <div id="lastUpdatedTag" class="tag info">آخر تحديث: —</div>
        <div id="billingTag" class="tag info">دورة بوشر: —</div>
        <div id="resetTag" class="tag info">تصفير اليوم: —</div>
      </div>
    </div>
    <div class="controls">
      <button id="refreshBtn">تحديث الآن</button>
      <button id="autoBtn" class="secondary">إيقاف التحديث</button>
      <a href="/monitor/details" class="btn secondary">التفاصيل الدقيقة</a>
    </div>
  </section>

  <section class="section">
    <div class="sectionHead">
      <div>
        <div class="sectionTitle">المؤشرات العاجلة</div>
        <div class="sectionDesc">الأهم في أعلى الصفحة: الأخطاء الفعلية، الضغط، والاستجابة.</div>
      </div>
      <div id="priorityBadge" class="tag info">بانتظار البيانات</div>
    </div>
    <div class="priorityGrid">
      <div class="card"><div class="label">أخطاء 5xx اليوم</div><div id="priority5xx" class="value">—</div></div>
      <div class="card"><div class="label">أخطاء 4xx المهمة</div><div id="priority4xx" class="value">—</div></div>
      <div class="card"><div class="label">نسبة الأخطاء المهمة</div><div id="priorityErrRate" class="value small">—</div></div>
      <div class="card"><div class="label">متوسط الاستجابة</div><div id="priorityLatency" class="value small">—</div></div>
      <div class="card"><div class="label">الاتصالات الحالية / 2000</div><div id="priorityConnections" class="value small">—</div></div>
      <div class="card"><div class="label">استهلاك رسائل بوشر</div><div id="priorityPusher" class="value small">—</div></div>
    </div>
  </section>

  <section class="section">
    <div class="sectionHead">
      <div>
        <div class="sectionTitle">الحالة العامة والتنبيهات</div>
        <div class="sectionDesc">تنبيهات عربية واضحة فقط لما يستحق الانتباه.</div>
      </div>
      <div id="alertsBadge" class="tag info">بانتظار البيانات</div>
    </div>
    <div id="alertsBox" class="alerts">
      <div class="empty">بانتظار أول تحديث…</div>
    </div>
  </section>

  <section class="section">
    <div class="sectionHead">
      <div>
        <div class="sectionTitle">آخر الأخطاء المهمة</div>
        <div class="sectionDesc">الأخطاء غير المهمة لا تظهر هنا.</div>
      </div>
      <div id="errorsBadge" class="tag info">بانتظار البيانات</div>
    </div>
    <div class="tableWrap">
      <table>
        <thead><tr><th>الوقت</th><th>النوع</th><th>المسار</th><th>الغرفة</th><th>الشرح</th></tr></thead>
        <tbody id="errorsBody"><tr><td colspan="5" class="empty">لا توجد أخطاء مهمة الآن</td></tr></tbody>
      </table>
    </div>
  </section>

  <section class="section">
    <div class="sectionHead">
      <div>
        <div class="sectionTitle">ملخص مباشر</div>
        <div class="sectionDesc">كل ما يخص اللعب الحالي اليوم.</div>
      </div>
      <div id="overallBadge" class="tag info">بانتظار البيانات</div>
    </div>
    <div class="grid4">
      <div class="card"><div class="label">حالة الـ Worker</div><div id="workerStatus" class="value small">—</div></div>
      <div class="card"><div class="label">حالة Pusher</div><div id="pusherStatus" class="value small">—</div></div>
      <div class="card"><div class="label">التقييم العام</div><div id="overallStatus" class="value small">—</div></div>
      <div class="card"><div class="label">عدد الغرف الحالية</div><div id="roomsCurrent" class="value">—</div></div>
      <div class="card"><div class="label">الاتصالات الحالية</div><div id="liveConnections" class="value">—</div></div>
      <div class="card"><div class="label">الغرف النشطة الآن</div><div id="liveRooms" class="value">—</div></div>
      <div class="card"><div class="label">الغرف التي لُعبت اليوم</div><div id="liveRoomsToday" class="value small">—</div></div>
      <div class="card"><div class="label">إجمالي المتصلين اليوم</div><div id="uniquePlayersToday" class="value small">—</div></div>
      <div class="card"><div class="label">غرف حُذفت بالخمول اليوم</div><div id="roomsExpiredToday" class="value small">—</div></div>
      <div class="card"><div class="label">رسائل بوشر اليوم</div><div id="pusherToday" class="value small">—</div></div>
      <div class="card"><div class="label">المتبقي من رسائل بوشر</div><div id="pusherRemaining" class="value small">—</div></div>
      <div class="card"><div class="label">طلبات كلاودفلير اليوم</div><div id="cfRequestsToday" class="value small">—</div></div>
    </div>
  </section>

  <section class="section">
    <div class="sectionHead">
      <div>
        <div class="sectionTitle">بوشر وكلاودفلير</div>
        <div class="sectionDesc">ملخص سريع يغنيك عن التنقل للوحاتهما في المتابعة اليومية.</div>
      </div>
    </div>
    <div class="grid3">
      <div class="card">
        <div class="label">رسائل بوشر من دورة الاشتراك الحالية</div>
        <div id="pusherMain" class="value small">—</div>
        <div id="pusherSub" class="foot"></div>
      </div>
      <div class="card">
        <div class="label">استخدام طلبات كلاودفلير هذا الشهر</div>
        <div id="cfMonthMain" class="value small">—</div>
        <div id="cfMonthSub" class="foot"></div>
      </div>
      <div class="card">
        <div class="label">تفصيل أخطاء اليوم</div>
        <div id="cfErrMain" class="value small">—</div>
        <div id="cfErrSub" class="foot"></div>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="sectionHead">
      <div>
        <div class="sectionTitle">الغرف الحالية</div>
        <div class="sectionDesc">اضغط على الغرفة لفتح التفاصيل أو إغلاقها. الغرف الخاملة ساعتين تُحذف تلقائيًا من الصفحة.</div>
      </div>
      <div id="roomsBadge" class="tag info">بانتظار البيانات</div>
    </div>
    <div id="roomsBox" class="rooms">
      <div class="empty">لا توجد غرف حالية الآن</div>
    </div>
    <div class="foot">المدة = من أول ظهور للغرفة حتى الآن. عدد الداخلين = عدد المعرّفات المختلفة التي دخلت الغرفة خلال حياتها الحالية.</div>
  </section>
</div>

<script>
const $ = (id) => document.getElementById(id);
const fmt = (n) => Number(n || 0).toLocaleString('en-US');
const pct = (n) => Number(n || 0).toFixed(1) + '%';
const msText = (n) => Math.round(Number(n || 0)) + 'ms';

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

function formatDateShort(ts){
  const n = Number(ts || 0);
  if (!n) return '—';
  return new Date(n).toLocaleString('ar-SA');
}

function setBadge(el, text, kind){
  el.className = 'tag ' + kind;
  el.textContent = text;
}

function setValueColor(el, kind){
  el.classList.remove('textGood','textWarn','textBad');
  if (kind === 'ok') el.classList.add('textGood');
  if (kind === 'warn') el.classList.add('textWarn');
  if (kind === 'bad') el.classList.add('textBad');
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

function connectionLevel(connections, maxConnections){
  const c = Number(connections || 0);
  const m = Math.max(1, Number(maxConnections || 2000));
  const p = (c / m) * 100;
  if (p >= 75) return ['قلق','bad'];
  if (p >= 45) return ['متوسط','warn'];
  return ['طبيعي','ok'];
}

function overallLevel(sum){
  const p = Number(sum && sum.pusher ? sum.pusher.usagePercentMonth : 0);
  const c = Number(sum && sum.pusher ? sum.pusher.connectionUsagePercent : 0);
  const e = Number(sum && sum.cloudflare ? sum.cloudflare.errorRatePercent : 0);
  const l = Number(sum && sum.cloudflare ? sum.cloudflare.avgLatencyMs : 0);
  const s5 = Number(sum && sum.cloudflare ? sum.cloudflare.status5xx : 0);

  if (s5 > 0 || p >= 80 || c >= 75 || e > 2 || l > 800) return ['يحتاج انتباه','bad'];
  if (p >= 50 || c >= 45 || e >= 0.5 || l >= 300) return ['مستقر مع متابعة','warn'];
  return ['ممتاز','ok'];
}

function sevRank(v){
  if (v === 'bad') return 3;
  if (v === 'warn') return 2;
  return 1;
}

function translateError(row){
  const status = Number(row && row.status || 0);
  const path = String(row && row.path || '');
  const msg = String(row && row.msg || '');

  if (msg === 'ACTION_BAD_RESPONSE') return 'استجابة غير صالحة من غرفة اللعبة عند تنفيذ أمر.';
  if (msg === 'PUSHER_TRIGGER_FAILED') return 'فشل إرسال التحديث إلى بوشر.';
  if (msg === 'PUSHER_NOT_CONFIGURED') return 'بوشر غير مضبوط داخل العامل.';
  if (msg === 'SESSION_EXPIRED') return 'الجلسة انتهت.';
  if (msg === 'NOT_FOUND' && path === '/action') return 'تم طلب مسار لعب غير موجود.';
  if (status >= 500 && path === '/action') return 'خطأ داخلي أثناء تنفيذ إجراء داخل اللعبة.';
  if (status >= 500 && path === '/state') return 'تعذر قراءة حالة الغرفة من العامل.';
  if (status >= 500 && path === '/stats') return 'تعذر قراءة إحصاءات الغرفة.';
  if (status >= 500 && path === '/pusher/trigger') return 'فشل إرسال حدث التحديث إلى بوشر.';
  if (status >= 500) return 'خطأ داخلي في العامل.';
  if (status >= 400 && path === '/action') return 'تم رفض طلب مهم داخل اللعبة.';
  if (status >= 400) return 'طلب غير ناجح داخل مسار مهم.';
  return msg || 'سجل متابعة داخلي.';
}

function renderAlerts(alerts){
  const box = $('alertsBox');
  const sorted = (alerts || []).slice().sort(function(a,b){ return sevRank(b.level) - sevRank(a.level); });

  if (!sorted.length) {
    box.innerHTML = '<div class="empty">لا توجد تنبيهات مقلقة الآن — الوضع يبدو طبيعيًا.</div>';
    setBadge($('alertsBadge'),'لا توجد تنبيهات','ok');
    return;
  }
  setBadge($('alertsBadge'),'عدد التنبيهات: ' + sorted.length, sorted.some(function(a){ return a.level === 'bad'; }) ? 'bad' : 'warn');
  box.innerHTML = sorted.map(function(a){
    const cls = a.level === 'bad' ? 'bad' : (a.level === 'warn' ? 'warn' : 'info');
    return '<div class="alert ' + cls + '"><strong>' + a.title + '</strong><div>' + a.text + '</div></div>';
  }).join('');
}

function renderErrors(errors){
  const body = $('errorsBody');
  if (!errors || !errors.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">لا توجد أخطاء مهمة الآن</td></tr>';
    setBadge($('errorsBadge'),'لا توجد أخطاء','ok');
    return;
  }
  setBadge($('errorsBadge'),'عدد السجلات: ' + errors.length, errors.some(function(e){ return Number(e.status || 0) >= 500; }) ? 'bad' : 'warn');
  body.innerHTML = errors.map(function(e){
    const s = Number(e.status || 0);
    const cls = s >= 500 ? 'bad' : (s >= 400 ? 'warn' : 'info');
    const kind = s === 299 ? 'معلومة' : (s >= 500 ? 'خطأ شديد' : (s >= 400 ? 'تحذير' : 'متابعة'));
    return '<tr>' +
      '<td>' + ago(e.ts) + '</td>' +
      '<td><span class="tag ' + cls + '">' + kind + '</span></td>' +
      '<td>' + (e.path || '—') + '</td>' +
      '<td>' + (e.room || '—') + '</td>' +
      '<td>' + translateError(e) + '</td>' +
      '</tr>';
  }).join('');
}

function renderRooms(rooms){
  const box = $('roomsBox');
  if (!rooms || !rooms.length) {
    box.innerHTML = '<div class="empty">لا توجد غرف حالية الآن</div>';
    setBadge($('roomsBadge'),'0 غرفة حالية','info');
    $('roomsCurrent').textContent = '0';
    return;
  }

  $('roomsCurrent').textContent = fmt(rooms.length);
  setBadge($('roomsBadge'),'الغرف الحالية: ' + rooms.length, rooms.length >= 70 ? 'warn' : 'info');

  box.innerHTML = rooms.map(function(r){
    const cls = r.isActive ? 'ok' : 'info';
    const statusText = r.isActive ? 'نشطة' : 'هادئة';
    return '' +
      '<details class="roomItem">' +
        '<summary>' +
          '<div class="roomMain">' +
            '<span class="roomName">' + r.room + '</span>' +
            '<span class="tag ' + cls + '">' + statusText + '</span>' +
            '<span class="tag info">الآن: ' + fmt(r.clientsNow) + '</span>' +
            '<span class="tag info">دخلها: ' + fmt(r.uniquePlayersTotal) + '</span>' +
            '<span class="tag info">المدة: ' + (r.durationLabel || '—') + '</span>' +
          '</div>' +
          '<div class="roomMeta">' +
            '<span class="tag info">آخر ظهور: ' + ago(r.lastSeenAt) + '</span>' +
          '</div>' +
        '</summary>' +
        '<div class="roomBody">' +
          '<div class="roomGrid">' +
            '<div class="mini"><div class="label">المتصلون الآن</div><div class="value small">' + fmt(r.clientsNow) + '</div></div>' +
            '<div class="mini"><div class="label">إجمالي الداخلين</div><div class="value small">' + fmt(r.uniquePlayersTotal) + '</div></div>' +
            '<div class="mini"><div class="label">مدة الغرفة</div><div class="value small">' + (r.durationLabel || '—') + '</div></div>' +
            '<div class="mini"><div class="label">أول ظهور</div><div class="value tiny">' + formatDateShort(r.firstSeenAt) + '</div></div>' +
            '<div class="mini"><div class="label">آخر ظهور</div><div class="value tiny">' + ago(r.lastSeenAt) + '</div></div>' +
            '<div class="mini"><div class="label">آخر Pusher</div><div class="value tiny">' + ago(r.lastPusherAt) + '</div></div>' +
            '<div class="mini"><div class="label">طلبات اليوم</div><div class="value small">' + fmt(r.requestsToday) + '</div></div>' +
            '<div class="mini"><div class="label">رسائل اليوم</div><div class="value small">' + fmt(r.pusherMsgsToday) + '</div></div>' +
          '</div>' +
          '<div class="foot">آخر مسار: ' + (r.lastPath || '—') + ' — Rev: ' + fmt(r.rev) + '</div>' +
        '</div>' +
      '</details>';
  }).join('');
}

function render(summary){
  $('lastUpdatedTag').textContent = 'آخر تحديث: ' + ago(summary.generatedAt);
  $('billingTag').textContent = 'بوشر من تاريخ: ' + formatDateShort(summary.pusher && summary.pusher.cycleStartAt);
  $('resetTag').textContent = 'تصفير اليوم بعد: ' + ((summary.dailyReset && summary.dailyReset.hoursLabel) || '—');

  const workerOk = summary.system && summary.system.worker ? 'شغال' : 'غير واضح';
  $('workerStatus').textContent = workerOk;
  setValueColor($('workerStatus'), summary.system && summary.system.worker ? 'ok' : 'warn');

  const pusherOk = summary.system && summary.system.pusherConfigured ? 'مربوط' : 'غير مضبوط';
  $('pusherStatus').textContent = pusherOk;
  setValueColor($('pusherStatus'), summary.system && summary.system.pusherConfigured ? 'ok' : 'warn');

  const overall = overallLevel(summary);
  $('overallStatus').textContent = overall[0];
  setValueColor($('overallStatus'), overall[1]);
  setBadge($('overallBadge'), overall[0], overall[1]);

  const p = summary.pusher || {};
  const c = summary.cloudflare || {};
  const live = summary.live || {};
  const planConnections = Number(summary.system && summary.system.pusherPlanConnections || 2000);

  $('priority5xx').textContent = fmt(c.status5xx);
  setValueColor($('priority5xx'), Number(c.status5xx || 0) > 0 ? 'bad' : 'ok');

  const fourKind = Number(c.status4xx || 0) >= 40 ? 'bad' : (Number(c.status4xx || 0) >= 10 ? 'warn' : 'ok');
  $('priority4xx').textContent = fmt(c.status4xx);
  setValueColor($('priority4xx'), fourKind);

  const er = errorLevel(c.errorRatePercent);
  $('priorityErrRate').textContent = pct(c.errorRatePercent);
  setValueColor($('priorityErrRate'), er[1]);

  const lt = latencyLevel(c.avgLatencyMs);
  $('priorityLatency').textContent = msText(c.avgLatencyMs);
  setValueColor($('priorityLatency'), lt[1]);

  const ck = connectionLevel(live.connectionsNow, planConnections);
  $('priorityConnections').textContent = fmt(live.connectionsNow) + ' / ' + fmt(planConnections);
  setValueColor($('priorityConnections'), ck[1]);

  const pu = usageLevel(p.usagePercentMonth);
  $('priorityPusher').textContent = pct(p.usagePercentMonth);
  setValueColor($('priorityPusher'), pu[1]);

  const priorityKinds = [Number(c.status5xx || 0) > 0 ? 'bad' : 'ok', fourKind, er[1], lt[1], ck[1], pu[1]];
  const priorityKind = priorityKinds.indexOf('bad') !== -1 ? 'bad' : (priorityKinds.indexOf('warn') !== -1 ? 'warn' : 'ok');
  setBadge($('priorityBadge'), priorityKind === 'bad' ? 'تنبيه عاجل' : (priorityKind === 'warn' ? 'تحتاج متابعة' : 'الوضع طبيعي'), priorityKind);

  $('liveConnections').textContent = fmt(live.connectionsNow);
  $('liveRooms').textContent = fmt(live.roomsActiveNow);
  $('liveRoomsToday').textContent = fmt(live.roomsSeenToday);
  $('uniquePlayersToday').textContent = fmt(live.uniquePlayersToday);
  $('roomsExpiredToday').textContent = fmt(live.roomsExpiredToday);
  $('pusherToday').textContent = fmt(p.messagesToday);
  $('pusherRemaining').textContent = fmt(p.remainingMessages);
  $('cfRequestsToday').textContent = fmt(c.requestsToday);

  $('pusherMain').textContent = fmt(p.messagesMonth) + ' / ' + fmt(p.planMessages);
  $('pusherSub').textContent = 'المتبقي: ' + fmt(p.remainingMessages) + ' — يتصفّر بعد: ' + (p.resetLabel || '—');

  $('cfMonthMain').textContent = fmt(c.requestsMonth) + ' / ' + fmt(c.planRequestsMonth);
  $('cfMonthSub').textContent = 'المتبقي: ' + fmt(c.remainingRequestsMonth) + ' — استخدام الشهر: ' + pct(c.usagePercentMonth);

  $('cfErrMain').textContent = '5xx: ' + fmt(c.status5xx) + ' — 4xx المهم: ' + fmt(c.status4xx);
  $('cfErrSub').textContent = 'نسبة الأخطاء المهمة: ' + pct(c.errorRatePercent) + ' — 404 الخارجية: ' + fmt(c.external404Today);

  renderAlerts(summary.alerts || []);
  renderErrors(summary.lastErrors || []);
  renderRooms(summary.rooms || []);
}

let timer = null;
let paused = false;

async function refresh(){
  try{
    const res = await fetch('/monitor/summary', { cache:'no-store' });
    const data = await res.json();
    if (!res.ok || !data || !data.ok) throw new Error((data && data.msg) || 'MONITOR_FAILED');
    render(data);
  }catch(err){
    setBadge($('alertsBadge'),'تعذر قراءة البيانات','bad');
    setBadge($('errorsBadge'),'تعذر قراءة البيانات','bad');
    setBadge($('priorityBadge'),'تعذر قراءة البيانات','bad');
    $('alertsBox').innerHTML = '<div class="alert bad"><strong>تعذر جلب البيانات</strong><div>' + String(err && err.message ? err.message : err) + '</div></div>';
    $('errorsBody').innerHTML = '<tr><td colspan="5" class="empty">تعذر قراءة الأخطاء الآن</td></tr>';
  }
}

function start(){
  if (timer) clearInterval(timer);
  timer = setInterval(function(){ if (!paused) refresh(); }, 5000);
}

$('refreshBtn').addEventListener('click', refresh);
$('autoBtn').addEventListener('click', function(){
  paused = !paused;
  $('autoBtn').textContent = paused ? 'استئناف التحديث' : 'إيقاف التحديث';
});

refresh();
start();
</script>
</body>
</html>`;
}

function monitorDetailsPageHtml() {
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
<title>تفاصيل مراقبة سباق الحروف</title>
<style>
:root{
  --bg:#08101f; --panel:#0e1930; --line:rgba(148,163,184,.16); --text:#f8fbff; --muted:#9db0d1;
  --blue:#4f8cff; --green:#19c37d; --yellow:#f6b93b; --red:#ff5d73; --cyan:#27c7f8; --shadow:0 18px 40px rgba(2,8,23,.32);
}
*{box-sizing:border-box}
html,body{margin:0}
body{
  color:var(--text); font-family:Arial,sans-serif;
  background:linear-gradient(180deg,#050b16 0%,#0a1121 38%,#0f1a32 100%);
  min-height:100vh;
}
.wrap{width:min(1450px,100%); margin:0 auto; padding:16px}
.top{display:flex; justify-content:space-between; gap:12px; align-items:flex-start; flex-wrap:wrap; background:linear-gradient(180deg, rgba(17,27,47,.94), rgba(12,20,38,.96)); border:1px solid var(--line); border-radius:26px; padding:18px; box-shadow:var(--shadow)}
.title{font-size:28px; font-weight:900}
.sub{margin-top:8px; color:var(--muted); font-size:14px}
.controls{display:flex; gap:10px; flex-wrap:wrap}
a.btn,button{
  border:0; border-radius:16px; padding:13px 18px; font-weight:800; font-size:15px; cursor:pointer; color:#fff; text-decoration:none;
  background:linear-gradient(135deg,var(--blue),#355dff); box-shadow:0 12px 26px rgba(53,93,255,.22);
}
button.secondary,a.btn.secondary{background:rgba(255,255,255,.05); border:1px solid var(--line); box-shadow:none}
.section{margin-top:14px; border:1px solid var(--line); border-radius:26px; background:linear-gradient(180deg, rgba(16,26,49,.95), rgba(10,16,32,.96)); box-shadow:var(--shadow); padding:16px}
.sectionHead{display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; margin-bottom:12px}
.sectionTitle{font-size:18px; font-weight:900}
.sectionDesc{margin-top:4px; color:var(--muted); font-size:12px}
.grid3{display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px}
.grid2{display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px}
.card{border:1px solid var(--line); border-radius:20px; padding:14px; background:linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02))}
.label{font-size:12px; color:var(--muted)}
.value{margin-top:6px; font-size:24px; font-weight:900}
.chartWrap{border:1px solid var(--line); border-radius:18px; padding:12px; background:rgba(255,255,255,.03)}
.chartTitle{font-size:14px; font-weight:900; margin-bottom:8px}
svg{width:100%; height:220px; display:block}
.axisLabel{fill:#9db0d1; font-size:10px}
.barReq{fill:#4f8cff}
.barPusher{fill:#19c37d}
.barErr{fill:#ff5d73}
.line{stroke:#27c7f8; stroke-width:2; fill:none}
.tableWrap{overflow:auto; border:1px solid var(--line); border-radius:18px; background:rgba(8,14,28,.42)}
table{width:100%; border-collapse:collapse; min-width:720px}
th,td{padding:12px 10px; text-align:right; border-bottom:1px solid rgba(148,163,184,.12); font-size:13px; vertical-align:top}
th{position:sticky; top:0; background:#0d1628; color:#d6e7ff; font-size:12px}
.empty{padding:18px; text-align:center; color:var(--muted)}
.tag{display:inline-flex; align-items:center; justify-content:center; min-height:34px; padding:8px 12px; border-radius:999px; font-size:12px; font-weight:800; border:1px solid var(--line); background:rgba(255,255,255,.05); color:#d7e6ff}
.ok{background:rgba(25,195,125,.16); border-color:rgba(25,195,125,.45); color:#cbffe8}
.warn{background:rgba(246,185,59,.16); border-color:rgba(246,185,59,.45); color:#fff3cd}
.bad{background:rgba(255,93,115,.16); border-color:rgba(255,93,115,.45); color:#ffd7dd}
.info{background:rgba(39,199,248,.12); border-color:rgba(39,199,248,.38); color:#d6f8ff}
@media (max-width:1000px){.grid3,.grid2{grid-template-columns:repeat(1,minmax(0,1fr))}}
</style>
</head>
<body>
<div class="wrap">
  <section class="top">
    <div>
      <div class="title">التفاصيل الدقيقة</div>
      <div class="sub">رسومات اليوم والأسبوع والشهر، مع جداول المسارات والتفاصيل الأقرب لما تحتاجه بدل فتح اللوحات الخارجية.</div>
    </div>
    <div class="controls">
      <a href="/monitor" class="btn secondary">العودة للصفحة الرئيسية</a>
      <button id="refreshBtn">تحديث الآن</button>
      <button id="autoBtn" class="secondary">إيقاف التحديث</button>
    </div>
  </section>

  <section class="section">
    <div class="sectionHead">
      <div>
        <div class="sectionTitle">ملخص تقني مختصر</div>
        <div class="sectionDesc">أهم أرقام كلاودفلير وبوشر واللعبة في مكان واحد.</div>
      </div>
      <div id="detailsBadge" class="tag info">بانتظار البيانات</div>
    </div>
    <div class="grid3">
      <div class="card"><div class="label">طلبات اليوم</div><div id="sumReqToday" class="value">—</div></div>
      <div class="card"><div class="label">أخطاء اللعبة المهمة اليوم</div><div id="sumErrToday" class="value">—</div></div>
      <div class="card"><div class="label">رسائل بوشر اليوم</div><div id="sumPusherToday" class="value">—</div></div>
      <div class="card"><div class="label">استخدام بوشر من الدورة</div><div id="sumPusherMonth" class="value">—</div></div>
      <div class="card"><div class="label">الاتصالات الحالية / الحد</div><div id="sumConn" class="value">—</div></div>
      <div class="card"><div class="label">الغرف التي لُعبت اليوم</div><div id="sumRoomsToday" class="value">—</div></div>
    </div>
  </section>

  <section class="section">
    <div class="sectionHead">
      <div>
        <div class="sectionTitle">رسومات اليوم</div>
        <div class="sectionDesc">بالساعات.</div>
      </div>
    </div>
    <div class="grid2">
      <div class="chartWrap">
        <div class="chartTitle">طلبات اليوم بالساعة</div>
        <div id="chartTodayRequests"></div>
      </div>
      <div class="chartWrap">
        <div class="chartTitle">رسائل بوشر اليوم بالساعة</div>
        <div id="chartTodayPusher"></div>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="sectionHead">
      <div>
        <div class="sectionTitle">رسومات الأسبوع والشهر</div>
        <div class="sectionDesc">بالأيام.</div>
      </div>
    </div>
    <div class="grid2">
      <div class="chartWrap">
        <div class="chartTitle">طلبات آخر 7 أيام</div>
        <div id="chartWeekRequests"></div>
      </div>
      <div class="chartWrap">
        <div class="chartTitle">رسائل بوشر آخر 7 أيام</div>
        <div id="chartWeekPusher"></div>
      </div>
      <div class="chartWrap">
        <div class="chartTitle">طلبات آخر 30 يوم</div>
        <div id="chartMonthRequests"></div>
      </div>
      <div class="chartWrap">
        <div class="chartTitle">أخطاء آخر 30 يوم</div>
        <div id="chartMonthErrors"></div>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="sectionHead">
      <div>
        <div class="sectionTitle">تفصيل مسارات العامل</div>
        <div class="sectionDesc">مختصر شبيه بالماتركس لكن أوضح لك بالعربي.</div>
      </div>
    </div>
    <div class="tableWrap">
      <table>
        <thead><tr><th>المسار</th><th>الطلبات</th><th>الأخطاء</th><th>متوسط الاستجابة</th></tr></thead>
        <tbody id="routesBody"><tr><td colspan="4" class="empty">بانتظار البيانات</td></tr></tbody>
      </table>
    </div>
  </section>

  <section class="section">
    <div class="sectionHead">
      <div>
        <div class="sectionTitle">آخر الأخطاء المهمة</div>
        <div class="sectionDesc">آخر ما يحتاج مراجعة فقط.</div>
      </div>
    </div>
    <div class="tableWrap">
      <table>
        <thead><tr><th>الوقت</th><th>الحالة</th><th>المسار</th><th>الغرفة</th><th>الشرح</th></tr></thead>
        <tbody id="errorsBody"><tr><td colspan="5" class="empty">لا توجد أخطاء مهمة الآن</td></tr></tbody>
      </table>
    </div>
  </section>
</div>

<script>
const $ = (id) => document.getElementById(id);
const fmt = (n) => Number(n || 0).toLocaleString('en-US');
const pct = (n) => Number(n || 0).toFixed(1) + '%';
const msText = (n) => Math.round(Number(n || 0)) + 'ms';

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

function translateError(row){
  const status = Number(row && row.status || 0);
  const path = String(row && row.path || '');
  const msg = String(row && row.msg || '');

  if (msg === 'ACTION_BAD_RESPONSE') return 'استجابة غير صالحة من غرفة اللعبة عند تنفيذ أمر.';
  if (msg === 'PUSHER_TRIGGER_FAILED') return 'فشل إرسال التحديث إلى بوشر.';
  if (msg === 'PUSHER_NOT_CONFIGURED') return 'بوشر غير مضبوط داخل العامل.';
  if (msg === 'NOT_FOUND' && path === '/action') return 'تم طلب مسار لعب غير موجود.';
  if (status >= 500 && path === '/action') return 'خطأ داخلي أثناء تنفيذ إجراء داخل اللعبة.';
  if (status >= 500 && path === '/state') return 'تعذر قراءة حالة الغرفة من العامل.';
  if (status >= 500 && path === '/stats') return 'تعذر قراءة إحصاءات الغرفة.';
  if (status >= 500 && path === '/pusher/trigger') return 'فشل إرسال حدث التحديث إلى بوشر.';
  if (status >= 500) return 'خطأ داخلي في العامل.';
  if (status >= 400 && path === '/action') return 'تم رفض طلب مهم داخل اللعبة.';
  if (status >= 400) return 'طلب غير ناجح داخل مسار مهم.';
  return msg || 'سجل متابعة داخلي.';
}

function setBadge(el, text, kind){
  el.className = 'tag ' + kind;
  el.textContent = text;
}

function renderSimpleBarChart(containerId, rows, valueKey, labelKey, barClass){
  const root = $(containerId);
  const list = Array.isArray(rows) ? rows : [];
  if (!list.length) {
    root.innerHTML = '<div class="empty">لا توجد بيانات بعد</div>';
    return;
  }

  const max = Math.max(1, ...list.map(function(r){ return Number(r[valueKey] || 0); }));
  const width = 760;
  const height = 220;
  const left = 34;
  const bottom = 26;
  const top = 12;
  const chartWidth = width - left - 10;
  const chartHeight = height - top - bottom;
  const step = chartWidth / list.length;
  const barWidth = Math.max(6, step * 0.64);

  let svg = '<svg viewBox="0 0 ' + width + ' ' + height + '" preserveAspectRatio="none">';
  svg += '<line x1="' + left + '" y1="' + top + '" x2="' + left + '" y2="' + (top + chartHeight) + '" stroke="rgba(255,255,255,.16)"/>';
  svg += '<line x1="' + left + '" y1="' + (top + chartHeight) + '" x2="' + (left + chartWidth) + '" y2="' + (top + chartHeight) + '" stroke="rgba(255,255,255,.16)"/>';

  list.forEach(function(r, i){
    const val = Number(r[valueKey] || 0);
    const x = left + (i * step) + ((step - barWidth) / 2);
    const h = (val / max) * chartHeight;
    const y = top + chartHeight - h;
    const label = String(r[labelKey] || '');
    svg += '<rect class="' + barClass + '" x="' + x.toFixed(2) + '" y="' + y.toFixed(2) + '" width="' + barWidth.toFixed(2) + '" height="' + h.toFixed(2) + '"></rect>';
    if (i % Math.ceil(list.length / 8) === 0 || list.length <= 8 || i === list.length - 1) {
      svg += '<text class="axisLabel" x="' + (x + (barWidth/2)).toFixed(2) + '" y="' + (height - 8) + '" text-anchor="middle">' + label + '</text>';
    }
  });

  svg += '</svg>';
  root.innerHTML = svg;
}

function renderErrors(errors){
  const body = $('errorsBody');
  if (!errors || !errors.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">لا توجد أخطاء مهمة الآن</td></tr>';
    return;
  }
  body.innerHTML = errors.map(function(e){
    return '<tr>' +
      '<td>' + ago(e.ts) + '</td>' +
      '<td>' + Number(e.status || 0) + '</td>' +
      '<td>' + (e.path || '—') + '</td>' +
      '<td>' + (e.room || '—') + '</td>' +
      '<td>' + translateError(e) + '</td>' +
      '</tr>';
  }).join('');
}

function renderRoutes(routes){
  const body = $('routesBody');
  const list = Array.isArray(routes) ? routes : [];
  if (!list.length) {
    body.innerHTML = '<tr><td colspan="4" class="empty">لا توجد بيانات بعد</td></tr>';
    return;
  }
  body.innerHTML = list.map(function(r){
    return '<tr>' +
      '<td>' + (r.path || '—') + '</td>' +
      '<td>' + fmt(r.count) + '</td>' +
      '<td>' + fmt(r.errors) + '</td>' +
      '<td>' + msText(r.avgLatencyMs) + '</td>' +
      '</tr>';
  }).join('');
}

function render(summary){
  const p = summary.pusher || {};
  const c = summary.cloudflare || {};
  const live = summary.live || {};

  $('sumReqToday').textContent = fmt(c.requestsToday);
  $('sumErrToday').textContent = fmt(c.errorsToday);
  $('sumPusherToday').textContent = fmt(p.messagesToday);
  $('sumPusherMonth').textContent = pct(p.usagePercentMonth);
  $('sumConn').textContent = fmt(live.connectionsNow) + ' / ' + fmt(summary.system && summary.system.pusherPlanConnections || 2000);
  $('sumRoomsToday').textContent = fmt(live.roomsSeenToday);

  const badgeKind = Number(c.status5xx || 0) > 0 ? 'bad' : (Number(c.errorsToday || 0) > 0 ? 'warn' : 'ok');
  setBadge($('detailsBadge'), badgeKind === 'bad' ? 'تنبيه موجود' : (badgeKind === 'warn' ? 'فيه متابعة' : 'الوضع طبيعي'), badgeKind);

  renderSimpleBarChart('chartTodayRequests', summary.charts ? summary.charts.todayHours : [], 'requests', 'label', 'barReq');
  renderSimpleBarChart('chartTodayPusher', summary.charts ? summary.charts.todayHours : [], 'pusher', 'label', 'barPusher');
  renderSimpleBarChart('chartWeekRequests', summary.charts ? summary.charts.last7Days : [], 'requests', 'label', 'barReq');
  renderSimpleBarChart('chartWeekPusher', summary.charts ? summary.charts.last7Days : [], 'pusher', 'label', 'barPusher');
  renderSimpleBarChart('chartMonthRequests', summary.charts ? summary.charts.last30Days : [], 'requests', 'label', 'barReq');
  renderSimpleBarChart('chartMonthErrors', summary.charts ? summary.charts.last30Days : [], 'errors', 'label', 'barErr');
  renderRoutes(summary.routeStats || []);
  renderErrors(summary.lastErrors || []);
}

let timer = null;
let paused = false;

async function refresh(){
  try{
    const res = await fetch('/monitor/summary', { cache:'no-store' });
    const data = await res.json();
    if (!res.ok || !data || !data.ok) throw new Error((data && data.msg) || 'MONITOR_FAILED');
    render(data);
  }catch(err){
    setBadge($('detailsBadge'),'تعذر قراءة البيانات','bad');
  }
}

function start(){
  if (timer) clearInterval(timer);
  timer = setInterval(function(){ if (!paused) refresh(); }, 5000);
}

$('refreshBtn').addEventListener('click', refresh);
$('autoBtn').addEventListener('click', function(){
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

    if (url.pathname === "/monitor/details" && request.method === "GET") {
      const res = html(monitorDetailsPageHtml());
      queueMonitorRequest(ctx, env, {
        ts: Date.now(),
        path: url.pathname,
        pathKey: "monitorDetailsUI",
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
                msg: "PUSHER_TRIGGER_FAILED",
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

function hourBucketKey(ts) {
  return new Date(ts).toISOString().slice(0, 13);
}

function dayBucketKey(ts) {
  return new Date(ts).toISOString().slice(0, 10);
}

function formatRoomDuration(ms) {
  const totalMinutes = Math.max(0, Math.floor(Number(ms || 0) / (60 * 1000)));
  const days = Math.floor(totalMinutes / (60 * 24));
  const hours = Math.floor((totalMinutes - (days * 24 * 60)) / 60);
  const minutes = totalMinutes % 60;
  if (days > 0) return days + "ي " + hours + "س";
  if (hours > 0) return hours + "س " + minutes + "د";
  return Math.max(0, minutes) + "د";
}

export class RoomDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;

    const ms = Number(env?.ROOM_IDLE_MS || DEFAULT_IDLE_MS);
    this.IDLE_MS = clampMin(ms, 60 * 1000);

    this.roomName = null;
    this.runtimeMetrics = null;
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

  _loadMetrics(now = Date.now()) {
    const day = utcDayKey(now);
    if (!this.runtimeMetrics || this.runtimeMetrics.day !== day) {
      this.runtimeMetrics = {
        day,
        actionsToday: 0,
        pusherMsgsToday: 0,
        peakClientsToday: 0,
        seen: {},
      };
    }
    this.runtimeMetrics.seen = this._gcSeen(this.runtimeMetrics.seen, now);
    return this.runtimeMetrics;
  }

  _touchRuntimeSeen(pid, now = Date.now()) {
    const safePid = normalizePid(pid || "");
    const m = this._loadMetrics(now);
    if (!safePid) return m;
    m.seen[safePid] = now;
    const clientsNow = this._clientsNow(m.seen, now);
    m.peakClientsToday = Math.max(Number(m.peakClientsToday || 0), clientsNow);
    return m;
  }

  _trimHourly(hourly, now) {
    const out = {};
    const minTs = now - (48 * 60 * 60 * 1000);
    for (const [k, v] of Object.entries(hourly || {})) {
      const ts = Date.parse(String(k) + ":00:00Z");
      if (Number.isFinite(ts) && ts >= minTs) out[k] = v;
    }
    return out;
  }

  _trimDaily(daily, now) {
    const out = {};
    const minTs = now - (35 * 24 * 60 * 60 * 1000);
    for (const [k, v] of Object.entries(daily || {})) {
      const ts = Date.parse(String(k) + "T00:00:00Z");
      if (Number.isFinite(ts) && ts >= minTs) out[k] = v;
    }
    return out;
  }

  _ensureHourBucket(m, ts) {
    const key = hourBucketKey(ts);
    if (!m.hourly[key]) {
      m.hourly[key] = {
        requests: 0,
        errors: 0,
        pusher: 0,
        action: 0,
        state: 0,
      };
    }
    return m.hourly[key];
  }

  _ensureDayBucket(m, ts) {
    const key = dayBucketKey(ts);
    if (!m.daily[key]) {
      m.daily[key] = {
        requests: 0,
        errors: 0,
        pusher: 0,
        uniquePlayers: 0,
        roomsPlayed: 0,
      };
    }
    return m.daily[key];
  }

  async _loadMonitor(now = Date.now()) {
    const day = utcDayKey(now);
    const month = utcMonthKey(now);
    const pusherCycle = pusherBillingCycleInfo(now, this.env?.PUSHER_BILLING_START || DEFAULT_PUSHER_BILLING_START);

    let m = (await this.state.storage.get("monitor")) || {};
    const prevDay = String(m.day || "");
    const prevMonth = String(m.month || "");
    const prevPusherCycleKey = String(m.pusherCycleKey || "");

    if (!m || typeof m !== "object") m = {};
    if (!m.rooms || typeof m.rooms !== "object") m.rooms = {};
    if (!m.routes || typeof m.routes !== "object") m.routes = {};
    if (!Array.isArray(m.lastErrors)) m.lastErrors = [];
    if (!m.hourly || typeof m.hourly !== "object") m.hourly = {};
    if (!m.daily || typeof m.daily !== "object") m.daily = {};
    if (!m.uniquePlayersTodaySet || typeof m.uniquePlayersTodaySet !== "object") m.uniquePlayersTodaySet = {};

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
      m.roomsExpiredToday = 0;
      m.uniquePlayersTodaySet = {};

      for (const roomInfo of Object.values(m.rooms)) {
        if (!roomInfo || typeof roomInfo !== "object") continue;
        roomInfo.requestsToday = 0;
        roomInfo.pusherMsgsToday = 0;
      }
    }

    if (prevMonth !== month) {
      m.requestsMonth = 0;
    }

    if (prevPusherCycleKey !== pusherCycle.cycleKey) {
      m.pusherMsgsMonth = 0;
    }

    m.day = day;
    m.month = month;
    m.pusherCycleKey = pusherCycle.cycleKey;
    m.pusherCycleStartAt = pusherCycle.startTs;
    m.pusherCycleResetAt = pusherCycle.nextResetTs;

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
    m.roomsExpiredToday = toFiniteNumber(m.roomsExpiredToday, 0);

    m.rooms = this._gcMonitorRooms(m.rooms, now);
    m.hourly = this._trimHourly(m.hourly, now);
    m.daily = this._trimDaily(m.daily, now);
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
    const staleMs = Math.max(this.IDLE_MS + (10 * 60 * 1000), MONITOR_ROOM_STALE_MS / 3);

    for (const [room, raw] of Object.entries(rooms || {})) {
      if (!raw || typeof raw !== "object") continue;
      const info = { ...raw };
      info.pids = this._gcSeen(info.pids || {}, now);
      info.uniquePids = info.uniquePids && typeof info.uniquePids === "object" ? info.uniquePids : {};
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

      const recent = Math.max(info.lastSeenAt, info.lastActionAt, info.lastStateAt, info.lastStatsAt, info.lastPusherAt, info.firstSeenAt);
      if (recent && now - recent > staleMs) continue;
      out[room] = info;
    }
    return out;
  }

  _pushLastError(list, item) {
    const arr = Array.isArray(list) ? list.slice(0) : [];
    arr.unshift(item);
    return arr.slice(0, 25);
  }

  _shouldStoreImportantError(path, status, msg) {
    const s = Number(status || 0);
    const p = String(path || "");
    const m = String(msg || "");

    if (isIgnorableExternal404(p, s)) return false;
    if ((p === "/pusher/auth") && (s === 401 || s === 403) && m === "FORBIDDEN_PUSHER_AUTH") return false;
    if ((p === "/monitor" || p === "/monitor/summary" || p === "/monitor/details") && s < 500) return false;
    return isImportantRequestError(p, s);
  }

  _buildAlerts(summary) {
    const alerts = [];
    const usage = Number(summary?.pusher?.usagePercentMonth || 0);
    const connectionUsage = Number(summary?.pusher?.connectionUsagePercent || 0);
    const errorRate = Number(summary?.cloudflare?.errorRatePercent || 0);
    const avgLatencyMs = Number(summary?.cloudflare?.avgLatencyMs || 0);
    const activeRooms = Number(summary?.live?.roomsActiveNow || 0);
    const roomsExpiredToday = Number(summary?.live?.roomsExpiredToday || 0);
    const cfUsage = Number(summary?.cloudflare?.usagePercentMonth || 0);
    const external404Today = Number(summary?.cloudflare?.external404Today || 0);
    const status5xx = Number(summary?.cloudflare?.status5xx || 0);
    const status4xx = Number(summary?.cloudflare?.status4xx || 0);

    if (status5xx > 0) {
      alerts.push({
        level: "bad",
        title: "تم رصد أخطاء 5xx",
        text: `يوجد ${status5xx} أخطاء 5xx اليوم، وهذا يحتاج فحصًا مباشرًا فورًا.`
      });
    }

    if (status4xx >= 40) {
      alerts.push({
        level: "bad",
        title: "أخطاء 4xx المهمة مرتفعة",
        text: `تم رصد ${status4xx} من أخطاء 4xx المهمة اليوم داخل مسارات اللعبة.`
      });
    } else if (status4xx >= 10) {
      alerts.push({
        level: "warn",
        title: "أخطاء 4xx المهمة تحتاج متابعة",
        text: `تم رصد ${status4xx} من أخطاء 4xx المهمة اليوم.`
      });
    }

    if (usage >= 80) {
      alerts.push({
        level: "bad",
        title: "استهلاك رسائل Pusher اقترب من الحد",
        text: `الاستهلاك الحالي وصل إلى ${usage.toFixed(1)}% من الحد المسموح في دورة الاشتراك الحالية.`
      });
    } else if (usage >= 50) {
      alerts.push({
        level: "warn",
        title: "استهلاك رسائل Pusher في المنطقة المتوسطة",
        text: `الاستهلاك الحالي عند ${usage.toFixed(1)}% ويستحسن متابعته.`
      });
    }

    if (connectionUsage >= 75) {
      alerts.push({
        level: "bad",
        title: "الاتصالات الحالية اقتربت من حد بوشر",
        text: `الاستخدام الحالي للاتصالات وصل إلى ${connectionUsage.toFixed(1)}% من حد 2000 اتصال متزامن.`
      });
    } else if (connectionUsage >= 45) {
      alerts.push({
        level: "warn",
        title: "الضغط المباشر على الاتصالات متصاعد",
        text: `الاستخدام الحالي للاتصالات وصل إلى ${connectionUsage.toFixed(1)}% من حد بوشر المتزامن.`
      });
    }

    if (errorRate > 2) {
      alerts.push({
        level: "bad",
        title: "نسبة الأخطاء مرتفعة",
        text: `نسبة الأخطاء المهمة اليوم ${errorRate.toFixed(2)}% وهي أعلى من الحد المريح.`
      });
    } else if (errorRate >= 0.5) {
      alerts.push({
        level: "warn",
        title: "نسبة الأخطاء تحتاج متابعة",
        text: `نسبة الأخطاء المهمة اليوم ${errorRate.toFixed(2)}% وهي أعلى من الطبيعي.`
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

    if (roomsExpiredToday > 0) {
      alerts.push({
        level: "info",
        title: "تم حذف غرف خاملة من الصفحة",
        text: `تم حذف ${roomsExpiredToday} غرف من الصفحة اليوم بسبب خمولها لمدة ساعتين.`
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

      const hourBucket = this._ensureHourBucket(m, ts);
      hourBucket.requests += 1;
      if (pathKey === "action") hourBucket.action += 1;
      if (pathKey === "state") hourBucket.state += 1;

      const dayBucket = this._ensureDayBucket(m, ts);
      dayBucket.requests += 1;

      if (status >= 500) m.status5xx += 1;
      else if (status >= 400) m.status4xx += 1;
      else if (status >= 200) m.status2xx += 1;

      const ignorable404 = isIgnorableExternal404(path, status);
      const importantError = this._shouldStoreImportantError(path, status, msg);

      if (status >= 400) m.rawErrorsToday += 1;
      if (importantError) {
        m.errorsToday += 1;
        hourBucket.errors += 1;
        dayBucket.errors += 1;
      }
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
      if (importantError) route.errors += 1;
      m.routes[pathKey] = route;

      if (room && room !== MONITOR_ROOM) {
        const info = (m.rooms[room] && typeof m.rooms[room] === "object") ? m.rooms[room] : {
          firstSeenAt: ts,
          pids: {},
          uniquePids: {},
          requestsToday: 0,
          pusherMsgsToday: 0,
        };
        info.firstSeenAt = toFiniteNumber(info.firstSeenAt, ts) || ts;
        info.lastSeenAt = ts;
        info.lastPath = path;
        info.lastStatus = status;
        info.requestsToday = toFiniteNumber(info.requestsToday, 0) + 1;
        info.rev = toFiniteNumber(evt?.rev, toFiniteNumber(info.rev, 0));

        if (path === "/state") info.lastStateAt = ts;
        if (path === "/action") info.lastActionAt = ts;
        if (path === "/stats") info.lastStatsAt = ts;

        info.pids = this._gcSeen(info.pids || {}, ts);

        if (pid) {
          info.pids[pid] = ts;
          info.uniquePids = info.uniquePids && typeof info.uniquePids === "object" ? info.uniquePids : {};
          info.uniquePids[pid] = ts;
          m.uniquePlayersTodaySet[pid] = ts;
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

      const hourBucket = this._ensureHourBucket(m, ts);
      hourBucket.pusher += 1;
      const dayBucket = this._ensureDayBucket(m, ts);
      dayBucket.pusher += 1;

      if (room && room !== MONITOR_ROOM) {
        const info = (m.rooms[room] && typeof m.rooms[room] === "object") ? m.rooms[room] : {
          firstSeenAt: ts,
          pids: {},
          uniquePids: {},
          requestsToday: 0,
          pusherMsgsToday: 0,
        };
        info.firstSeenAt = toFiniteNumber(info.firstSeenAt, ts) || ts;
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
        m.roomsExpiredToday = toFiniteNumber(m.roomsExpiredToday, 0) + 1;
        delete m.rooms[room];
      }
    }

    await this.state.storage.put("monitor", m);
    return m;
  }

  _buildChartSeries(m, now) {
    const todayHours = [];
    const weekDays = [];
    const monthDays = [];

    for (let i = 23; i >= 0; i--) {
      const ts = now - (i * 60 * 60 * 1000);
      const date = new Date(ts);
      const key = date.toISOString().slice(0, 13);
      const bucket = m.hourly[key] || {};
      todayHours.push({
        key,
        label: String(date.getUTCHours()).padStart(2, "0"),
        requests: toFiniteNumber(bucket.requests, 0),
        errors: toFiniteNumber(bucket.errors, 0),
        pusher: toFiniteNumber(bucket.pusher, 0),
      });
    }

    for (let i = 6; i >= 0; i--) {
      const ts = now - (i * 24 * 60 * 60 * 1000);
      const date = new Date(ts);
      const key = date.toISOString().slice(0, 10);
      const bucket = m.daily[key] || {};
      weekDays.push({
        key,
        label: key.slice(5),
        requests: toFiniteNumber(bucket.requests, 0),
        errors: toFiniteNumber(bucket.errors, 0),
        pusher: toFiniteNumber(bucket.pusher, 0),
      });
    }

    for (let i = 29; i >= 0; i--) {
      const ts = now - (i * 24 * 60 * 60 * 1000);
      const key = new Date(ts).toISOString().slice(0, 10);
      const bucket = m.daily[key] || {};
      monthDays.push({
        key,
        label: key.slice(5),
        requests: toFiniteNumber(bucket.requests, 0),
        errors: toFiniteNumber(bucket.errors, 0),
        pusher: toFiniteNumber(bucket.pusher, 0),
      });
    }

    return { todayHours, last7Days: weekDays, last30Days: monthDays };
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
      const planConnections = clampMin(Number(this.env?.PUSHER_PLAN_CONNECTIONS || DEFAULT_PUSHER_PLAN_CONNECTIONS), 1);
      const pusherCycle = pusherBillingCycleInfo(now, this.env?.PUSHER_BILLING_START || DEFAULT_PUSHER_BILLING_START);

      const rooms = [];
      let connectionsNow = 0;
      let roomsActiveNow = 0;
      let roomsSeenToday = 0;

      for (const [room, raw] of Object.entries(m.rooms || {})) {
        const info = raw || {};
        const pids = this._gcSeen(info.pids || {}, now);
        const clientsNow = this._clientsNow(pids, now);
        const lastSeenAt = toFiniteNumber(info.lastSeenAt, 0);
        const lastActionAt = toFiniteNumber(info.lastActionAt, 0);
        const lastPusherAt = toFiniteNumber(info.lastPusherAt, 0);
        const isActive = (clientsNow > 0 || (now - Math.max(lastActionAt, lastPusherAt, lastSeenAt) <= MONITOR_ACTIVE_ROOM_MS));
        const uniquePlayersTotal = Object.keys(info.uniquePids || {}).length;
        const durationMs = Math.max(0, now - toFiniteNumber(info.firstSeenAt, now));

        if (isActive) roomsActiveNow += 1;
        connectionsNow += clientsNow;
        if (toFiniteNumber(info.requestsToday, 0) > 0 || toFiniteNumber(info.pusherMsgsToday, 0) > 0) roomsSeenToday += 1;

        rooms.push({
          room,
          clientsNow,
          isActive,
          isEnded: false,
          firstSeenAt: toFiniteNumber(info.firstSeenAt, 0),
          lastSeenAt,
          lastActionAt,
          lastPusherAt,
          requestsToday: toFiniteNumber(info.requestsToday, 0),
          pusherMsgsToday: toFiniteNumber(info.pusherMsgsToday, 0),
          lastPath: String(info.lastPath || ""),
          lastStatus: toFiniteNumber(info.lastStatus, 0),
          rev: toFiniteNumber(info.rev, 0),
          uniquePlayersTotal,
          durationMs,
          durationLabel: formatRoomDuration(durationMs),
        });
      }

      rooms.sort((a, b) => {
        if (Number(b.isActive) !== Number(a.isActive)) return Number(b.isActive) - Number(a.isActive);
        if (b.clientsNow !== a.clientsNow) return b.clientsNow - a.clientsNow;
        return Math.max(toFiniteNumber(b.lastSeenAt, 0), toFiniteNumber(b.lastPusherAt, 0)) - Math.max(toFiniteNumber(a.lastSeenAt, 0), toFiniteNumber(a.lastPusherAt, 0));
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
      const connectionUsagePercent = Math.min(100, (connectionsNow / planConnections) * 100);

      const cfPlanRequestsMonth = clampMin(Number(this.env?.CF_PLAN_REQUESTS_MONTH || DEFAULT_CF_MONTHLY_REQUESTS), 1);
      const cfFreeDailyRequests = clampMin(Number(this.env?.CF_FREE_DAILY_REQUESTS || DEFAULT_CF_FREE_DAILY_REQUESTS), 1);
      const cfPlanName = String(this.env?.CF_PLAN_NAME || DEFAULT_CF_PLAN_NAME);
      const cfUsagePercentMonth = Math.min(100, (requestsMonth / cfPlanRequestsMonth) * 100);

      const routes = m.routes || {};
      const routeCount = (k) => toFiniteNumber((routes[k] && routes[k].count) || 0, 0);
      const breakdownAction = routeCount("action");
      const breakdownState = routeCount("state");
      const breakdownPusher = routeCount("pusherAuth") + routeCount("pusherConfig") + routeCount("pusherTrigger");
      const breakdownMonitor = routeCount("monitorUI") + routeCount("monitorSummary") + routeCount("monitorDetailsUI");
      const knownBreakdown = breakdownAction + breakdownState + breakdownPusher + breakdownMonitor;
      const breakdownOther = Math.max(0, requestsToday - knownBreakdown);

      const routeStats = Object.entries(routes).map(([pathKey, data]) => ({
        path: pathKey,
        count: toFiniteNumber(data?.count, 0),
        errors: toFiniteNumber(data?.errors, 0),
        avgLatencyMs: toFiniteNumber(data?.count, 0) > 0 ? (toFiniteNumber(data?.totalLatencyMs, 0) / toFiniteNumber(data?.count, 0)) : 0,
      })).sort((a, b) => b.count - a.count).slice(0, 12);

      const resetInfo = utcResetCountdown(now);

      const summary = {
        ok: true,
        generatedAt: now,
        system: {
          worker: true,
          pusherConfigured: pusherEnabled(this.env),
          monitor: true,
          pusherPlanConnections: planConnections,
        },
        pusher: {
          messagesToday: toFiniteNumber(m.pusherMsgsToday, 0),
          messagesMonth,
          planMessages,
          remainingMessages: Math.max(0, planMessages - messagesMonth),
          usagePercentMonth,
          planConnections,
          connectionUsagePercent,
          cycleStartAt: pusherCycle.startTs,
          resetAt: pusherCycle.nextResetTs,
          resetLabel: pusherCycle.label,
        },
        dailyReset: {
          resetAt: resetInfo.resetAt,
          hoursRemaining: resetInfo.hoursRemaining,
          minutesRemaining: resetInfo.minutesRemaining,
          hoursLabel: resetInfo.hoursLabel,
        },
        live: {
          connectionsNow,
          roomsActiveNow,
          roomsSeenToday,
          roomsTracked: rooms.length,
          roomsTrackedCurrent: rooms.length,
          roomsExpiredToday: toFiniteNumber(m.roomsExpiredToday, 0),
          roomsEndedVisible: 0,
          uniquePlayersToday: Object.keys(m.uniquePlayersTodaySet || {}).length,
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
        routeStats,
        charts: this._buildChartSeries(m, now),
        rooms: rooms.slice(0, 100),
        lastErrors: Array.isArray(m.lastErrors) ? m.lastErrors.slice(0, 25) : [],
        sources: {
          pusher: "عداد داخلي مبني على الرسائل التي يرسلها Worker إلى Pusher من بداية دورة الاشتراك الحالية",
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
        this._touchRuntimeSeen(pid, Date.now());
      }

      return json({ ok: true, state: s, rev });
    }

    if (url.pathname === "/stats") {
      const now = Date.now();
      const m = this._loadMetrics(now);
      const clientsNow = this._clientsNow(m.seen, now);
      m.peakClientsToday = Math.max(Number(m.peakClientsToday || 0), clientsNow);

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
        metricsMode: "runtime",
      });
    }

    if (url.pathname === "/mark-pusher-sent" && request.method === "POST") {
      const now = Date.now();
      const m = this._loadMetrics(now);
      m.pusherMsgsToday = Number(m.pusherMsgsToday || 0) + 1;
      return json({ ok: true, mode: "runtime" });
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

      if (actionType === "join") {
        const maxPlayers = clampMin(this.env?.MAX_ROOM_PLAYERS || 13, 1);
        const players = (current?.players && typeof current.players === "object") ? { ...current.players } : {};
        const incomingPlayer = (body?.player && typeof body.player === "object") ? body.player : body;
        const joinPid = normalizePid(incomingPlayer?.pid || body?.pid || "");
        const joinName = String(incomingPlayer?.name || body?.name || "").trim().slice(0, 80);
        let joinTeam = String(incomingPlayer?.team || body?.team || "").trim();

        if (!joinPid || !joinName) {
          return json({
            ok: false,
            accepted: false,
            reason: "BAD_JOIN_PAYLOAD",
            state: current,
            rev: currentRev,
            ts: now
          }, 400);
        }

        if (joinTeam !== "green" && joinTeam !== "orange") {
          let g = 0;
          let o = 0;
          for (const player of Object.values(players)) {
            if (player?.team === "orange") o += 1;
            else if (player?.team === "green") g += 1;
          }
          joinTeam = g <= o ? "green" : "orange";
        }

        const existingPlayer = (players[joinPid] && typeof players[joinPid] === "object") ? players[joinPid] : null;
        if (!existingPlayer && Object.keys(players).length >= maxPlayers) {
          return json({
            ok: true,
            accepted: false,
            action: "join",
            reason: "ROOM_FULL",
            maxPlayers,
            currentCount: Object.keys(players).length,
            state: current,
            rev: currentRev,
            ts: now
          });
        }

        const mergedPlayer = {
          name: joinName || String(existingPlayer?.name || "").trim().slice(0, 80),
          team: joinTeam || String(existingPlayer?.team || "").trim(),
          joinedAt: toFiniteNumber(existingPlayer?.joinedAt, now) || now,
        };
        players[joinPid] = mergedPlayer;

        next = {
          ...current,
          players,
        };

        patch = {
          action: "join",
          pid: joinPid,
          player: mergedPlayer,
          currentCount: Object.keys(players).length,
          maxPlayers,
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

        const m = this._loadMetrics(now);
        m.actionsToday = Number(m.actionsToday || 0) + 1;
        if (joinPid) this._touchRuntimeSeen(joinPid, now);
        const clientsNow = this._clientsNow(m.seen, now);
        m.peakClientsToday = Math.max(Number(m.peakClientsToday || 0), clientsNow);

        return json({
          ok: true,
          accepted: true,
          action: "join",
          alreadyJoined: Boolean(existingPlayer),
          player: mergedPlayer,
          currentCount: Object.keys(players).length,
          maxPlayers,
          state: next,
          rev: nextRev,
          patch,
          ts: now
        });
      }

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

        const m = this._loadMetrics(now);
        m.actionsToday = Number(m.actionsToday || 0) + 1;
        const actionPid = normalizePid(body?.pid || "");
        if (actionPid) this._touchRuntimeSeen(actionPid, now);
        const clientsNow = this._clientsNow(m.seen, now);
        m.peakClientsToday = Math.max(Number(m.peakClientsToday || 0), clientsNow);

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

      const existingBuzzer = current?.buzzer ?? null;
      if (Object.prototype.hasOwnProperty.call(patch, "buzzer")) {
        const incomingBuzzer = patch.buzzer;

        if (incomingBuzzer === null) {
          const safePatch = { ...patch };
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

      const m = this._loadMetrics(now);
      m.actionsToday = Number(m.actionsToday || 0) + 1;
      const actionPid = normalizePid(body?.pid || patch?.pid || "");
      if (actionPid) this._touchRuntimeSeen(actionPid, now);
      const clientsNow = this._clientsNow(m.seen, now);
      m.peakClientsToday = Math.max(Number(m.peakClientsToday || 0), clientsNow);

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
