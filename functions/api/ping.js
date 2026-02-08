// functions/api/ping.js
export async function onRequest({ request }) {
  const origin = request.headers.get("Origin") || "*";
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Device-Id",
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin",
    "Cache-Control": "no-store",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  return new Response(JSON.stringify({
    ok: true,
    ping: "pong",
    ts: new Date().toISOString(),
    path: new URL(request.url).pathname,
  }), { status: 200, headers });
}
