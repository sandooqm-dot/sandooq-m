export async function onRequestGet({ env }) {
  try {
    const r = await env.DB
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all();

    const tables = (r.results || []).map(x => x.name);

    return new Response(JSON.stringify({ ok: true, tables }, null, 2), {
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: String(e) }, null, 2), {
      status: 500,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
}
