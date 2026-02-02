export async function onRequestGet(context) {
  const env = context?.env;

  return new Response(
    JSON.stringify(
      {
        ok: true,
        hasEnv: !!env,
        hasDB: !!env?.DB,
        dbType: env?.DB ? typeof env.DB : null,
        envKeys: env ? Object.keys(env) : null,
      },
      null,
      2
    ),
    { headers: { "content-type": "application/json; charset=utf-8" } }
  );
}
