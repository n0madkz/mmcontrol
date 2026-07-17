const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
});

async function authorized(request, env) {
  const token = request.headers.get('authorization')?.replace(/^Bearer\s+/i, '');
  return Boolean(token && await env.PASSKEYS.get(`session:${token}`));
}

export async function onRequest(context) {
  const { request, env } = context;
  if (!await authorized(request, env)) return json({ error: 'Unauthorized' }, 401);

  if (request.method === 'GET') {
    const row = await env.DB.prepare('SELECT data, updated_at FROM app_state WHERE id = 1').first();
    return json({ data: row ? JSON.parse(row.data) : null, updatedAt: row?.updated_at || null });
  }

  if (request.method === 'PUT') {
    const data = await request.json();
    if (!data || !Array.isArray(data.objects) || !Array.isArray(data.payments) || !Array.isArray(data.expenses) || !Array.isArray(data.companies)) {
      return json({ error: 'Invalid database format' }, 400);
    }
    await env.DB.prepare(`
      INSERT INTO app_state (id, data, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP
    `).bind(JSON.stringify(data)).run();
    return json({ ok: true });
  }

  return json({ error: 'Method not allowed' }, 405);
}
