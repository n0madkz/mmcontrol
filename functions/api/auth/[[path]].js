const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
});
async function issueSession(env, user) {
  const token = crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '');
  await env.PASSKEYS.put(`session:${token}`, user, { expirationTtl: 604800 });
  return token;
}
async function revokeSessions(env) {
  let cursor;
  do {
    const page = await env.PASSKEYS.list({ prefix: 'session:', cursor });
    await Promise.all(page.keys.map(key => env.PASSKEYS.delete(key.name)));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}

export async function onRequest(context) {
  const action = Array.isArray(context.params.path) ? context.params.path.join('/') : context.params.path;
  try {
    const current = await context.env.PASSKEYS.get('auth-owner', 'json');
    if (action === 'status') return json({ configured: Boolean(current), user: current?.user || null });
    if (action === 'setup' && context.request.method === 'POST') {
      if (current) return json({ error: 'Owner already configured' }, 409);
      const body = await context.request.json();
      const user = String(body.user || '').trim();
      const hash = String(body.hash || '');
      if (!user || hash.length < 8) return json({ error: 'Invalid credentials' }, 400);
      await context.env.PASSKEYS.put('auth-owner', JSON.stringify({ user, hash }));
      return json({ ok: true, user, token: await issueSession(context.env, user) });
    }
    if (action === 'login' && context.request.method === 'POST') {
      if (!current) return json({ error: 'Owner is not configured' }, 404);
      const body = await context.request.json();
      const ok = String(body.user || '') === current.user && String(body.hash || '') === current.hash;
      return ok ? json({ ok: true, user: current.user, token: await issueSession(context.env, current.user) }) : json({ error: 'Invalid login' }, 401);
    }
    if (action === 'change-password' && context.request.method === 'POST') {
      if (!current) return json({ error: 'Owner is not configured' }, 404);
      const token = context.request.headers.get('authorization')?.replace(/^Bearer\s+/i, '');
      if (!token || !await context.env.PASSKEYS.get(`session:${token}`)) return json({ error: 'Unauthorized' }, 401);
      const body = await context.request.json();
      if (String(body.currentHash || '') !== current.hash) return json({ error: 'Invalid current password' }, 401);
      const newHash = String(body.newHash || '');
      if (newHash.length < 8 || newHash === current.hash) return json({ error: 'Invalid new password' }, 400);
      await context.env.PASSKEYS.put('auth-owner', JSON.stringify({ user: current.user, hash: newHash }));
      await revokeSessions(context.env);
      return json({ ok: true, user: current.user, token: await issueSession(context.env, current.user) });
    }
    return json({ error: 'Not found' }, 404);
  } catch (error) {
    return json({ error: error?.message || 'Auth error' }, 400);
  }
}
