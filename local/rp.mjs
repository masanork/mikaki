import { collect, retained } from './gc.mjs';
import {
  OP,
  RP,
  CLIENT,
  CALLBACK,
  ASSERTION_TYPE,
  p,
  now,
  uuid,
  random,
  hash,
  check,
  fail,
  cookie,
  setCookie,
  json,
  redirect,
  response,
  query,
  row,
  body,
  sameOrigin,
  uniqueParams,
  localOnly,
  clientAssertion,
  verified,
  errors,
} from './shared.mjs';

const BROWSER = '__Host-rp-browser',
  SESSION = '__Host-rp-session';
const html = (text, headers = {}) =>
  response(
    `<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Sakimori local RP</title><body><h1>Sakimori local RP</h1>${text}</body></html>`,
    200,
    { 'Content-Type': 'text/html; charset=utf-8', 'Referrer-Policy': 'same-origin', ...headers },
  );
const escape = (s) =>
  String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('"', '&quot;');
async function opCall(env, path, data) {
  const endpoint = `${OP}${path}`;
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      ...data,
      client_id: CLIENT,
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: await clientAssertion(env, endpoint),
    }),
    redirect: 'manual',
    signal: AbortSignal.timeout(p('oidc.backchannel.request_timeout') * 1000),
  });
  check(r.ok, 'login_restart_required', 401);
  return r.json();
}
async function checkedSession(env, sid, sub, authTime) {
  const started = now();
  const s = await opCall(env, '/session/check', { sid });
  check(
    s.active &&
      s.sid === sid &&
      s.sub === sub &&
      s.auth_time === authTime &&
      Number.isSafeInteger(s.expires_at) &&
      s.lease_ttl > 0 &&
      s.lease_ttl <= p('session.validation.lease_ttl'),
    'invalid_session',
    401,
  );
  const lease = Math.min(started + s.lease_ttl, s.expires_at);
  check(lease > now(), 'session_check_expired', 401);
  return { lease, parent: s.expires_at, idle: Math.min(now() + s.app_idle_timeout, s.expires_at) };
}
async function current(db, env, req) {
  const key = await hash(cookie(req, SESSION));
  const t = now();
  let s = await row(
    db,
    'SELECT * FROM app_session WHERE hash=? AND idle_expires_at>? AND parent_expires_at>? AND NOT EXISTS(SELECT 1 FROM tombstone WHERE sid=app_session.sid)',
    [key, t, t],
  );
  if (!s) return null;
  if (s.lease_until <= t) {
    try {
      const checked = await checkedSession(env, s.sid, s.sub, s.auth_time);
      const updated = await row(
        db,
        `UPDATE app_session SET lease_until=MIN(?,parent_expires_at) WHERE hash=? AND lease_until=? AND NOT EXISTS(SELECT 1 FROM tombstone WHERE sid=app_session.sid) RETURNING *`,
        [checked.lease, key, s.lease_until],
      );
      check(updated, 'invalid_session', 401);
      s = updated;
    } catch {
      fail('session_unavailable_retry', 503);
    }
  }
  // Retain the absolute parent bound; an idle refresh cannot revive a tombstoned sid.
  return row(
    db,
    `UPDATE app_session SET idle_expires_at=MIN(?,parent_expires_at) WHERE hash=? AND idle_expires_at>CAST(strftime('%s','now') AS INTEGER) AND parent_expires_at>CAST(strftime('%s','now') AS INTEGER) AND NOT EXISTS(SELECT 1 FROM tombstone WHERE sid=app_session.sid) RETURNING *`,
    [now() + p('session.app_idle_timeout'), key],
  );
}
async function start(db, req) {
  sameOrigin(req, RP);
  const input = await body(req, 'form'),
    browser = cookie(req, BROWSER);
  check(browser && input.csrf === (await hash(browser)), 'invalid_csrf', 403);
  const state = random(),
    nonce = random(),
    verifier = random();
  await query(
    db,
    'INSERT INTO login(state_hash,browser_hash,nonce,verifier,expires_at,gc_after) VALUES(?,?,?,?,?,?)',
    [
      await hash(state),
      await hash(browser),
      nonce,
      verifier,
      now() + p('oidc.login.transaction_ttl'),
      retained(now() + p('oidc.login.transaction_ttl')),
    ],
  ).run();
  const target = new URL(`${OP}/authorize`);
  target.search = new URLSearchParams({
    client_id: CLIENT,
    redirect_uri: CALLBACK,
    response_type: 'code',
    scope: 'openid',
    state,
    nonce,
    code_challenge: await hash(verifier),
    code_challenge_method: 'S256',
  }).toString();
  return redirect(target.href);
}
async function callback(db, env, req, url) {
  const input = uniqueParams(url.searchParams);
  check(input.iss === OP && typeof input.state === 'string' && typeof input.code === 'string');
  const l = await row(
    db,
    'UPDATE login SET consumed=1 WHERE state_hash=? AND browser_hash=? AND consumed=0 AND expires_at>? RETURNING *',
    [await hash(input.state), await hash(cookie(req, BROWSER)), now()],
  );
  check(l, 'invalid_transaction');
  // Never retry a lost exchange response with the same authorization code.
  const tokens = await opCall(env, '/token', {
    grant_type: 'authorization_code',
    code: input.code,
    redirect_uri: CALLBACK,
    code_verifier: l.verifier,
  });
  const id = await verified(env, 'op', tokens.id_token, CLIENT);
  check(
    id.nonce === l.nonce &&
      typeof id.sub === 'string' &&
      typeof id.sid === 'string' &&
      Number.isSafeInteger(id.auth_time) &&
      id.auth_time <= id.iat &&
      (!id.azp || id.azp === CLIENT) &&
      id.exp - id.iat <= p('oidc.id_token_ttl'),
    'invalid_id_token',
  );
  const checked = await checkedSession(env, id.sid, id.sub, id.auth_time),
    secret = random(),
    key = await hash(secret),
    operation = uuid();
  await db.batch([
    query(
      db,
      `INSERT INTO guard VALUES(?,CASE WHEN NOT EXISTS(SELECT 1 FROM tombstone WHERE sid=?) AND ?>CAST(strftime('%s','now') AS INTEGER) AND ?>CAST(strftime('%s','now') AS INTEGER) THEN 1 ELSE 0 END)`,
      [operation, id.sid, checked.lease, l.expires_at],
    ),
    query(db, 'INSERT INTO identity VALUES(?,?,?) ON CONFLICT(issuer,sub) DO NOTHING', [
      OP,
      id.sub,
      uuid(),
    ]),
    query(db, 'DELETE FROM app_session WHERE hash=?', [await hash(cookie(req, SESSION))]),
    query(db, 'INSERT INTO app_session VALUES(?,?,?,?,?,?,?,?,?)', [
      key,
      id.sid,
      id.sub,
      id.auth_time,
      checked.lease,
      checked.parent,
      checked.idle,
      tokens.id_token,
      retained(checked.parent),
    ]),
    query(db, 'DELETE FROM guard WHERE id=?', [operation]),
  ]);
  return redirect(`${RP}/`, {
    'Set-Cookie': setCookie(SESSION, secret, p('session.sso_absolute_ttl')),
  });
}
async function backchannel(db, env, req) {
  const input = await body(req, 'form'),
    claims = await verified(env, 'op', input.logout_token, CLIENT, 'logout+jwt');
  check(
    typeof claims.sid === 'string' &&
      typeof claims.jti === 'string' &&
      claims.jti.length <= p('limits.jti_bytes') &&
      !Object.hasOwn(claims, 'nonce') &&
      claims.events &&
      Object.hasOwn(claims.events, 'http://schemas.openid.net/event/backchannel-logout') &&
      JSON.stringify(claims.events['http://schemas.openid.net/event/backchannel-logout']) ===
        '{}' &&
      claims.exp - claims.iat <= p('oidc_logout.token_ttl'),
    'invalid_logout_token',
  );
  // Tombstones outlive pending callbacks, even when this sid has never been seen locally.
  await db.batch([
    query(db, 'INSERT INTO logout_use VALUES(?,?) ON CONFLICT DO NOTHING', [
      claims.jti,
      retained(claims.exp),
    ]),
    query(
      db,
      `INSERT INTO tombstone SELECT ?, MAX(?,COALESCE(MAX(parent_expires_at),0)+?) FROM app_session WHERE sid=?
      ON CONFLICT(sid) DO UPDATE SET expires_at=MAX(expires_at,excluded.expires_at)`,
      [
        claims.sid,
        retained(
          now() +
            Math.max(
              p('session.sso_absolute_ttl'),
              p('logout_delivery.retry_deadline'),
              p('oidc.login.transaction_ttl'),
              p('oidc.authorization_code_ttl') + p('oidc.id_token_ttl'),
            ),
        ),
        retained(0),
        claims.sid,
      ],
    ),
    query(db, 'DELETE FROM app_session WHERE sid=?', [claims.sid]),
  ]);
  return response(null, 200);
}
export default {
  async fetch(req, env) {
    try {
      localOnly(req, env, RP);
      const url = new URL(req.url),
        db = env.DB.withSession('first-primary');
      if (url.pathname === '/login' && req.method === 'POST') return await start(db, req);
      if (url.pathname === '/callback' && req.method === 'GET')
        return await callback(db, env, req, url);
      if (url.pathname === '/backchannel' && req.method === 'POST')
        return await backchannel(db, env, req);
      if (url.pathname === '/logout/callback' && req.method === 'GET') {
        const input = uniqueParams(url.searchParams);
        check(typeof input.state === 'string');
        const tx = await row(
          db,
          'DELETE FROM logout_transaction WHERE state_hash=? AND browser_hash=? AND expires_at>? RETURNING state_hash',
          [await hash(input.state), await hash(cookie(req, BROWSER)), now()],
        );
        check(tx, 'invalid_transaction');
        return redirect(`${RP}/`);
      }
      if (url.pathname === '/logout' && req.method === 'POST') {
        sameOrigin(req, RP);
        const input = await body(req, 'form');
        check(input.csrf === (await hash(cookie(req, BROWSER))), 'invalid_csrf', 403);
        const s = await current(db, env, req);
        check(s, 'invalid_session');
        const state = random();
        await db.batch([
          query(db, 'DELETE FROM app_session WHERE hash=?', [s.hash]),
          query(db, 'INSERT INTO logout_transaction VALUES(?,?,?,?)', [
            await hash(state),
            await hash(cookie(req, BROWSER)),
            now() + p('oidc.login.transaction_ttl'),
            retained(now() + p('oidc.login.transaction_ttl')),
          ]),
        ]);
        const target = new URL(`${OP}/logout`);
        target.search = new URLSearchParams({
          id_token_hint: s.id_token,
          post_logout_redirect_uri: `${RP}/logout/callback`,
          state,
        }).toString();
        return redirect(target.href, { 'Set-Cookie': setCookie(SESSION, '', 0) });
      }
      if (url.pathname === '/me' && req.method === 'GET') {
        const s = await current(db, env, req);
        return s ? json({ sub: s.sub, sid: s.sid }) : json({ error: 'login_required' }, 401);
      }
      if (url.pathname === '/' && req.method === 'GET') {
        let browser = cookie(req, BROWSER);
        if (!browser) browser = random();
        const csrf = await hash(browser),
          s = await current(db, env, req);
        return html(
          s
            ? `<p data-testid="signed-in">ログイン済み / Signed in</p><p data-testid="subject">${escape(s.sub)}</p><form method="post" action="/logout"><input type="hidden" name="csrf" value="${csrf}"><button>ログアウト / Sign out</button></form><form method="post" action="/login"><input type="hidden" name="csrf" value="${csrf}"><button>SSOを再確認 / Check SSO</button></form>`
            : `<p>開発用のRPです。 / Local development RP.</p><form method="post" action="/login"><input type="hidden" name="csrf" value="${csrf}"><button>ログイン / Sign in</button></form>`,
          { 'Set-Cookie': setCookie(BROWSER, browser, p('session.sso_absolute_ttl')) },
        );
      }
      return json({ error: 'not_found' }, 404);
    } catch (error) {
      return errors(error);
    }
  },
  async scheduled(_controller, env) {
    await collect(env.DB.withSession('first-primary'), 'rp');
  },
};
