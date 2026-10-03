import { z } from 'zod';
import { digest, json, now, opaque, operation, randomId, recipient, type Owner } from './model.js';
import { activeJoin, ownerJoin } from './store.js';
import {
  parseAuthorizationDetails,
  authorizationDetailsCondition,
} from './authorization-details.js';

type Registration = { client_id: string; client_name: string; redirect_uris: string };
type Pending = {
  request_id: string;
  client_id: string;
  redirect_uri: string;
  resource: string;
  scopes: string;
  authorization_details: string | null;
  state: string;
  challenge: string;
  expires_at: number;
  owner_account: string | null;
  owner_secret: string | null;
  decision: string | null;
};
import { clientId, registration } from './oauth-client.js';
const scopes = z
  .array(operation)
  .min(1)
  .max(5)
  .refine((v) => new Set(v).size === v.length);
const requestInput = z.strictObject({ request_id: opaque });
const decisionInput = requestInput.extend({ approve: z.boolean(), grant_id: opaque.nullable() });

export function ownerUrl(env: Env): URL | null {
  if (!env.AGENT_OWNER_URL) return null;
  const url = new URL(env.AGENT_OWNER_URL);
  if (
    url.protocol !== 'https:' ||
    url.pathname !== '/vault' ||
    url.search ||
    url.hash ||
    url.username ||
    url.password
  )
    throw new Error('Invalid owner URL');
  return url;
}
export function metadata(env: Env) {
  const origin = new URL(env.AGENT_RESOURCE).origin;
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/oauth/authorize`,
    token_endpoint: `${origin}/oauth/token`,
    revocation_endpoint: `${origin}/oauth/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'],
    scopes_supported: operation.options,
    authorization_details_types_supported: ['mikaki_agent_snapshot'],
    client_id_metadata_document_supported: false,
    authorization_response_iss_parameter_supported: true,
  };
}
async function registered(db: D1Database, id: string) {
  const row = await db
    .withSession('first-primary')
    .prepare(
      'SELECT client_id,client_name,redirect_uris FROM agent_oauth_client WHERE client_id=? AND active=1',
    )
    .bind(clientId.parse(id))
    .first<Registration>();
  if (!row) throw new Error('Unknown client');
  const checked = registration({ ...row, redirect_uris: JSON.parse(row.redirect_uris) });
  return checked;
}
function params(value: URLSearchParams, allowed: string[]) {
  for (const name of value.keys())
    if (!allowed.includes(name) || value.getAll(name).length !== 1)
      throw new Error('Invalid parameter');
  return Object.fromEntries(value);
}
function callback(
  row: Pick<Pending, 'redirect_uri' | 'state'>,
  issuer: string,
  key: 'code' | 'error',
  value: string,
) {
  const url = new URL(row.redirect_uri);
  url.searchParams.set(key, value);
  url.searchParams.set('state', row.state);
  url.searchParams.set('iss', issuer);
  return url.href;
}
const codeRequest = z.strictObject({
  response_type: z.literal('code'),
  client_id: clientId,
  redirect_uri: z.string().max(1024),
  resource: z.string(),
  scope: z.string().min(1).max(100),
  state: z.string().min(16).max(512),
  code_challenge: opaque,
  code_challenge_method: z.literal('S256'),
  authorization_details: z.string().optional(),
});
export async function authorize(request: Request, env: Env) {
  const destination = ownerUrl(env);
  if (!destination) return json({ error: 'temporarily_unavailable' }, 503);
  let input: z.infer<typeof codeRequest>;
  try {
    if (request.url.length > 4096) return json({ error: 'invalid_request' }, 414);
    const p = new URL(request.url).searchParams;
    input = codeRequest.parse(params(p, Object.keys(codeRequest.shape)));
    const c = await registered(env.DB, input.client_id);
    if (!c.redirect_uris.includes(input.redirect_uri) || input.resource !== env.AGENT_RESOURCE)
      throw new Error();
    const selected = scopes.parse(input.scope.split(' '));
    let details: string | null = null;
    if (input.authorization_details !== undefined) {
      try {
        details = JSON.stringify(
          parseAuthorizationDetails(input.authorization_details, input.resource, selected),
        );
      } catch {
        return json({ error: 'invalid_authorization_details' }, 400);
      }
    }
    const id = randomId(),
      time = now();
    const result = await env.DB.withSession('first-primary')
      .prepare(
        `
      INSERT INTO agent_oauth_request(request_id,client_id,redirect_uri,resource,scopes,state,challenge,created_at,expires_at,owner_origin,authorization_details)
      SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM agent_oauth_client WHERE client_id=? AND active=1)
      AND (SELECT count(*) FROM agent_oauth_request WHERE decision IS NULL AND expires_at>unixepoch())<1000
      AND (SELECT count(*) FROM agent_oauth_request WHERE client_id=? AND decision IS NULL AND expires_at>unixepoch())<100
    `,
      )
      .bind(
        id,
        input.client_id,
        input.redirect_uri,
        input.resource,
        JSON.stringify(selected),
        input.state,
        input.code_challenge,
        time,
        time + 600,
        destination.origin,
        details,
        input.client_id,
        input.client_id,
      )
      .run();
    if (!result.meta.changes) return json({ error: 'temporarily_unavailable' }, 429);
    destination.searchParams.set('agent_oauth_request', id);
    return new Response(null, {
      status: 302,
      headers: {
        Location: destination.href,
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
      },
    });
  } catch {
    return json({ error: 'invalid_request' }, 400);
  }
}

export async function preview(db: D1Database, owner: Owner, raw: unknown, env: Env) {
  const { request_id } = requestInput.parse(raw),
    session = db.withSession('first-primary');
  await session
    .prepare(
      `UPDATE agent_oauth_request SET owner_account=?,owner_secret=?
    WHERE request_id=? AND owner_account IS NULL AND decision IS NULL AND expires_at>unixepoch()
    AND resource=? AND EXISTS(SELECT 1 FROM agent_oauth_client c WHERE c.client_id=agent_oauth_request.client_id AND c.active=1)
    AND EXISTS(SELECT 1 ${ownerJoin} AND ss.expires_at>unixepoch())`,
    )
    .bind(
      owner.account,
      owner.secretHash,
      request_id,
      env.AGENT_RESOURCE,
      owner.secretHash,
      owner.account,
      now(),
    )
    .run();
  const row = await session
    .prepare(
      `SELECT r.*,c.client_name FROM agent_oauth_request r
    JOIN agent_oauth_client c ON c.client_id=r.client_id AND c.active=1
    WHERE r.request_id=? AND r.owner_account=? AND r.owner_secret=? AND r.resource=?
    AND r.decision IS NULL AND r.expires_at>unixepoch() AND EXISTS(SELECT 1 ${ownerJoin} AND ss.expires_at>unixepoch())`,
    )
    .bind(
      request_id,
      owner.account,
      owner.secretHash,
      env.AGENT_RESOURCE,
      owner.secretHash,
      owner.account,
      now(),
    )
    .first<Pending & { client_name: string }>();
  if (!row) throw new Error('Request unavailable');
  return {
    request_id: row.request_id,
    client_id: row.client_id,
    client_name: row.client_name,
    redirect_uri: row.redirect_uri,
    resource: row.resource,
    scopes: scopes.parse(JSON.parse(row.scopes)),
    authorization_details:
      row.authorization_details === null
        ? null
        : parseAuthorizationDetails(
            row.authorization_details,
            row.resource,
            scopes.parse(JSON.parse(row.scopes)),
          ),
    expires_at: row.expires_at,
  };
}

export async function decide(db: D1Database, owner: Owner, raw: unknown, env: Env) {
  const input = decisionInput.parse(raw),
    time = now();
  const reviewed = await preview(db, owner, { request_id: input.request_id }, env);
  const key = await recipient(env);
  const code = randomId(),
    codeHash = await digest(code),
    session = db.withSession('first-primary');
  if (input.approve && !input.grant_id) throw new Error('Grant required');
  const liveGrant = `EXISTS(SELECT 1 ${activeJoin} AND g.grant_id=? AND g.account_id=?
    AND g.expires_at>unixepoch() AND g.encrypted_snapshot IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(agent_oauth_request.scopes) s
      WHERE NOT EXISTS(SELECT 1 FROM json_each(g.operations) o WHERE o.value=s.value))
    AND ${authorizationDetailsCondition('agent_oauth_request.authorization_details')})`;
  const query = input.approve
    ? `UPDATE agent_oauth_request SET decision='approved',grant_id=?,
    grant_revision=(SELECT revision FROM agent_grant WHERE grant_id=?),code_hash=?,code_expires_at=min(expires_at,unixepoch()+120)
    WHERE request_id=? AND owner_account=? AND owner_secret=? AND decision IS NULL AND expires_at>unixepoch()
    AND ${liveGrant} AND EXISTS(SELECT 1 ${ownerJoin} AND ss.expires_at>unixepoch())
    AND EXISTS(SELECT 1 FROM agent_oauth_client c WHERE c.client_id=agent_oauth_request.client_id AND c.active=1)`
    : `UPDATE agent_oauth_request SET decision='denied' WHERE request_id=? AND owner_account=? AND owner_secret=?
       AND decision IS NULL AND expires_at>unixepoch() AND EXISTS(SELECT 1 ${ownerJoin} AND ss.expires_at>unixepoch())`;
  const values = input.approve
    ? [
        input.grant_id,
        input.grant_id,
        codeHash,
        input.request_id,
        owner.account,
        owner.secretHash,
        time,
        key.key_id,
        key.resource,
        input.grant_id,
        owner.account,
        owner.secretHash,
        owner.account,
        time,
      ]
    : [input.request_id, owner.account, owner.secretHash, owner.secretHash, owner.account, time];
  const result = await session
    .prepare(query)
    .bind(...values)
    .run();
  if (!result.meta.changes) throw new Error('Consent unavailable');
  const saved = await session
    .prepare('SELECT state FROM agent_oauth_request WHERE request_id=?')
    .bind(input.request_id)
    .first<{ state: string }>();
  if (!saved) throw new Error('Request unavailable');
  return {
    redirect: callback(
      { redirect_uri: reviewed.redirect_uri, state: saved.state },
      new URL(env.AGENT_RESOURCE).origin,
      input.approve ? 'code' : 'error',
      input.approve ? code : 'access_denied',
    ),
  };
}

async function form(request: Request) {
  if (request.headers.get('Authorization')) throw new Error('Public client required');
  if (
    request.headers.get('Content-Type')?.split(';')[0].trim() !==
    'application/x-www-form-urlencoded'
  )
    throw new Error('Invalid content type');
  // Reuse the streaming byte limit rather than buffering an unbounded form body.
  if (!request.body) throw new Error('Missing body');
  const reader = request.body.getReader();
  let text = '',
    length = 0;
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 4096) {
        await reader.cancel();
        throw new Error('Too large');
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } finally {
    reader.releaseLock();
  }
  return new URLSearchParams(text);
}
const exchangeInput = z.strictObject({
  grant_type: z.literal('authorization_code'),
  code: opaque,
  client_id: clientId,
  redirect_uri: z.string().max(1024),
  resource: z.string(),
  code_verifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/),
});
export async function token(request: Request, env: Env) {
  try {
    const input = exchangeInput.parse(
      params(await form(request), Object.keys(exchangeInput.shape)),
    );
    if (input.resource !== env.AGENT_RESOURCE) return json({ error: 'invalid_target' }, 400);
    await registered(env.DB, input.client_id);
    const key = await recipient(env);
    const hash = await digest(input.code),
      challenge = await digest(input.code_verifier);
    const access = `moa_${randomId()}`,
      tokenHash = await digest(access),
      session = env.DB.withSession('first-primary');
    const condition = `r.code_hash=? AND r.client_id=? AND r.redirect_uri=? AND r.resource=? AND r.challenge=?
      AND r.decision='approved' AND r.redeemed_at IS NULL AND r.code_expires_at>unixepoch()
      AND r.expires_at>unixepoch() AND g.expires_at>unixepoch() AND r.grant_revision=g.revision AND g.encrypted_snapshot IS NOT NULL
      AND EXISTS(SELECT 1 FROM agent_oauth_client oc WHERE oc.client_id=r.client_id AND oc.active=1)
      AND ${authorizationDetailsCondition('r.authorization_details')}
      AND NOT EXISTS(SELECT 1 FROM json_each(r.scopes) s
        WHERE NOT EXISTS(SELECT 1 FROM json_each(g.operations) o WHERE o.value=s.value))`;
    const exchangeJoin = activeJoin.replace(
      'FROM agent_grant g',
      'FROM agent_oauth_request r JOIN agent_grant g ON g.grant_id=r.grant_id',
    );
    await session.batch([
      session
        .prepare(
          `INSERT INTO agent_oauth_token(token_hash,request_id,client_id,grant_id,grant_revision,resource,scopes,created_at,expires_at,authorization_details)
        SELECT ?,r.request_id,r.client_id,g.grant_id,g.revision,r.resource,r.scopes,unixepoch(),min(unixepoch()+3600,g.expires_at),r.authorization_details
        ${exchangeJoin} AND ${condition}`,
        )
        .bind(
          tokenHash,
          now(),
          key.key_id,
          key.resource,
          hash,
          input.client_id,
          input.redirect_uri,
          input.resource,
          challenge,
        ),
      session
        .prepare(
          `UPDATE agent_oauth_request SET redeemed_at=unixepoch() WHERE code_hash=? AND redeemed_at IS NULL
        AND EXISTS(SELECT 1 FROM agent_oauth_token t WHERE t.request_id=agent_oauth_request.request_id AND t.token_hash=?)`,
        )
        .bind(hash, tokenHash),
      session
        .prepare(
          `INSERT INTO agent_oauth_guard SELECT ?,CASE WHEN EXISTS(SELECT 1 FROM agent_oauth_token t
        JOIN agent_oauth_request r ON r.request_id=t.request_id WHERE t.token_hash=? AND r.redeemed_at IS NOT NULL) THEN 1 ELSE 0 END`,
        )
        .bind(tokenHash, tokenHash),
      session.prepare('DELETE FROM agent_oauth_guard WHERE operation=?').bind(tokenHash),
    ]);
    const row = await session
      .prepare(
        `SELECT t.scopes,t.expires_at,t.authorization_details ${activeJoin}
        AND EXISTS(SELECT 1 FROM agent_oauth_client oc WHERE oc.client_id=t.client_id AND oc.active=1)
        AND t.token_hash=? AND t.grant_id=g.grant_id AND t.grant_revision=g.revision
        AND t.resource=g.resource AND t.revoked=0 AND t.expires_at>unixepoch()
        AND ${authorizationDetailsCondition('t.authorization_details')}`.replace(
          'FROM agent_grant g',
          'FROM agent_oauth_token t JOIN agent_grant g ON g.grant_id=t.grant_id',
        ),
      )
      .bind(now(), key.key_id, key.resource, tokenHash)
      .first<{ scopes: string; expires_at: number; authorization_details: string | null }>();
    if (!row) throw new Error('Invalid code');
    return json({
      access_token: access,
      token_type: 'Bearer',
      expires_in: Math.max(0, row.expires_at - now()),
      scope: scopes.parse(JSON.parse(row.scopes)).join(' '),
      ...(row.authorization_details === null
        ? {}
        : {
            authorization_details: parseAuthorizationDetails(
              row.authorization_details,
              input.resource,
              scopes.parse(JSON.parse(row.scopes)),
            ),
          }),
    });
  } catch {
    return json({ error: 'invalid_grant' }, 400);
  }
}
export async function revoke(request: Request, env: Env) {
  try {
    const input = z
      .strictObject({
        token: z.string().max(100),
        client_id: clientId,
        token_type_hint: z.literal('access_token').optional(),
      })
      .parse(params(await form(request), ['token', 'client_id', 'token_type_hint']));
    await registered(env.DB, input.client_id);
    await env.DB.withSession('first-primary')
      .prepare(
        `UPDATE agent_oauth_token SET revoked=1
      WHERE token_hash=? AND client_id=? AND revoked=0`,
      )
      .bind(await digest(input.token), input.client_id)
      .run();
    return new Response(null, { status: 200, headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return json({ error: 'invalid_request' }, 400);
  }
}
export async function cleanup(db: D1Database) {
  await db.batch([
    db.prepare('DELETE FROM owner_login_transaction WHERE expires_at<unixepoch()-86400'),
    db.prepare('DELETE FROM agent_oauth_request WHERE created_at<unixepoch()-172800'),
  ]);
}
