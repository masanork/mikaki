import {
  catalog,
  selectLocale,
  errorMessage,
  LOCALE_COOKIE,
  type Catalog,
  type MessageKey,
} from './i18n';
import { demoMessages, demoDocument, formatDemoTime } from './demo';
import {
  createRemoteJWKSet,
  decodeProtectedHeader,
  errors,
  importJWK,
  jwtVerify,
  SignJWT,
} from 'jose';
import wasmModule from './pkg/mikaki_helpdesk_rp_bg.wasm';
import {
  __wbg_set_wasm,
  __wbindgen_init_externref_table,
  articles_json,
  validate_reply,
  validate_ticket,
} from './pkg/mikaki_helpdesk_rp_bg.js';

const wasm = new WebAssembly.Instance(wasmModule, {
  './mikaki_helpdesk_rp_bg.js': { __wbindgen_init_externref_table },
});
__wbg_set_wasm(wasm.exports);
(wasm.exports.__wbindgen_start as () => void)();

type Env = HelpdeskEnv &
  Partial<Pick<HelpdeskDemoEnv, 'DEMO_ONLY' | 'DEMO_LIMITER'>> & {
    RP_PRIVATE_JWK: string;
    LOCAL_ONLY?: string;
  };
type Session = {
  token_hash: string;
  sid: string;
  sub: string;
  auth_time: number;
  lease_until: number;
  parent_expires_at: number;
  idle_expires_at: number;
  idle_timeout_seconds: number;
};
type Ticket = {
  id: string;
  owner_sub: string;
  title: string;
  status: string;
  created_at: number;
  updated_at: number;
};
type Message = { author_sub: string; body: string; created_at: number };
type Article = { slug: string; title_key: MessageKey; body_key: MessageKey };
const ARTICLES: Article[] = JSON.parse(articles_json());
const BROWSER = '__Host-help-browser';
const SESSION = '__Host-help-session';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const jwksByIssuer = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function issuerKeys(issuer: string): ReturnType<typeof createRemoteJWKSet> {
  let keys = jwksByIssuer.get(issuer);
  if (!keys) {
    keys = createRemoteJWKSet(new URL(`${issuer}/jwks`), { timeoutDuration: 5000 });
    jwksByIssuer.set(issuer, keys);
  }
  return keys;
}
const now = () => Math.floor(Date.now() / 1000);
const random = () => crypto.randomUUID() + crypto.randomUUID();
const b64 = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
const hash = async (value: string) =>
  b64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
const escape = (value: unknown) =>
  String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
const cookieHeader = (name: string, value: string, maxAge: number) =>
  `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;

class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
function fail(status: number, message: string): never {
  throw new HttpError(status, message);
}
function cookie(request: Request, name: string): string {
  const matches = (request.headers.get('cookie') ?? '')
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${name}=`));
  if (matches.length > 1) fail(400, 'duplicate_cookie');
  return matches[0]?.slice(name.length + 1) ?? '';
}
function baseHeaders(env: Env): Headers {
  return new Headers({
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'strict-origin',
    'X-Robots-Tag': env.DEMO_ONLY === 'true' ? 'noindex, nofollow' : 'noindex',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${env.ISSUER}; frame-ancestors 'none'; base-uri 'none'`,
  });
}
function html(
  env: Env,
  strings: Catalog,
  content: string,
  status = 200,
  setCookie?: string,
  path = '/',
): Response {
  const t = (key: MessageKey) => escape(strings.message(key));
  const demo = env.DEMO_ONLY === 'true' ? demoMessages(strings.locale) : null;
  const title = demo ? escape(demo.title) : t('helpTitle');
  const languageUrl = new URL(path, env.RP_ORIGIN);
  // Keep the current page when switching, without replaying callback parameters or POSTs.
  if (languageUrl.pathname === '/callback') languageUrl.pathname = '/';
  languageUrl.search = '';
  languageUrl.searchParams.set('lang', strings.locale === 'ja' ? 'en' : 'ja');
  const headers = baseHeaders(env);
  headers.set('Content-Type', 'text/html; charset=utf-8');
  headers.set('Content-Language', strings.locale);
  headers.append('Set-Cookie', cookieHeader(LOCALE_COOKIE, strings.locale, 31536000));
  if (setCookie) headers.append('Set-Cookie', setCookie);
  if (demo)
    return new Response(
      demoDocument(
        strings.locale,
        content,
        languageUrl.pathname + languageUrl.search,
        new URL(path, env.RP_ORIGIN).pathname,
      ),
      { status, headers },
    );
  return new Response(
    `<!doctype html><html lang="${strings.locale}"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>body{font:16px system-ui;max-width:760px;margin:2rem auto;padding:0 1rem;line-height:1.6}nav a{margin-right:1rem}textarea,input[type=text]{width:100%;box-sizing:border-box;padding:.5rem}textarea{min-height:9rem}article{padding:1rem 0;border-bottom:1px solid #ddd}button{padding:.45rem .8rem}pre{white-space:pre-wrap}</style><nav><a href="/">${title}</a><a href="/help">${t('helpHeading')}</a><a href="/tickets">${t('helpTickets')}</a><a href="${escape(languageUrl.pathname + languageUrl.search)}" lang="${strings.locale === 'ja' ? 'en' : 'ja'}" aria-label="${t('language')}">${strings.locale === 'ja' ? 'English' : '日本語'}</a></nav><main>${content}</main></html>`,
    { status, headers },
  );
}
function redirect(env: Env, path: string, setCookie?: string): Response {
  const headers = baseHeaders(env);
  headers.set('Location', path.startsWith('http') ? path : `${env.RP_ORIGIN}${path}`);
  if (setCookie) headers.set('Set-Cookie', setCookie);
  return new Response(null, { status: 303, headers });
}
function sameOrigin(request: Request, env: Env): void {
  if (request.headers.get('origin') !== env.RP_ORIGIN) fail(403, 'invalid_origin');
}
async function readForm(request: Request, env: Env): Promise<URLSearchParams> {
  sameOrigin(request, env);
  if (request.headers.get('content-type')?.split(';')[0] !== 'application/x-www-form-urlencoded')
    fail(415, 'unsupported_media_type');
  const reader = request.body?.getReader();
  if (!reader) fail(400, 'missing_body');
  let size = 0;
  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 8192) {
      await reader.cancel();
      fail(413, 'request_too_large');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  const form = new URLSearchParams(
    new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes),
  );
  if ([...form].length > 12 || new Set([...form.keys()]).size !== [...form].length)
    fail(400, 'invalid_form');
  const csrf = await hash(cookie(request, BROWSER));
  if (!cookie(request, BROWSER) || form.get('csrf') !== csrf) fail(403, 'invalid_csrf');
  return form;
}
async function assertion(env: Env, audience: string): Promise<string> {
  const jwk = JSON.parse(env.RP_PRIVATE_JWK) as JsonWebKey & { kid?: string };
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.kid) fail(503, 'rp_key_unavailable');
  const issued = now();
  return new SignJWT({ sub: env.CLIENT_ID, jti: random() })
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: jwk.kid })
    .setIssuer(env.CLIENT_ID)
    .setAudience(audience)
    .setIssuedAt(issued)
    .setExpirationTime(issued + 60)
    .sign(await importJWK(jwk, 'ES256'));
}
async function opPost(
  env: Env,
  path: string,
  values: Record<string, string>,
): Promise<Record<string, unknown>> {
  const endpoint = `${env.ISSUER}${path}`;
  const data = {
    ...values,
    client_id: env.CLIENT_ID,
    client_assertion_type: ASSERTION_TYPE,
    client_assertion: await assertion(env, endpoint),
  };
  // The disposable local OP uses a form for this endpoint; the product OP uses JSON.
  const jsonBody = path === '/session/check' && env.LOCAL_ONLY !== 'true';
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': jsonBody ? 'application/json' : 'application/x-www-form-urlencoded',
    },
    body: jsonBody ? JSON.stringify(data) : new URLSearchParams(data),
    redirect: 'manual',
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) fail(503, 'issuer_unavailable');
  const reader = response.body?.getReader();
  if (!reader) fail(503, 'issuer_response_missing');
  let size = 0;
  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 16384) {
      await reader.cancel();
      fail(503, 'issuer_response_too_large');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text) as Record<string, unknown>;
}
async function checkSession(env: Env, sid: string, sub: string, authTime: number) {
  const started = now();
  const result = await opPost(env, '/session/check', { sid });
  if (
    result.active !== true ||
    result.sub !== sub ||
    result.auth_time !== authTime ||
    typeof result.expires_at !== 'number' ||
    typeof result.lease_ttl !== 'number' ||
    typeof result.app_idle_timeout !== 'number' ||
    !Number.isSafeInteger(result.expires_at) ||
    !Number.isSafeInteger(result.lease_ttl) ||
    !Number.isSafeInteger(result.app_idle_timeout) ||
    result.lease_ttl <= 0 ||
    result.lease_ttl > 300 ||
    result.app_idle_timeout <= 0
  )
    fail(401, 'session_inactive');
  const lease = Math.min(started + result.lease_ttl, result.expires_at);
  if (lease <= now()) fail(401, 'session_expired');
  return {
    lease,
    parent: result.expires_at,
    idle: Math.min(now() + result.app_idle_timeout, result.expires_at),
    idleTimeout: result.app_idle_timeout,
  };
}
async function current(request: Request, env: Env, forceCheck = false): Promise<Session | null> {
  const token = cookie(request, SESSION);
  if (!token) return null;
  const db = env.DB.withSession('first-primary');
  let session = await db
    .prepare(
      'SELECT * FROM rp_session WHERE token_hash=? AND idle_expires_at>? AND parent_expires_at>?',
    )
    .bind(await hash(token), now(), now())
    .first<Session>();
  if (!session) return null;
  let valid: Awaited<ReturnType<typeof checkSession>> | null = null;
  if (forceCheck || session.lease_until <= now()) {
    try {
      valid = await checkSession(env, session.sid, session.sub, session.auth_time);
    } catch (error) {
      // A known revocation must also invalidate a still-unexpired cached lease.
      if (error instanceof HttpError && error.status === 401)
        await db
          .prepare('DELETE FROM rp_session WHERE token_hash=?')
          .bind(session.token_hash)
          .run();
      throw error;
    }
  }
  const timestamp = now();
  if (valid && valid.lease <= timestamp) fail(401, 'session_expired');
  const parent = Math.min(session.parent_expires_at, valid?.parent ?? session.parent_expires_at);
  session = await db
    .prepare(
      'UPDATE rp_session SET lease_until=MIN(MAX(lease_until,?),?), parent_expires_at=MIN(parent_expires_at,?), idle_timeout_seconds=?, idle_expires_at=MIN(?+?,parent_expires_at,?) WHERE token_hash=? AND idle_expires_at>? AND parent_expires_at>? AND (lease_until>? OR ?=1) RETURNING *',
    )
    .bind(
      valid?.lease ?? session.lease_until,
      parent,
      parent,
      valid?.idleTimeout ?? session.idle_timeout_seconds,
      timestamp,
      valid?.idleTimeout ?? session.idle_timeout_seconds,
      parent,
      session.token_hash,
      timestamp,
      timestamp,
      timestamp,
      valid ? 1 : 0,
    )
    .first<Session>();
  if (!session) fail(401, 'session_changed');
  return session;
}
async function requireSession(request: Request, env: Env, forceCheck = false): Promise<Session> {
  const session = await current(request, env, forceCheck);
  if (!session) fail(401, 'login_required');
  return session;
}
async function staff(env: Env, sub: string): Promise<boolean> {
  return !!(await env.DB.withSession('first-primary')
    .prepare('SELECT sub FROM staff WHERE sub=?')
    .bind(sub)
    .first());
}
function formCsrf(value: string): string {
  return `<input type="hidden" name="csrf" value="${escape(value)}">`;
}
async function browserCsrf(request: Request): Promise<string> {
  return hash(cookie(request, BROWSER));
}
async function login(request: Request, env: Env): Promise<Response> {
  await readForm(request, env);
  const browser = cookie(request, BROWSER);
  const state = random(),
    nonce = random(),
    verifier = random();
  await env.DB.prepare(
    'INSERT INTO login_transaction(state_hash,browser_hash,nonce,verifier,expires_at) VALUES(?,?,?,?,?)',
  )
    .bind(await hash(state), await hash(browser), nonce, verifier, now() + 300)
    .run();
  const target = new URL(`${env.ISSUER}/authorize`);
  target.search = new URLSearchParams({
    client_id: env.CLIENT_ID,
    redirect_uri: `${env.RP_ORIGIN}/callback`,
    response_type: 'code',
    scope: 'openid',
    state,
    nonce,
    code_challenge: await hash(verifier),
    code_challenge_method: 'S256',
    ui_locales: selectLocale(request),
  }).toString();
  return redirect(env, target.href);
}
async function callback(request: Request, env: Env, url: URL): Promise<Response> {
  if ([...url.searchParams].length !== new Set([...url.searchParams.keys()]).size)
    fail(400, 'invalid_callback');
  const state = url.searchParams.get('state'),
    code = url.searchParams.get('code');
  if (!state || !code || url.searchParams.get('iss') !== env.ISSUER) fail(400, 'invalid_callback');
  const transaction = await env.DB.prepare(
    'DELETE FROM login_transaction WHERE state_hash=? AND browser_hash=? AND expires_at>? RETURNING nonce,verifier',
  )
    .bind(await hash(state), await hash(cookie(request, BROWSER)), now())
    .first<{ nonce: string; verifier: string }>();
  if (!transaction) fail(400, 'invalid_transaction');
  const token = await opPost(env, '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: `${env.RP_ORIGIN}/callback`,
    code_verifier: transaction.verifier,
  });
  if (typeof token.id_token !== 'string' || token.id_token.length > 16384)
    fail(401, 'invalid_id_token');
  const header = decodeProtectedHeader(token.id_token);
  if (
    header.alg !== 'ES256' ||
    header.typ !== 'JWT' ||
    !header.kid ||
    header.jku ||
    header.jwk ||
    header.x5u
  )
    fail(401, 'invalid_id_token');
  const { payload } = await jwtVerify(
    token.id_token,
    createRemoteJWKSet(new URL(`${env.ISSUER}/jwks`)),
    {
      issuer: env.ISSUER,
      audience: env.CLIENT_ID,
      algorithms: ['ES256'],
      typ: 'JWT',
      clockTolerance: 60,
      requiredClaims: ['iat', 'exp', 'iss', 'aud', 'sub'],
    },
  );
  if (
    payload.nonce !== transaction.nonce ||
    payload.aud !== env.CLIENT_ID ||
    typeof payload.sub !== 'string' ||
    typeof payload.sid !== 'string' ||
    typeof payload.auth_time !== 'number' ||
    !Number.isSafeInteger(payload.auth_time) ||
    !payload.iat ||
    !payload.exp ||
    payload.exp - payload.iat > 600 ||
    payload.auth_time > payload.iat ||
    (payload.azp && payload.azp !== env.CLIENT_ID)
  )
    fail(401, 'invalid_id_token');
  const valid = await checkSession(env, payload.sid, payload.sub, payload.auth_time);
  if (env.DEMO_ONLY === 'true') {
    valid.parent = Math.min(valid.parent, now() + 3600);
    valid.lease = Math.min(valid.lease, valid.parent);
    valid.idle = Math.min(valid.idle, valid.parent);
  }
  const secret = random();
  const inserted = await env.DB.prepare(
    'INSERT INTO rp_session(token_hash,sid,sub,auth_time,lease_until,parent_expires_at,idle_expires_at,idle_timeout_seconds) SELECT ?,?,?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM logout_tombstone WHERE sid=? AND expires_at>?)',
  )
    .bind(
      await hash(secret),
      payload.sid,
      payload.sub,
      payload.auth_time,
      valid.lease,
      valid.parent,
      valid.idle,
      valid.idleTimeout,
      payload.sid,
      now(),
    )
    .run();
  if (inserted.meta.changes !== 1) fail(401, 'session_revoked');
  return redirect(
    env,
    env.DEMO_ONLY === 'true' ? '/session' : '/tickets',
    cookieHeader(SESSION, secret, valid.parent - now()),
  );
}

async function backchannel(request: Request, env: Env): Promise<Response> {
  if (request.headers.get('content-type')?.split(';')[0] !== 'application/x-www-form-urlencoded')
    fail(415, 'unsupported_media_type');
  const reader = request.body?.getReader();
  if (!reader) fail(400, 'missing_body');
  let size = 0;
  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 16384) {
      await reader.cancel();
      fail(413, 'request_too_large');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  let params: URLSearchParams;
  try {
    params = new URLSearchParams(
      new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes),
    );
  } catch {
    fail(400, 'invalid_form');
  }
  const tokens = params.getAll('logout_token');
  if (tokens.length !== 1 || tokens[0].length > 12000) fail(400, 'invalid_logout_token');
  let header;
  try {
    header = decodeProtectedHeader(tokens[0]);
  } catch {
    fail(400, 'invalid_logout_token');
  }
  if (
    header.alg !== 'ES256' ||
    header.typ !== 'logout+jwt' ||
    !header.kid ||
    header.jku ||
    header.jwk ||
    header.x5u
  )
    fail(400, 'invalid_logout_token');
  let payload;
  try {
    ({ payload } = await jwtVerify(tokens[0], issuerKeys(env.ISSUER), {
      issuer: env.ISSUER,
      audience: env.CLIENT_ID,
      algorithms: ['ES256'],
      typ: 'logout+jwt',
      clockTolerance: 60,
      requiredClaims: ['iss', 'aud', 'iat', 'exp', 'jti'],
    }));
  } catch (error) {
    if (
      error instanceof TypeError ||
      error instanceof errors.JWKSTimeout ||
      (error instanceof errors.JOSEError && error.constructor === errors.JOSEError)
    )
      fail(503, 'issuer_keys_unavailable');
    fail(400, 'invalid_logout_token');
  }
  const event = payload.events;
  const marker =
    event && typeof event === 'object' && !Array.isArray(event)
      ? event['http://schemas.openid.net/event/backchannel-logout']
      : null;
  if (
    typeof payload.sid !== 'string' ||
    !payload.sid ||
    payload.sid.length > 128 ||
    (payload.sub !== undefined && (typeof payload.sub !== 'string' || !payload.sub)) ||
    typeof payload.jti !== 'string' ||
    !payload.jti ||
    typeof payload.iat !== 'number' ||
    typeof payload.exp !== 'number' ||
    payload.exp <= payload.iat ||
    payload.exp - payload.iat > 300 ||
    payload.iat > now() + 60 ||
    Object.hasOwn(payload, 'nonce') ||
    !marker ||
    typeof marker !== 'object' ||
    Array.isArray(marker) ||
    Object.keys(marker).length !== 0
  )
    fail(400, 'invalid_logout_token');
  const existing = await env.DB.withSession('first-primary')
    .prepare('SELECT sub FROM rp_session WHERE sid=? LIMIT 1')
    .bind(payload.sid)
    .first<{ sub: string }>();
  if (existing && payload.sub !== undefined && existing.sub !== payload.sub)
    fail(400, 'invalid_logout_token');
  await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO logout_tombstone(sid,expires_at) VALUES(?,?) ON CONFLICT(sid) DO UPDATE SET expires_at=MAX(expires_at,excluded.expires_at)',
    ).bind(payload.sid, now() + 32 * 86400),
    env.DB.prepare('DELETE FROM rp_session WHERE sid=?').bind(payload.sid),
  ]);
  return new Response(null, { status: 200, headers: baseHeaders(env) });
}
async function ticketList(request: Request, env: Env, strings: Catalog): Promise<Response> {
  const t = (key: MessageKey) => escape(strings.message(key));
  const session = await requireSession(request, env);
  const agent = await staff(env, session.sub);
  const rows = agent
    ? await env.DB.prepare('SELECT * FROM ticket ORDER BY updated_at DESC LIMIT 50').all<Ticket>()
    : await env.DB.prepare(
        'SELECT * FROM ticket WHERE owner_sub=? ORDER BY updated_at DESC LIMIT 50',
      )
        .bind(session.sub)
        .all<Ticket>();
  const csrf = await browserCsrf(request);
  return html(
    env,
    strings,
    `<h1>${t('helpTickets')}</h1><p>${agent ? t('helpStaffTickets') : t('helpYourTickets')}</p><p><a href="/tickets/new">${t('helpNewTicket')}</a></p>${(rows.results ?? []).map((item) => `<article><a href="/tickets/${escape(item.id)}">${escape(item.title)}</a> — ${item.status === 'open' ? t('helpOpen') : t('helpClosed')}</article>`).join('') || `<p>${t('helpEmptyTickets')}</p>`}<form method="post" action="/logout">${formCsrf(csrf)}<button>${t('helpLogout')}</button></form>`,
    200,
    undefined,
    new URL(request.url).pathname,
  );
}
async function ticketPage(
  request: Request,
  env: Env,
  id: string,
  strings: Catalog,
): Promise<Response> {
  const t = (key: MessageKey) => escape(strings.message(key));
  const session = await requireSession(request, env);
  const ticket = await env.DB.prepare('SELECT * FROM ticket WHERE id=?').bind(id).first<Ticket>();
  if (!ticket || (ticket.owner_sub !== session.sub && !(await staff(env, session.sub))))
    fail(404, 'not_found');
  const rows = await env.DB.prepare(
    'SELECT author_sub,body,created_at FROM ticket_message WHERE ticket_id=? ORDER BY created_at,id',
  )
    .bind(id)
    .all<Message>();
  const csrf = await browserCsrf(request);
  return html(
    env,
    strings,
    `<h1>${escape(ticket.title)}</h1><p>${ticket.status === 'open' ? t('helpOpen') : t('helpClosed')}</p>${(rows.results ?? []).map((message) => `<article><strong>${message.author_sub === ticket.owner_sub ? t('helpRequester') : t('helpAgent')}</strong><pre>${escape(message.body)}</pre></article>`).join('')}${ticket.status === 'open' ? `<h2>${t('helpReply')}</h2><form method="post" action="/tickets/${escape(id)}/reply">${formCsrf(csrf)}<label>${t('helpReply')}<textarea name="message" maxlength="4000" required></textarea></label><p><button>${t('helpSend')}</button></p></form><form method="post" action="/tickets/${escape(id)}/close">${formCsrf(csrf)}<button>${t('helpCloseTicket')}</button></form>` : ''}`,
    200,
    undefined,
    new URL(request.url).pathname,
  );
}
async function createTicket(request: Request, env: Env): Promise<Response> {
  const session = await requireSession(request, env);
  const form = await readForm(request, env);
  const title = form.get('title') ?? '',
    message = form.get('message') ?? '';
  const error = validate_ticket(title, message);
  if (error) fail(400, error);
  const id = crypto.randomUUID(),
    timestamp = now();
  const [created, inserted] = await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO ticket(id,owner_sub,title,created_at,updated_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM rp_session WHERE token_hash=? AND lease_until>? AND idle_expires_at>? AND parent_expires_at>?)',
    ).bind(
      id,
      session.sub,
      title.trim(),
      timestamp,
      timestamp,
      session.token_hash,
      timestamp,
      timestamp,
      timestamp,
    ),
    env.DB.prepare(
      'INSERT INTO ticket_message(id,ticket_id,author_sub,body,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM ticket WHERE id=? AND owner_sub=?)',
    ).bind(crypto.randomUUID(), id, session.sub, message.trim(), timestamp, id, session.sub),
  ]);
  if (created.meta.changes !== 1 || inserted.meta.changes !== 1) fail(409, 'session_changed');
  return redirect(env, `/tickets/${id}`);
}
async function mutateTicket(
  request: Request,
  env: Env,
  id: string,
  action: 'reply' | 'close',
): Promise<Response> {
  const session = await requireSession(request, env);
  const form = await readForm(request, env);
  const ticket = await env.DB.prepare('SELECT * FROM ticket WHERE id=?').bind(id).first<Ticket>();
  if (!ticket || (ticket.owner_sub !== session.sub && !(await staff(env, session.sub))))
    fail(404, 'not_found');
  if (ticket.status !== 'open') fail(409, 'ticket_closed');
  const timestamp = now();
  if (action === 'reply') {
    const message = form.get('message') ?? '';
    const error = validate_reply(message);
    if (error) fail(400, error);
    const [updated, inserted] = await env.DB.batch([
      env.DB.prepare(
        "UPDATE ticket SET updated_at=? WHERE id=? AND status='open' AND (owner_sub=? OR EXISTS(SELECT 1 FROM staff WHERE sub=?)) AND EXISTS(SELECT 1 FROM rp_session WHERE token_hash=? AND lease_until>? AND idle_expires_at>? AND parent_expires_at>?)",
      ).bind(
        timestamp,
        id,
        session.sub,
        session.sub,
        session.token_hash,
        timestamp,
        timestamp,
        timestamp,
      ),
      env.DB.prepare(
        "INSERT INTO ticket_message(id,ticket_id,author_sub,body,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM ticket WHERE id=? AND status='open' AND (owner_sub=? OR EXISTS(SELECT 1 FROM staff WHERE sub=?))) AND EXISTS(SELECT 1 FROM rp_session WHERE token_hash=? AND lease_until>? AND idle_expires_at>? AND parent_expires_at>?)",
      ).bind(
        crypto.randomUUID(),
        id,
        session.sub,
        message.trim(),
        timestamp,
        id,
        session.sub,
        session.sub,
        session.token_hash,
        timestamp,
        timestamp,
        timestamp,
      ),
    ]);
    if (updated.meta.changes !== 1 || inserted.meta.changes !== 1) fail(409, 'ticket_changed');
  } else {
    const changed = await env.DB.prepare(
      "UPDATE ticket SET status='closed',updated_at=? WHERE id=? AND status='open' AND (owner_sub=? OR EXISTS(SELECT 1 FROM staff WHERE sub=?)) AND EXISTS(SELECT 1 FROM rp_session WHERE token_hash=? AND lease_until>? AND idle_expires_at>? AND parent_expires_at>?)",
    )
      .bind(
        timestamp,
        id,
        session.sub,
        session.sub,
        session.token_hash,
        timestamp,
        timestamp,
        timestamp,
      )
      .run();
    if (changed.meta.changes !== 1) fail(409, 'ticket_changed');
  }
  return redirect(env, `/tickets/${id}`);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const strings = catalog(selectLocale(request));
    const t = (key: MessageKey) => escape(strings.message(key));
    try {
      const url = new URL(request.url);
      const issuer = new URL(env.ISSUER);
      const rp = new URL(env.RP_ORIGIN);
      if (
        url.origin !== env.RP_ORIGIN ||
        issuer.origin !== env.ISSUER ||
        rp.origin !== env.RP_ORIGIN ||
        (env.LOCAL_ONLY !== 'true' && (issuer.protocol !== 'https:' || rp.protocol !== 'https:')) ||
        !env.CLIENT_ID
      )
        fail(400, 'invalid_configuration');
      if (env.DEMO_ONLY === 'true') {
        const demo = demoMessages(strings.locale);
        if (
          ![
            '/',
            '/health',
            '/login',
            '/callback',
            '/backchannel',
            '/logout',
            '/session',
            '/session/check',
          ].includes(url.pathname)
        )
          fail(404, 'not_found');
        if (request.method === 'GET' && url.pathname === '/health') {
          if (!env.RP_PRIVATE_JWK || !env.DEMO_LIMITER) fail(503, 'invalid_configuration');
          await env.DB.prepare('SELECT token_hash FROM rp_session LIMIT 1').first();
          return Response.json(
            { status: 'ok', issuer: env.ISSUER, origin: env.RP_ORIGIN, mode: 'login-demo' },
            { headers: baseHeaders(env) },
          );
        }
        if (request.method === 'POST' && ['/login', '/session/check'].includes(url.pathname)) {
          if (!env.DEMO_LIMITER) fail(503, 'invalid_configuration');
          if (!(await env.DEMO_LIMITER.limit({ key: `mikaki-demo:${url.pathname}` })).success)
            return html(
              env,
              strings,
              `<h1>${escape(demo.title)}</h1><p>${escape(demo.rateLimited)}</p>`,
              429,
            );
        }
        if (request.method === 'GET' && url.pathname === '/') {
          const browser = cookie(request, BROWSER) || random();
          const session = await current(request, env);
          const prefix = strings.locale === 'en' ? '/en' : '';
          return html(
            env,
            strings,
            `<header class="demo-intro"><p class="eyebrow">${escape(demo.title)}</p><h1>${escape(demo.home)}</h1><p>${escape(demo.intro)}</p></header><section class="task-panel" aria-labelledby="demo-action-title"><h2 id="demo-action-title"${session ? ' class="status"' : ''}>${escape(session ? demo.active : demo.start)}</h2>${session ? `<p><a class="button" href="/session">${escape(demo.session)}</a></p>` : `<form method="post" action="/login">${formCsrf(await hash(browser))}<button>${escape(demo.login)}</button></form>`}</section><section class="demo-steps" aria-labelledby="demo-steps-title"><h2 id="demo-steps-title">${escape(demo.steps)}</h2><ol><li>${escape(demo.stepLogin)}</li><li>${escape(demo.stepCheck)}</li><li>${escape(demo.stepLogout)}</li></ol></section><aside class="privacy-note" aria-labelledby="demo-privacy-title"><h2 id="demo-privacy-title">${escape(demo.privacyTitle)}</h2><p>${escape(demo.privacy)}</p><a href="https://mikaki.org${prefix}/contact">${escape(demo.invitation)}</a><a href="https://mikaki.org${prefix}/integration-demo">${escape(demo.guide)}</a></aside>`,
            200,
            cookieHeader(BROWSER, browser, 86400),
          );
        }
        if (
          (request.method === 'GET' && url.pathname === '/session') ||
          (request.method === 'POST' && url.pathname === '/session/check')
        ) {
          const force = request.method === 'POST';
          if (force) await readForm(request, env);
          const session = await requireSession(request, env, force);
          if (force) return redirect(env, '/session');
          const csrf = formCsrf(await browserCsrf(request));
          return html(
            env,
            strings,
            `<header class="demo-intro"><p class="eyebrow">${escape(demo.title)}</p><h1>${escape(demo.session)}</h1></header><section class="task-panel"><h2 class="status">${escape(demo.active)}</h2><p>${escape(demo.sessionBody)}</p><dl class="session-times"><div><dt>${escape(demo.lease)}</dt><dd><time datetime="${new Date(session.lease_until * 1000).toISOString()}">${escape(formatDemoTime(session.lease_until, strings.locale))}</time></dd></div><div><dt>${escape(demo.expires)}</dt><dd><time datetime="${new Date(session.parent_expires_at * 1000).toISOString()}">${escape(formatDemoTime(session.parent_expires_at, strings.locale))}</time></dd></div></dl><div class="session-actions"><form method="post" action="/session/check">${csrf}<button>${escape(demo.check)}</button></form><form method="post" action="/logout">${csrf}<button class="secondary">${escape(demo.logout)}</button></form></div><p class="logout-note">${escape(demo.logoutBody)}</p></section><details class="op-logout"><summary>${escape(demo.opLogoutDetails)}</summary><p>${escape(demo.opLogoutWarning)}</p><a href="${env.ISSUER}/logout">${escape(demo.opLogout)}</a></details>`,
            200,
            undefined,
            '/session',
          );
        }
      }
      if (request.method === 'GET' && url.pathname === '/') {
        let browser = cookie(request, BROWSER);
        if (!browser) browser = random();
        const session = await current(request, env);
        return html(
          env,
          strings,
          `<h1>${t('helpHomeHeading')}</h1><p>${t('helpHomeBody')}</p><p><a href="/help">${t('helpReadArticles')}</a> · <a href="/tickets">${t('helpTickets')}</a></p>${session ? `<p>${t('helpLoggedIn')}</p>` : `<form method="post" action="/login">${formCsrf(await hash(browser))}<button>${t('helpLogin')}</button></form>`}`,
          200,
          cookieHeader(BROWSER, browser, 86400),
        );
      }
      if (request.method === 'GET' && url.pathname === '/help')
        return html(
          env,
          strings,
          `<h1>${t('helpHeading')}</h1>${ARTICLES.map((article) => `<article><a href="/help/${article.slug}">${t(article.title_key)}</a></article>`).join('')}`,
          200,
          undefined,
          url.pathname,
        );
      if (request.method === 'GET' && url.pathname.startsWith('/help/')) {
        const article = ARTICLES.find((entry) => `/help/${entry.slug}` === url.pathname);
        if (!article) fail(404, 'not_found');
        return html(
          env,
          strings,
          `<h1>${t(article.title_key)}</h1><p>${t(article.body_key)}</p>`,
          200,
          undefined,
          url.pathname,
        );
      }
      if (request.method === 'POST' && url.pathname === '/login') return await login(request, env);
      if (request.method === 'POST' && url.pathname === '/backchannel')
        return await backchannel(request, env);
      if (request.method === 'GET' && url.pathname === '/callback')
        return await callback(request, env, url);
      if (request.method === 'POST' && url.pathname === '/logout') {
        await readForm(request, env);
        const token = cookie(request, SESSION);
        if (token)
          await env.DB.prepare('DELETE FROM rp_session WHERE token_hash=?')
            .bind(await hash(token))
            .run();
        return redirect(env, '/', cookieHeader(SESSION, '', 0));
      }
      if (request.method === 'GET' && url.pathname === '/tickets')
        return await ticketList(request, env, strings);
      if (request.method === 'GET' && url.pathname === '/tickets/new') {
        await requireSession(request, env);
        return html(
          env,
          strings,
          `<h1>${t('helpNewTicket')}</h1><form method="post" action="/tickets">${formCsrf(await browserCsrf(request))}<label>${t('helpSubject')}<input type="text" name="title" maxlength="120" required></label><label>${t('helpMessage')}<textarea name="message" maxlength="4000" required></textarea></label><p><button>${t('helpSend')}</button></p></form>`,
          200,
          undefined,
          url.pathname,
        );
      }
      if (request.method === 'POST' && url.pathname === '/tickets')
        return await createTicket(request, env);
      const match = /^\/tickets\/([0-9a-f-]{36})(?:\/(reply|close))?$/.exec(url.pathname);
      if (match && request.method === 'GET' && !match[2])
        return await ticketPage(request, env, match[1], strings);
      if (match && request.method === 'POST' && (match[2] === 'reply' || match[2] === 'close'))
        return await mutateTicket(request, env, match[1], match[2]);
      fail(404, 'not_found');
    } catch (error) {
      const failure =
        error instanceof HttpError ? error : new HttpError(503, 'service_unavailable');
      if (!(error instanceof HttpError))
        console.error('helpdesk_request_failed', error instanceof Error ? error.name : 'unknown');
      return html(
        env,
        strings,
        `<h1>${failure.status === 404 ? t('helpNotFound') : t('helpErrorHeading')}</h1><p>${escape(env.DEMO_ONLY === 'true' && failure.message === 'login_required' ? demoMessages(strings.locale).loginRequired : errorMessage(strings, failure.message))}</p><p><a href="/">${t('helpBackHome')}</a></p>`,
        failure.status,
        undefined,
        new URL(request.url).pathname,
      );
    }
  },
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const expired = now();
    await env.DB.batch([
      env.DB.prepare('DELETE FROM login_transaction WHERE expires_at<?').bind(expired),
      env.DB.prepare('DELETE FROM logout_tombstone WHERE expires_at<?').bind(expired),
      env.DB.prepare('DELETE FROM rp_session WHERE idle_expires_at<? OR parent_expires_at<?').bind(
        expired,
        expired,
      ),
    ]);
  },
};
