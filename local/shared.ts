import { SignJWT, importJWK, jwtVerify, decodeProtectedHeader } from 'jose';
import policy from './generated/policy.json' with { type: 'json' };

export const OP = 'http://localhost:18877';
export const RP = 'http://127.0.0.1:18878';
export const CLIENT = 'local-rp';
export const CALLBACK = `${RP}/callback`;
export const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
export const p = (key) => policy[key];
export const now = () => Math.floor(Date.now() / 1000);
export const uuid = () => crypto.randomUUID();
export const b64 = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
export const random = () => b64(crypto.getRandomValues(new Uint8Array(32)));
export const hash = async (value) =>
  b64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
export function fail(code = 'invalid_request', status = 400) {
  throw Object.assign(new Error(code), { status });
}
export const check = (ok, code = 'invalid_request', status = 400) => {
  if (!ok) fail(code, status);
};
export function cookie(req, name) {
  const matches = (req.headers.get('cookie') ?? '')
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.startsWith(`${name}=`));
  check(matches.length <= 1);
  return matches[0]?.slice(name.length + 1) ?? '';
}
export const setCookie = (name, value, age) =>
  `${name}=${value}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}`;
export function response(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': `default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' ${OP} ${RP}`,
      ...headers,
    },
  });
}
export const json = (body, status = 200, headers = {}) =>
  response(JSON.stringify(body), status, { 'Content-Type': 'application/json', ...headers });
export const redirect = (location, headers = {}) =>
  response(null, 303, { Location: location, ...headers });
export const sqlParts = (sql) =>
  sql
    .replace(/^\s*--.*$/gm, '')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
export const query = (db, sql, args = []) => db.prepare(sql).bind(...args);
export const row = (db, sql, args = []) => query(db, sql, args).first();
export function statements(db, sql, params) {
  return sqlParts(sql).map((s) => {
    const values = [];
    const text = s.replace(/:([a-z_]+)/g, (_, key) => {
      check(Object.hasOwn(params, key));
      values.push(params[key]);
      return '?';
    });
    return query(db, text, values);
  });
}
export function guard(db, predicate, args = []) {
  const id = uuid();
  return [
    query(db, `INSERT INTO atomic_guard VALUES(?, CASE WHEN ${predicate} THEN 1 ELSE 0 END)`, [
      id,
      ...args,
    ]),
    query(db, 'DELETE FROM atomic_guard WHERE operation_id=?', [id]),
  ];
}
export function uniqueParams(params) {
  check([...params].length <= p('limits.parameter_count'));
  const seen = new Set();
  for (const [key] of params) {
    check(!seen.has(key));
    seen.add(key);
  }
  return Object.fromEntries(params);
}
export async function body(
  req,
  kind = 'json',
  validator?: (text: string, limit: number, depth: number) => boolean,
) {
  const limit = kind === 'json' ? p('limits.webauthn_body_bytes') : p('limits.form_body_bytes');
  check(
    req.headers.get('content-type')?.split(';')[0] ===
      (kind === 'json' ? 'application/json' : 'application/x-www-form-urlencoded'),
  );
  const reader = req.body?.getReader();
  check(reader);
  let length = 0;
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > limit) {
      await reader.cancel();
      fail('request_too_large', 413);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.length;
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (kind === 'form') return uniqueParams(new URLSearchParams(text));
  check(validator?.(text, limit, p('limits.webauthn_depth')), 'invalid_json');
  const value = JSON.parse(text);
  check(value && typeof value === 'object' && !Array.isArray(value));
  return value;
}
export function sameOrigin(req, origin) {
  check(req.headers.get('origin') === origin, 'invalid_origin', 403);
}
export function localOnly(req, env, origin) {
  check(env.LOCAL_ONLY === 'true' && new URL(req.url).origin === origin, 'local_only', 403);
  check(req.url.length <= p('limits.request_target_bytes'), 'request_too_large', 413);
}
export async function signed(env, role, claims, audience, ttl, typ = 'JWT') {
  const jwk = JSON.parse(role === 'op' ? env.OP_PRIVATE_JWK : env.RP_PRIVATE_JWK);
  const t = now();
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', kid: jwk.kid, typ })
    .setIssuer(role === 'op' ? OP : CLIENT)
    .setAudience(audience)
    .setIssuedAt(t)
    .setExpirationTime(t + ttl)
    .sign(await importJWK(jwk, 'ES256'));
}
export async function verified(env, role, token, audience, typ = 'JWT', allowExpiredHint = false) {
  check(typeof token === 'string' && token.length <= p('limits.jwt_bytes'), 'invalid_token', 401);
  const jwk = JSON.parse(role === 'op' ? env.OP_PUBLIC_JWK : env.RP_PUBLIC_JWK);
  const h = decodeProtectedHeader(token);
  check(
    h.alg === 'ES256' && h.kid === jwk.kid && h.typ === typ && !h.jku && !h.x5u && !h.jwk,
    'invalid_token',
    401,
  );
  const { payload } = await jwtVerify(token, await importJWK(jwk, 'ES256'), {
    issuer: role === 'op' ? OP : CLIENT,
    audience,
    algorithms: ['ES256'],
    typ,
    clockTolerance: p(allowExpiredHint ? 'session.sso_absolute_ttl' : 'oidc.validation.clock_skew'),
    requiredClaims: ['iat', 'exp', 'iss', 'aud'],
  });
  check(
    Number.isSafeInteger(payload.iat) &&
      Number.isSafeInteger(payload.exp) &&
      payload.iat <= now() + p('oidc.validation.clock_skew') &&
      payload.exp > payload.iat &&
      payload.aud === audience,
    'invalid_token',
    401,
  );
  return payload;
}
export async function clientAssertion(env, endpoint) {
  return signed(
    env,
    'rp',
    { sub: CLIENT, jti: random() },
    endpoint,
    p('oidc.client_authentication.assertion_ttl'),
  );
}
export function errors(error) {
  // Never log bodies, assertions, tokens, invitation secrets or SQL arguments.
  if (!error.status) console.error('adapter_error', error.name, error.code ?? '');
  return json({ error: error.status ? error.message : 'operation_failed' }, error.status ?? 400);
}
