// A disposable reference RP, not the deployed narashi/helpdesk application.
// It uses the actual Rust OP for token exchange and every session check.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { importJWK, jwtVerify, SignJWT, type JWK } from 'jose';
import { readProfileFromUserInfo } from './profile-rp.ts';

type Transport = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string | URLSearchParams;
  },
) => Promise<{
  status: number;
  ok: boolean;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
}>;
const secret = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
const html = (body: string, status = 200) =>
  new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
export async function journeyRp(
  issuer: string,
  origin: string,
  clientId: string,
  privateKey: CryptoKey,
  publicJwk: JWK,
  transport: Transport,
  profile = false,
) {
  const opKey = await importJWK(publicJwk, 'ES256');
  const transactions = new Map<string, { browser: string; nonce: string; verifier: string }>();
  const sessions = new Map<string, { sid: string; sub: string; authTime: number }>();
  let lastExchange: { code: string; verifier: string } | null = null;
  let lastProfile: { sub: string; name?: string } | null = null;
  let lastAccessToken: string | null = null;
  async function post(path: string, values: Record<string, string>) {
    const endpoint = `${issuer}${path}`;
    const assertion = await new SignJWT({ sub: clientId, jti: randomUUID() })
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: 'journey-rp' })
      .setIssuer(clientId)
      .setAudience(endpoint)
      .setIssuedAt()
      .setExpirationTime('60s')
      .sign(privateKey);
    const body = {
      ...values,
      client_id: clientId,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion,
    };
    return transport(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type':
          path === '/session/check' ? 'application/json' : 'application/x-www-form-urlencoded',
      },
      body: path === '/session/check' ? JSON.stringify(body) : new URLSearchParams(body),
    });
  }
  const cookie = (request: Request, name: string) =>
    (request.headers.get('cookie') ?? '')
      .split(';')
      .map((value) => value.trim())
      .find((value) => value.startsWith(`${name}=`))
      ?.slice(name.length + 1);
  const redirect = (location: string, name?: string, value?: string) => {
    const headers = new Headers({ Location: location, 'Cache-Control': 'no-store' });
    if (name) headers.set('Set-Cookie', `${name}=${value}; Secure; HttpOnly; SameSite=Lax; Path=/`);
    return new Response(null, { status: 302, headers });
  };
  return {
    post,
    get lastExchange() {
      return lastExchange;
    },
    get lastProfile() {
      return lastProfile;
    },
    get lastAccessToken() {
      return lastAccessToken;
    },
    async handle(request: Request): Promise<Response> {
      const url = new URL(request.url);
      if (url.origin !== origin) return html('Wrong origin', 400);
      if (url.pathname === '/')
        return html('<h1>Reference application</h1><a href="/login">Sign in</a>');
      if (url.pathname === '/login') {
        lastProfile = null;
        lastAccessToken = null;
        const state = secret(),
          browser = secret(),
          nonce = secret(),
          verifier = secret();
        transactions.set(state, { browser: hash(browser), nonce, verifier });
        const target = new URL('/authorize', issuer);
        target.search = new URLSearchParams({
          client_id: clientId,
          redirect_uri: `${origin}/callback`,
          response_type: 'code',
          scope: profile ? 'openid profile' : 'openid',
          state,
          nonce,
          code_challenge: hash(verifier),
          code_challenge_method: 'S256',
          ui_locales: 'en',
        }).toString();
        return redirect(target.href, '__Host-journey-browser', browser);
      }
      if (url.pathname === '/callback') {
        const state = url.searchParams.get('state') ?? '',
          code = url.searchParams.get('code');
        const transaction = transactions.get(state);
        if (
          !transaction ||
          !code ||
          url.searchParams.get('iss') !== issuer ||
          transaction.browser !== hash(cookie(request, '__Host-journey-browser') ?? '') ||
          [...url.searchParams.keys()].length !== new Set(url.searchParams.keys()).size
        )
          return html('<h1>Callback rejected</h1>', 400);
        transactions.delete(state);
        const response = await post('/token', {
          grant_type: 'authorization_code',
          code,
          redirect_uri: `${origin}/callback`,
          code_verifier: transaction.verifier,
        });
        if (!response.ok) return html('<h1>Token exchange failed</h1>', 401);
        const token = (await response.json()) as { id_token: string; access_token?: string };
        const { payload } = await jwtVerify(token.id_token, opKey, {
          issuer,
          audience: clientId,
          algorithms: ['ES256'],
          typ: 'JWT',
          requiredClaims: ['sub', 'sid', 'nonce', 'auth_time', 'iat', 'exp'],
        });
        if (
          payload.nonce !== transaction.nonce ||
          typeof payload.sid !== 'string' ||
          typeof payload.sub !== 'string' ||
          typeof payload.auth_time !== 'number'
        )
          return html('<h1>ID token rejected</h1>', 401);
        const checked = await post('/session/check', { sid: payload.sid });
        const status = (await checked.json()) as {
          active?: boolean;
          sub?: string;
          auth_time?: number;
        };
        if (
          !checked.ok ||
          !status.active ||
          status.sub !== payload.sub ||
          status.auth_time !== payload.auth_time
        )
          return html('<h1>Session rejected</h1>', 401);
        if (profile) {
          if (typeof token.access_token !== 'string')
            return html('<h1>Access token missing</h1>', 401);
          lastProfile = await readProfileFromUserInfo(
            issuer,
            token.access_token,
            payload.sub,
            (url, init) =>
              transport(url, {
                method: 'GET',
                headers: Object.fromEntries(new Headers(init?.headers)),
              }),
          );
          lastAccessToken = token.access_token;
        }
        const session = secret();
        sessions.set(hash(session), {
          sid: payload.sid,
          sub: payload.sub,
          authTime: payload.auth_time,
        });
        lastExchange = { code, verifier: transaction.verifier };
        return redirect(`${origin}/protected`, '__Host-journey-session', session);
      }
      if (url.pathname === '/protected') {
        const session = sessions.get(hash(cookie(request, '__Host-journey-session') ?? ''));
        if (!session) return html('<h1>Sign-in required</h1>', 401);
        const checked = await post('/session/check', { sid: session.sid });
        const status = (await checked.json()) as {
          active?: boolean;
          sub?: string;
          auth_time?: number;
        };
        if (
          !checked.ok ||
          !status.active ||
          status.sub !== session.sub ||
          status.auth_time !== session.authTime
        )
          return html('<h1>Sign-in required</h1>', 401);
        return html('<h1>Signed-in application</h1>');
      }
      return html('Not found', 404);
    },
  };
}
