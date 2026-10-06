import {
  BROWSER,
  random,
  hash,
  escape,
  cookieHeader,
  HttpError,
  fail,
  cookie,
  baseHeaders,
  redirect,
  readForm,
  current,
  formCsrf,
  login,
  callback,
  backchannel,
  logout,
  cleanup,
} from '../../crates/helpdesk-rp/oidc';
import { catalog, selectLocale, errorMessage, LOCALE_COOKIE } from '../../crates/helpdesk-rp/i18n';

type Env = DocsEnv & { LOCAL_ONLY?: string };
const labels = {
  ja: {
    title: 'ログイン状態',
    home: 'ドキュメントへ戻る',
    login: 'mikakiでサインイン',
    intro: 'ドキュメントはサインインせずに読めます。ここではDocsへのログイン状態を確認できます。',
    privacy:
      '名前・メール・Vaultの内容は要求しません。ログインに必要な識別子とセッション情報を専用DBに一時保存します。',
    active: 'サインイン済み',
    check: 'セッションを再確認',
    logout: 'Docsからログアウト',
    logoutBody: 'Docsのログイン状態を削除します。mikakiのSSOや他のアプリのログインは終了しません。',
    lease: '次の確認期限（UTC）',
    expires: 'セッションの有効期限（UTC）',
    rateLimited: '操作が集中しています。少し待ってから、もう一度お試しください。',
    error: '操作を完了できませんでした',
    skip: '本文へ移動',
  },
  en: {
    title: 'Login state',
    home: 'Back to the documentation',
    login: 'Sign in with mikaki',
    intro: 'You can read the documentation without signing in. Check your Docs login state here.',
    privacy:
      'Docs does not request your name, email or Vault contents. It temporarily stores the identifiers and session information needed for login in a separate database.',
    active: 'Signed in',
    check: 'Check session again',
    logout: 'Sign out of Docs',
    logoutBody:
      'This removes your Docs login state. It does not end mikaki SSO or sign you out of other applications.',
    lease: 'Next session check due (UTC)',
    expires: 'Session expires (UTC)',
    rateLimited: 'Too many operations. Please wait a little and try again.',
    error: 'Unable to complete this operation',
    skip: 'Skip to content',
  },
};
function page(env: Env, locale: 'ja' | 'en', content: string, status = 200, browser?: string) {
  const t = labels[locale];
  const headers = baseHeaders(env);
  headers.set('Content-Type', 'text/html; charset=utf-8');
  headers.set('Content-Language', locale);
  headers.set(
    'Content-Security-Policy',
    `default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self' ${env.ISSUER}; frame-ancestors 'none'; base-uri 'none'`,
  );
  headers.append('Set-Cookie', cookieHeader(LOCALE_COOKIE, locale, 31536000));
  if (browser) headers.append('Set-Cookie', cookieHeader(BROWSER, browser, 86400));
  return new Response(
    `<!doctype html><html lang="${locale}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${t.title} · mikaki Docs</title><link rel="icon" href="/favicon.svg"><link rel="stylesheet" href="/style.css"></head><body><a class="skip-link" href="#main-content">${t.skip}</a><header class="site-header"><div class="header-inner"><a class="brand" href="${locale === 'en' ? '/en/' : '/'}">mikaki Docs</a><a class="language-link" href="/session?lang=${locale === 'ja' ? 'en' : 'ja'}" lang="${locale === 'ja' ? 'en' : 'ja'}">${locale === 'ja' ? 'English' : '日本語'}</a></div></header><main class="app-main prose" id="main-content" tabindex="-1">${content}<p><a href="${locale === 'en' ? '/en/' : '/'}">${t.home}</a></p></main></body></html>`,
    { status, headers },
  );
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const locale = selectLocale(request),
      t = labels[locale];
    try {
      const url = new URL(request.url),
        issuer = new URL(env.ISSUER),
        rp = new URL(env.RP_ORIGIN);
      if (
        url.origin !== rp.origin ||
        rp.origin !== env.RP_ORIGIN ||
        issuer.origin !== env.ISSUER ||
        !env.CLIENT_ID ||
        (env.LOCAL_ONLY !== 'true' && (rp.protocol !== 'https:' || issuer.protocol !== 'https:'))
      )
        fail(400, 'invalid_configuration');
      if (request.method === 'POST' && ['/login', '/session/check'].includes(url.pathname)) {
        const requester =
          request.headers.get('cf-connecting-ip') || cookie(request, BROWSER) || 'unknown';
        if (
          !(await env.AUTH_LIMITER.limit({ key: `${url.pathname}:${await hash(requester)}` }))
            .success
        )
          return page(env, locale, `<h1>${t.error}</h1><p>${t.rateLimited}</p>`, 429);
      }
      if (request.method === 'GET' && url.pathname === '/version') {
        const version = env.CF_VERSION_METADATA;
        if (!version?.id || !version.tag) fail(503, 'version_metadata_unavailable');
        return Response.json(
          { id: version.id, tag: version.tag, timestamp: version.timestamp },
          { headers: baseHeaders(env) },
        );
      }
      if (request.method === 'GET' && url.pathname === '/health') {
        if (!env.RP_PRIVATE_JWK || !env.AUTH_LIMITER) fail(503, 'invalid_configuration');
        await env.DB.prepare('SELECT token_hash FROM rp_session LIMIT 1').first();
        return Response.json(
          { status: 'ok', issuer: env.ISSUER, origin: env.RP_ORIGIN, mode: 'docs' },
          { headers: baseHeaders(env) },
        );
      }
      if (request.method === 'GET' && url.pathname === '/session') {
        const browser = cookie(request, BROWSER) || random();
        const session = await current(request, env);
        const csrf = formCsrf(await hash(browser));
        const time = (seconds: number) =>
          `<time datetime="${new Date(seconds * 1000).toISOString()}">${escape(new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' }).format(new Date(seconds * 1000)))}</time>`;
        return page(
          env,
          locale,
          `<h1>${t.title}</h1><p>${t.intro}</p>${session ? `<h2>${t.active}</h2><dl><dt>${t.lease}</dt><dd>${time(session.lease_until)}</dd><dt>${t.expires}</dt><dd>${time(session.parent_expires_at)}</dd></dl><form method="post" action="/session/check">${csrf}<button class="button button-primary">${t.check}</button></form><form method="post" action="/logout">${csrf}<button class="button button-outline">${t.logout}</button></form><p>${t.logoutBody}</p>` : `<form method="post" action="/login">${csrf}<button class="button button-primary">${t.login}</button></form>`}<p>${t.privacy}</p>`,
          200,
          browser,
        );
      }
      if (request.method === 'POST' && url.pathname === '/login')
        return await login(request, env, locale);
      if (request.method === 'GET' && url.pathname === '/callback')
        return await callback(request, env, url, '/session');
      if (request.method === 'POST' && url.pathname === '/backchannel')
        return await backchannel(request, env);
      if (request.method === 'POST' && url.pathname === '/logout')
        return await logout(request, env);
      if (request.method === 'POST' && url.pathname === '/session/check') {
        await readForm(request, env);
        if (!(await current(request, env, true))) fail(401, 'session_inactive');
        return redirect(env, '/session');
      }
      if (
        ['/login', '/callback', '/backchannel', '/logout', '/health', '/version'].includes(
          url.pathname,
        ) ||
        url.pathname === '/session' ||
        url.pathname.startsWith('/session/')
      )
        fail(405, 'unsupported_method');
      if (!['GET', 'HEAD'].includes(request.method)) fail(405, 'unsupported_method');
      return await env.DOCS_ASSETS.fetch(request);
    } catch (error) {
      const failure =
        error instanceof HttpError ? error : new HttpError(503, 'service_unavailable');
      if (!(error instanceof HttpError))
        console.error(
          JSON.stringify({
            event: 'docs_request_failed',
            error: error instanceof Error ? error.name : 'unknown',
          }),
        );
      return page(
        env,
        locale,
        `<h1>${t.error}</h1><p>${escape(errorMessage(catalog(locale), failure.message))}</p>`,
        failure.status,
      );
    }
  },
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    await cleanup(env);
  },
} satisfies ExportedHandler<Env>;
