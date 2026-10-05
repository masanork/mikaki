import {
  BROWSER,
  SESSION,
  now,
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
  requireSession,
  formCsrf,
  browserCsrf,
  login,
  callback,
  backchannel,
  cleanup,
} from './oidc';
import {
  catalog,
  selectLocale,
  errorMessage,
  LOCALE_COOKIE,
  type Catalog,
  type MessageKey,
} from './i18n';
import { demoMessages, demoDocument, formatDemoTime } from './demo';
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
async function staff(env: Env, sub: string): Promise<boolean> {
  return !!(await env.DB.withSession('first-primary')
    .prepare('SELECT sub FROM staff WHERE sub=?')
    .bind(sub)
    .first());
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
      if (request.method === 'POST' && url.pathname === '/login')
        return await login(request, env, strings.locale);
      if (request.method === 'POST' && url.pathname === '/backchannel')
        return await backchannel(request, env);
      if (request.method === 'GET' && url.pathname === '/callback')
        return await callback(
          request,
          env,
          url,
          env.DEMO_ONLY === 'true' ? '/session' : '/tickets',
        );
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
    await cleanup(env);
  },
};
