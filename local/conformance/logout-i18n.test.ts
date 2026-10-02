import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

test('product logout preserves locale through switching and confirmation, with CSRF protection', async () => {
  const issuer = 'https://mikaki.test';
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        vars: { MIKAKI_ISSUER: issuer },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'logout i18n' });
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('account',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('credential','account',1)"),
    ]);
    for (const locale of ['ja', 'en']) {
      const secret = randomBytes(32).toString('base64url');
      const now = Math.floor(Date.now() / 1000);
      await DB.batch([
        DB.prepare('INSERT INTO sso_session VALUES(?,?,?,?,?,0)').bind(
          locale,
          'account',
          'credential',
          1,
          now + 3600,
        ),
        DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(
          locale,
          createHash('sha256').update(secret).digest('base64url'),
          now,
        ),
      ]);
      const cookie = `__Host-op-sso=${secret}`;
      const state = 'kept{{action}}';
      const initial = await worker.fetch(
        `${issuer}/logout?ui_locales=${locale}-JP&state=${encodeURIComponent(state)}`,
        {
          headers: { Cookie: cookie, 'Accept-Language': locale === 'en' ? 'ja' : 'en' },
        },
      );
      assert.equal(initial.status, 200);
      assert.equal(initial.headers.get('content-language'), locale);
      const initialHtml = await initial.text();
      assert.match(initialHtml, new RegExp(`<html lang="${locale}">`));
      assert.match(initialHtml, locale === 'ja' ? /ログアウト/ : /Log out/);
      assert.match(initialHtml, /<strong>mikaki\.test<\/strong>/);
      assert.match(initialHtml, /data-renderer="css"/);
      assert.doesNotMatch(initialHtml, /PRIVATE BY DESIGN/);
      const switchPath = /<a href="([^"]*lang=[^"]+)"/
        .exec(initialHtml)![1]
        .replaceAll('&amp;', '&');
      const switchUrl = new URL(switchPath, issuer);
      assert.equal(switchUrl.searchParams.get('state'), state);
      assert.equal(switchUrl.searchParams.get('ui_locales'), `${locale}-JP`);
      const other = locale === 'ja' ? 'en' : 'ja';
      assert.equal(switchUrl.searchParams.get('lang'), other);
      const switched = await worker.fetch(switchUrl.href, { headers: { Cookie: cookie } });
      assert.equal(switched.status, 200);
      assert.equal(switched.headers.get('content-language'), other);
      const html = await switched.text();
      const action = /<form method="post" action="([^"]+)"/.exec(html)![1];
      const csrf = /name="csrf" value="([^"]+)"/.exec(html)![1];
      const logoutCookie = /__Host-op-logout=([^; ,]+)/.exec(
        switched.headers.get('set-cookie')!,
      )![1];
      const confirm = (value: string) =>
        worker.fetch(new URL(action, issuer).href, {
          method: 'POST',
          headers: {
            Cookie: `${cookie}; __Host-op-logout=${logoutCookie}`,
            Origin: issuer,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({ csrf: value }).toString(),
        });
      const rejected = await confirm('x'.repeat(43));
      assert.equal(rejected.status, 400);
      assert.match(
        await rejected.text(),
        other === 'en' ? /logout request is invalid/ : /リクエストが無効/,
      );
      const completed = await confirm(csrf);
      assert.equal(completed.status, 200);
      assert.equal(completed.headers.get('content-language'), other);
      assert.match(
        await completed.text(),
        other === 'en' ? /You have logged out/ : /ログアウトしました/,
      );
      const session = await DB.prepare('SELECT revoked FROM sso_session WHERE sso_id=?')
        .bind(locale)
        .first();
      assert.equal(session?.revoked, 1);
    }
  } finally {
    await harness.close();
  }
});
