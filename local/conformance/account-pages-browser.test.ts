import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

test('account pages use the product styles under CSP and fit a mobile viewport', async () => {
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
  let browser;
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'account page browser test' });
    const secret = randomBytes(32).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security(account_id,epoch,active) VALUES('account',1,1)"),
      DB.prepare(
        "INSERT INTO credential(credential_id,account_id,active) VALUES('credential','account',1)",
      ),
      DB.prepare(
        "INSERT INTO passkey_credential(credential_id,public_key,user_handle,counter,backup_eligible,backup_state,revision) VALUES('credential','public-key','user-handle',0,0,0,1)",
      ),
      DB.prepare("INSERT INTO account_role(account_id,role,active) VALUES('account','admin',1)"),
      DB.prepare('INSERT INTO sso_session VALUES(?,?,?,?,?,0)').bind(
        'session',
        'account',
        'credential',
        1,
        now + 3600,
      ),
      DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(
        'session',
        createHash('sha256').update(secret).digest('base64url'),
        now,
      ),
    ]);
    const stylesheet = await worker.fetch(`${issuer}/ui/product.css`);
    assert.equal(stylesheet.status, 200);
    assert.match(stylesheet.headers.get('content-type') ?? '', /text\/css/);
    assert.match(await stylesheet.text(), /\.product-header/);

    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    await context.addCookies([
      {
        name: '__Host-op-sso',
        value: secret,
        domain: 'mikaki.test',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
      },
    ]);
    const page = await context.newPage();
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route(`${issuer}/**`, async (route) => {
      const request = route.request();
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: await request.allHeaders(),
        redirect: 'manual',
        ...(request.postDataBuffer() ? { body: request.postDataBuffer() } : {}),
      });
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: await response.text(),
      });
    });

    for (const width of [1440, 375]) {
      await page.setViewportSize({ width, height: 900 });
      for (const [path, heading] of [
        ['/admin?lang=ja', '招待を発行'],
        ['/enroll/complete?lang=en', 'Registration complete'],
        ['/logout?lang=ja', 'ログアウト'],
      ]) {
        await page.goto(`${issuer}${path}`);
        await page.getByRole('heading', { name: heading, exact: true }).waitFor();
        assert.equal(await page.locator('.product-header').count(), 1);
        assert.equal(
          await page.evaluate(() => getComputedStyle(document.body).backgroundColor),
          'rgb(246, 248, 251)',
        );
        assert.equal(
          await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
          true,
          `${path} overflows at ${width}px`,
        );
      }
    }
    await page.goto(`${issuer}/admin?lang=ja`);
    await page.getByRole('combobox', { name: '言語' }).selectOption('en');
    await page.getByRole('heading', { name: 'Issue an invitation' }).waitFor();
    assert.deepEqual(errors, []);
  } finally {
    await browser?.close();
    await harness.close();
  }
});
