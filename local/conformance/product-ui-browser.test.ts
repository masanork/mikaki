import { auditAccessibility } from './support/accessibility-audit.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

test('current product routes preserve CSP, locale, keyboard and mobile access', async () => {
  const origin = 'https://mikaki.test';
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        vars: { MIKAKI_ISSUER: origin },
      },
    ],
  });
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  let failure: unknown;
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const policy = JSON.parse(
      await (
        await import('node:fs/promises')
      ).readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, {
      actor: 'test',
      reason: 'Current product UI regression',
    });
    const credentialId = randomBytes(32).toString('base64url');
    const cookie = randomBytes(32).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(credentialId),
      DB.prepare(
        "INSERT INTO passkey_credential VALUES(?,'synthetic-key','synthetic-user',0,0,0,1)",
      ).bind(credentialId),
      DB.prepare("INSERT INTO account_role VALUES('owner','admin',1)"),
      DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(
        credentialId,
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
        createHash('sha256').update(cookie).digest('base64url'),
        now,
      ),
    ]);
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await page.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: { ...(await request.allHeaders()), cookie: `__Host-op-sso=${cookie}` },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    for (const locale of ['ja', 'en']) {
      for (const [path, heading] of [
        ['/vault', 'Vault'],
        ['/admin', locale === 'ja' ? '招待を発行' : 'Issue an invitation'],
        ['/enroll/complete', locale === 'ja' ? '登録が完了しました' : 'Registration complete'],
        ['/logout', locale === 'ja' ? 'ログアウト' : 'Log out'],
      ]) {
        const response = await page.goto(`${origin}${path}?lang=${locale}`);
        assert.equal(response?.status(), 200);
        assert.match(response!.headers()['content-security-policy'], /style-src 'self'/);
        await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
        assert.equal(await page.locator('html').getAttribute('lang'), locale);
        await expect(page.locator('.product-header')).toHaveCSS('color', 'rgb(255, 255, 255)');
        if (path === '/vault') {
          await expect(page.locator('.product-origin strong')).toHaveText('mikaki.test');
          await page.locator('.gate-background[data-renderer="canvas"]').waitFor();
          assert.match(
            await page
              .locator('.vault-shell')
              .evaluate((node) => node.style.getPropertyValue('--page-hue')),
            /^\d+$/,
          );
          assert.equal(await page.locator('.gate-fallback span').count(), 1);
          assert.doesNotMatch(response!.headers()['content-security-policy']!, /unsafe-inline/);
        }
        assert.equal(await page.locator('main').count(), 1);
        await auditAccessibility(page, `${path.split('/').filter(Boolean).join('-')}-${locale}`);
        const skip = page.getByRole('link', {
          name: locale === 'ja' ? '本文へ移動' : 'Skip to content',
          exact: true,
        });
        assert.ok((await skip.boundingBox())!.y < 0, 'Shortcut stays offscreen until focused');
        await page.keyboard.press('Tab');
        await expect(skip).toBeFocused();
        await expect(skip).toBeInViewport();
        const hashBefore = new URL(page.url()).hash;
        await page.keyboard.press('Enter');
        await expect(page.locator('#product-main')).toBeFocused();
        if (path !== '/logout') assert.equal(new URL(page.url()).hash, hashBefore);
        await page.keyboard.press('Tab');
        assert.ok(
          await page
            .locator('#product-main')
            .evaluate((main) => main.contains(document.activeElement)),
          'Tab continues inside the main content rather than returning to the header',
        );
        for (const width of [1440, 390, 320]) {
          await page.setViewportSize({ width, height: 900 });
          assert.equal(
            await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),
            false,
            `${path}/${locale}/${width}`,
          );
        }
      }
    }
  } catch (error) {
    failure = error;
  } finally {
    await browser?.close();
    await harness.close();
  }
  if (failure !== undefined) throw failure;
});
