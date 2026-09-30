import { chromium } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = fileURLToPath(new URL('../..', import.meta.url));
const harness = createTestHarness({
  root,
  workers: [
    { configPath: fileURLToPath(new URL('../../crates/worker/wrangler.jsonc', import.meta.url)) },
  ],
});
let browser;
try {
  await harness.listen();
  const worker = harness.getWorker('mikaki-op-worker');
  const assets = new Map();
  for (const path of ['/login/login.js', '/login/login.css']) {
    assets.set(path, await (await worker.fetch(`https://mikaki.test${path}`)).text());
  }
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript(() => {
    if (!location.search.includes('no-webgl')) return;
    const original = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (kind, ...args) {
      return kind === 'webgl' ? null : Reflect.apply(original, this, [kind, ...args]);
    };
  });
  await page.route('https://mikaki.test/**', async (route) => {
    const url = new URL(route.request().url());
    if (assets.has(url.pathname)) {
      await route.fulfill({
        contentType: url.pathname.endsWith('.css') ? 'text/css' : 'text/javascript',
        body: assets.get(url.pathname),
      });
      return;
    }
    if (url.pathname === '/login/cue') {
      await route.fulfill({ json: { seed: 'c'.repeat(43), refresh_in_ms: 20_000 } });
      return;
    }
    await route.fulfill({
      contentType: 'text/html',
      headers: {
        'Content-Security-Policy':
          "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
      },
      body: `<!doctype html><html lang="${url.searchParams.get('lang') === 'en' ? 'en' : 'ja'}"><head><meta charset="utf-8"><link rel="stylesheet" href="/login/login.css"></head><body><div id="app" data-tx="${'a'.repeat(43)}" data-challenge="${'b'.repeat(43)}" data-rp-id="mikaki.test" data-rp-uri="https://helpdesk.mikaki.test/callback" data-client="mikaki-helpdesk-local" data-enrollment="${url.searchParams.has('enroll')}"></div><script type="module" src="/login/login.js"></script></body></html>`,
    });
  });

  async function capture(name) {
    if (!(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)))
      await page.locator('.auth-session-cue[data-cue-live="true"]').waitFor();
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await page.screenshot({
      path: fileURLToPath(new URL(`./${name}.png`, import.meta.url)),
      fullPage: true,
      animations: 'disabled',
    });
  }
  await page.goto('https://mikaki.test/login');
  await page.getByRole('button', { name: 'Passkeyで許可してログイン' }).waitFor();
  await capture('sign-in');
  await page.getByRole('button', { name: '招待で登録する' }).click();
  await page.getByRole('alert').waitFor();
  await capture('input-error');
  await page.goto('https://mikaki.test/login?enroll=1');
  await page.getByRole('heading', { name: 'アカウントを登録' }).waitFor();
  await capture('enrollment');
  await page.goto('https://mikaki.test/login');
  await page.getByRole('button', { name: 'Passkeyで許可してログイン' }).waitFor();
  await page.setViewportSize({ width: 375, height: 812 });
  await capture('mobile-sign-in');
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('https://mikaki.test/login?lang=en');
  await page.getByRole('button', { name: 'Allow and sign in with passkey' }).waitFor();
  await capture('sign-in-en');
  await page.goto('https://mikaki.test/login?no-webgl=1');
  await page.getByRole('button', { name: 'Passkeyで許可してログイン' }).waitFor();
  await capture('sign-in-svg');
  assert.equal(await page.locator('.auth-seal').getAttribute('data-renderer'), 'svg');
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('https://mikaki.test/login');
  await page.getByRole('button', { name: 'Passkeyで許可してログイン' }).waitFor();
  await capture('sign-in-reduced-motion');
  assert.equal(await page.locator('.auth-seal').getAttribute('data-renderer'), 'svg');
  assert.deepEqual(errors, []);
} finally {
  await browser?.close();
  await harness.close();
}
