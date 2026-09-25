import { chromium } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { fileURLToPath } from 'node:url';

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
  await page.route('https://mikaki.test/**', async (route) => {
    const url = new URL(route.request().url());
    if (assets.has(url.pathname)) {
      await route.fulfill({
        contentType: url.pathname.endsWith('.css') ? 'text/css' : 'text/javascript',
        body: assets.get(url.pathname),
      });
      return;
    }
    await route.fulfill({
      contentType: 'text/html',
      body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><link rel="stylesheet" href="/login/login.css"></head><body><div id="app" data-tx="${'a'.repeat(43)}" data-challenge="${'b'.repeat(43)}" data-rp-id="mikaki.test" data-client="mikaki-helpdesk-local" data-enrollment="${url.searchParams.has('enroll')}"></div><script type="module" src="/login/login.js"></script></body></html>`,
    });
  });

  async function capture(name) {
    await page.screenshot({
      path: fileURLToPath(new URL(`./${name}.png`, import.meta.url)),
      fullPage: true,
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
} finally {
  await browser?.close();
  await harness.close();
}
