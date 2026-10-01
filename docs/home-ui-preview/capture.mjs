import { chromium } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = fileURLToPath(new URL('../..', import.meta.url));
const harness = createTestHarness({
  root,
  workers: [{ configPath: `${root}/crates/worker/wrangler.jsonc` }],
});
let browser;
try {
  await harness.listen();
  const worker = harness.getWorker('mikaki-op-worker');
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript(() => {
    if (!location.search.includes('no-canvas')) return;
    const original = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (kind, ...args) {
      return kind === '2d' ? null : Reflect.apply(original, this, [kind, ...args]);
    };
  });
  await page.route('**/*', async (route) => {
    const response = await worker.fetch(route.request().url());
    await route.fulfill({
      status: response.status,
      headers: Object.fromEntries(response.headers),
      body: Buffer.from(await response.arrayBuffer()),
    });
  });
  async function capture(name, url) {
    await page.goto(url);
    await page.locator('.home-shell h1').waitFor();
    if (!url.includes('no-canvas'))
      await page.locator('.gate-background[data-renderer="canvas"]').waitFor();
    await page.waitForTimeout(250);
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await page.screenshot({
      path: fileURLToPath(new URL(`./${name}.png`, import.meta.url)),
      fullPage: true,
    });
  }
  await capture('home', 'https://mikaki.tossa.app/?lang=ja');
  await capture('home-en', 'https://mikaki.tossa.app/?lang=en');
  await capture('other-origin', 'https://other.test/?lang=ja');
  await page.setViewportSize({ width: 390, height: 844 });
  await capture('home-mobile', 'https://mikaki.tossa.app/?lang=ja');
  await capture('home-fallback', 'https://mikaki.tossa.app/?lang=ja&no-canvas=1');
  assert.deepEqual(errors, []);
} finally {
  await browser?.close();
  await harness.close();
}
