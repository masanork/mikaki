import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import { createTestHarness } from 'wrangler';

test('Worker login and Vault mount their Svelte screens in both locales', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      { configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname },
    ],
  });
  let browser;
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    const scripts = new Map();
    for (const path of ['/login/login.js', '/vault/vault.js']) {
      const response = await worker.fetch(`https://mikaki.test${path}`);
      assert.equal(response.status, 200);
      scripts.set(path, await response.text());
    }
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('https://mikaki.test/**', async (route) => {
      const url = new URL(route.request().url());
      if (scripts.has(url.pathname)) {
        await route.fulfill({
          status: 200,
          contentType: 'text/javascript; charset=utf-8',
          body: scripts.get(url.pathname),
        });
        return;
      }
      if (url.pathname === '/vault/session') {
        await route.fulfill({ json: { credential_id: 'Y3JlZGVudGlhbA' } });
        return;
      }
      if (url.pathname === '/vault/attributes/name') {
        await route.fulfill({ status: 404, headers: { ETag: '"1"' }, body: '' });
        return;
      }
      const locale = url.searchParams.get('lang') === 'en' ? 'en' : 'ja';
      if (url.pathname === '/login') {
        await route.fulfill({
          contentType: 'text/html; charset=utf-8',
          body: `<!doctype html><html lang="${locale}"><head><title>mikaki</title></head><body><div id="app" data-tx="${'a'.repeat(43)}" data-challenge="${'b'.repeat(43)}" data-rp-id="mikaki.test" data-client="test-rp"></div><script type="module" src="/login/login.js"></script></body></html>`,
        });
        return;
      }
      if (url.pathname === '/vault') {
        await route.fulfill({
          contentType: 'text/html; charset=utf-8',
          body: `<!doctype html><html lang="${locale}"><head><title>mikaki Vault</title></head><body><div id="app"></div><script type="module" src="/vault/vault.js"></script></body></html>`,
        });
        return;
      }
      await route.fulfill({ status: 404, body: '' });
    });

    await page.goto('https://mikaki.test/login');
    await page.getByRole('button', { name: 'Passkeyで許可してログイン' }).waitFor();
    assert.equal(await page.getByText('test-rp').count(), 1);
    await page.getByRole('combobox', { name: '言語' }).selectOption('en');
    await page.getByRole('button', { name: 'Allow and sign in with passkey' }).waitFor();
    assert.match(page.url(), /lang=en/);

    await page.goto('https://mikaki.test/vault');
    await page.getByRole('button', { name: 'Passkeyで開く' }).waitFor();
    await page.getByText('表示名は未登録です。Passkeyで開いて登録できます。').waitFor();
    await page.getByRole('combobox', { name: '言語' }).selectOption('en');
    await page.getByRole('button', { name: 'Unlock with passkey' }).waitFor();
    assert.deepEqual(errors, []);
  } finally {
    await browser?.close();
    await harness.close();
  }
});
