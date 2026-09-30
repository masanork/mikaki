import { startBrowserEvidence } from './support/browser-evidence.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { execFileSync } from 'node:child_process';

test('Worker login and Vault mount their Svelte screens in both locales', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      { configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname },
    ],
  });
  let browser;
  let evidence: Awaited<ReturnType<typeof startBrowserEvidence>> | undefined;
  let failure: unknown;
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    const versionResponse = await worker.fetch('https://mikaki.test/version');
    assert.equal(versionResponse.status, 200);
    assert.equal(versionResponse.headers.get('Cache-Control'), 'no-store');
    const version = (await versionResponse.json()) as Record<string, unknown>;
    assert.equal(version.worker, 'mikaki-op');
    assert.match(String(version.version_id), /^[0-9a-f-]{36}$/i);
    assert.equal(
      version.source_commit,
      execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    );
    assert.equal(typeof version.source_clean, 'boolean');
    const scripts = new Map();
    for (const path of ['/login/login.js', '/login/login.css', '/vault/vault.js']) {
      const response = await worker.fetch(`https://mikaki.test${path}`);
      assert.equal(response.status, 200);
      scripts.set(path, await response.text());
    }
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    evidence = await startBrowserEvidence(page.context(), 'worker-ui');
    const errors: string[] = [];
    let cueRequests = 0;
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('https://mikaki.test/**', async (route) => {
      const url = new URL(route.request().url());
      if (scripts.has(url.pathname)) {
        await route.fulfill({
          status: 200,
          contentType: url.pathname.endsWith('.css')
            ? 'text/css; charset=utf-8'
            : 'text/javascript; charset=utf-8',
          body: scripts.get(url.pathname),
        });
        return;
      }
      if (url.pathname === '/login/cue') {
        cueRequests += 1;
        await route.fulfill({
          json: { seed: (cueRequests === 1 ? 'c' : 'd').repeat(43), refresh_in_ms: 1_000 },
        });
        return;
      }
      if (url.pathname === '/vault/session') {
        await route.fulfill({
          json: {
            credential_id: 'Y3JlZGVudGlhbA',
            account_id: 'owner',
            session_tag: 's'.repeat(43),
          },
        });
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
          body: `<!doctype html><html lang="${locale}"><head><title>mikaki</title><link rel="stylesheet" href="/login/login.css"></head><body><div id="app" data-tx="${'a'.repeat(43)}" data-challenge="${'b'.repeat(43)}" data-rp-id="mikaki.test" data-rp-uri="https://${url.searchParams.has('other-rp') ? 'other.example' : 'client.example'}/callback" data-client="test-rp" data-enrollment="${url.searchParams.has('enroll')}"></div><script type="module" src="/login/login.js"></script></body></html>`,
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
    assert.equal(await page.locator('.auth-origin-host').first().textContent(), 'mikaki.test');
    assert.equal(await page.locator('.auth-origin-host').nth(1).textContent(), 'client.example');
    assert.equal(await page.locator('.auth-session-tile').count(), 16);
    await page.locator('.auth-session-cue[data-cue-live="true"]').waitFor();
    const firstPattern = await page.locator('.auth-session-pattern').innerHTML();
    await page.waitForFunction(
      (oldPattern) => document.querySelector('.auth-session-pattern')?.innerHTML !== oldPattern,
      firstPattern,
    );
    assert.ok(cueRequests >= 2);
    const firstStyle = await page.locator('.auth-session-cue').getAttribute('style');
    await page.goto('https://mikaki.test/login?other-rp=1');
    await page.getByRole('button', { name: 'Passkeyで許可してログイン' }).waitFor();
    assert.notEqual(await page.locator('.auth-session-cue').getAttribute('style'), firstStyle);
    await page.goto('https://mikaki.test/login');
    await page.getByRole('button', { name: 'Passkeyで許可してログイン' }).waitFor();
    assert.equal(
      await page
        .locator('.auth-primary')
        .evaluate((node) => getComputedStyle(node).backgroundColor),
      'rgb(23, 89, 173)',
    );
    await page.getByRole('button', { name: '招待で登録する' }).click();
    await page.getByRole('alert').getByText('招待コードを入力してください。').waitFor();
    assert.equal(await page.getByLabel('招待コード').getAttribute('aria-invalid'), 'true');
    await page.getByRole('combobox', { name: '言語' }).selectOption('en');
    await page.getByRole('button', { name: 'Allow and sign in with passkey' }).waitFor();
    assert.match(page.url(), /lang=en/);
    await page.setViewportSize({ width: 375, height: 812 });
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await page.goto('https://mikaki.test/login?enroll=1');
    await page.getByRole('heading', { name: 'アカウントを登録' }).first().waitFor();
    assert.equal(await page.locator('#passkey').count(), 0);
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );

    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('https://mikaki.test/login');
    await page.getByRole('button', { name: 'Passkeyで許可してログイン' }).waitFor();
    assert.equal(await page.locator('.auth-session-cue').getAttribute('data-cue-live'), 'false');
    assert.equal(
      await page
        .locator('.auth-session-tile')
        .first()
        .evaluate((node) => getComputedStyle(node).animationName),
      'none',
    );
    await page.emulateMedia({ reducedMotion: 'no-preference' });

    await page.goto('https://mikaki.test/vault');
    await page.getByRole('button', { name: 'Passkeyで開く' }).waitFor();
    await page.getByText('表示名は未登録です。Passkeyで開いて登録できます。').waitFor();
    await page.getByRole('combobox', { name: '言語' }).selectOption('en');
    await page.getByRole('button', { name: 'Unlock with passkey' }).waitFor();
    assert.deepEqual(errors, []);
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    await evidence?.finish(failure);
    await browser?.close();
    await harness.close();
  }
});
