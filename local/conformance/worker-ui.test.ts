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
    for (const [path, contentType] of [
      ['/favicon.svg', 'image/svg+xml'],
      ['/favicon.ico', 'image/x-icon'],
      ['/favicon-32x32.png', 'image/png'],
    ]) {
      const asset = await worker.fetch(`https://mikaki.test${path}`);
      assert.equal(asset.status, 200);
      assert.equal(asset.headers.get('Content-Type'), contentType);
      assert.equal(asset.headers.get('X-Content-Type-Options'), 'nosniff');
      assert.ok((await asset.arrayBuffer()).byteLength > 0);
      const callbackHost = await worker.fetch(`https://mikaki-native.tossa.app${path}`);
      assert.equal(callbackHost.status, 404, 'branding must not expand callback-host routes');
    }
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
    for (const path of [
      '/login/login.js',
      '/login/login.css',
      '/ui/product.css',
      '/vault/vault.js',
    ]) {
      const response = await worker.fetch(`https://mikaki.test${path}`);
      assert.equal(response.status, 200);
      scripts.set(path, await response.text());
    }
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    evidence = await startBrowserEvidence(page.context(), 'worker-ui');
    const errors: string[] = [];

    let vaultSessionFailures = 0;
    page.on('pageerror', (error) => errors.push(error.message));
    await page.addInitScript(() => {
      if (location.search.includes('pending-passkey')) {
        Object.defineProperty(navigator.credentials, 'get', {
          value({ signal }: { signal?: AbortSignal }) {
            return new Promise<never>((_resolve, reject) => {
              signal?.addEventListener(
                'abort',
                () => reject(new DOMException('Aborted', 'AbortError')),
                { once: true },
              );
            });
          },
        });
      }
      if (!location.search.includes('no-canvas')) return;
      const original = HTMLCanvasElement.prototype.getContext;
      Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', {
        value(this: HTMLCanvasElement, kind: string, ...args: unknown[]) {
          return kind === '2d' ? null : Reflect.apply(original, this, [kind, ...args]);
        },
      });
    });
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
      if (url.pathname === '/vault/session') {
        if (vaultSessionFailures > 0) {
          vaultSessionFailures -= 1;
          await route.fulfill({ status: 503, body: '' });
          return;
        }
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
          body: `<!doctype html><html lang="${locale}"><head><title>mikaki Vault</title><link rel="stylesheet" href="/ui/product.css"></head><body><div id="app"></div><script type="module" src="/vault/vault.js"></script></body></html>`,
        });
        return;
      }
      await route.fulfill({ status: 404, body: '' });
    });

    await page.goto('https://mikaki.test/login');
    await page.getByRole('button', { name: 'Passkeyでサインイン' }).waitFor();
    assert.equal(await page.getByText('test-rp').count(), 1);
    assert.equal(await page.locator('.origin strong').first().textContent(), 'mikaki.test');
    assert.equal(await page.locator('.origin strong').nth(1).textContent(), 'client.example');
    assert.equal(await page.locator('#deny, .auth-brand, .auth-description').count(), 0);
    await page.locator('.gate-background[data-renderer="canvas"]').waitFor();
    const firstStyle = await page
      .locator('.auth-shell')
      .evaluate((node) => (node as HTMLElement).style.getPropertyValue('--rp-hue'));
    // Ambient motion must work with no pointer input.
    const firstFrame = await page
      .locator('canvas')
      .evaluate((canvas) => (canvas as HTMLCanvasElement).toDataURL());
    await page.waitForFunction(
      (oldFrame) =>
        (document.querySelector('canvas') as HTMLCanvasElement)?.toDataURL() !== oldFrame,
      firstFrame,
    );
    await page
      .locator('canvas')
      .evaluate((canvas) => canvas.dispatchEvent(new Event('contextlost')));
    await page.locator('.gate-background[data-renderer="css"]').waitFor();
    assert.equal(await page.locator('#passkey').isEnabled(), true);
    await page.goto('https://mikaki.test/login?other-rp=1');
    await page.getByRole('button', { name: 'Passkeyでサインイン' }).waitFor();
    assert.notEqual(
      await page
        .locator('.auth-shell')
        .evaluate((node) => (node as HTMLElement).style.getPropertyValue('--rp-hue')),
      firstStyle,
    );
    await page.goto('https://mikaki.test/login');
    await page.getByRole('button', { name: 'Passkeyでサインイン' }).waitFor();
    assert.equal(
      await page
        .locator('.auth-shell')
        .evaluate((node) => (node as HTMLElement).style.getPropertyValue('--rp-hue')),
      firstStyle,
    );
    await page.goto('https://mikaki.test/login?pending-passkey=1');
    await page.locator('.auth-shell[data-paused="true"]').waitFor();
    await page.locator('#passkey').click();
    assert.equal(await page.locator('#passkey').isDisabled(), true);
    assert.equal(await page.locator('.auth-shell').getAttribute('data-paused'), 'true');
    await page.goto('https://mikaki.test/login?no-canvas=1');
    await page.getByRole('button', { name: 'Passkeyでサインイン' }).waitFor();
    assert.equal(await page.locator('.gate-background').getAttribute('data-renderer'), 'css');
    await page.locator('summary').click();
    await page.getByRole('button', { name: '招待で登録する' }).click();
    await page.getByRole('alert').getByText('招待コードを入力してください。').waitFor();
    assert.equal(await page.getByLabel('招待コード').getAttribute('aria-invalid'), 'true');
    await page.getByRole('combobox', { name: '言語' }).selectOption('en');
    await page.getByRole('button', { name: 'Sign in with passkey' }).waitFor();
    assert.match(page.url(), /lang=en/);
    await page.setViewportSize({ width: 375, height: 812 });
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await page.goto('https://mikaki.test/login?enroll=1');
    await page.getByRole('heading', { name: 'アカウントを登録' }).first().waitFor();
    assert.equal(await page.locator('#passkey').count(), 0);
    assert.equal(await page.getByLabel('招待コード').isVisible(), true);
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto('https://mikaki.test/login');
    await page.getByRole('button', { name: 'Passkeyでサインイン' }).waitFor();
    await page.locator('.auth-shell[data-light-phase="still"]').waitFor();
    const still = await page
      .locator('canvas')
      .evaluate((canvas) => (canvas as HTMLCanvasElement).toDataURL());
    await page.waitForTimeout(250);
    assert.equal(
      await page.locator('canvas').evaluate((canvas) => (canvas as HTMLCanvasElement).toDataURL()),
      still,
    );
    await page.emulateMedia({ reducedMotion: 'no-preference' });

    await page.goto('https://mikaki.test/vault');
    await page.getByRole('button', { name: 'Passkeyで開く' }).waitFor();
    await page.getByText('表示名は未登録です。Passkeyで開いて登録できます。').waitFor();
    assert.equal(await page.locator('.product-header').count(), 1);
    assert.equal(await page.locator('.product-nav a').count(), 4);
    assert.equal(
      await page.evaluate(() => getComputedStyle(document.body).backgroundColor),
      'rgb(246, 248, 251)',
    );
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await page.getByRole('combobox', { name: '言語' }).selectOption('en');
    await page.getByRole('button', { name: 'Unlock with passkey' }).waitFor();
    await page.getByRole('link', { name: 'Sharing & connections' }).click();
    assert.match(page.url(), /#connections$/);
    await page.waitForFunction(
      () =>
        document.querySelector('a[href="#connections"]')?.getAttribute('aria-current') ===
        'location',
    );
    assert.equal(
      await page.getByRole('link', { name: 'Sharing & connections' }).getAttribute('aria-current'),
      'location',
    );
    vaultSessionFailures = 1;
    await page.goto('https://mikaki.test/vault?lang=en');
    await page.locator('#status').getByText('Loading failed.', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Reload profile' }).waitFor();
    assert.equal(
      await page.getByRole('button', { name: 'Unlock with passkey' }).isDisabled(),
      true,
    );
    await page.getByRole('button', { name: 'Reload profile' }).click();
    await page
      .getByText('No display name is saved. Unlock with your passkey to add one.')
      .waitFor();
    assert.equal(await page.getByRole('button', { name: 'Unlock with passkey' }).isEnabled(), true);
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
