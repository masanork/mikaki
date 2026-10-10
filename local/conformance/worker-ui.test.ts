import { auditAccessibility } from './support/accessibility-audit.ts';
import { startBrowserEvidence } from './support/browser-evidence.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium, expect } from '@playwright/test';
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
    await worker.applyD1Migrations('DB');
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
      const callbackHost = await worker.fetch(`https://app.mikaki.org${path}`);
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

    page.on('pageerror', (error) => errors.push(error.message));
    await page.addInitScript(() => {
      if (location.search.includes('silent-motion-change')) {
        const original = window.matchMedia.bind(window);
        window.matchMedia = (query) => {
          const media = original(query);
          if (query === '(prefers-reduced-motion: reduce)') {
            // Exercise a preference observed by RAF before a change notification.
            media.addEventListener = () => {};
          }
          return media;
        };
      }
      if (location.search.includes('early-pointer')) {
        // Deliver a pointer event before the renderer's first size notification.
        // A zero-size callback also occurs when the login scene is removed quickly.
        const Observer = ResizeObserver;
        window.ResizeObserver = class extends Observer {
          constructor(callback: ResizeObserverCallback) {
            let first = true;
            super((entries, observer) => {
              const scene = entries[0]?.target as HTMLElement | undefined;
              if (first && scene?.classList.contains('auth-shell')) {
                first = false;
                const rect = scene.getBoundingClientRect();
                scene.dispatchEvent(
                  new PointerEvent('pointermove', {
                    pointerType: 'mouse',
                    clientX: rect.left,
                    clientY: rect.top,
                  }),
                );
                if (location.search.includes('zero-height')) {
                  const original = scene.getBoundingClientRect.bind(scene);
                  scene.getBoundingClientRect = () => new DOMRect(rect.x, rect.y, rect.width, 0);
                  try {
                    callback(entries, observer);
                  } finally {
                    scene.getBoundingClientRect = original;
                  }
                }
              }
              callback(entries, observer);
            });
          }
        };
      }
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
    await page.route('https://*.test/**', async (route) => {
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
      const locale = url.searchParams.get('lang') === 'en' ? 'en' : 'ja';
      if (url.pathname === '/') {
        const response = await worker.fetch(url.href);
        await route.fulfill({
          status: response.status,
          headers: Object.fromEntries(response.headers),
          body: await response.text(),
        });
        return;
      }
      if (url.pathname === '/login') {
        await route.fulfill({
          contentType: 'text/html; charset=utf-8',
          body: `<!doctype html><html lang="${locale}"><head><title>mikaki</title><link rel="stylesheet" href="/login/login.css"></head><body><div id="app" data-tx="${'a'.repeat(43)}" data-challenge="${'b'.repeat(43)}" data-rp-id="mikaki.test" data-rp-uri="https://${url.searchParams.has('other-rp') ? 'other.example' : 'client.example'}/callback" data-client="test-rp" data-enrollment="${url.searchParams.has('enroll')}"></div><script type="module" src="/login/login.js"></script></body></html>`,
        });
        return;
      }
      if (url.pathname === '/register/start') {
        // The synthetic login page has no bound invitation transaction.
        await route.fulfill({ status: 204 });
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

    await page.goto('https://mikaki.test/login?enroll=1&early-pointer=1');
    await page.locator('.gate-background[data-renderer="canvas"]').waitFor();
    await page.waitForTimeout(200);
    assert.deepEqual(errors, [], 'pre-layout input and zero-height resizes must not break light');
    assert.equal(
      await page
        .locator('.auth-shell')
        .evaluate((node) =>
          Number.isFinite(parseFloat((node as HTMLElement).style.getPropertyValue('--light-x'))),
        ),
      true,
    );

    await page.goto('https://mikaki.test/login?enroll=1&early-pointer=1&zero-height=1');
    await page.locator('.gate-background[data-renderer="canvas"]').waitFor();
    await page.waitForTimeout(200);
    assert.deepEqual(errors, [], 'zero-height resize must not draw an empty material canvas');

    await page.goto('https://mikaki.test/login');
    await page.locator('#passkey').waitFor();
    await auditAccessibility(page, 'login-ja');
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
    await expect(page.getByLabel('招待コード')).toBeFocused();
    await auditAccessibility(page, 'login-invitation-error-ja');
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
    await page.getByLabel('招待コード').waitFor();
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
    await page.locator('#vault-lock-title').waitFor();
    assert.equal(await page.locator('.product-header').count(), 1);
    assert.equal(await page.locator('#vault-lock-title').count(), 1);
    assert.equal(
      await page.evaluate(() => getComputedStyle(document.body).backgroundColor),
      'rgb(246, 248, 251)',
    );
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await page.getByRole('combobox', { name: '言語' }).selectOption('en');
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await page.locator('#vault-lock-title').waitFor();
    await page.goto('https://mikaki.test/?lang=ja');
    await page.getByRole('heading', { name: 'Passkeyでサインイン' }).waitFor();
    await page.locator('.gate-background[data-renderer="canvas"]').waitFor();
    assert.equal(await page.locator('.gate-fallback span').count(), 1);
    assert.equal(await page.locator('.bolt, #passkey').count(), 0);
    assert.equal(
      await page.getByRole('link', { name: 'サインイン', exact: true }).getAttribute('href'),
      '/signin?lang=ja',
    );
    assert.equal(await page.locator('.plate .origin strong').textContent(), 'mikaki.test');
    assert.equal(
      await page.getByRole('link', { name: '招待から登録' }).getAttribute('href'),
      '/enroll?lang=ja',
    );
    const hue = await page
      .locator('.auth-shell')
      .evaluate((scene) => scene.style.getPropertyValue('--page-hue'));
    const phase = await page.locator('.auth-shell').getAttribute('data-light-phase');
    await page.waitForFunction(
      (old) => document.querySelector('.auth-shell')?.getAttribute('data-light-phase') !== old,
      phase,
    );
    await page.goto('https://other.test/?lang=en');
    await page.getByRole('heading', { name: 'Sign in with your passkey' }).waitFor();
    await page.locator('.gate-background[data-renderer="canvas"]').waitFor();
    assert.equal(await page.locator('.plate .origin strong').textContent(), 'other.test');
    assert.notEqual(
      await page
        .locator('.auth-shell')
        .evaluate((scene) => scene.style.getPropertyValue('--page-hue')),
      hue,
    );
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.waitForFunction(
      () => document.querySelector('.auth-shell')?.getAttribute('data-light-phase') === 'still',
    );
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.goto('https://mikaki.test/?silent-motion-change=1');
    await page.locator('.gate-background[data-renderer="canvas"]').waitFor();
    await page.waitForFunction(() => {
      const phase = document.querySelector('.auth-shell')?.getAttribute('data-light-phase');
      return phase !== null && phase !== undefined && phase !== 'still';
    });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.locator('.auth-shell[data-light-phase="still"]').waitFor();
    const reducedFrame = await page
      .locator('canvas')
      .evaluate((canvas) => (canvas as HTMLCanvasElement).toDataURL());
    await page.waitForTimeout(250);
    assert.equal(
      await page.locator('canvas').evaluate((canvas) => (canvas as HTMLCanvasElement).toDataURL()),
      reducedFrame,
    );
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await page.goto('https://mikaki.test/?no-canvas=1');
    await page.getByRole('heading', { name: 'Passkeyでサインイン' }).waitFor();
    assert.equal(await page.locator('.gate-background').getAttribute('data-renderer'), 'css');
    assert.equal(await page.locator('.gate-fallback span').count(), 1);
    assert.deepEqual(errors, []);
    const staticPage = await browser.newPage({
      javaScriptEnabled: false,
      viewport: { width: 390, height: 844 },
    });
    await staticPage.route('https://mikaki.test/**', async (route) => {
      const response = await worker.fetch(route.request().url());
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: await response.text(),
      });
    });
    await staticPage.goto('https://mikaki.test/');
    await staticPage.getByRole('heading', { name: 'Passkeyでサインイン' }).waitFor();
    assert.equal(await staticPage.locator('.gate-fallback span').count(), 1);
    assert.equal(await staticPage.locator('#passkey, canvas').count(), 0);
    assert.equal(
      await staticPage.getByRole('link', { name: 'サインイン', exact: true }).getAttribute('href'),
      '/signin?lang=ja',
    );
    await staticPage.getByRole('link', { name: 'English' }).click();
    await staticPage.getByRole('heading', { name: 'Sign in with your passkey' }).waitFor();
    assert.equal(
      await staticPage
        .getByRole('link', { name: 'Register with an invitation' })
        .getAttribute('href'),
      '/enroll?lang=en',
    );
    assert.equal(
      await staticPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await staticPage.close();
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    await evidence?.finish(failure);
    await browser?.close();
    await harness.close();
  }
});
