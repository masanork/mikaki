import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, expect, type Browser } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { auditAccessibility } from './support/accessibility-audit.ts';
import { LOGIN_HISTORY_KEY } from '../../crates/worker/ui/login-history.ts';

const issuer = 'https://mikaki.test';

test(
  'connection recognition holds proofs until approval and records only accepted sign-ins',
  { timeout: 180_000 },
  async (t) => {
    const harness = createTestHarness({
      root: new URL('../..', import.meta.url).pathname,
      workers: [
        { configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname },
      ],
    });
    let browser: Browser | undefined;
    try {
      await harness.listen();
      const worker = harness.getWorker('mikaki-op-worker');
      const js = await (await worker.fetch(`${issuer}/login/login.js`)).text();
      const css = await (await worker.fetch(`${issuer}/login/login.css`)).text();
      browser = await chromium.launch({ headless: true });
      await mkdir('artifacts/login-recognition', { recursive: true });

      async function fixture(
        options: {
          blocked?: boolean;
          manualRegistration?: boolean;
          manualPasskey?: boolean;
          mobile?: boolean;
          locale?: string;
        } = {},
      ) {
        const context = await browser!.newContext({
          viewport: options.mobile ? { width: 320, height: 740 } : { width: 1000, height: 1000 },
        });
        if (options.blocked)
          await context.addInitScript(() => {
            Object.defineProperty(window, 'localStorage', {
              get() {
                throw new DOMException('blocked', 'SecurityError');
              },
            });
          });
        if (options.manualRegistration)
          await context.addInitScript(() => {
            Object.defineProperty(navigator.credentials, 'get', {
              value: () => Promise.reject(new DOMException('cancelled', 'NotAllowedError')),
            });
          });
        if (options.manualPasskey)
          await context.addInitScript(() => {
            const get = navigator.credentials.get.bind(navigator.credentials);
            let calls = 0;
            Object.defineProperty(navigator.credentials, 'get', {
              value: (options: CredentialRequestOptions) => {
                if (++calls === 1)
                  return Promise.reject(
                    new DOMException('A fresh gesture is required', 'NotAllowedError'),
                  );
                return get(options);
              },
            });
          });
        const page = await context.newPage();
        const errors: string[] = [];
        page.on('pageerror', (error) => errors.push(error.message));
        const requests: { path: string; body: Record<string, unknown> }[] = [];
        const config = {
          destination: 'https://rp.example/callback',
          scope: 'openid',
          status: 200,
          location: `${issuer}/done`,
          expires: 300_000,
        };
        await page.route(`${issuer}/**`, async (route) => {
          const request = route.request();
          const url = new URL(request.url());
          if (url.pathname === '/login/login.js' || url.pathname === '/login/login.css') {
            await route.fulfill({
              contentType: url.pathname.endsWith('.js') ? 'text/javascript' : 'text/css',
              body: url.pathname.endsWith('.js') ? js : css,
            });
          } else if (url.pathname === '/login') {
            await route.fulfill({
              headers: {
                'content-type': 'text/html',
                'content-security-policy':
                  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
              },
              body: `<!doctype html><html lang="${options.locale ?? 'ja'}"><head><link rel="stylesheet" href="/login/login.css"></head><body><div id="app" data-tx="${'a'.repeat(43)}" data-challenge="${'b'.repeat(43)}" data-rp-id="mikaki.test" data-rp-uri="${config.destination}" data-client="test-app" data-login-scope="${config.scope}" data-expires-in-ms="${config.expires}"></div><script type="module" src="/login/login.js"></script></body></html>`,
            });
          } else if (url.pathname === '/register/start') {
            await route.fulfill({
              json: {
                challenge: 'c'.repeat(43),
                user_handle: 'd'.repeat(43),
                rp_id: 'mikaki.test',
              },
            });
          } else if (request.method() === 'POST') {
            requests.push({
              path: url.pathname,
              body: request.postDataJSON() as Record<string, unknown>,
            });
            await route.fulfill({ status: config.status, json: { location: config.location } });
          } else {
            await route.fulfill({
              contentType: 'text/html',
              body: '<!doctype html><html><body><main><h1>Done</h1></main></body></html>',
            });
          }
        });
        const cdp = await context.newCDPSession(page);
        await cdp.send('WebAuthn.enable', { enableUI: false });
        async function addAuthenticator() {
          const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
            options: {
              protocol: 'ctap2',
              ctap2Version: 'ctap2_1',
              transport: 'internal',
              hasResidentKey: true,
              hasUserVerification: true,
              automaticPresenceSimulation: true,
              isUserVerified: true,
            },
          });
          await page.goto(`${issuer}/setup`);
          const id = await page.evaluate(async () => {
            const credential = await navigator.credentials.create({
              publicKey: {
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                rp: { id: 'mikaki.test', name: 'mikaki' },
                user: {
                  id: crypto.getRandomValues(new Uint8Array(32)),
                  name: 'test',
                  displayName: 'test',
                },
                pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
                authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
              },
            });
            return credential!.id;
          });
          return { authenticatorId, id };
        }
        const authenticator = await addAuthenticator();
        const stored = () => page.evaluate((key) => localStorage.getItem(key), LOGIN_HISTORY_KEY);
        return {
          page,
          context,
          config,
          requests,
          errors,
          cdp,
          authenticator,
          addAuthenticator,
          stored,
        };
      }

      await t.test(
        'first visit and reload remain unconfirmed; approval sends exactly once, and a known connection stays quick',
        async () => {
          const f = await fixture({ manualPasskey: true });
          try {
            await f.page.goto(`${issuer}/login`);
            await f.page.locator('#passkey').click();
            await expect(f.page.locator('#connection-approve')).toBeVisible();
            assert.equal(f.requests.length, 0);
            assert.equal(await f.stored(), null);
            await f.page.reload();
            await f.page.locator('#passkey').click();
            await expect(f.page.locator('#connection-approve')).toBeVisible();
            assert.equal(f.requests.length, 0);
            assert.equal(await f.stored(), null);
            assert.equal(
              await f.page
                .locator('#connection-review-title')
                .evaluate((e) => e === document.activeElement),
              true,
            );
            await f.page.screenshot({
              path: 'artifacts/login-recognition/first-desktop.png',
              fullPage: true,
            });
            await f.page.locator('#connection-approve').evaluate((element) => {
              element.addEventListener('click', () => (element as HTMLButtonElement).click(), {
                once: true,
              });
            });
            await f.page.locator('#connection-approve').click();
            await expect(f.page.getByRole('heading', { name: 'Done' })).toBeVisible();
            assert.equal(f.requests.length, 1);
            assert.equal(f.requests[0]?.path, '/login/finish');
            assert.equal(f.requests[0]?.body['consent'], true);
            assert.ok(!(await f.stored())!.includes(f.authenticator.id));
            await f.page.goto(`${issuer}/login`);
            await f.page.locator('#passkey').click();
            await expect(f.page.getByRole('heading', { name: 'Done' })).toBeVisible();
            assert.equal(f.requests.length, 2);

            f.config.destination = 'https://new.example:8443/callback';
            await f.page.goto(`${issuer}/login`);
            await f.page.locator('#passkey').click();
            await expect(f.page.locator('#connection-approve')).toBeVisible();
            await expect(f.page.locator('.connection-review')).toContainText('https://rp.example');
            await expect(f.page.locator('.connection-review')).toContainText(
              'https://new.example:8443',
            );
            await expect(f.page.locator('.connection-memory')).toHaveAttribute(
              'data-recognition',
              'changed',
            );
            assert.equal(f.requests.length, 2);
            await f.page.screenshot({
              path: 'artifacts/login-recognition/changed-desktop.png',
              fullPage: true,
            });
            // The accessibility audit opens/detaches its own DevTools session;
            // perform it after the virtual-authenticator ceremonies.
            await auditAccessibility(f.page, 'login-connection-review');
            await f.page.locator('#connection-cancel').click();
            await f.page.waitForURL(`${issuer}/?lang=ja`);
            assert.equal(f.requests.at(-1)?.path, '/login/deny');
            assert.deepEqual(Object.keys(f.requests.at(-1)!.body), ['tx']);
            assert.ok(!(await f.stored())!.includes('new.example'));
            assert.deepEqual(f.errors, []);
          } finally {
            await f.context.close();
          }
        },
      );

      await t.test(
        'a narrow screen keeps initial and changed connection details readable',
        async () => {
          const f = await fixture({ mobile: true });
          try {
            await f.page.goto(`${issuer}/login`);
            await expect(f.page.locator('#connection-approve')).toBeVisible();
            assert.equal(
              await f.page.evaluate(() => document.documentElement.scrollWidth > innerWidth),
              false,
            );
            await f.page.screenshot({
              path: 'artifacts/login-recognition/first-mobile.png',
              fullPage: true,
            });
            await f.page.locator('#connection-approve').click();
            await f.page.waitForURL(`${issuer}/done`);
            f.config.destination = 'https://another-application.example:8443/callback';
            await f.page.goto(`${issuer}/login`);
            await expect(f.page.locator('#connection-approve')).toBeVisible();
            assert.equal(
              await f.page.evaluate(() => document.documentElement.scrollWidth > innerWidth),
              false,
            );
            await f.page.screenshot({
              path: 'artifacts/login-recognition/changed-mobile.png',
              fullPage: true,
            });
            assert.deepEqual(f.errors, []);
          } finally {
            await f.context.close();
          }
        },
      );

      await t.test(
        'scope changes need approval; rejection preserves the old history and another Passkey cannot inherit it',
        async () => {
          const f = await fixture();
          try {
            await f.page.goto(`${issuer}/login`);
            await f.page.locator('#connection-approve').click();
            await f.page.waitForURL(`${issuer}/done`);
            const original = await f.stored();
            f.config.scope = 'openid profile';
            f.config.status = 401;
            await f.page.goto(`${issuer}/login`);
            await expect(f.page.locator('.connection-change')).toBeVisible();
            await f.page.locator('#connection-approve').click();
            await expect(f.page.getByRole('alert')).toBeVisible();
            assert.equal(await f.stored(), original);
            f.config.status = 200;
            await f.page.goto(`${issuer}/login`);
            await f.page.locator('#connection-approve').click();
            await f.page.waitForURL(`${issuer}/done`);
            f.config.scope = 'profile openid';
            await f.page.goto(`${issuer}/login`);
            await f.page.waitForURL(`${issuer}/done`);
            await f.cdp.send('WebAuthn.removeVirtualAuthenticator', {
              authenticatorId: f.authenticator.authenticatorId,
            });
            await f.addAuthenticator();
            await f.page.goto(`${issuer}/login`);
            await expect(f.page.locator('#connection-approve')).toBeVisible();
            await expect(f.page.locator('.connection-memory')).toHaveAttribute(
              'data-recognition',
              'first',
            );
            assert.deepEqual(f.errors, []);
          } finally {
            await f.context.close();
          }
        },
      );

      await t.test(
        'blocked storage permits an explicitly reviewed sign-in in English',
        async () => {
          const f = await fixture({ blocked: true, locale: 'en' });
          try {
            await f.page.goto(`${issuer}/login`);
            await expect(
              f.page.getByRole('heading', { name: 'Review this connection' }),
            ).toBeVisible();
            await expect(f.page.locator('.connection-memory')).toHaveAttribute(
              'data-recognition',
              'unavailable',
            );
            assert.equal(f.requests.length, 0);
            await f.page.getByRole('button', { name: 'Continue this connection' }).click();
            await f.page.waitForURL(`${issuer}/done`);
            assert.equal(f.requests.length, 1);
            assert.deepEqual(f.errors, []);
          } finally {
            await f.context.close();
          }
        },
      );

      await t.test(
        'expired proofs and invalid finish continuations never create history',
        async () => {
          const f = await fixture();
          try {
            await f.page.clock.install();
            await f.page.goto(`${issuer}/login`);
            await expect(f.page.locator('#connection-approve')).toBeVisible();
            await f.page.clock.fastForward(120_001);
            await expect(f.page.locator('#connection-approve')).toHaveCount(0);
            await expect(f.page.getByRole('alert')).toContainText('有効時間');
            assert.equal(f.requests.length, 0);
            assert.equal(await f.stored(), null);
            f.config.location = 'https://attacker.example/';
            await f.page.goto(`${issuer}/login`);
            await f.page.locator('#connection-approve').click();
            await expect(f.page.getByRole('alert')).toBeVisible();
            assert.equal(await f.stored(), null);
            assert.equal(new URL(f.page.url()).origin, issuer);
            assert.deepEqual(f.errors, []);
          } finally {
            await f.context.close();
          }
        },
      );

      await t.test(
        'page lifecycle suspension discards the pending proof before resume',
        async () => {
          const f = await fixture();
          try {
            await f.page.goto(`${issuer}/login`);
            await expect(f.page.locator('#connection-approve')).toBeVisible();
            await f.page.evaluate(() =>
              window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })),
            );
            await expect(f.page.locator('#connection-approve')).toHaveCount(0);
            await f.page.evaluate(() =>
              window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })),
            );
            await expect(f.page.getByRole('alert')).toContainText('有効時間');
            assert.equal(f.requests.length, 0);
            assert.equal(await f.stored(), null);
            await f.page.locator('#passkey').click();
            await expect(f.page.locator('#connection-approve')).toBeVisible();
            assert.equal(f.requests.length, 0);
            assert.deepEqual(f.errors, []);
          } finally {
            await f.context.close();
          }
        },
      );

      await t.test(
        'registration through an RP also waits for connection approval before sending its attestation',
        async () => {
          const f = await fixture({ manualRegistration: true });
          try {
            await f.page.goto(`${issuer}/login`);
            await f.page.locator('summary').click();
            await f.page.getByLabel('招待コード').fill('test-invitation');
            await f.page.locator('#register').click();
            await expect(f.page.locator('#connection-approve')).toBeVisible();
            assert.equal(f.requests.length, 0);
            assert.equal(await f.stored(), null);
            await f.page.locator('#connection-approve').click();
            await f.page.waitForURL(`${issuer}/done`);
            assert.equal(f.requests[0]?.path, '/register/finish');
            assert.ok(await f.stored());
            assert.deepEqual(f.errors, []);
          } finally {
            await f.context.close();
          }
        },
      );
    } finally {
      await browser?.close();
      await harness.close();
    }
  },
);
