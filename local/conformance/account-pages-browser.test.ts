import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { chromium, type BrowserContext, type Page } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { startBrowserEvidence } from './support/browser-evidence.ts';
import { journeyServer } from './support/journey-server.ts';

async function waitForFonts(page: Page) {
  const failed = await page.evaluate(async () => {
    await document.fonts.ready;
    return [...document.fonts].filter((font) => font.status === 'error').map((font) => font.family);
  });
  assert.deepEqual(failed, [], 'account-page web fonts must decode before checking layout');
}

function barrier() {
  let release = () => {};
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, resolve: () => release() };
}

test('account pages use the product styles under CSP and fit a mobile viewport', async () => {
  let dispatch: Parameters<typeof journeyServer>[0] = async () => {
    throw new Error('Account page fixture not ready');
  };
  // Real HTTPS keeps cancelled font requests independent of Playwright route ownership.
  const server = await journeyServer((url, init) => dispatch(url, init));
  const issuer = `https://mikaki.test:${server.port}`;
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
  let context: BrowserContext | undefined;
  let staticContext: BrowserContext | undefined;
  let releaseLateFont = () => {};
  let evidence: Awaited<ReturnType<typeof startBrowserEvidence>> | undefined;
  let staticEvidence: Awaited<ReturnType<typeof startBrowserEvidence>> | undefined;
  let failure: unknown;
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
        "INSERT INTO credential(credential_id,account_id,active) VALUES('Y3JlZGVudGlhbA','account',1)",
      ),
      DB.prepare(
        "INSERT INTO passkey_credential(credential_id,public_key,user_handle,counter,backup_eligible,backup_state,revision) VALUES('Y3JlZGVudGlhbA','public-key','user-handle',0,0,0,1)",
      ),
      DB.prepare("INSERT INTO account_role(account_id,role,active) VALUES('account','admin',1)"),
      DB.prepare('INSERT INTO sso_session VALUES(?,?,?,?,?,0)').bind(
        'session',
        'account',
        'Y3JlZGVudGlhbA',
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

    browser = await chromium.launch({
      headless: true,
      args: ['--host-resolver-rules=MAP mikaki.test 127.0.0.1', '--no-proxy-server'],
    });
    context = await browser.newContext({ ignoreHTTPSErrors: true });
    evidence = await startBrowserEvidence(context, 'account-pages');
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
    await page.addInitScript(() => {
      if (location.search.includes('no-canvas')) {
        HTMLCanvasElement.prototype.getContext = () => null;
      }
    });
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    const lateFontStarted = barrier();
    const lateFontReleased = barrier();
    const lateFontFinished = barrier();
    releaseLateFont = lateFontReleased.resolve;
    dispatch = async (url, init) => {
      const response = await worker.fetch(url, { ...init, redirect: 'manual' });
      const delayed = new URL(url).searchParams.has('late-font');
      if (delayed) {
        lateFontStarted.resolve();
        await lateFontReleased.promise;
      }
      return {
        status: response.status,
        headers: response.headers,
        async arrayBuffer() {
          try {
            return await response.arrayBuffer();
          } finally {
            if (delayed) lateFontFinished.resolve();
          }
        },
      };
    };

    for (const width of [1440, 375]) {
      await page.setViewportSize({ width, height: 900 });
      for (const [path, heading] of [
        ['/admin?lang=ja', '招待を発行'],
        ['/enroll/complete?lang=en', 'Registration complete'],
        ['/logout?lang=ja', 'ログアウト'],
        ['/vault?lang=en', 'Wallet'],
      ]) {
        await page.goto(`${issuer}${path}`);
        await page.getByRole('heading', { name: heading, exact: true }).waitFor();
        await waitForFonts(page);
        assert.equal(await page.locator('.product-header').count(), 1);
        assert.equal(
          await page.locator('.product-origin strong').textContent(),
          new URL(issuer).host,
        );
        if (path.startsWith('/vault')) {
          assert.equal(await page.locator('.gate-background').count(), 0);
          assert.deepEqual(
            await page
              .getByRole('navigation', { name: 'Pages' })
              .getByRole('button')
              .allTextContents(),
            ['Wallet', 'Chat'],
          );
          assert.equal(
            await page
              .locator('.product-mvp')
              .evaluate((node) => getComputedStyle(node).backgroundColor),
            'rgb(248, 249, 251)',
          );
        } else {
          await page.locator('.gate-background[data-renderer="canvas"]').waitFor();
          assert.equal(await page.locator('.gate-fallback span').count(), 1);
          assert.match(
            await page
              .locator('.vault-shell, .product-material-shell')
              .evaluate((node) => (node as HTMLElement).style.getPropertyValue('--page-hue')),
            /^\d+$/,
          );
        }
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
    const fontManifest = JSON.parse(
      await readFile(new URL('../../assets/fonts/manifest.json', import.meta.url), 'utf8'),
    ) as { files: { file: string }[] };
    await page.evaluate((url) => {
      void fetch(url).catch(() => {});
    }, `${issuer}/fonts/${fontManifest.files[0]!.file}?late-font=1`);
    await lateFontStarted.promise;
    await page.goto(`${issuer}/admin?lang=ja`);
    releaseLateFont();
    await lateFontFinished.promise;
    await page.getByRole('combobox', { name: '言語' }).selectOption('en');
    await page.getByRole('heading', { name: 'Issue an invitation' }).waitFor();
    await waitForFonts(page);
    await page.goto(`${issuer}/admin?lang=en&no-canvas=1`);
    await page.getByRole('heading', { name: 'Issue an invitation' }).waitFor();
    await waitForFonts(page);
    assert.equal(await page.locator('.gate-background').getAttribute('data-renderer'), 'css');
    const fallback = page.locator('.gate-fallback');
    assert.equal(await fallback.isVisible(), true);
    assert.notEqual(
      await fallback.evaluate((node) => getComputedStyle(node).backgroundImage),
      'none',
    );
    assert.deepEqual(errors, []);
    staticContext = await browser.newContext({
      javaScriptEnabled: false,
      ignoreHTTPSErrors: true,
    });
    staticEvidence = await startBrowserEvidence(staticContext, 'account-pages-no-javascript');
    await staticContext.addCookies(await context.cookies());
    const staticPage = await staticContext.newPage();
    await staticPage.goto(`${issuer}/logout?lang=en`);
    await waitForFonts(staticPage);
    assert.equal(
      await staticPage.locator('.product-origin strong').textContent(),
      new URL(issuer).host,
    );
    assert.equal(await staticPage.locator('.gate-fallback').isVisible(), true);
    const confirmed = staticPage.waitForResponse(
      (response) => response.request().method() === 'POST' && response.url().includes('/logout'),
    );
    await staticPage.getByRole('button', { name: 'Log out', exact: true }).click();
    assert.equal((await confirmed).status(), 200);
    await staticPage.getByRole('heading', { name: 'You have logged out', exact: true }).waitFor();
    await waitForFonts(staticPage);
    assert.equal(await staticPage.locator('body').getAttribute('data-session-state'), 'ended');
    await staticEvidence.finish();
    await staticContext.close();
    staticContext = undefined;
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    releaseLateFont();
    try {
      await Promise.all([evidence?.finish(failure), staticEvidence?.finish(failure)]);
    } finally {
      try {
        await browser?.close();
      } finally {
        try {
          await server.close();
        } finally {
          await harness.close();
        }
      }
    }
  }
});
