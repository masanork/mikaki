import { auditAccessibility } from './support/accessibility-audit.ts';
import { startBrowserEvidence } from './support/browser-evidence.ts';
import { startBrowserSourceCoverage } from './support/browser-source-coverage.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { sealAttribute } from '../../crates/worker/ui/vault-crypto.ts';

test('product screens preserve CSP, locale, keyboard/mobile access and profile failure/retry state', async () => {
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
  let evidence: Awaited<ReturnType<typeof startBrowserEvidence>> | undefined;
  let failure: unknown;
  let releaseSave = () => {};
  let releaseReads = () => {};
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Product UI regression' });
    const credential = new Uint8Array(randomBytes(32));
    const credentialId = Buffer.from(credential).toString('base64url');
    const cookie = randomBytes(32).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const prf = new Uint8Array(32).fill(0x71);
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
    const headers = {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: origin,
      'Content-Type': 'application/json',
    };
    const sealed = await sealAttribute(
      new TextEncoder().encode('Saved owner'),
      prf,
      credential,
      new Uint8Array(32).fill(0x29),
      origin,
      'name',
      1,
    );
    const written = await worker.fetch(`${origin}/vault/attributes/name`, {
      method: 'PUT',
      headers: {
        ...headers,
        'X-Operation-ID': randomBytes(32).toString('base64url'),
        'If-None-Match': '*',
      },
      body: JSON.stringify(sealed),
    });
    assert.equal(written.status, 200);
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const sourceCoverage = startBrowserSourceCoverage(page, origin);
    evidence = await startBrowserEvidence(page.context(), 'product-ui-browser');
    const errors: string[] = [];
    const violations: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.exposeFunction('recordCspViolation', (directive: string) =>
      violations.push(directive),
    );
    await page.addInitScript(
      ({ credential, prf }) => {
        type PreviewWindow = Window & {
          cancelPrf?: boolean;
          holdPrf?: boolean;
          releasePrf?: () => void;
          recordCspViolation: (directive: string) => void;
        };
        const preview = window as unknown as PreviewWindow;
        document.addEventListener('securitypolicyviolation', (event) =>
          preview.recordCspViolation(event.violatedDirective),
        );
        class MockCredential {
          rawId = Uint8Array.from(credential).buffer;
          getClientExtensionResults() {
            return { prf: { results: { first: Uint8Array.from(prf).buffer } } };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: {
            get: async () => {
              if (preview.holdPrf) {
                preview.holdPrf = false;
                await new Promise<void>((resolve) => {
                  preview.releasePrf = resolve;
                });
              }
              if (preview.cancelPrf) {
                preview.cancelPrf = false;
                throw new DOMException('Raw platform cancellation detail', 'NotAllowedError');
              }
              return new MockCredential();
            },
          },
        });
      },
      { credential: [...credential], prf: [...prf] },
    );
    let holdReads = false;
    const readPaths = new Set([
      '/vault/shares/userinfo/name',
      '/vault/releases/name',
      '/vault/attributes/name',
    ]);
    const observedReads = new Set<string>();
    const readBarrier = new Promise<void>((resolve) => {
      releaseReads = resolve;
    });
    let failLoad = false;
    const puts: { id: string; body: string }[] = [];
    let saveStarted = () => {};
    const started = new Promise<void>((resolve) => {
      saveStarted = resolve;
    });
    const held = new Promise<void>((resolve) => {
      releaseSave = resolve;
    });
    let loseSave = true;
    await page.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (path === '/vault/session' && failLoad) {
        failLoad = false;
        await route.fulfill({ status: 503 });
        return;
      }
      const requestHeaders = await request.allHeaders();
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: {
          ...requestHeaders,
          cookie: `__Host-op-sso=${cookie}${requestHeaders.cookie ? '; ' + requestHeaders.cookie : ''}`,
        },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      if (path === '/vault/attributes/name' && request.method() === 'PUT') {
        puts.push({ id: requestHeaders['x-operation-id'], body: request.postData()! });
        if (loseSave) {
          loseSave = false;
          saveStarted();
          await held;
          await route.abort();
          return;
        }
      }
      // Miniflare wraps Undici's response stream. Consume it before awaiting
      // browser cookie updates: GC may otherwise cancel the original response.
      const body = Buffer.from(await response.arrayBuffer());
      if (holdReads && request.method() === 'GET' && readPaths.has(path)) {
        observedReads.add(path);
        await readBarrier;
      }
      const confirmation = /__Host-op-logout=([^;, ]+)/.exec(
        response.headers.get('set-cookie') ?? '',
      );
      if (confirmation) {
        if (global.gc) {
          await new Promise<void>((resolve) => setImmediate(resolve));
          global.gc();
        }
        await page.context().addCookies([
          {
            name: '__Host-op-logout',
            value: confirmation[1],
            url: origin,
            secure: true,
            httpOnly: true,
            sameSite: 'Lax',
          },
        ]);
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body,
      });
    });
    for (const locale of ['ja', 'en']) {
      for (const [path, heading] of [
        ['/vault', 'Vault'],
        ['/admin', locale === 'ja' ? '招待を発行' : 'Issue an invitation'],
        ['/enroll/complete', locale === 'ja' ? '登録が完了しました' : 'Registration complete'],
        ['/logout', locale === 'ja' ? 'ログアウト' : 'Log out'],
      ]) {
        const response = await sourceCoverage.goto(`${origin}${path}?lang=${locale}`);
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
    for (const section of ['connections', 'security']) {
      await sourceCoverage.goto(`${origin}/vault?lang=en#${section}`);
      await expect(page.locator(`#${section}`)).toHaveAttribute('open', '');
      await expect(page.locator(`#${section} > summary`)).toBeVisible();
    }
    // None of the independent reads may wait for another read's response.
    holdReads = true;
    await sourceCoverage.goto(`${origin}/vault?lang=en`);
    try {
      await expect.poll(() => observedReads.size).toBe(3);
      await expect(page.locator('#unlock')).toBeDisabled();
    } finally {
      holdReads = false;
      releaseReads();
    }
    await expect(page.locator('#unlock')).toBeEnabled();
    // Scrolling the decorative header offscreen stops its work, and scrolling back resumes it.
    await page.locator('#notes').scrollIntoViewIfNeeded();
    await expect
      .poll(() =>
        page.locator('.product-header').evaluate((node) => node.getBoundingClientRect().bottom),
      )
      .toBeLessThanOrEqual(0);
    await page.waitForTimeout(150);
    const offscreenPhase = await page.locator('.product-header').getAttribute('data-light-phase');
    await page.waitForTimeout(250);
    assert.equal(
      await page.locator('.product-header').getAttribute('data-light-phase'),
      offscreenPhase,
    );
    await page.evaluate(() => scrollTo(0, 0));
    await expect
      .poll(() => page.locator('.product-header').getAttribute('data-light-phase'))
      .not.toBe(offscreenPhase);
    failLoad = true;
    await sourceCoverage.goto(`${origin}/vault?lang=en`);
    await expect(page.locator('#status')).toHaveText('Loading failed.');
    await expect(page.locator('#unlock')).toBeDisabled();
    const reload = page.getByRole('button', {
      name: 'Reload profile',
      exact: true,
    });
    await expect(reload).toBeEnabled();
    await reload.click();
    await expect(page.locator('#unlock')).toBeEnabled();
    await expect(page.locator('#connections')).not.toHaveAttribute('open', '');
    await expect(page.locator('#security')).not.toHaveAttribute('open', '');
    await expect(page.getByRole('button', { name: 'Open note', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Export saved note', exact: true })).toBeHidden();
    // Native links are reachable by keyboard and update the selected section.
    await page.getByRole('link', { name: 'Owner note', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('link', { name: 'Owner note', exact: true })).toHaveAttribute(
      'aria-current',
      'location',
    );
    // A child editor awaiting Passkey verification must also quiet the shared scene.
    await page.evaluate(() => {
      (window as unknown as { holdPrf: boolean }).holdPrf = true;
    });
    await page.getByRole('button', { name: 'Open note', exact: true }).click();
    const courtyardMotion = () =>
      page
        .locator('.vault-shell')
        .evaluate((node) => getComputedStyle(node, '::before').animationPlayState);
    await expect.poll(courtyardMotion).toBe('paused');
    const movedFocus = page.getByRole('link', { name: 'Sharing & connections', exact: true });
    await movedFocus.focus();
    await page.evaluate(() => {
      (window as unknown as { releasePrf: () => void }).releasePrf();
    });
    await expect(page.getByLabel('Note title', { exact: true })).toBeEnabled();
    await expect(movedFocus).toBeFocused();
    await expect.poll(courtyardMotion).toBe('running');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    assert.equal(
      await page
        .locator('.vault-shell')
        .evaluate((node) => getComputedStyle(node, '::before').animationName),
      'none',
    );
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    const disabledSave = page.locator('#save');
    await expect(disabledSave).toBeDisabled();
    const disabledColor = await disabledSave.evaluate(
      (node) => getComputedStyle(node).backgroundColor,
    );
    await disabledSave.hover();
    assert.equal(
      await disabledSave.evaluate((node) => getComputedStyle(node).backgroundColor),
      disabledColor,
    );
    await page.evaluate(() => {
      (window as unknown as Window & { cancelPrf: boolean }).cancelPrf = true;
    });
    await page.locator('#unlock').click();
    await expect(page.locator('#status')).toHaveText(
      'Passkey confirmation was cancelled or timed out. You can try again.',
    );
    await expect(page.locator('#unlock')).toBeEnabled();
    await expect(page.locator('#unlock')).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.locator('#name')).toHaveValue('Saved owner');
    await expect(page.locator('#name')).toBeFocused();
    page.once('dialog', (dialog) => {
      void dialog.dismiss();
    });
    await page.locator('#delete').click();
    await expect(page.locator('#name')).toHaveValue('Saved owner');
    await expect(page.locator('#status')).toHaveText(
      'You can edit your display name. Saving will use your passkey again.',
    );
    await page.locator('#name').fill('Unsaved owner');
    await expect(page.locator('[data-draft-state="profile"]')).toBeVisible();
    // Optional panels remain mounted: opening/closing them never discards edits.
    await page.getByLabel('Note title', { exact: true }).fill('Draft note title');
    const sharingLink = page.getByRole('link', { name: 'Sharing & connections', exact: true });
    await sharingLink.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#connections')).toHaveAttribute('open', '');
    await page.getByRole('link', { name: 'Skip to content', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#product-main')).toBeFocused();
    assert.equal(new URL(page.url()).hash, '#connections');
    await expect(page.locator('#name')).toHaveValue('Unsaved owner');
    await expect(page.getByLabel('Note title', { exact: true })).toHaveValue('Draft note title');
    await page.locator('#connections > summary').click();
    await expect(page.locator('#connections')).not.toHaveAttribute('open', '');
    // The same hash can be selected again after manually closing its panel.
    await sharingLink.click();
    await expect(page.locator('#connections')).toHaveAttribute('open', '');
    await page.getByRole('link', { name: 'Passkey management', exact: true }).click();
    await expect(page.locator('#security')).toHaveAttribute('open', '');
    await expect
      .poll(() =>
        page.evaluate(() => {
          const summary = document.querySelector('#security > summary')!;
          const navigation = document.querySelector('.product-nav')!;
          return summary.getBoundingClientRect().top >= navigation.getBoundingClientRect().bottom;
        }),
      )
      .toBe(true);
    await page.locator('#security > summary').click();
    await page.getByRole('link', { name: 'Profile', exact: true }).click();
    await expect(page.locator('#name')).toHaveValue('Unsaved owner');
    await expect(page.getByLabel('Note title', { exact: true })).toHaveValue('Draft note title');
    // Real beforeunload dialogs protect full-page links and language changes.
    let unloadDialogs = 0;
    page.once('dialog', (dialog) => {
      assert.equal(dialog.type(), 'beforeunload');
      unloadDialogs += 1;
      void dialog.dismiss();
    });
    await page.getByRole('link', { name: 'Log out', exact: false }).click();
    await expect(page.locator('#name')).toHaveValue('Unsaved owner');
    assert.equal(unloadDialogs, 1);
    page.once('dialog', (dialog) => {
      assert.equal(dialog.type(), 'beforeunload');
      unloadDialogs += 1;
      void dialog.dismiss();
    });
    await page.getByRole('combobox', { name: 'Language', exact: true }).selectOption('ja');
    await expect(page.locator('#name')).toHaveValue('Unsaved owner');
    await expect(page.getByRole('combobox', { name: 'Language', exact: true })).toHaveValue('en');
    assert.equal(unloadDialogs, 2);
    page.once('dialog', (dialog) => {
      void dialog.dismiss();
    });
    await reload.click();
    await expect(page.locator('#name')).toHaveValue('Unsaved owner');
    // Inject overlapping activations while the real server commits but its reply is held.
    await page.locator('#save').evaluate((button) => {
      button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });
    await started;
    await expect(page.locator('#save')).toBeDisabled();
    await expect(page.locator('#delete')).toBeDisabled();
    await expect(page.locator('#name')).toBeDisabled();
    await expect(reload).toBeDisabled();
    assert.equal(puts.length, 1);
    releaseSave();
    await expect(page.locator('#status')).toHaveText(
      'Save failed. You can retry with the same value.',
    );
    await expect(page.locator('#name')).toBeDisabled();
    await expect(page.locator('#save')).toBeEnabled();
    await expect(page.locator('#save')).toBeFocused();
    await expect(page.locator('#delete')).toBeDisabled();
    await page.locator('#save').click();
    await expect(page.locator('#status')).toHaveText(
      'Saved. Unlock with your passkey to verify it.',
    );
    await expect(page.locator('#unlock')).toBeFocused();
    assert.equal(puts.length, 2);
    assert.deepEqual(puts[0], puts[1]);
    const record = (await (
      await worker.fetch(`${origin}/vault/attributes/name`, { headers })
    ).json()) as { revision: number };
    assert.equal(record.revision, 2);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Unsaved owner');
    await page.locator('#name').fill('Discard this edit');
    page.once('dialog', (dialog) => {
      void dialog.accept();
    });
    await reload.click();
    await expect(page.locator('#name')).toHaveValue('');
    await expect(page.locator('#unlock')).toBeEnabled();
    // An acknowledged commit followed by a failed refresh is not an uncertain save.
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Unsaved owner');
    await page.locator('#name').fill('Acknowledged owner');
    failLoad = true;
    await page.locator('#save').click();
    await expect(page.locator('#status')).toHaveText(
      'Your change was applied, but the updated profile could not be loaded. Reload to verify it.',
    );
    await expect(page.locator('#save')).toBeDisabled();
    await expect(reload).toBeEnabled();
    await reload.click();
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Acknowledged owner');
    assert.equal(puts.length, 3);
    const acknowledged = (await (
      await worker.fetch(`${origin}/vault/attributes/name`, { headers })
    ).json()) as { revision: number };
    assert.equal(acknowledged.revision, 3);
    await expect(page.locator('[data-draft-state="profile"]')).toHaveCount(0);
    page.once('dialog', (dialog) => {
      void dialog.accept();
    });
    await page.locator('#delete').click();
    await expect(page.locator('#status')).toHaveText('Deleted.');
    assert.equal((await worker.fetch(`${origin}/vault/attributes/name`, { headers })).status, 404);
    assert.deepEqual(errors, []);
    assert.deepEqual(violations, []);
    await sourceCoverage.finish();
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    releaseSave();
    releaseReads();
    await evidence?.finish(failure);
    await browser?.close();
    await harness.close();
  }
});
