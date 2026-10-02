import { startBrowserEvidence } from './support/browser-evidence.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { sealAttribute } from '../../crates/worker/ui/vault-crypto.ts';

type Notifications = 'available' | 'storage-only' | 'unavailable';
async function exerciseLifecycle(notifications: Notifications) {
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
  let finishCheck = () => {};
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
    let cookie = randomBytes(32).toString('base64url');
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
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    await context.addInitScript((notifications) => {
      const denied = { channel: 0, storage: 0 };
      Object.defineProperty(window, 'deniedVaultNotifications', { value: denied });
      if (notifications !== 'available') {
        Object.defineProperty(window, 'BroadcastChannel', {
          value: class {
            constructor() {
              denied.channel++;
              throw new DOMException('Channel access denied', 'SecurityError');
            }
          },
        });
      }
      if (notifications === 'unavailable') {
        Object.defineProperty(window, 'localStorage', {
          get() {
            denied.storage++;
            throw new DOMException('Storage access denied', 'SecurityError');
          },
        });
      }
    }, notifications);
    const page = await context.newPage();
    evidence = await startBrowserEvidence(page.context(), `vault-lifecycle-${notifications}`);
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.addInitScript(
      ({ credential, prf }) => {
        type Controls = Window & {
          holdPrf: boolean;
          releasePrf: () => void;
          hiddenForTest: boolean;
        };
        const controls = window as unknown as Controls;
        controls.hiddenForTest = false;
        Object.defineProperty(document, 'visibilityState', {
          configurable: true,
          get: () => (controls.hiddenForTest ? 'hidden' : 'visible'),
        });
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
              if (controls.holdPrf)
                await new Promise<void>((resolve) => {
                  controls.releasePrf = resolve;
                });
              return new MockCredential(); // Deliberately ignores AbortSignal, as a platform may do.
            },
          },
        });
      },
      { credential: [...credential], prf: [...prf] },
    );
    let sessionFailure = false;
    let holdCheck: Promise<void> | null = null;
    let writes = 0;
    let dropMutation = false;
    await page.context().route(`${origin}/**`, async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (path === '/vault/session') {
        if (holdCheck) await holdCheck;
        if (sessionFailure) {
          await route.fulfill({ status: 503 });
          return;
        }
      }
      if (request.method() === 'PUT') {
        writes++;
        if (dropMutation) {
          dropMutation = false;
          await route.abort();
          return;
        }
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
      const confirmation = /__Host-op-logout=([^;, ]+)/.exec(
        response.headers.get('set-cookie') ?? '',
      );
      if (confirmation)
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
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    const lock = page.getByRole('button', { name: 'Lock Vault', exact: true });
    const reopen = page.getByRole('button', { name: 'Check session and reopen', exact: true });
    const locked = page.getByRole('heading', { name: 'Vault is locked', exact: true });
    async function open() {
      await page.goto(`${origin}/vault?lang=en`);
      await expect(page.locator('#unlock')).toBeEnabled();
      await page.locator('#unlock').click();
      await expect(page.locator('#name')).toHaveValue('Saved owner');
    }
    async function visibility(hidden: boolean) {
      await page.evaluate((hidden) => {
        (window as unknown as Window & { hiddenForTest: boolean }).hiddenForTest = hidden;
        document.dispatchEvent(new Event('visibilitychange'));
      }, hidden);
    }
    await open();
    await page.locator('#connections > summary').click();
    const agent = page.getByRole('region', { name: 'Share with an AI agent' });
    await agent.getByRole('checkbox', { name: 'Share my saved name' }).check();
    await agent.getByRole('checkbox', { name: 'I approve disclosure' }).check();
    await agent.getByRole('button', { name: 'Prepare a local MCP export' }).click();
    await expect(
      agent.getByRole('heading', { name: 'Saved name, revision 1', exact: true }),
    ).toBeVisible();
    await page.locator('#name').fill('Discarded private draft');
    await page.getByRole('button', { name: 'Open note', exact: true }).click();
    await page.locator('textarea').fill('Discarded private note');
    // Cancelling a voluntary lock retains both editors and decrypted previews.
    page.once('dialog', (dialog) => {
      void dialog.dismiss();
    });
    await lock.click();
    await expect(page.locator('#name')).toHaveValue('Discarded private draft');
    await expect(page.locator('textarea')).toHaveValue('Discarded private note');
    await expect(locked).toHaveCount(0);
    page.once('dialog', (dialog) => {
      void dialog.accept();
    });
    await lock.click();
    await expect(locked).toBeVisible();
    await expect(locked).toBeFocused();
    await page.getByRole('link', { name: 'Skip to content', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#vault-status-main')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(reopen).toBeFocused();
    assert.equal(await page.locator('#name, textarea').count(), 0);
    await expect(
      page.getByRole('heading', { name: 'Saved name, revision 1', exact: true }),
    ).toHaveCount(0);
    await reopen.click();
    await expect(page.locator('#name')).toHaveValue('');
    await expect(page.locator('textarea')).toHaveValue('');
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Saved owner');
    await page.getByRole('button', { name: 'Reload profile', exact: true }).click();
    // A late authenticator reply cannot revive an unmounted view or send a write.
    await page.evaluate(() => {
      (window as unknown as Window & { holdPrf: boolean }).holdPrf = true;
    });
    await page.locator('#unlock').click();
    await expect
      .poll(() =>
        page.evaluate(
          () => typeof (window as unknown as Window & { releasePrf: unknown }).releasePrf,
        ),
      )
      .toBe('function');
    await lock.click();
    await page.evaluate(() => {
      (window as unknown as Window & { releasePrf: () => void }).releasePrf();
    });
    await expect(locked).toBeVisible();
    assert.equal(await page.locator('#name').count(), 0);
    assert.equal(writes, 0);
    await open();
    await page.locator('#name').fill('Abandoned uncertain operation');
    dropMutation = true;
    await page.locator('#save').click();
    await expect(page.locator('#status')).toHaveText(
      'Save failed. You can retry with the same value.',
    );
    page.once('dialog', (dialog) => {
      void dialog.accept();
    });
    await lock.click();
    await reopen.click();
    await expect(page.locator('#save')).toBeDisabled();
    await expect(page.locator('#name')).toHaveValue('');
    assert.equal(writes, 1);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Saved owner');
    await page.locator('#name').fill('Preserved same-session draft');
    await visibility(true);
    await expect(page.locator('#name')).toBeHidden();
    await page.getByRole('link', { name: 'Skip to content', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#vault-status-main')).toBeFocused();
    holdCheck = new Promise<void>((resolve) => {
      finishCheck = resolve;
    });
    await visibility(false);
    await expect(
      page.getByRole('heading', { name: 'Checking your session', exact: true }),
    ).toBeVisible();
    await expect(page.locator('#name')).toBeHidden();
    await visibility(true); // A tab can hide again while its resume check is in flight.
    const checkedWhileHidden = page.waitForResponse(`${origin}/vault/session`);
    finishCheck();
    holdCheck = null;
    await checkedWhileHidden;
    await expect(page.locator('#name')).toBeHidden();
    await visibility(false);
    await expect(page.locator('#name')).toHaveValue('Preserved same-session draft');
    await expect(page.locator('#name')).toBeVisible();
    // Even a new login for the same account and credential has a different session tag.
    const replacement = randomBytes(32).toString('base64url');
    await DB.batch([
      DB.prepare("INSERT INTO sso_session VALUES('replacement','owner',?,1,?,0)").bind(
        credentialId,
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('replacement',?,?)").bind(
        createHash('sha256').update(replacement).digest('base64url'),
        now,
      ),
    ]);
    await visibility(true);
    cookie = replacement;
    await visibility(false);
    await expect(locked).toBeVisible();
    assert.equal(await page.locator('#name').count(), 0);
    await reopen.click();
    await expect(page.locator('#unlock')).toBeEnabled();
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Saved owner');
    await visibility(true);
    sessionFailure = true;
    await visibility(false);
    await expect(locked).toBeVisible();
    assert.equal(await page.locator('#name').count(), 0);
    sessionFailure = false;
    await open();
    await page.clock.install();
    await page.clock.fastForward(15 * 60_000);
    await expect(locked).toBeVisible();
    await reopen.click();
    await expect(page.locator('#unlock')).toBeEnabled();
    await page.locator('#unlock').click();
    for (let minute = 10; minute < 60; minute += 10) {
      await page.clock.fastForward(10 * 60_000);
      await page.locator('#name').fill(`Activity at ${minute}`);
    }
    await page.clock.fastForward(10 * 60_000);
    await expect(locked).toBeVisible();
    await reopen.click();
    await expect(page.locator('#unlock')).toBeEnabled();
    await page.locator('#unlock').click();
    // pagehide disposes the view rather than retaining it in the back/forward cache.
    await page.evaluate(() =>
      window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })),
    );
    await expect(locked).toBeVisible();
    await reopen.click();
    await expect(page.locator('#unlock')).toBeEnabled();
    await page.locator('#unlock').click();
    const other = await page.context().newPage();
    other.on('pageerror', (error) => errors.push(error.message));
    await other.goto(`${origin}/logout?lang=en`);
    await other.getByRole('button', { name: 'Log out', exact: true }).click();
    await expect(
      other.getByRole('heading', { name: 'You have logged out', exact: true }),
    ).toBeVisible();
    if (notifications === 'unavailable') {
      // With both notification APIs denied, the visible tab receives no logout hint.
      // Server authorization must still reject its next protected operation.
      await expect(page.locator('#name')).toHaveValue('Saved owner');
      await expect(locked).toHaveCount(0);
      await page.getByRole('button', { name: 'Reload profile', exact: true }).click();
    }
    await expect(locked).toBeVisible();
    assert.equal(await page.locator('#name, textarea').count(), 0);
    const denied = await other.evaluate(
      () =>
        (
          window as unknown as Window & {
            deniedVaultNotifications: { channel: number; storage: number };
          }
        ).deniedVaultNotifications,
    );
    if (notifications !== 'available') assert.ok(denied.channel > 0);
    if (notifications === 'unavailable') assert.ok(denied.storage > 0);
    await reopen.click();
    await expect(locked).toBeVisible();
    await expect(page.locator('#unlock')).toHaveCount(0);
    assert.deepEqual(errors, []);
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    finishCheck();
    await evidence?.finish(failure);
    await browser?.close();
    await harness.close();
  }
}

for (const notifications of ['available', 'storage-only', 'unavailable'] as const) {
  test(`Vault lifecycle with ${notifications} cross-tab notifications`, () =>
    exerciseLifecycle(notifications));
}
