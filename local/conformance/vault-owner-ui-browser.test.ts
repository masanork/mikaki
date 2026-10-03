import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { startBrowserEvidence } from './support/browser-evidence.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';

test('owner preview uses one unlock for names/notes, exact retries, explicit recreation and fail-closed lifecycle', async () => {
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
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Unified owner preview' });
    const credential = randomBytes(32),
      credentialId = credential.toString('base64url'),
      now = Math.floor(Date.now() / 1000);
    let cookie = randomBytes(32).toString('base64url');
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(credentialId),
      DB.prepare(
        "INSERT INTO passkey_credential VALUES(?,'synthetic-key','synthetic-user',0,0,0,1)",
      ).bind(credentialId),
      DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(
        credentialId,
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
        createHash('sha256').update(cookie).digest('base64url'),
        now,
      ),
    ]);
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    evidence = await startBrowserEvidence(context, 'owner-vault-preview');
    await context.addInitScript(
      ({ credential }) => {
        type Controls = Window & {
          prfCalls: number;
          hiddenForTest: boolean;
          holdPrf: boolean;
          releasePrf: () => void;
          wrongPrf: boolean;
          absentPrf: boolean;
          cancelPrf: boolean;
        };
        const controls = window as unknown as Controls;
        controls.prfCalls = 0;
        controls.hiddenForTest = false;
        Object.defineProperty(document, 'visibilityState', {
          configurable: true,
          get: () => (controls.hiddenForTest ? 'hidden' : 'visible'),
        });
        class MockCredential {
          rawId = Uint8Array.from(controls.wrongPrf ? [1, 2, 3] : credential).buffer;
          getClientExtensionResults() {
            return controls.absentPrf
              ? {}
              : { prf: { results: { first: new Uint8Array(32).fill(0x71).buffer } } };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: {
            get: async () => {
              controls.prfCalls++;
              if (controls.cancelPrf) throw new DOMException('Cancelled', 'NotAllowedError');
              if (controls.holdPrf)
                await new Promise<void>((resolve) => {
                  controls.releasePrf = resolve;
                });
              return new MockCredential();
            },
          },
        });
      },
      { credential: [...credential] },
    );
    const page = await context.newPage(),
      errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    const requests: {
      path: string;
      method: string;
      body: string;
      operation: string;
      precondition: string;
    }[] = [];
    let holdRead: Promise<void> | null = null;
    let enteredRead: (() => void) | null = null;
    let dropMutation = false,
      invalidNameRead = false,
      sessionFailure = false;
    await context.route(`${origin}/**`, async (route) => {
      const request = route.request(),
        path = new URL(request.url()).pathname;
      if (path === '/vault/session' && sessionFailure) {
        await route.fulfill({ status: 503 });
        return;
      }
      const headers = await request.allHeaders();
      if (path.startsWith('/vault/records/') && ['PUT', 'DELETE'].includes(request.method()))
        requests.push({
          path,
          method: request.method(),
          body: request.postData()!,
          operation: headers['x-operation-id']!,
          precondition: headers['if-match'] ?? headers['if-none-match']!,
        });
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: {
          ...headers,
          cookie: `__Host-op-sso=${cookie}${headers['cookie'] ? '; ' + headers['cookie'] : ''}`,
        },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      const body = Buffer.from(await response.arrayBuffer());
      if (holdRead && path === '/vault/records/personal/name' && request.method() === 'GET') {
        enteredRead?.();
        await holdRead;
      }
      if (dropMutation && path.startsWith('/vault/records/') && request.method() === 'PUT') {
        dropMutation = false;
        await route.abort();
        return;
      }
      if (
        invalidNameRead &&
        path === '/vault/records/personal/name' &&
        request.method() === 'GET' &&
        response.ok
      ) {
        const bad = JSON.parse(body.toString());
        bad.kind = 'unsupported';
        await route.fulfill({
          status: response.status,
          headers: Object.fromEntries(response.headers),
          body: JSON.stringify(bad),
        });
        return;
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body,
      });
    });
    const open = page.locator('#owner-unlock'),
      name = page.locator('#owner-name'),
      save = page.locator('#owner-profile-save');
    const calls = () => page.evaluate(() => (window as unknown as { prfCalls: number }).prfCalls);
    const visibility = async (hidden: boolean) =>
      page.evaluate((value) => {
        (window as unknown as { hiddenForTest: boolean }).hiddenForTest = value;
        document.dispatchEvent(new Event('visibilitychange'));
      }, hidden);
    await page.goto(`${origin}/vault?lang=en&storage=owner-v2`);
    await expect(open).toBeEnabled();
    await expect(page.getByRole('link', { name: 'mikaki', exact: true })).toHaveAttribute(
      'href',
      '/vault?lang=en&storage=owner-v2',
    );
    await expect(name).toHaveCount(0);
    assert.equal(await calls(), 0);
    await open.click();
    await expect(name).toBeEnabled();
    assert.equal(await calls(), 1);
    await name.fill('New owner');
    await save.click();
    await expect(page.locator('#owner-profile-status')).toHaveText(
      'Saved and verified. Vault stays open.',
    );
    await expect(name).toHaveValue('New owner');
    await expect(name).toBeEnabled();
    await page.locator('#owner-note-title').fill('A saved result');
    await page.locator('#owner-note-text').fill('Private note text');
    await page.locator('#owner-note-save').click();
    await expect(page.locator('#owner-note-status')).toHaveText(
      'Saved and verified. Vault stays open.',
    );
    await name.fill('Second owner');
    await save.click();
    await expect(page.locator('#owner-profile-status')).toHaveText(
      'Saved and verified. Vault stays open.',
    );
    assert.equal(await calls(), 1);
    await auditAccessibility(page, 'unified-owner-preview');
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
      true,
    );
    page.once('dialog', (dialog) => {
      void dialog.accept();
    });
    await page.locator('#owner-profile-delete').click();
    await expect(page.locator('#owner-profile-status')).toHaveText('Deleted. Vault stays open.');
    await expect(save).toBeFocused();
    await name.fill('After deletion');
    page.once('dialog', (dialog) => {
      void dialog.dismiss();
    });
    await save.click();
    await expect(save).toHaveText('Save new content after deletion');
    page.once('dialog', (dialog) => {
      void dialog.accept();
    });
    await save.click();
    await expect(page.locator('#owner-profile-status')).toHaveText(
      'Saved and verified. Vault stays open.',
    );
    await name.fill('Uncertain save');
    dropMutation = true;
    await save.click();
    await expect(save).toHaveText('Retry the same save');
    await expect(name).toBeDisabled();
    const lost = requests.at(-1)!;
    // A later deletion must remain authoritative when the exact lost save is retried.
    const source = JSON.parse(lost.body);
    const deletion = {
      format_version: 2,
      vault_id: source.vault_id,
      key_generation: source.key_generation,
      owner_key_revision: source.owner_key_revision,
      kind: source.kind,
      revision: source.revision + 1,
    };
    const deleted = await worker.fetch(`${origin}${lost.path}`, {
      method: 'DELETE',
      headers: {
        Cookie: `__Host-op-sso=${cookie}`,
        Origin: origin,
        'Content-Type': 'application/json',
        'X-Operation-ID': randomBytes(32).toString('base64url'),
        'If-Match': `"${source.revision}"`,
      },
      body: JSON.stringify(deletion),
    });
    assert.equal(deleted.status, 200, await deleted.text());
    await save.click();
    await expect(page.locator('#owner-profile-status')).toHaveText(
      'The operation was confirmed. A newer saved revision is now shown.',
    );
    assert.deepEqual(requests.at(-1), lost);
    await expect(name).toHaveValue('');
    await expect(save).toHaveText('Save new content after deletion');
    assert.equal(await calls(), 1);
    await name.fill('Fresh content');
    page.once('dialog', (dialog) => {
      void dialog.accept();
    });
    await save.click();
    await expect(page.locator('#owner-profile-status')).toHaveText(
      'Saved and verified. Vault stays open.',
    );
    await name.fill('Unsaved draft');
    await visibility(true);
    await expect(name).toBeHidden();
    await visibility(false);
    await expect(name).toBeVisible();
    await expect(name).toHaveValue('Unsaved draft');
    assert.equal(await calls(), 1);
    page.once('dialog', (dialog) => {
      void dialog.dismiss();
    });
    await page.getByRole('button', { name: 'Lock Vault', exact: true }).click();
    await expect(name).toHaveValue('Unsaved draft');
    page.once('dialog', (dialog) => {
      void dialog.accept();
    });
    await page.getByRole('button', { name: 'Lock Vault', exact: true }).click();
    await expect(name).toHaveCount(0);
    await expect(open).toBeEnabled();
    await open.click();
    await expect(name).toHaveValue('Fresh content');
    await expect(page.locator('#owner-note-text')).toHaveValue('Private note text');
    assert.equal(await calls(), 2);
    invalidNameRead = true;
    await page.locator('#owner-profile-reload').click();
    await expect(name).toBeDisabled();
    await expect(save).toBeDisabled();
    invalidNameRead = false;
    await page.locator('#owner-profile-reload').click();
    await expect(name).toBeEnabled();
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
    await name.fill('Draft from the old session');
    await visibility(true);
    cookie = replacement;
    await visibility(false);
    await expect(name).toHaveCount(0);
    await open.click();
    await expect(name).toHaveValue('Fresh content');
    let releaseRead!: () => void;
    const readStarted = new Promise<void>((resolve) => {
      enteredRead = resolve;
    });
    holdRead = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    await page.locator('#owner-profile-reload').click();
    await readStarted;
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
    holdRead = null;
    releaseRead();
    await expect(name).toHaveCount(0);
    await open.click();
    await expect(name).toHaveValue('Fresh content');
    sessionFailure = true;
    await visibility(true);
    await visibility(false);
    await expect(name).toHaveCount(0);
    sessionFailure = false;
    await page.evaluate(() => {
      (window as unknown as { holdPrf: boolean }).holdPrf = true;
    });
    await open.click();
    await page.waitForFunction(
      () => typeof (window as unknown as { releasePrf?: unknown }).releasePrf === 'function',
    );
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
    await page.evaluate(() => {
      const control = window as unknown as { holdPrf: boolean; releasePrf: () => void };
      control.holdPrf = false;
      control.releasePrf();
    });
    await expect(name).toHaveCount(0);
    await expect(open).toBeEnabled();
    await page.evaluate(() => {
      (window as unknown as { wrongPrf: boolean }).wrongPrf = true;
    });
    await open.click();
    await expect(open).toBeEnabled();
    await expect(name).toHaveCount(0);
    await page.evaluate(() => {
      const control = window as unknown as { wrongPrf: boolean; absentPrf: boolean };
      control.wrongPrf = false;
      control.absentPrf = true;
    });
    await open.click();
    await expect(open).toBeEnabled();
    await expect(name).toHaveCount(0);
    await page.evaluate(() => {
      const control = window as unknown as { absentPrf: boolean; cancelPrf: boolean };
      control.absentPrf = false;
      control.cancelPrf = true;
    });
    await open.click();
    await expect(page.getByRole('status')).toContainText('cancelled');
    await page.evaluate(() => {
      (window as unknown as { cancelPrf: boolean }).cancelPrf = false;
    });
    await open.click();
    await expect(name).toHaveValue('Fresh content');
    await name.fill('An expired draft');
    await page.clock.install();
    await page.clock.fastForward(15 * 60_000);
    await expect(name).toHaveCount(0);
    await expect(open).toBeEnabled();
    assert.deepEqual(
      await page.evaluate(async () => ({
        local: localStorage.length,
        session: sessionStorage.length,
        idb: (await indexedDB.databases()).length,
        caches: (await caches.keys()).length,
      })),
      { local: 0, session: 0, idb: 0, caches: 0 },
    );
    assert.equal(
      requests.some((request) => request.path.startsWith('/vault/attributes/')),
      false,
    );
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
