import { startBrowserEvidence } from './support/browser-evidence.ts';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { sealAttribute, openAttribute } from '../../crates/worker/ui/vault-crypto.ts';
import {
  newOwnerNote,
  encodeOwnerNote,
  decodeOwnerNote,
} from '../../crates/worker/ui/vault-note.ts';

test('owner note HTTP and browser paths preserve schema, conflicts, exact retries and legacy name', async () => {
  const origin = 'https://mikaki.test';
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        secrets: { MIKAKI_ISSUER: origin },
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
    const env = await worker.getEnv();
    const credential = new Uint8Array(randomBytes(32));
    const prf = new Uint8Array(32).fill(0x71);
    const cookie = randomBytes(32).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      env.DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(
        Buffer.from(credential).toString('base64url'),
      ),
      env.DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(
        Buffer.from(credential).toString('base64url'),
        now + 3600,
      ),
      env.DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
        createHash('sha256').update(cookie).digest('base64url'),
        now,
      ),
    ]);
    const headers = {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: origin,
      'Content-Type': 'application/json',
    };
    const write = async (attribute: string, bytes: Uint8Array<ArrayBuffer>, revision: number) => {
      const sealed = await sealAttribute(
        bytes,
        prf,
        credential,
        new Uint8Array(32).fill(0x29),
        origin,
        attribute,
        revision,
      );
      const response = await worker.fetch(`${origin}/vault/attributes/${attribute}`, {
        method: 'PUT',
        headers: {
          ...headers,
          'X-Operation-ID': randomBytes(32).toString('base64url'),
          ...(revision === 1 ? { 'If-None-Match': '*' } : { 'If-Match': `"${revision - 1}"` }),
        },
        body: JSON.stringify(sealed),
      });
      assert.equal(response.status, 200, await response.clone().text());
    };
    const current = async () =>
      (await (
        await worker.fetch(`${origin}/vault/attributes/owner_note`, { headers })
      ).json()) as Awaited<ReturnType<typeof sealAttribute>> & { revision: number };
    const read = async () => {
      const record = await current();
      return decodeOwnerNote(
        await openAttribute(record, prf, credential, origin, 'owner_note', record.revision),
      );
    };
    await write('name', new TextEncoder().encode('Legacy owner name'), 1);
    await write('owner_note', encodeOwnerNote(newOwnerNote('Node title', 'Node text')), 1);
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    evidence = await startBrowserEvidence(page.context(), 'vault-note-browser');
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.addInitScript(
      ({ credential, prf }) => {
        class MockCredential {
          rawId = Uint8Array.from(credential).buffer;
          getClientExtensionResults() {
            return { prf: { results: { first: Uint8Array.from(prf).buffer } } };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: { get: async () => new MockCredential() },
        });
      },
      { credential: [...credential], prf: [...prf] },
    );
    let loseResponse = false;
    let loseDeleteResponse = false;
    let failNextNoteRead = false;
    const puts: { body: string; id: string }[] = [];
    const deletes: { id: string; revision: string }[] = [];
    await page.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: { ...request.headers(), Cookie: `__Host-op-sso=${cookie}` },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      if (failNextNoteRead && request.method() === 'GET' && request.url().endsWith('/owner_note')) {
        failNextNoteRead = false;
        await route.fulfill({ status: 503 });
        return;
      }
      if (request.method() === 'PUT' && request.url().endsWith('/owner_note')) {
        puts.push({ body: request.postData()!, id: request.headers()['x-operation-id']! });
        if (loseResponse) {
          loseResponse = false;
          await route.abort();
          return;
        }
      }
      if (request.method() === 'DELETE' && request.url().endsWith('/owner_note')) {
        deletes.push({
          id: request.headers()['x-operation-id']!,
          revision: request.headers()['if-match']!,
        });
        if (loseDeleteResponse) {
          loseDeleteResponse = false;
          await route.abort();
          return;
        }
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    await page.goto(`${origin}/vault?lang=en`);
    await page.getByRole('button', { name: 'Unlock with passkey', exact: true }).click();
    await expect(page.locator('#name')).toHaveValue('Legacy owner name');
    const panel = page.getByRole('region', { name: 'Owner note', exact: true });
    const title = panel.getByLabel('Note title', { exact: true });
    const text = panel.getByLabel('Note text', { exact: true });
    const unlock = panel.getByRole('button', { name: 'Open note', exact: true });
    const save = panel.getByRole('button', { name: 'Save note', exact: true });
    const reload = panel.getByRole('button', {
      name: 'Discard edits and retry state, then reload note',
    });
    await unlock.click();
    await expect(title).toHaveValue('Node title');
    await expect(panel.locator('[data-draft-state]')).toHaveCount(0);
    await text.fill('Keep this draft');
    let navigationCancelled = false;
    page.once('dialog', (dialog) => {
      assert.equal(dialog.type(), 'beforeunload');
      navigationCancelled = true;
      void dialog.dismiss();
    });
    await page.getByRole('link', { name: 'Log out', exact: false }).click();
    assert.equal(navigationCancelled, true);
    await expect(text).toHaveValue('Keep this draft');
    page.once('dialog', (dialog) => {
      void dialog.dismiss();
    });
    await reload.click();
    await expect(text).toHaveValue('Keep this draft');
    await text.fill('Node text');
    await expect(panel.locator('[data-draft-state]')).toHaveCount(0);
    await title.fill('Browser title');
    await text.fill('Browser text 🗾');
    loseResponse = true;
    await save.click();
    await expect(panel.getByRole('status')).toContainText('Could not save.');
    await expect(title).toBeDisabled();
    await save.click();
    await expect(panel.getByRole('status')).toHaveText('Note encrypted and saved.');
    assert.deepEqual(puts[0], puts[1]);
    assert.equal((await current()).revision, 2);
    assert.deepEqual(await read(), newOwnerNote('Browser title', 'Browser text 🗾'));
    const storedName = (await (
      await worker.fetch(`${origin}/vault/attributes/name`, { headers })
    ).json()) as Awaited<ReturnType<typeof sealAttribute>> & { revision: number };
    assert.equal(storedName.revision, 1);
    assert.equal(
      new TextDecoder().decode(await openAttribute(storedName, prf, credential, origin, 'name', 1)),
      'Legacy owner name',
    );
    await unlock.click();
    await text.fill('Unsaved text');
    await panel.getByText('Import or export a note', { exact: true }).click();
    const exportButton = panel.getByRole('button', { name: 'Export saved note', exact: true });
    await expect(exportButton).toBeDisabled();
    await panel.getByRole('checkbox').check();
    const downloadEvent = page.waitForEvent('download');
    await exportButton.click();
    const download = await downloadEvent;
    assert.deepEqual(
      decodeOwnerNote(new Uint8Array(await readFile((await download.path())!))),
      newOwnerNote('Browser title', 'Browser text 🗾'),
    );
    const fileInput = panel.getByLabel('Import note JSON', { exact: true });
    await fileInput.setInputFiles({
      name: 'future.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify({ ...newOwnerNote('Bad', 'Bad'), version: 2 })),
    });
    await expect(panel.getByRole('status')).toContainText('Unsupported note file.');
    await expect(text).toHaveValue('Unsaved text');
    await fileInput.setInputFiles({
      name: 'valid.json',
      mimeType: 'application/json',
      buffer: Buffer.from(encodeOwnerNote(newOwnerNote('Imported', 'Imported text'))),
    });
    await expect(panel.getByRole('status')).toContainText('Note imported into the editor.');
    await expect(title).toHaveValue('Imported');
    assert.equal((await current()).revision, 2);
    // Concurrent Node owner edit must win; the browser cannot silently overwrite it.
    await write('owner_note', encodeOwnerNote(newOwnerNote('Concurrent', 'Newest')), 3);
    await save.click();
    await expect(panel.getByRole('status')).toContainText('Another update conflicted');
    assert.equal((await current()).revision, 3);
    page.once('dialog', (dialog) => {
      void dialog.accept();
    });
    await reload.click();
    await unlock.click();
    await expect(title).toHaveValue('Concurrent');
    page.once('dialog', (dialog) => {
      void dialog.dismiss();
    });
    await panel.getByRole('button', { name: 'Delete note', exact: true }).click();
    assert.equal((await current()).revision, 3);
    await expect(title).toHaveValue('Concurrent');
    page.once('dialog', (dialog) => {
      void dialog.accept();
    });
    loseDeleteResponse = true;
    await panel.getByRole('button', { name: 'Delete note', exact: true }).click();
    await expect(panel.getByRole('status')).toContainText('Deletion could not be confirmed.');
    await expect(title).toBeDisabled();
    await expect(save).toBeDisabled();
    let retryDialogs = 0;
    const rejectUnexpectedDialog = (dialog: import('@playwright/test').Dialog) => {
      retryDialogs += 1;
      void dialog.dismiss();
    };
    page.on('dialog', rejectUnexpectedDialog);
    await panel.getByRole('button', { name: 'Delete note', exact: true }).click();
    await expect(panel.getByRole('status')).toHaveText('Note deleted.');
    page.off('dialog', rejectUnexpectedDialog);
    assert.equal(retryDialogs, 0);
    assert.equal(deletes.length, 2);
    assert.deepEqual(deletes[0], deletes[1]);
    await unlock.click();
    await title.fill('Recreated');
    await text.fill('After tombstone');
    failNextNoteRead = true;
    await save.click();
    await expect(panel.getByRole('status')).toHaveText(
      'Your change was applied, but the updated note could not be loaded. Reload to verify it.',
    );
    await expect(save).toBeDisabled();
    await reload.click();
    assert.equal((await current()).revision, 5);
    // Unsupported encrypted data remains opaque and cannot be overwritten via this UI.
    await write(
      'owner_note',
      new TextEncoder().encode(JSON.stringify({ ...newOwnerNote('Future', 'Future'), version: 2 })),
      6,
    );
    const future = await current();
    await reload.click();
    await unlock.click();
    await expect(panel.getByRole('status')).toContainText('Unsupported formats or versions');
    await expect(save).toBeDisabled();
    await expect(text).toBeDisabled();
    assert.deepEqual(await current(), future);
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
