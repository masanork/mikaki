import { startBrowserEvidence } from './support/browser-evidence.ts';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { chromium, expect } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import {
  sealAttribute,
  openAttribute,
  parseOwnerEnvelope,
  transferAttribute,
} from '../../crates/worker/ui/vault-crypto.ts';
import {
  newOwnerNote,
  encodeOwnerNote,
  decodeOwnerNote,
} from '../../crates/worker/ui/vault-note.ts';

const origin = 'https://mikaki.test';
const id = () => randomBytes(32).toString('base64url');

test('typed transfer rejects unsupported saved note data before producing a candidate', async () => {
  const source = new Uint8Array(randomBytes(32));
  const target = new Uint8Array(randomBytes(32));
  const prf = new Uint8Array(32).fill(0x35);
  const saved = await sealAttribute(
    new TextEncoder().encode(JSON.stringify({ ...newOwnerNote('Title', 'Body'), version: 99 })),
    prf,
    source,
    new Uint8Array(32),
    origin,
    'owner_note',
    1,
  );
  await assert.rejects(
    transferAttribute(
      saved,
      prf,
      prf,
      target,
      new Uint8Array(32),
      origin,
      'owner_note',
      1,
      (bytes) => {
        decodeOwnerNote(bytes);
      },
    ),
    /Unsupported note type or version/,
  );
});

test('note transfer preserves saved schema independently of name, retries exactly and reopens with the target key', async () => {
  const login = new Uint8Array(randomBytes(32));
  const source = new Uint8Array(randomBytes(32));
  const target = new Uint8Array(randomBytes(32));
  const targetId = Buffer.from(target).toString('base64url');
  const sourcePrf = new Uint8Array(32).fill(0x35);
  const targetPrf = new Uint8Array(32).fill(0x74);
  const cookie = id();
  const note = newOwnerNote('保存済みの題名 🗾', 'Saved note\nSecond line');
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
    const now = Math.floor(Date.now() / 1000);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('note-transfer-owner',1,1)"),
      ...[login, source, target].flatMap((credential) => {
        const value = Buffer.from(credential).toString('base64url');
        return [
          env.DB.prepare("INSERT INTO credential VALUES(?,'note-transfer-owner',1)").bind(value),
          env.DB.prepare("INSERT INTO passkey_credential VALUES(?,'fixture-key',?,0,0,0,1)").bind(
            value,
            id(),
          ),
        ];
      }),
      env.DB.prepare(
        "INSERT INTO sso_session VALUES('note-transfer-session','note-transfer-owner',?,1,?,0)",
      ).bind(Buffer.from(login).toString('base64url'), now + 3600),
      env.DB.prepare("INSERT INTO sso_context VALUES('note-transfer-session',?,?)").bind(
        createHash('sha256').update(cookie).digest('base64url'),
        now,
      ),
    ]);
    const headers = {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: origin,
      'Content-Type': 'application/json',
    };
    const write = async (
      attribute: string,
      bytes: Uint8Array<ArrayBuffer>,
      revision: number,
      credential = source,
    ) => {
      const sealed = await sealAttribute(
        bytes,
        credential === target ? targetPrf : sourcePrf,
        credential,
        new Uint8Array(32).fill(0x26),
        origin,
        attribute,
        revision,
      );
      const response = await worker.fetch(`${origin}/vault/attributes/${attribute}`, {
        method: 'PUT',
        headers: {
          ...headers,
          'X-Operation-ID': id(),
          ...(revision === 1 ? { 'If-None-Match': '*' } : { 'If-Match': `"${revision - 1}"` }),
        },
        body: JSON.stringify(sealed),
      });
      assert.equal(response.status, 200, await response.text());
    };
    const read = async (attribute: string) => {
      const response = await worker.fetch(`${origin}/vault/attributes/${attribute}`, { headers });
      assert.equal(response.status, 200);
      return (await response.json()) as {
        ciphertext: string;
        owner_envelope: string;
        revision: number;
        format_version: 1;
      };
    };
    await write('owner_note', encodeOwnerNote(note), 1);
    await write('name', new TextEncoder().encode('Separate name'), 1, login);
    const nameBefore = await read('name');
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    evidence = await startBrowserEvidence(page.context(), 'vault-note-transfer');
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.addInitScript(
      ({ sourcePrf, targetPrf, targetId }) => {
        class MockCredential {
          rawId: ArrayBuffer;
          constructor(bytes: BufferSource) {
            this.rawId = new Uint8Array(bytes as ArrayBuffer).buffer;
          }
          getClientExtensionResults() {
            if (sessionStorage.getItem('cancel-prf'))
              throw new DOMException('Cancelled', 'NotAllowedError');
            const id = btoa(String.fromCharCode(...new Uint8Array(this.rawId)))
              .replaceAll('+', '-')
              .replaceAll('/', '_')
              .replaceAll('=', '');
            if (id === targetId && sessionStorage.getItem('missing-target-prf')) return {};
            return {
              prf: {
                results: { first: Uint8Array.from(id === targetId ? targetPrf : sourcePrf).buffer },
              },
            };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: {
            get: async (options: CredentialRequestOptions) =>
              new MockCredential(options.publicKey!.allowCredentials![0]!.id),
          },
        });
      },
      { sourcePrf: [...sourcePrf], targetPrf: [...targetPrf], targetId },
    );
    let loseResponse = true;
    const requests: { body: string; operation: string; base: string }[] = [];
    await page.route(`${origin}/**`, async (route) => {
      const request = route.request();
      if (request.url().endsWith('/owner_note/transfer'))
        requests.push({
          body: request.postData()!,
          operation: request.headers()['x-operation-id']!,
          base: request.headers()['if-match']!,
        });
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: { ...request.headers(), Cookie: `__Host-op-sso=${cookie}` },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      if (
        request.url().endsWith('/owner_note/transfer') &&
        loseResponse &&
        response.status === 200
      ) {
        loseResponse = false;
        await route.abort();
        return;
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    await page.goto(`${origin}/vault?lang=en&storage=legacy-v1`);
    const editor = page.getByRole('region', { name: 'Owner note', exact: true });
    await page.getByText('Move the note to another Passkey', { exact: true }).click();
    await page.locator('#connections > summary').click();
    const transfer = page.getByRole('region', {
      name: 'Move my saved note to another Passkey',
      exact: true,
    });
    const move = transfer.getByRole('button', {
      name: 'Move the saved note to this Passkey',
      exact: true,
    });
    await expect(editor.getByRole('button', { name: 'Open note', exact: true })).toBeEnabled();
    await editor.getByRole('button', { name: 'Open note', exact: true }).click();
    await editor.getByLabel('Note text', { exact: true }).fill('Unsaved edit must not move');
    page.on('dialog', (dialog) => {
      assert.equal(dialog.type(), 'confirm');
      assert.equal(
        dialog.message(),
        'Moving saved content will discard unsaved edits in this editor. Continue?',
      );
      void dialog.accept();
    });
    const agent = page.getByRole('region', { name: 'Share with an AI agent' });
    await agent
      .getByRole('checkbox', { name: 'Share my saved owner note through local MCP', exact: true })
      .check();
    await agent.getByRole('checkbox', { name: 'I approve disclosure' }).check();
    await agent.getByRole('button', { name: 'Prepare a local MCP export', exact: true }).click();
    const localDownload = agent.getByRole('button', {
      name: 'Download selected plaintext',
      exact: true,
    });
    await expect(localDownload).toBeVisible();
    await transfer.getByRole('combobox').selectOption(targetId);
    await expect(move).toBeDisabled();
    await transfer.getByRole('checkbox').check();
    await page.evaluate(() => sessionStorage.setItem('missing-target-prf', '1'));
    await move.click();
    await expect(transfer.getByRole('status')).toContainText('does not support PRF');
    assert.equal(requests.length, 0);
    assert.equal((await read('owner_note')).revision, 1);
    await page.evaluate(() => {
      sessionStorage.removeItem('missing-target-prf');
      sessionStorage.setItem('cancel-prf', '1');
    });
    await move.click();
    await expect(transfer.getByRole('status')).toContainText('Cancelled');
    assert.equal(requests.length, 0);
    await page.evaluate(() => sessionStorage.removeItem('cancel-prf'));
    await move.click();
    await expect(
      transfer.getByRole('button', { name: 'Forget the pending request', exact: true }),
    ).toBeVisible();
    await move.click();
    await expect(transfer.getByRole('status')).toContainText('Saved note moved.');
    await expect(localDownload).toHaveCount(0);
    assert.equal(requests.length, 2);
    assert.deepEqual(requests[0], requests[1]);
    const moved = await read('owner_note');
    assert.equal(moved.revision, 2);
    assert.equal(
      Buffer.from(parseOwnerEnvelope(moved.owner_envelope).credentialId).toString('base64url'),
      targetId,
    );
    assert.deepEqual(
      decodeOwnerNote(await openAttribute(moved, targetPrf, target, origin, 'owner_note', 2)),
      note,
    );
    await assert.rejects(openAttribute(moved, sourcePrf, source, origin, 'owner_note', 2));
    assert.deepEqual(await read('name'), nameBefore);
    // A fresh page uses the saved envelope's credential, independently of login and name.
    await page.reload();
    await expect(editor.getByRole('button', { name: 'Open note', exact: true })).toBeEnabled();
    await editor.getByRole('button', { name: 'Open note', exact: true }).click();
    await expect(editor.getByLabel('Note title', { exact: true })).toHaveValue(note.title);
    await expect(editor.getByLabel('Note text', { exact: true })).toHaveValue(note.text);
    await page.getByText('Move the note to another Passkey', { exact: true }).click();
    // A concurrent owner edit must win; the prepared stale transfer must not overwrite it.
    await write(
      'owner_note',
      encodeOwnerNote(newOwnerNote('New saved title', 'New body')),
      3,
      target,
    );
    await transfer.getByRole('combobox').selectOption(Buffer.from(source).toString('base64url'));
    await transfer.getByRole('checkbox').check();
    await move.click();
    await expect(transfer.getByRole('status')).toContainText('Another update conflicted');
    assert.equal((await read('owner_note')).revision, 3);
    await editor
      .getByRole('button', { name: 'Discard edits and retry state, then reload note', exact: true })
      .click();
    await expect(
      transfer.getByRole('button', { name: 'Forget the pending request', exact: true }),
    ).toHaveCount(0);
    await expect(transfer.getByRole('checkbox')).not.toBeChecked();
    await write(
      'owner_note',
      new TextEncoder().encode(JSON.stringify({ ...note, version: 99 })),
      4,
      target,
    );
    await editor
      .getByRole('button', { name: 'Discard edits and retry state, then reload note', exact: true })
      .click();
    await editor.getByRole('button', { name: 'Open note', exact: true }).click();
    await expect(editor.getByRole('status')).toContainText('Unsupported formats or versions');
    await expect(move).toBeDisabled();
    assert.equal(requests.length, 3);
    assert.deepEqual(await read('name'), nameBefore);
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
