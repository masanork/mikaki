import { startBrowserEvidence } from './support/browser-evidence.ts';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium, expect } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { toolOutputs } from '../../crates/agent-worker/tool-results.ts';
import { sealAttribute } from '../../crates/worker/ui/vault-crypto.ts';
import { newOwnerNote, encodeOwnerNote } from '../../crates/worker/ui/vault-note.ts';

test('saved note selection reaches local MCP without name unlock, edits, writes or owner keys', async () => {
  const origin = 'https://mikaki.test';
  const loginCredential = new Uint8Array(randomBytes(32));
  const noteCredential = new Uint8Array(randomBytes(32));
  const prf = new Uint8Array(32).fill(0x62);
  const cookie = randomBytes(32).toString('base64url');
  const note = newOwnerNote(
    'N'.repeat(256),
    'Saved synthetic memo 🗾\n<img src=x onerror="alert(1)">',
  );
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        secrets: { MIKAKI_ISSUER: origin },
      },
    ],
  });
  const temporary = await mkdtemp(join(tmpdir(), 'mikaki-note-agent-'));
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  let evidence: Awaited<ReturnType<typeof startBrowserEvidence>> | undefined;
  let failure: unknown;
  let client: Client | undefined;
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-worker');
    await op.applyD1Migrations('DB');
    const env = await op.getEnv();
    const now = Math.floor(Date.now() / 1000);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('note-owner',1,1)"),
      ...[loginCredential, noteCredential].map((credential) =>
        env.DB.prepare("INSERT INTO credential VALUES(?,'note-owner',1)").bind(
          Buffer.from(credential).toString('base64url'),
        ),
      ),
      env.DB.prepare("INSERT INTO sso_session VALUES('note-session','note-owner',?,1,?,0)").bind(
        Buffer.from(loginCredential).toString('base64url'),
        now + 3600,
      ),
      env.DB.prepare("INSERT INTO sso_context VALUES('note-session',?,?)").bind(
        createHash('sha256').update(cookie).digest('base64url'),
        now,
      ),
    ]);
    const writeNote = async (bytes: Uint8Array<ArrayBuffer>, revision: number) => {
      const sealed = await sealAttribute(
        bytes,
        prf,
        noteCredential,
        new Uint8Array(32).fill(0x42),
        origin,
        'owner_note',
        revision,
      );
      const response = await op.fetch(`${origin}/vault/attributes/owner_note`, {
        method: 'PUT',
        headers: {
          Cookie: `__Host-op-sso=${cookie}`,
          Origin: origin,
          'Content-Type': 'application/json',
          'X-Operation-ID': randomBytes(32).toString('base64url'),
          ...(revision === 1 ? { 'If-None-Match': '*' } : { 'If-Match': `"${revision - 1}"` }),
        },
        body: JSON.stringify(sealed),
      });
      assert.equal(response.status, 200, await response.text());
    };
    await writeNote(encodeOwnerNote(note), 1);
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    evidence = await startBrowserEvidence(page.context(), 'owner-note-agent-browser');
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.addInitScript(
      ({ prf }) => {
        class MockCredential {
          rawId: ArrayBuffer;
          constructor(id: BufferSource) {
            this.rawId = new Uint8Array(id as ArrayBuffer).buffer;
          }
          getClientExtensionResults() {
            return sessionStorage.getItem('missing-prf')
              ? {}
              : { prf: { results: { first: Uint8Array.from(prf).buffer } } };
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
      { prf: [...prf] },
    );
    let changeDuringPreparation = false;
    await page.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const response = await op.fetch(request.url(), {
        method: request.method(),
        headers: { ...request.headers(), Cookie: `__Host-op-sso=${cookie}` },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      if (
        changeDuringPreparation &&
        request.method() === 'GET' &&
        request.url().endsWith('/owner_note')
      ) {
        changeDuringPreparation = false;
        await writeNote(encodeOwnerNote(newOwnerNote('New saved title', 'New saved body')), 2);
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    await page.goto(`${origin}/vault?lang=en`);
    await page.locator('#connections > summary').click();
    const panel = page.getByRole('region', { name: 'Share with an AI agent' });
    const notePanel = page.getByRole('region', { name: 'Owner note', exact: true });
    const select = panel.getByRole('checkbox', {
      name: 'Share my saved owner note through local MCP',
      exact: true,
    });
    const prepare = panel.getByRole('button', { name: 'Prepare a local MCP export', exact: true });
    await expect(select).toBeEnabled();
    await expect(prepare).toBeDisabled();
    await select.check();
    await expect(prepare).toBeDisabled();
    await panel.getByRole('checkbox', { name: 'I approve disclosure' }).check();
    await expect(prepare).toBeEnabled();
    // The note's envelope uses a different credential from the account login, and no name exists.
    await notePanel.getByRole('button', { name: 'Open note', exact: true }).click();
    await notePanel.getByLabel('Note text', { exact: true }).fill('Unsaved edit must stay private');
    await page.evaluate(() => sessionStorage.setItem('missing-prf', 'true'));
    await prepare.click();
    await expect(panel.getByRole('status')).toContainText('could not be completed');
    await expect(panel.getByRole('button', { name: 'Download selected plaintext' })).toHaveCount(0);
    await page.evaluate(() => sessionStorage.removeItem('missing-prf'));
    await prepare.click();
    await expect(
      panel.getByRole('heading', { name: 'Review the saved content to export' }),
    ).toBeVisible();
    await expect(panel).toContainText('Saved synthetic memo');
    await expect(panel).not.toContainText('Unsaved edit');
    await expect(panel.locator('img')).toHaveCount(0);
    if (process.env['MIKAKI_CAPTURE_NOTE_EXPORT'])
      await panel.screenshot({ path: process.env['MIKAKI_CAPTURE_NOTE_EXPORT'] });
    const download = async (label: string) => {
      const event = page.waitForEvent('download');
      await panel.getByRole('button', { name: label, exact: true }).click();
      return readFile((await (await event).path())!, 'utf8');
    };
    const bundleText = await download('Download selected plaintext');
    const grantText = await download('Download local access grant');
    const bundle = JSON.parse(bundleText);
    const grant = JSON.parse(grantText);
    const sourceInfo = bundle.documents[0].source_info;
    assert.ok(Number.isSafeInteger(sourceInfo.confirmed_at) && sourceInfo.confirmed_at > 0);
    assert.ok(sourceInfo.confirmed_at <= Math.floor(Date.now() / 1000));
    assert.deepEqual(sourceInfo, {
      kind: 'vault',
      attribute: 'owner_note',
      revision: 1,
      provenance: 'self-asserted',
      confirmed_at: sourceInfo.confirmed_at,
    });
    assert.deepEqual(bundle.documents, [
      {
        id: 'owner_note',
        title: 'Owner note',
        source: 'vault:owner_note:1:self-asserted',
        source_info: sourceInfo,
        text: new TextDecoder().decode(encodeOwnerNote(note)),
      },
    ]);
    assert.deepEqual(grant.document_ids, ['owner_note']);
    assert.deepEqual(grant.operations, ['list', 'search', 'read']);
    assert.equal(grant.expires_at - grant.not_before, 3600);
    assert.equal(grant.export_sha256, createHash('sha256').update(bundleText).digest('hex'));
    assert.ok(!(bundleText + grantText).includes(Buffer.from(prf).toString('base64url')));
    assert.equal(
      (await env.DB.prepare('SELECT count(*) AS total FROM agent_grant').first()).total,
      0,
    );
    assert.doesNotMatch(
      bundleText + grantText,
      /ciphertext|owner_envelope|credential_id|Unsaved edit/,
    );
    const grantPath = join(temporary, 'grant.json');
    const bundlePath = join(temporary, 'export.json');
    const auditPath = join(temporary, 'audit.jsonl');
    await writeFile(grantPath, grantText, { mode: 0o600 });
    await writeFile(bundlePath, bundleText, { mode: 0o600 });
    client = new Client({ name: 'note-export-test', version: '1' });
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: ['local/agent-mcp.ts', grantPath, bundlePath, auditPath, 'codex-local'],
      }),
    );
    assert.deepEqual((await client.listTools()).tools.map((tool) => tool.name).sort(), [
      'mikaki_list',
      'mikaki_read',
      'mikaki_search',
    ]);
    const read = await client.callTool({ name: 'mikaki_read', arguments: { id: 'owner_note' } });
    assert.equal(read.isError, undefined);
    assert.match(JSON.stringify(read), /Saved synthetic memo/);
    assert.deepEqual(toolOutputs.read.parse(read.structuredContent).source_info, sourceInfo);
    assert.equal(toolOutputs.read.parse(read.structuredContent).access.source_check, 'not-checked');
    assert.equal(
      (await client.callTool({ name: 'mikaki_read', arguments: { id: 'name' } })).isError,
      true,
    );
    await writeFile(grantPath, JSON.stringify({ ...grant, revoked: true }));
    assert.equal(
      (await client.callTool({ name: 'mikaki_read', arguments: { id: 'owner_note' } })).isError,
      true,
    );
    assert.doesNotMatch(await readFile(auditPath, 'utf8'), /Saved synthetic memo|Unsaved edit/);
    // Selection changes clear prepared plaintext before another download.
    await panel.getByLabel('Access duration').selectOption('14400');
    await expect(panel.getByRole('button', { name: 'Download selected plaintext' })).toHaveCount(0);
    changeDuringPreparation = true;
    await prepare.click();
    await expect(panel.getByRole('status')).toContainText('could not be completed');
    await expect(panel.getByRole('button', { name: 'Download selected plaintext' })).toHaveCount(0);
    page.once('dialog', (dialog) => {
      assert.equal(dialog.type(), 'confirm');
      assert.equal(
        dialog.message(),
        'Discard note edits and unfinished operations, then reload the saved note?',
      );
      void dialog.accept();
    });
    await notePanel
      .getByRole('button', { name: 'Discard edits and retry state, then reload note' })
      .click();
    await panel.getByRole('checkbox', { name: 'I approve disclosure' }).check();
    await prepare.click();
    await expect(panel).toContainText('New saved body');
    await expect(panel).toContainText('revision 2');
    await notePanel.getByRole('button', { name: 'Open note', exact: true }).click();
    await notePanel.getByLabel('Note text', { exact: true }).fill('Owner saved another revision');
    await notePanel.getByRole('button', { name: 'Save note', exact: true }).click();
    await expect(notePanel.getByRole('status')).toHaveText('Note encrypted and saved.');
    await expect(panel.getByRole('button', { name: 'Download selected plaintext' })).toHaveCount(0);
    // Incompatible saved schemas remain intact and cannot reach an export.
    await writeNote(new TextEncoder().encode(JSON.stringify({ ...note, version: 99 })), 4);
    await notePanel
      .getByRole('button', { name: 'Discard edits and retry state, then reload note' })
      .click();
    await panel.getByRole('checkbox', { name: 'I approve disclosure' }).check();
    await prepare.click();
    await expect(panel.getByRole('status')).toContainText('could not be completed');
    await expect(panel.getByRole('button', { name: 'Download selected plaintext' })).toHaveCount(0);
    assert.deepEqual(errors, []);
    const deletion = await op.fetch(`${origin}/vault/attributes/owner_note`, {
      method: 'DELETE',
      headers: {
        Cookie: `__Host-op-sso=${cookie}`,
        Origin: origin,
        'If-Match': '"4"',
        'X-Operation-ID': randomBytes(32).toString('base64url'),
      },
    });
    assert.equal(deletion.status, 200);
    await notePanel
      .getByRole('button', { name: 'Discard edits and retry state, then reload note' })
      .click();
    // A disappeared target must still be deselectable; never trap a checked disabled selection.
    await expect(select).toBeEnabled();
    await select.uncheck();
    await expect(prepare).toBeDisabled();
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    await client?.close();
    await evidence?.finish(failure);
    await browser?.close();
    await harness.close();
    await rm(temporary, { recursive: true, force: true });
  }
});
