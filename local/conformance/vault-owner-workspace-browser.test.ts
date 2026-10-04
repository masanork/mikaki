import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';
import { sealAttribute } from '../../crates/worker/ui/vault-crypto.ts';
import { agentKeyId } from '../../crates/worker/ui/agent-crypto.ts';
import { newOwnerNote } from '../../crates/worker/ui/vault-note.ts';
import { parseThreadArchive } from '../../crates/worker/ui/vault-thread-archive.ts';

test('archive schema accepts human/AI messages and rejects malformed content', () => {
  const archive = {
    format_version: 1,
    title: 'Conversation',
    messages: [
      { speaker: 'Alice', actor: 'human', text: 'Hello', timestamp: '2026-10-03T00:00:00.000Z' },
    ],
  };
  assert.equal(parseThreadArchive(archive).messages[0]?.text, 'Hello');
  for (const invalid of [
    null,
    { ...archive, format_version: 2 },
    { ...archive, messages: [] },
    { ...archive, messages: [{ ...archive.messages[0], actor: 'system' }] },
    { ...archive, messages: [{ ...archive.messages[0], timestamp: 'yesterday' }] },
  ])
    assert.throws(() => parseThreadArchive(invalid));
});
test('new owner Vault uses one PRF for profile and conversation reads/writes, exact retries and local search; lock clears display', async () => {
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
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Owner Vault UI' });
    const credential = randomBytes(32),
      id = credential.toString('base64url'),
      secret = randomBytes(32).toString('base64url'),
      now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(id),
      DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(id, now + 3600),
      DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
        createHash('sha256').update(secret).digest('base64url'),
        now,
      ),
    ]);
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const keys = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt'],
    );
    const publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
    let revoked = false;
    const legacyStatus = () => ({
      recipient: {
        key_id: '',
        resource: 'https://agent.test/mcp',
        enabled: true,
        public_jwk: publicJwk,
      },
      grants: [
        {
          grant_id: 'legacy-grant',
          delegate: 'Legacy synthetic connection',
          provider: 'Test',
          resource: 'https://agent.test/mcp',
          expires_at: now + 3600,
          revoked: revoked ? 1 : 0,
          source_revision: 1,
          created_at: now,
          active: revoked ? 0 : 1,
          operations: '["list","search","read","propose","execute"]',
        },
      ],
      proposals: [
        {
          proposal_id: 'legacy-draft',
          request_hash: 'draft-hash',
          title: 'Hidden legacy draft',
          text: 'Never approve here',
          state: 'pending',
          expires_at: now + 3600,
        },
      ],
      drafts: [],
      audit: [],
      note_revision: 0,
      attribute_proposals: ['pending', 'approved'].map((state) => ({
        proposal_id: `legacy-note-${state}`,
        request_hash: `note-${state}`,
        payload: JSON.stringify(newOwnerNote('Hidden legacy proposal', 'Never commit here')),
        attribute_id: 'owner_note',
        base_revision: 0,
        expires_at: now + 3600,
        state,
        delegate: 'Legacy synthetic connection',
        provider: 'Test',
        destination: 'owner-vault',
        grant_id: 'legacy-grant',
        operation_id: null,
        candidate: null,
        result_revision: null,
      })),
    });
    const keyId = await agentKeyId(publicJwk);
    const legacyRequests: string[] = [];
    const legacyModeRequests: string[] = [];
    let ceremonies = 0;
    await context.exposeFunction('recordCeremony', () => {
      ceremonies++;
    });
    await context.addInitScript(
      ({ credential }) => {
        let hidden = false;
        Object.defineProperty(document, 'visibilityState', {
          get: () => (hidden ? 'hidden' : 'visible'),
        });
        Object.defineProperty(window, 'setVaultHidden', {
          value: (value: boolean) => {
            hidden = value;
            document.dispatchEvent(new Event('visibilitychange'));
          },
        });
        class MockCredential {
          rawId = Uint8Array.from(credential).buffer;
          getClientExtensionResults() {
            return { prf: { results: { first: new Uint8Array(32).fill(0x71).buffer } } };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: {
            get: async () => {
              await (window as unknown as { recordCeremony: () => Promise<void> }).recordCeremony();
              return new MockCredential();
            },
          },
        });
      },
      { credential: [...credential] },
    );
    let lose = false,
      failSession = false,
      failSearch = false;
    const searchAssets: string[] = [];
    const recordBodies: string[] = [];
    const errors: string[] = [];
    await context.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (path === '/vault/search.js' || path === '/vault/sqlite3.wasm') {
        searchAssets.push(path);
        if (failSearch) {
          await route.abort();
          return;
        }
      }
      if (path.startsWith('/vault/agents/') || path.startsWith('/vault/attributes/'))
        (request.frame().url().includes('storage=legacy-v1')
          ? legacyModeRequests
          : legacyRequests
        ).push(`${request.method()} ${path}`);
      if (path === '/vault/agents/status' || path === '/vault/agents/connections') {
        const status = legacyStatus();
        status.recipient.key_id = keyId;
        if (path === '/vault/agents/connections') {
          status.proposals = [];
          status.drafts = [];
          status.attribute_proposals = [];
        }
        await route.fulfill({ json: status });
        return;
      }
      if (path === '/vault/agents/revoke') {
        assert.deepEqual(request.postDataJSON(), { grant_id: 'legacy-grant' });
        revoked = true;
        await route.fulfill({ json: { ok: true } });
        return;
      }
      if (failSession && path === '/vault/session') {
        await route.fulfill({ status: 503 });
        return;
      }
      if (path.startsWith('/vault/records/') && request.method() === 'PUT')
        recordBodies.push(request.postData()!);
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: { ...(await request.allHeaders()), cookie: `__Host-op-sso=${secret}` },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      if (path === '/vault/search.js') {
        assert.match(response.headers.get('Content-Security-Policy')!, /'wasm-unsafe-eval'/);
        assert.equal(response.headers.get('Content-Type'), 'text/javascript; charset=utf-8');
      }
      if (path === '/vault' && response.ok) {
        assert.match(response.headers.get('Content-Security-Policy')!, /worker-src 'self'/);
        assert.doesNotMatch(response.headers.get('Content-Security-Policy')!, /wasm-unsafe-eval/);
      }
      if (path === '/vault/sqlite3.wasm') {
        assert.equal(response.headers.get('Content-Type'), 'application/wasm');
        assert.equal(response.headers.get('Cache-Control'), 'no-store');
        assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
      }
      const body = Buffer.from(await response.arrayBuffer());
      if (
        lose &&
        path === '/vault/records/personal/name' &&
        request.method() === 'PUT' &&
        response.ok
      ) {
        lose = false;
        await route.abort();
        return;
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body,
      });
    });
    // A retained v1 name without a v2 root must not trap this account in the
    // old per-attribute unlock UI. The same ciphertext remains readable later.
    const legacyName = await sealAttribute(
      new TextEncoder().encode('Retained legacy name'),
      new Uint8Array(32).fill(0x71),
      new Uint8Array(credential),
      new Uint8Array(32).fill(0x42),
      origin,
      'name',
      1,
    );
    const savedLegacy = await worker.fetch(`${origin}/vault/attributes/name`, {
      method: 'PUT',
      headers: {
        Cookie: `__Host-op-sso=${secret}`,
        Origin: origin,
        'Content-Type': 'application/json',
        'X-Operation-ID': randomBytes(32).toString('base64url'),
        'If-None-Match': '*',
      },
      body: JSON.stringify(legacyName),
    });
    assert.equal(savedLegacy.status, 200, await savedLegacy.text());
    const page = await context.newPage();
    page.on('pageerror', (e) => errors.push(e.message));
    page.on('dialog', (d) => void d.accept());
    await page.goto(`${origin}/vault?lang=en`);
    // A populated credential, active legacy grant and both pending/approved note
    // proposals must not expose legacy data actions in the default v2 workspace.
    await page.locator('#connections summary').click();
    const connections = page.locator('#connections');
    await expect(
      connections.getByText('Legacy synthetic connection · Test · https://agent.test/mcp', {
        exact: true,
      }),
    ).toBeVisible();
    const assertConnectionsOnly = async () => {
      for (const label of [
        'Allow note proposals for this connection',
        'Approve this note proposal (do not save yet)',
        'Encrypt and save the approved note',
        'Retry the same encrypted commit',
        'Approve this exact draft',
        'Prepare a local MCP export',
        'Create remote access',
      ])
        await expect(connections.getByRole('button', { name: label, exact: true })).toHaveCount(0);
      await expect(connections.getByText('Hidden legacy proposal', { exact: true })).toHaveCount(0);
      await expect(connections.getByText('Hidden legacy draft', { exact: true })).toHaveCount(0);
      assert.ok(
        legacyRequests.every((request) =>
          ['GET /vault/agents/connections', 'POST /vault/agents/revoke'].includes(request),
        ),
        legacyRequests.join('\n'),
      );
    };
    await assertConnectionsOnly();
    assert.equal(ceremonies, 0);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toBeEnabled();
    await expect(page.locator('#name')).toBeFocused();
    assert.equal(ceremonies, 1);
    await assertConnectionsOnly();
    await connections.getByRole('button', { name: 'Refresh', exact: true }).click();
    await assertConnectionsOnly();
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(true),
    );
    await expect(page.locator('#name')).not.toBeVisible();
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(false),
    );
    await expect(page.locator('#name')).toBeVisible();
    await page.locator('#reload-profile').click();
    await expect(page.locator('#archive-file')).toBeEnabled();
    assert.equal(ceremonies, 1);
    await page.locator('#name').fill('New owner');
    lose = true;
    await page.locator('#save').click();
    await expect(page.locator('#retry-write')).toBeVisible();
    await page.locator('#retry-write').click();
    await expect(page.locator('#retry-write')).toHaveCount(0);
    await expect(page.locator('#name')).toHaveValue('New owner');
    assert.equal(recordBodies[0], recordBodies[1]);
    assert.equal(ceremonies, 1);
    const archive = {
      format_version: 1,
      title: '申請の相談',
      messages: [
        {
          speaker: 'Alice',
          actor: 'human',
          text: '前の説明。'.repeat(100) + '保育園の申請について相談したい',
          timestamp: '2026-10-03T00:00:00.000Z',
        },
        {
          speaker: 'Assistant',
          actor: 'ai',
          text: '必要な情報を整理しましょう',
          timestamp: '2026-10-03T00:01:00.000Z',
        },
      ],
    };
    await expect(page.locator('#archive-file')).toBeEnabled();
    await page.locator('#archive-file').setInputFiles({
      name: 'conversation.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(archive)),
    });
    await expect(page.getByRole('button', { name: '申請の相談', exact: true })).toBeVisible();
    await page.getByRole('button', { name: '申請の相談', exact: true }).click();
    await expect(page.getByText('必要な情報を整理しましょう', { exact: true })).toBeVisible();
    await page.locator('#archive-file').setInputFiles({
      name: 'other-conversation.json',
      mimeType: 'application/json',
      buffer: Buffer.from(
        JSON.stringify({
          ...archive,
          title: '別の相談',
          messages: [{ ...archive.messages[0], text: '保育園の申請を別の会話で相談' }],
        }),
      ),
    });
    await expect(page.getByRole('button', { name: '別の相談', exact: true })).toBeVisible();
    await page.locator('#thread-search-scope').selectOption({ label: '申請の相談' });
    assert.equal(searchAssets.length, 0, 'SQLite loads only for a search');
    await page.locator('#thread-search').fill('園 園 園 園 園 園 園 園 園');
    await expect(page.locator('#thread-search')).toHaveAttribute('aria-invalid', 'true');
    await expect(page.locator('#thread-search-results [role=status]')).toHaveText(
      'Use up to 8 space-separated search terms (256 characters maximum).',
    );
    await expect(page.locator('#thread-search-results button')).toHaveCount(0);
    assert.equal(searchAssets.length, 0, 'Invalid query does not load SQLite or offer retry');
    await page.locator('#thread-search').fill('園　園　園　園　園　園　園　園');
    await expect(page.locator('#thread-search')).toHaveAttribute('aria-invalid', 'false');
    await expect(page.locator('#thread-search-results button')).toHaveCount(1);
    await page.locator('#thread-search').fill('園 申請');
    const results = page.locator('#thread-search-results');
    await expect(results.getByRole('button')).toHaveCount(1);
    await expect(results.getByRole('button')).toContainText('保育園の申請について相談したい');
    assert.ok(
      (await results.getByRole('button').textContent())!.length < 350,
      'late match uses a bounded excerpt',
    );
    await expect(results.getByRole('button')).toContainText('Alice');
    await page.locator('#thread-search-scope').selectOption('');
    await expect(results.getByRole('button')).toHaveCount(2);
    await page.locator('#thread-search-scope').selectOption({ label: '別の相談' });
    await expect(results.getByRole('button')).toHaveCount(1);
    await expect(results.getByRole('button')).toContainText('別の相談');
    await expect(results.getByText('申請の相談', { exact: true })).toHaveCount(0);
    await page.locator('#thread-search-scope').selectOption({ label: '申請の相談' });
    await expect(results.getByRole('button')).toHaveCount(1);
    assert.ok(searchAssets.includes('/vault/search.js'));
    assert.ok(searchAssets.includes('/vault/sqlite3.wasm'));
    await results.getByRole('button').click();
    await expect(page.locator('#thread-message-0')).toBeFocused();
    await page.locator('#thread-search').fill('園 園 園 園 園 園 園 園 園');
    await expect(page.locator('#thread-search')).toHaveAttribute('aria-invalid', 'true');
    await expect(results.getByRole('button')).toHaveCount(0);
    await page.locator('#thread-search').fill('園 申請');
    await expect(results.getByRole('button')).toHaveCount(1);

    await mkdir('artifacts', { recursive: true });
    await page.screenshot({ path: 'artifacts/mikaki-owner-search-mobile.png', fullPage: true });
    await page.locator('#thread-search').fill('absent');
    await expect(results.getByRole('status')).toHaveText('No matching conversations.');
    await expect(results.getByRole('button')).toHaveCount(0);
    await page.locator('#thread-search').fill('園 申請');
    await expect(results.getByRole('button')).toHaveCount(1);
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(true),
    );
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(false),
    );
    await expect(page.locator('#thread-search')).toHaveValue('');
    await expect(results.getByRole('button')).toHaveCount(0);
    await page.locator('#thread-search').fill('情報');
    await expect(results.getByRole('button')).toHaveCount(1);
    await results.getByRole('button').click();
    await expect(page.locator('#thread-message-1')).toBeFocused();
    await page.locator('#thread-search').fill('');
    await page.locator('#reload-profile').click();
    await expect(page.locator('#name')).toHaveValue('New owner');
    failSearch = true;
    await page.locator('#thread-search').fill('情報');
    await expect(results.getByRole('status')).toHaveText(
      'Search is unavailable. Please try again.',
    );
    failSearch = false;
    await results.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(results.getByRole('button')).toHaveCount(1);
    await page.locator('#thread-search').fill('');
    assert.equal(ceremonies, 1);
    await auditAccessibility(page, 'owner-vault-mobile');
    await mkdir('artifacts', { recursive: true });
    await page.screenshot({ path: 'artifacts/mikaki-owner-vault-mobile.png', fullPage: true });
    await page.getByRole('button', { name: 'Lock Vault', exact: true }).click();
    await expect(page.locator('#name')).toHaveCount(0);
    await expect(page.getByText('必要な情報を整理しましょう', { exact: true })).toHaveCount(0);
    await page.getByRole('button', { name: 'Check session and reopen', exact: true }).click();
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('New owner');
    assert.equal(ceremonies, 2);
    await page.reload();
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('New owner');
    await expect(page.getByRole('button', { name: '申請の相談', exact: true })).toBeVisible();
    assert.equal(ceremonies, 3);
    await page.locator('#delete').click();
    await expect(page.locator('#name')).toHaveValue('');
    await page.locator('#name').fill('Recreated');
    await page.locator('#save').click();
    await expect(page.locator('#status')).toHaveText('Saved.');
    await expect(page.locator('#name')).toHaveValue('Recreated');
    assert.equal(ceremonies, 3);
    await page.locator('#owner-note-title').fill('Canonical note');
    await page.locator('#owner-note-text').fill('Same record in both presentations.');
    await page.locator('#owner-note-save').click();
    await expect(page.locator('#owner-note-status')).toHaveText(
      'Saved and verified. Vault stays open.',
    );
    assert.equal(ceremonies, 3);
    await page.goto(`${origin}/vault?lang=en&storage=owner-v2`);
    await page.locator('#owner-unlock').click();
    await expect(page.locator('#owner-name')).toHaveValue('Recreated');
    await expect(page.locator('#owner-note-text')).toHaveValue(
      'Same record in both presentations.',
    );
    await page.locator('#owner-name').fill('Updated in preview');
    await page.locator('#owner-profile-save').click();
    await expect(page.locator('#owner-profile-status')).toHaveText(
      'Saved and verified. Vault stays open.',
    );
    await page.goto(`${origin}/vault?lang=en`);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Updated in preview');
    await expect(page.locator('#owner-note-text')).toHaveValue(
      'Same record in both presentations.',
    );
    await expect(page.getByRole('button', { name: '申請の相談', exact: true })).toBeVisible();
    await page.getByRole('button', { name: '申請の相談', exact: true }).click();
    await page.locator('#thread-search').fill('申請');
    await page.locator('#thread-search-scope').selectOption({ label: '申請の相談' });
    await expect(page.locator('#thread-search-results button')).toHaveCount(2);
    await page.locator('#threads .product-danger').click();
    await expect(page.locator('#thread-search')).toHaveValue('');
    await expect(page.locator('#thread-search-scope')).toHaveValue('');
    await expect(page.locator('#thread-search-results button')).toHaveCount(0);
    await page.locator('#thread-search').fill('申請');
    await expect(page.locator('#thread-search-results button')).toHaveCount(1);
    await expect(page.locator('#thread-search-results button')).toContainText('別の相談');
    await page.locator('#thread-search').fill('');
    await page.locator('#connections summary').click();
    await assertConnectionsOnly();
    // Existing v1 data remains accessible in an explicitly separate presentation,
    // even when a v2 root and canonical v2 records already exist.
    const legacyPage = await context.newPage();
    await legacyPage.goto(
      new URL(
        (await connections
          .getByRole('link', { name: 'Open existing legacy names and notes', exact: true })
          .getAttribute('href'))!,
        origin,
      ).href,
    );
    await legacyPage.locator('#unlock').click();
    await expect(legacyPage.locator('#name')).toHaveValue('Retained legacy name');
    await legacyPage.locator('#connections summary').click();
    await expect(
      legacyPage.getByRole('button', {
        name: 'Allow note proposals for this connection',
        exact: true,
      }),
    ).toBeVisible();
    await expect(
      legacyPage.getByRole('button', {
        name: 'Approve this note proposal (do not save yet)',
        exact: true,
      }),
    ).toBeVisible();
    await expect(
      legacyPage.getByRole('button', { name: 'Encrypt and save the approved note', exact: true }),
    ).toBeEnabled();
    assert.ok(legacyModeRequests.includes('GET /vault/attributes/name'));
    await legacyPage.close();
    await expect(page.locator('#name')).toHaveValue('Updated in preview');
    await assertConnectionsOnly();
    await connections.getByRole('button', { name: 'Revoke access', exact: true }).click();
    await expect(
      connections.getByRole('button', { name: 'Revoke access', exact: true }),
    ).toHaveCount(0);
    assert.ok(legacyRequests.includes('POST /vault/agents/revoke'));
    await assertConnectionsOnly();
    assert.equal(ceremonies, 6);
    assert.deepEqual(errors, []);
    failSession = true;
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(true),
    );
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(false),
    );
    await expect(page.getByRole('heading', { name: 'Vault is locked', exact: true })).toBeVisible();
    await expect(page.locator('#name')).toHaveCount(0);
    assert.equal(ceremonies, 6);
    assert.ok(
      recordBodies.every((body) => !body.includes('New owner') && !body.includes('保育園')),
    );
  } finally {
    await browser?.close();
    await harness.close();
  }
});
