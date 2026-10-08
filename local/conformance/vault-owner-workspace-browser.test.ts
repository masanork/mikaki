import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';
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
      DB.prepare(
        "INSERT INTO passkey_credential VALUES(?,'synthetic-key','synthetic-user',0,0,0,1)",
      ).bind(id),
      DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(id, now + 3600),
      DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
        createHash('sha256').update(secret).digest('base64url'),
        now,
      ),
    ]);
    const targetCredential = randomBytes(32),
      targetId = targetCredential.toString('base64url'),
      targetSecret = randomBytes(32).toString('base64url');
    await DB.batch([
      DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(targetId),
      DB.prepare(
        "INSERT INTO passkey_credential VALUES(?,'synthetic-target-key','synthetic-user',0,0,0,1)",
      ).bind(targetId),
      DB.prepare("INSERT INTO sso_session VALUES('target-session','owner',?,1,?,0)").bind(
        targetId,
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('target-session',?,?)").bind(
        createHash('sha256').update(targetSecret).digest('base64url'),
        now,
      ),
    ]);
    let activeSecret = secret;
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    let ceremonies = 0;
    let holdCeremonyAt = 0;
    const ceremonyControl: {
      started: (() => void) | null;
      release: (() => void) | null;
      gate: Promise<void>;
    } = { started: null, release: null, gate: new Promise<void>(() => {}) };
    await context.exposeFunction('recordCeremony', async () => {
      ceremonies++;
      if (ceremonies === holdCeremonyAt) {
        ceremonyControl.started?.();
        await new Promise<void>((resolve) => (ceremonyControl.release = resolve));
      }
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
            const source = new Uint8Array(this.rawId).every(
              (byte, index) => byte === credential[index],
            );
            return {
              prf: { results: { first: new Uint8Array(32).fill(source ? 0x71 : 0x72).buffer } },
            };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: {
            get: async (options: CredentialRequestOptions) => {
              await (window as unknown as { recordCeremony: () => Promise<void> }).recordCeremony();
              const result = new MockCredential();
              const requested = options.publicKey?.allowCredentials?.[0]?.id;
              if (!(requested instanceof ArrayBuffer || ArrayBuffer.isView(requested)))
                throw new Error('Pinned credential required');
              result.rawId =
                requested instanceof ArrayBuffer
                  ? requested.slice(0)
                  : new Uint8Array(
                      requested.buffer,
                      requested.byteOffset,
                      requested.byteLength,
                    ).slice().buffer;
              return result;
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
    let loseWrapper = false,
      rejectWrapper = false;
    let bootstrapWrites = 0;
    const wrapperRequests: { body: string; operation: string | null; revision: string | null }[] =
      [];
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
      if (failSession && path === '/vault/session') {
        await route.fulfill({ status: 503 });
        return;
      }
      if (path.startsWith('/vault/records/') && request.method() === 'PUT')
        recordBodies.push(request.postData()!);
      if (path === '/vault/owner-key' && request.method() === 'PUT') bootstrapWrites++;
      if (path === '/vault/owner-key/wrappers' && request.method() === 'PUT')
        wrapperRequests.push({
          body: request.postData()!,
          operation: request.headers()['x-operation-id'] ?? null,
          revision: request.headers()['if-match'] ?? null,
        });
      if (rejectWrapper && path === '/vault/owner-key/wrappers' && request.method() === 'DELETE') {
        rejectWrapper = false;
        await route.fulfill({
          status: 400,
          contentType: 'text/html',
          body: '<h1>Bad Request</h1>',
        });
        return;
      }
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: { ...(await request.allHeaders()), cookie: `__Host-op-sso=${activeSecret}` },
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
        loseWrapper &&
        path === '/vault/owner-key/wrappers' &&
        request.method() === 'PUT' &&
        response.ok
      ) {
        loseWrapper = false;
        await route.abort();
        return;
      }
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
    const page = await context.newPage();
    page.on('pageerror', (e) => errors.push(e.message));
    page.on('dialog', (d) => void d.accept());
    await page.goto(`${origin}/vault?lang=en`);
    assert.equal(ceremonies, 0);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toBeEnabled();
    await expect(page.locator('#name')).toBeFocused();
    assert.equal(ceremonies, 1);
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
    await page.locator('#thread-search-scope').selectOption({ label: '申請の相談' });
    await page.locator('#thread-search').fill('情報');
    await expect(results.getByRole('button')).toHaveCount(1);
    await results.getByRole('button').click();
    await expect(page.locator('#thread-message-1')).toBeFocused();
    await page.locator('#threads .product-danger').click();
    await expect(page.locator('#thread-search')).toHaveValue('');
    await expect(page.locator('#thread-search-scope')).toHaveValue('');
    await expect(results.getByRole('button')).toHaveCount(0);
    await page.locator('#thread-search').fill('申請');
    await expect(results.getByRole('button')).toHaveCount(1);
    await expect(results.getByRole('button')).toContainText('別の相談');
    await page.locator('#thread-search').fill('');
    await page.locator('#reload-profile').click();
    await expect(page.locator('#name')).toHaveValue('New owner');
    failSearch = true;
    await page.locator('#thread-search').fill('申請');
    await expect(results.getByRole('status')).toHaveText(
      'Search is unavailable. Please try again.',
    );
    failSearch = false;
    await results.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(results.getByRole('button')).toHaveCount(1);
    await expect(results.getByRole('button')).toContainText('別の相談');
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
    await expect(page.getByRole('button', { name: '別の相談', exact: true })).toBeVisible();
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
    await page.locator('#owner-local-export summary').click();
    await page.locator('#owner-local-export-source').selectOption('name');
    await page.locator('#owner-local-export-delegate').fill('reviewer_1');
    await page.locator('#owner-local-export-service').fill('Local review');
    await page.locator('#owner-local-export-lifetime').selectOption('3600');
    await page.locator('#owner-local-export-prepare').click();
    await expect(page.locator('#owner-local-export-preview')).toHaveText('Recreated');
    await expect(page.locator('#owner-local-export-review-heading')).toBeVisible();
    await expect(page.locator('#owner-local-export')).toContainText('Exact source revision:');
    await expect(page.locator('#owner-local-export')).toContainText('reviewer_1');
    await expect(page.locator('#owner-local-export')).toContainText('Local review');
    await expect(page.locator('#owner-local-export')).toContainText('source_check=not-checked');
    await expect(page.locator('#owner-local-export')).toContainText(
      'Permissions: list, search, and read',
    );
    await expect(page.locator('#owner-local-export')).toContainText('revoked to true');
    await expect(page.locator('#owner-local-export-download-bundle')).toBeDisabled();
    await page.locator('#owner-local-export-consent').check();
    const [bundleDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.locator('#owner-local-export-download-bundle').click(),
    ]);
    assert.match(bundleDownload.suggestedFilename(), /^mikaki-v2-bundle-[A-Za-z0-9_-]+\.json$/);
    const bundlePath = await bundleDownload.path();
    assert.ok(bundlePath);
    const exportedBundle = JSON.parse(await readFile(bundlePath, 'utf8'));
    assert.equal(exportedBundle.version, 2);
    assert.equal(exportedBundle.documents.length, 1);
    assert.equal(exportedBundle.documents[0].id, 'name');
    assert.equal(exportedBundle.documents[0].text, 'Recreated');
    const [grantDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.locator('#owner-local-export-download-grant').click(),
    ]);
    assert.match(grantDownload.suggestedFilename(), /^mikaki-v2-grant-[A-Za-z0-9_-]+\.json$/);
    const grantPath = await grantDownload.path();
    assert.ok(grantPath);
    const exportedGrant = JSON.parse(await readFile(grantPath, 'utf8'));
    assert.equal(exportedGrant.version, 2);
    assert.equal(exportedGrant.delegate, 'reviewer_1');
    assert.deepEqual(exportedGrant.document_ids, ['name']);
    assert.equal(
      exportedGrant.sources[0].source.revision,
      exportedBundle.documents[0].source_info.source.revision,
    );
    assert.ok(exportedGrant.expires_at > Math.floor(Date.now() / 1000));
    assert.equal(exportedGrant.revoked, false);
    await page.locator('#owner-local-export-clear').click();
    await page.locator('#owner-local-export-source').selectOption('owner_note');
    await page.locator('#owner-local-export-delegate').fill('note_reader');
    await page.locator('#owner-local-export-service').fill('Local note review');
    await page.locator('#owner-local-export-prepare').click();
    await expect(page.locator('#owner-local-export-preview')).toContainText(
      'Same record in both presentations.',
    );
    await expect(page.locator('#owner-local-export')).toContainText('Exact source revision:');
    assert.deepEqual(errors, []);
    await page.locator('#owner-passkeys summary').click();
    await expect(page.locator('#owner-passkeys')).toContainText(
      'Login only · Vault access not enabled',
    );
    await page.locator('#owner-note-text').fill('Unsaved draft');
    await expect(
      page
        .locator('#owner-passkeys')
        .getByRole('button', { name: 'Allow Vault access', exact: true }),
    ).toBeDisabled();
    await page.locator('#owner-note-text').fill('Same record in both presentations.');
    holdCeremonyAt = ceremonies + 1;
    ceremonyControl.gate = new Promise<void>((resolve) => (ceremonyControl.started = resolve));
    await page
      .locator('#owner-passkeys')
      .getByRole('button', { name: 'Allow Vault access', exact: true })
      .click();
    await ceremonyControl.gate;
    await expect(page.locator('#owner-note-text')).toBeDisabled();
    await page.locator('#owner-note-text').evaluate((element) => {
      const input = element as HTMLTextAreaElement;
      input.value = 'Injected draft during PRF';
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    ceremonyControl.release?.();
    holdCeremonyAt = 0;
    await expect(page.locator('#owner-passkeys [role="status"]')).toHaveText(
      'Unsaved changes. Save before leaving this page.',
    );
    assert.equal(wrapperRequests.length, 0, 'A draft appearing during PRF prevents submission');
    await page.locator('#owner-note-text').fill('Same record in both presentations.');
    loseWrapper = true;
    await page.locator('#owner-passkeys-retry').click();
    await expect(page.locator('#owner-passkeys-retry')).toBeVisible();
    await expect(page.locator('#owner-passkeys-retry')).toBeEnabled();
    assert.equal(ceremonies, 5, 'Adding a wrapper requires fresh source and target PRF');
    await expect(page.locator('#owner-note-text')).toBeDisabled();
    await expect(page.locator('#name')).toBeDisabled();
    await page.locator('#owner-passkeys-retry').click();
    await expect(page.getByRole('heading', { name: 'Vault is locked', exact: true })).toBeVisible();
    await expect(page.locator('#owner-local-export-preview')).toHaveCount(0);
    assert.deepEqual(
      wrapperRequests[0],
      wrapperRequests[1],
      'Lost response reuses exact body, revision and operation',
    );
    assert.ok(
      wrapperRequests.every(
        (request) => !request.body.includes('Recreated') && !request.body.includes('Same record'),
      ),
    );
    assert.equal(ceremonies, 5, 'Retry does not repeat a ceremony');
    activeSecret = targetSecret;
    await page.reload();
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Recreated');
    await expect(page.locator('#owner-note-text')).toHaveValue(
      'Same record in both presentations.',
    );
    await expect(page.getByRole('button', { name: '別の相談', exact: true })).toBeVisible();
    assert.equal(
      ceremonies,
      6,
      'Fresh target login opens the existing profile, note and conversation',
    );
    activeSecret = secret;
    await page.reload();
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Recreated');
    await page.locator('#owner-passkeys summary').click();
    rejectWrapper = true;
    await page
      .locator('#owner-passkeys')
      .getByRole('button', { name: 'Remove Vault access', exact: true })
      .click();
    await expect(page.locator('#owner-passkeys-retry')).toHaveCount(0);
    await expect(page.locator('#name')).toHaveValue('Recreated');
    await page
      .locator('#owner-passkeys')
      .getByRole('button', { name: 'Remove Vault access', exact: true })
      .click();
    await expect(page.getByRole('heading', { name: 'Vault is locked', exact: true })).toBeVisible();
    activeSecret = targetSecret;
    await page.reload();
    await page.locator('#unlock').click();
    await expect(page.locator('#owner-passkeys')).toHaveCount(0);
    assert.equal(bootstrapWrites, 1, 'A login-only credential never bootstraps a replacement root');
    activeSecret = secret;
    await page.reload();
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Recreated');
    assert.equal(ceremonies, 8);
    failSession = true;
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(true),
    );
    await page.evaluate(() =>
      (window as unknown as { setVaultHidden: (value: boolean) => void }).setVaultHidden(false),
    );
    await expect(page.getByRole('heading', { name: 'Vault is locked', exact: true })).toBeVisible();
    await expect(page.locator('#name')).toHaveCount(0);
    assert.equal(ceremonies, 8);
    assert.ok(
      recordBodies.every((body) => !body.includes('New owner') && !body.includes('保育園')),
    );
  } finally {
    await browser?.close();
    await harness.close();
  }
});
