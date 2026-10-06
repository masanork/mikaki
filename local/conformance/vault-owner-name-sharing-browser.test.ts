import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';

test('OwnerWorkspace shares the fresh saved name separately with UserInfo and one chosen RP', async () => {
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
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Owner name sharing UI' });

    const credential = randomBytes(32);
    const credentialId = credential.toString('base64url');
    const secret = randomBytes(32).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
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
        createHash('sha256').update(secret).digest('base64url'),
        now,
      ),
    ]);

    const recipientKeys = ml_kem768.keygen(randomBytes(64));
    const publicKey = Buffer.from(recipientKeys.publicKey);
    const recipient = {
      service_id: 'userinfo',
      algorithm: 'ML-KEM-768',
      envelope_suite: 'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-record-v2',
      key_id: createHash('sha256').update(publicKey).digest('base64url'),
      public_key: publicKey.toString('base64url'),
      generation: 1,
      revision: 1,
    };
    const fixture: {
      nameSource: Record<string, unknown> | null;
      authority: Record<string, unknown> | null;
      systemGrant: Record<string, unknown> | null;
      release: Record<string, unknown> | null;
    } = { nameSource: null, authority: null, systemGrant: null, release: null };
    function currentSystemGrant(): Record<string, unknown> {
      const grant = fixture.systemGrant as Record<string, unknown> | null;
      if (!grant) throw new Error('system grant fixture missing');
      return grant;
    }
    const operationReceipts = new Map<
      string,
      { client_id: string; release_version: number; acknowledged: true }
    >();
    let mockNow = now;
    let rejectShareOnce = false;
    let revokeStaleShareOnce = false;
    let loseReleaseOnce = false;
    let loseWithdrawOnce = false;
    let recipientUnavailable = false;
    let holdRecipient = false;
    let recipientStarted = () => {};
    let recipientGate = Promise.resolve();
    const statusReads = { sharing: 0, releases: 0 };
    let completedProfileWrites = 0;
    const mutations: {
      path: string;
      method: string;
      body: string;
      operation: string | undefined;
      ifMatch: string | undefined;
    }[] = [];
    const errors: string[] = [];
    let stage = 'setup';

    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    await context.addInitScript(
      ({ credentialBytes }) => {
        let ceremonies = 0;
        Object.defineProperty(window, 'readCeremonies', { value: () => ceremonies });
        class MockCredential {
          rawId = Uint8Array.from(credentialBytes).buffer;
          getClientExtensionResults() {
            return { prf: { results: { first: new Uint8Array(32).fill(0x71).buffer } } };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: {
            get: async (options: CredentialRequestOptions) => {
              ceremonies++;
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
      { credentialBytes: [...credential] },
    );

    await context.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const headers = await request.allHeaders();
      const body = request.postData() ?? '';
      if (url.pathname === '/vault/record-recipient-keys/userinfo' && request.method() === 'GET') {
        if (holdRecipient) {
          holdRecipient = false;
          recipientStarted();
          await recipientGate;
        }
        if (recipientUnavailable) {
          await route.fulfill({
            status: 503,
            contentType: 'application/json',
            body: '{}',
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(recipient),
        });
        return;
      }
      if (url.pathname === '/vault/records/personal/name/sharing') {
        if (request.method() === 'GET') {
          statusReads.sharing++;
          const value = {
            enabled: true,
            policy_revision: 3,
            grant_ttl_seconds: 604800,
            grant: fixture.systemGrant,
          };
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(value),
          });
          return;
        }
        mutations.push({
          path: url.pathname,
          method: request.method(),
          body,
          operation: headers['x-operation-id'],
          ifMatch: headers['if-match'],
        });
        if (request.method() === 'POST') {
          const submitted = JSON.parse(body) as Record<string, unknown>;
          if (rejectShareOnce) {
            rejectShareOnce = false;
            await route.fulfill({
              status: 409,
              contentType: 'application/json',
              body: JSON.stringify({ error: 'release_conflict' }),
            });
            return;
          }
          fixture.nameSource = submitted['source'] as Record<string, unknown>;
          fixture.authority = submitted['authority'] as Record<string, unknown>;
          const grantVersion = Number(fixture.systemGrant?.['version'] ?? 0) + 1;
          const grant: Record<string, unknown> = {
            storage_version: 2,
            owner_id: 'owner',
            vault_id: fixture.nameSource['vault_id'],
            origin,
            collection_id: 'personal',
            record_id: 'name',
            kind: 'name',
            record_revision: fixture.nameSource['revision'],
            ciphertext_sha256: fixture.nameSource['ciphertext_sha256'],
            key_generation: fixture.authority['key_generation'],
            owner_key_revision: fixture.authority['owner_key_revision'],
            version: grantVersion,
            status: 'active',
            expires_at: mockNow + 604800,
            authority_current: 1,
            recipient_key_id: submitted['key_id'],
            recipient_generation: submitted['generation'],
            directory_revision: submitted['directory_revision'],
            policy_revision: submitted['policy_revision'],
          };
          if (revokeStaleShareOnce) {
            revokeStaleShareOnce = false;
            grant['status'] = 'revoked';
            grant['authority_current'] = 0;
          }
          fixture.systemGrant = grant;
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              grant_version: grantVersion,
              record_revision: fixture.nameSource['revision'],
              acknowledged: true,
            }),
          });
          return;
        }
        if (request.method() === 'DELETE') {
          if (fixture.systemGrant) {
            fixture.systemGrant['status'] = 'revoked';
            fixture.systemGrant['version'] = Number(fixture.systemGrant['version']) + 1;
            fixture.systemGrant['authority_current'] = 0;
          }
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              grant_version: Number(fixture.systemGrant?.['version'] ?? 1),
              record_revision: fixture.nameSource?.['revision'],
              acknowledged: true,
            }),
          });
          return;
        }
      }
      if (url.pathname === '/vault/records/personal/name/releases') {
        if (request.method() === 'GET') {
          statusReads.releases++;
          const client = {
            client_id: 'client-one',
            sector_identifier: 'https://app.example',
            client_revision: 4,
            connection_grant_version: 2,
            release_version: fixture.release?.['release_version'] ?? null,
            release_status: fixture.release?.['release_status'] ?? null,
            expires_at: fixture.release?.['expires_at'] ?? null,
            source_storage_version: fixture.release?.['source_storage_version'] ?? null,
            source_origin: fixture.release?.['source_origin'] ?? null,
            source_vault_id: fixture.release?.['source_vault_id'] ?? null,
            source_collection_id: fixture.release?.['source_collection_id'] ?? null,
            source_record_id: fixture.release?.['source_record_id'] ?? null,
            source_kind: fixture.release?.['source_kind'] ?? null,
            attribute_revision: fixture.release?.['attribute_revision'] ?? null,
            source_ciphertext_sha256: fixture.release?.['source_ciphertext_sha256'] ?? null,
            source_key_generation: fixture.release?.['source_key_generation'] ?? null,
            source_owner_key_revision: fixture.release?.['source_owner_key_revision'] ?? null,
            system_grant_version: fixture.release?.['system_grant_version'] ?? null,
            authority_current: fixture.release?.['authority_current'] ?? 0,
          };
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              enabled: true,
              policy_revision: 2,
              ttl_seconds: 86400,
              clients: [client],
            }),
          });
          return;
        }
        mutations.push({
          path: url.pathname,
          method: request.method(),
          body,
          operation: headers['x-operation-id'],
          ifMatch: headers['if-match'],
        });
        const submitted = JSON.parse(body) as Record<string, unknown>;
        if (request.method() === 'POST') {
          const existing = operationReceipts.get(headers['x-operation-id'] ?? '');
          if (existing) {
            await route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify(existing),
            });
            return;
          }
          assert.equal(submitted['client_id'], 'client-one');
          const version = Number(fixture.release?.['release_version'] ?? 0) + 1;
          fixture.release = {
            release_version: version,
            release_status: 'active',
            expires_at: mockNow + 60,
            authority_current: 1,
            source_storage_version: 2,
            source_origin: (submitted['source'] as Record<string, unknown>)['origin'],
            source_vault_id: (submitted['source'] as Record<string, unknown>)['vault_id'],
            source_collection_id: 'personal',
            source_record_id: 'name',
            source_kind: 'name',
            attribute_revision: (submitted['source'] as Record<string, unknown>)['revision'],
            source_ciphertext_sha256: (submitted['source'] as Record<string, unknown>)[
              'ciphertext_sha256'
            ],
            source_key_generation: (submitted['authority'] as Record<string, unknown>)[
              'key_generation'
            ],
            source_owner_key_revision: (submitted['authority'] as Record<string, unknown>)[
              'owner_key_revision'
            ],
            system_grant_version: fixture.systemGrant?.['version'],
          };
          const receipt = {
            client_id: 'client-one',
            release_version: version,
            acknowledged: true as const,
          };
          operationReceipts.set(headers['x-operation-id'] ?? '', receipt);
          if (loseReleaseOnce) {
            loseReleaseOnce = false;
            await route.abort();
            return;
          }
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(receipt),
          });
          return;
        }
        if (request.method() === 'DELETE') {
          fixture.release = {
            ...fixture.release,
            release_version: Number(fixture.release?.['release_version'] ?? 0) + 1,
            release_status: 'revoked',
          };
          if (loseWithdrawOnce) {
            loseWithdrawOnce = false;
            await route.abort();
            return;
          }
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              client_id: 'client-one',
              release_version: fixture.release['release_version'],
              acknowledged: true,
            }),
          });
          return;
        }
      }
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: { ...headers, cookie: `__Host-op-sso=${secret}` },
        ...(body ? { body } : {}),
      });
      if (
        url.pathname === '/vault/records/personal/name' &&
        request.method() === 'PUT' &&
        response.ok
      ) {
        completedProfileWrites++;
        if (fixture.systemGrant) {
          fixture.systemGrant['status'] = 'revoked';
          fixture.systemGrant['version'] = Number(fixture.systemGrant['version']) + 1;
          fixture.systemGrant['authority_current'] = 0;
        }
        if (fixture.release) {
          fixture.release['release_version'] = Number(fixture.release['release_version']) + 1;
          fixture.release['release_status'] = 'revoked';
          fixture.release['authority_current'] = 0;
        }
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });

    const page = await context.newPage();
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('dialog', (dialog) => void dialog.accept());
    await page.clock.install({ time: new Date(now * 1000) });
    stage = 'unlock';
    await page.goto(`${origin}/vault?lang=en`);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toBeEnabled();
    await page.locator('#name').fill('Initial name');
    await page.locator('#save').click();
    await expect.poll(() => completedProfileWrites).toBe(1);
    await expect(page.locator('#status')).toHaveText('Saved.');
    await expect(page.locator('#save')).toBeEnabled();
    await page.locator('#name').fill('A self-asserted name');
    await page.locator('#save').click();
    await expect(page.locator('#name')).toHaveValue('A self-asserted name');
    await expect.poll(() => completedProfileWrites).toBe(2);
    await expect(page.locator('#status')).toHaveText('Saved.');
    await expect(page.locator('#save')).toBeEnabled();
    assert.equal(statusReads.sharing, 0, 'unlock and save do not load sharing state');
    assert.equal(statusReads.releases, 0, 'unlock and save do not load RP permissions');

    stage = 'lazy-load-sharing';
    await page.locator('#owner-name-sharing summary').click();
    await expect(page.locator('#owner-name-sharing-preview-heading')).toBeVisible();
    await expect(page.locator('#owner-name-sharing')).toContainText('A self-asserted name');
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'Current encrypted record revision: 2',
    );
    await expect(page.locator('#owner-name-sharing-share')).toBeEnabled();
    assert.ok(statusReads.sharing > 0 && statusReads.releases > 0);
    await auditAccessibility(page, 'owner-name-sharing-mobile');

    await page.locator('#name').fill('Unsaved parent draft');
    const beforeShare = mutations.length;
    await page.locator('#owner-name-sharing-share').click();
    await expect(page.locator('#owner-name-sharing-status')).toHaveText(
      'Unsaved changes. Save before leaving this page.',
    );
    assert.equal(
      mutations.length,
      beforeShare,
      'unsaved parent draft blocks sharing before submit',
    );
    await page.locator('#reload-profile').click();
    await expect(page.locator('#name')).toHaveValue('A self-asserted name');

    stage = 'async-draft-guard';
    let signalRecipient!: () => void;
    let unblockRecipient!: () => void;
    recipientGate = new Promise<void>((resolve) => (unblockRecipient = resolve));
    const nextRecipientRequest = new Promise<void>((resolve) => (signalRecipient = resolve));
    recipientStarted = signalRecipient;
    holdRecipient = true;
    await page.locator('#owner-name-sharing-share').click();
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(async () => {
        const [buttonDisabled, name, sharingStatus] = await Promise.all([
          page.locator('#owner-name-sharing-share').isDisabled(),
          page.locator('#name').inputValue(),
          page.locator('#owner-name-sharing-status').innerText(),
        ]);
        reject(
          new Error(
            `Timed out waiting for recipient request during ${stage}; sharingRequests=${statusReads.sharing}, releasesRequests=${statusReads.releases}, mutations=${mutations.length}, buttonDisabled=${buttonDisabled}, name=${name}, sharingStatus=${sharingStatus}, errors=${errors.join('; ')}`,
          ),
        );
      }, 5000);
      void nextRecipientRequest.then(
        () => {
          clearTimeout(timer);
          resolve();
        },
        (error: unknown) => {
          clearTimeout(timer);
          reject(error);
        },
      );
    });
    await page.locator('#name').evaluate((element) => {
      const input = element as HTMLInputElement;
      input.value = 'Injected draft during preparation';
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    unblockRecipient();
    await expect(page.locator('#owner-name-sharing-status')).toHaveText(
      'Unsaved changes. Save before leaving this page.',
    );
    assert.equal(
      mutations.length,
      beforeShare,
      'draft added during async preparation prevents submit',
    );
    await page.locator('#reload-profile').click();
    await expect(page.locator('#name')).toHaveValue('A self-asserted name');

    rejectShareOnce = true;
    await page.locator('#owner-name-sharing-share').click();
    await expect(page.locator('#owner-name-sharing-retry')).toHaveCount(0);
    await expect(page.locator('#owner-name-sharing-status')).toHaveText(
      'The service rejected this change. Check the current status before approving again.',
    );
    assert.equal(
      mutations.filter((request) => request.path.endsWith('/sharing')).length,
      beforeShare + 1,
    );

    revokeStaleShareOnce = true;
    await page.locator('#owner-name-sharing-share').click();
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'The previous UserInfo share was revoked.',
    );
    await expect(page.locator('#owner-name-sharing')).not.toContainText(
      'Shared with UserInfo service until',
    );
    const shareRequests = mutations.filter((request) => request.path.endsWith('/sharing'));
    const rejectedShare = shareRequests[0]!;
    const shareRequest = shareRequests[1]!;
    assert.notEqual(
      rejectedShare.operation,
      shareRequest.operation,
      'definite rejection requires a new operation',
    );
    const shareBody = JSON.parse(shareRequest.body) as Record<string, unknown>;
    assert.equal(shareRequest.ifMatch, '"2"', 'system sharing CAS uses saved record revision');
    assert.equal((shareBody['source'] as Record<string, unknown>)['revision'], 2);
    assert.equal(shareRequest.method, 'POST');
    await mkdir('artifacts', { recursive: true });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
      ),
      true,
      'the sharing panel fits a mobile viewport without horizontal overflow',
    );
    await page.screenshot({
      path: 'artifacts/mikaki-owner-name-sharing-mobile.png',
      fullPage: true,
    });

    // Model another authorized status change; the UI trusts a new GET, never an old receipt.
    currentSystemGrant()['status'] = 'active';
    currentSystemGrant()['authority_current'] = 1;
    await page.locator('#owner-name-sharing-refresh').click();
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'Shared with UserInfo service until',
    );
    await page.locator('#owner-name-sharing-client').selectOption('client-one');
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'Allowing https://app.example lets this app receive the saved name in identity information.',
    );
    loseReleaseOnce = true;
    await page.locator('#owner-name-sharing-allow').click();
    await expect(page.locator('#owner-name-sharing-retry')).toBeVisible();
    await expect(page.locator('#owner-name-sharing-retry')).toBeEnabled();
    await expect(page.locator('#name')).toBeDisabled();
    const firstRelease = mutations.filter((request) => request.path.endsWith('/releases'))[0]!;
    const firstReleaseBody = JSON.parse(firstRelease.body) as Record<string, unknown>;
    assert.equal(firstRelease.ifMatch, '"1"', 'RP grant CAS uses current system grant version');
    assert.equal(firstReleaseBody['expected_release_version'], 0);
    assert.equal(firstReleaseBody['client_id'], 'client-one');
    fixture.release = {
      ...fixture.release,
      release_version: 2,
      release_status: 'revoked',
    };
    await page.locator('#owner-name-sharing-retry').click();
    await expect(page.locator('#owner-name-sharing-retry')).toHaveCount(0);
    // The durable receipt is historical: the fresh status read says another actor
    // revoked it, so the UI must not display the name as currently released.
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'The prior app permission was withdrawn.',
    );
    await expect(page.locator('#owner-name-sharing')).not.toContainText(
      'This app can receive the name until',
    );
    await expect(page.locator('#owner-name-sharing-allow')).toBeVisible();
    await page.locator('#owner-name-sharing-allow').click();
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'This app can receive the name until',
    );
    const consentRequests = mutations.filter(
      (request) => request.path.endsWith('/releases') && request.method === 'POST',
    );
    assert.equal(
      (JSON.parse(consentRequests[2]!.body) as Record<string, unknown>)['expected_release_version'],
      2,
    );

    await page.clock.fastForward(61_000);
    mockNow += 61;
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'The prior app permission has expired.',
    );
    await expect(page.locator('#owner-name-sharing')).not.toContainText(
      'This app can receive the name until',
    );
    await page.locator('#owner-name-sharing-refresh').click();
    await expect(page.locator('#owner-name-sharing-allow')).toBeVisible();
    await page.locator('#owner-name-sharing-allow').click();
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'This app can receive the name until',
    );
    const releaseAttempts = mutations.filter(
      (request) => request.path.endsWith('/releases') && request.method === 'POST',
    );
    assert.equal(releaseAttempts.length, 4);
    assert.deepEqual(
      releaseAttempts[0],
      releaseAttempts[1],
      'retry uses identical body, fence and operation ID',
    );
    assert.equal(
      (JSON.parse(releaseAttempts[0]!.body) as Record<string, unknown>)['client_id'],
      'client-one',
    );
    assert.equal(
      (JSON.parse(releaseAttempts[3]!.body) as Record<string, unknown>)['expected_release_version'],
      3,
      'renewal after expiry uses the version observed by the fresh status read',
    );

    await page.locator('#name').fill('Updated self-asserted name');
    await page.locator('#save').click();
    await expect(page.locator('#name')).toHaveValue('Updated self-asserted name');
    await expect.poll(() => completedProfileWrites).toBe(3);
    await expect(page.locator('#status')).toHaveText('Saved.');
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'The saved name changed. Refresh sharing status before reviewing access.',
    );
    await expect(page.locator('#owner-name-sharing-preview-heading')).toHaveCount(0);
    await expect(page.locator('#owner-name-sharing')).not.toContainText(
      'This app can receive the name until',
    );
    await page.locator('#owner-name-sharing-refresh').click();
    await expect(page.locator('#owner-name-sharing')).toContainText('Updated self-asserted name');
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'Current encrypted record revision: 3',
    );
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'The previous UserInfo share was revoked.',
    );
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'The prior app permission was withdrawn.',
    );
    await expect(page.locator('#owner-name-sharing-withdraw')).toHaveCount(0);
    await expect(page.locator('#owner-name-sharing')).not.toContainText(
      'Shared with UserInfo service until',
    );
    await expect(page.locator('#owner-name-sharing')).not.toContainText(
      'This app can receive the name until',
    );
    await page.locator('#owner-name-sharing-share').click();
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'Shared with UserInfo service until',
    );
    await page.locator('#owner-name-sharing-allow').click();
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'This app can receive the name until',
    );
    const revisedShare = mutations
      .filter((request) => request.path.endsWith('/sharing') && request.method === 'POST')
      .at(-1)!;
    const revisedShareBody = JSON.parse(revisedShare.body) as Record<string, unknown>;
    assert.equal(revisedShare.ifMatch, '"3"', 'new name share uses its saved revision');
    assert.equal((revisedShareBody['source'] as Record<string, unknown>)['revision'], 3);
    assert.equal(revisedShareBody['expected_grant_version'], 2);
    const revisedRelease = mutations
      .filter((request) => request.path.endsWith('/releases') && request.method === 'POST')
      .at(-1)!;
    assert.equal(revisedRelease.ifMatch, '"3"', 'RP consent uses the new system grant version');
    assert.equal(
      (JSON.parse(revisedRelease.body) as Record<string, unknown>)['expected_release_version'],
      5,
      'RP reconsent uses the trigger-revoked release version',
    );

    recipientUnavailable = true;
    await page.locator('#owner-name-sharing-refresh').click();
    await expect(page.locator('#owner-name-sharing')).toContainText(
      'The UserInfo recipient key could not be verified. New sharing grants are unavailable; existing access can still be withdrawn.',
    );
    await expect(page.locator('#owner-name-sharing-allow')).toHaveCount(0);
    await expect(page.locator('#owner-name-sharing-withdraw')).toBeVisible();

    loseWithdrawOnce = true;
    await page.locator('#owner-name-sharing-withdraw').click();
    await expect(page.locator('#owner-name-sharing-retry')).toBeVisible();
    await expect(page.locator('#owner-name-sharing-retry')).toBeEnabled();
    await expect(page.locator('#name')).toBeDisabled();
    await page.getByRole('button', { name: 'Lock Vault', exact: true }).click();
    await expect(page.locator('#owner-name-sharing')).toHaveCount(0);
    await expect(page.locator('#owner-name-sharing-retry')).toHaveCount(0);
    await expect(page.locator('#name')).toHaveCount(0);
    assert.equal(
      await page.evaluate(() =>
        (window as unknown as { readCeremonies: () => number }).readCeremonies(),
      ),
      1,
      'sharing uses the unlocked owner key without another passkey ceremony',
    );
    assert.deepEqual(errors, []);
  } finally {
    await browser?.close();
    await harness.close();
  }
});
