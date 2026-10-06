import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';
import { newOwnerNote, encodeOwnerNote } from '../../crates/worker/ui/vault-note.ts';
import { agentKeyId } from '../../crates/worker/ui/agent-crypto.ts';
import { encodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';

test('OwnerWorkspace reviews an untrusted note proposal and separately retries its exact encrypted save', async () => {
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
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Owner note proposal review' });

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

    const rsa = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt'],
    );
    const recipientJwk = await crypto.subtle.exportKey('jwk', rsa.publicKey);
    const recipientKeyId = await agentKeyId(recipientJwk);
    const grantId = encodeBase64Url(randomBytes(32));
    const proposalId = encodeBase64Url(randomBytes(32));
    const requestHash = encodeBase64Url(randomBytes(32));
    const payload = new TextDecoder().decode(
      encodeOwnerNote(newOwnerNote('Suggested profile', 'Untrusted self-asserted note.')),
    );
    const expiresAt = now + 1800;
    let vaultId: string | null = null;
    let proposalState: 'pending' | 'approved' | 'committed' = 'pending';
    let committedCandidate: Record<string, unknown> | null = null;
    let committedRecord: Record<string, unknown> | null = null;
    let statusReads = 0;
    let loseCommitResponse = false;
    const decisionBodies: string[] = [];
    const prepares: { body: string; operation: string | undefined }[] = [];
    const commits: { body: string; operation: string | undefined; fence: string | undefined }[] =
      [];
    const errors: string[] = [];

    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    await context.addInitScript(
      ({ credentialBytes }) => {
        let ceremonies = 0;
        Object.defineProperty(window, 'readOwnerNoteCeremonies', { value: () => ceremonies });
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

    const grant = () => ({
      grant_id: grantId,
      account_id: 'owner',
      delegate: 'writer',
      provider: 'test-provider',
      resource: 'https://agent.test/mcp',
      source_revision: 1,
      operations: '["read","propose"]',
      document_ids: '["owner_note"]',
      created_at: now - 60,
      expires_at: expiresAt + 3600,
      revoked: 0,
      revision: 1,
      recipient_key_id: recipientKeyId,
      storage_version: 2,
      source_origin: origin,
      source_vault_id: vaultId,
      source_collection_id: 'personal',
      source_record_id: 'name',
      source_kind: 'name',
      source_ciphertext_sha256: encodeBase64Url(randomBytes(32)),
      source_key_generation: 1,
      source_owner_key_revision: 1,
      active: 1,
    });
    const target = () => ({
      storage_version: 2,
      origin,
      owner_id: 'owner',
      vault_id: vaultId,
      collection_id: 'personal',
      record_id: 'owner_note',
      kind: 'owner_note',
      revision: 0,
      ciphertext_sha256: null,
      deleted: false,
    });
    const authority = { key_generation: 1, owner_key_revision: 1 };
    const proposal = () => ({
      proposal_id: proposalId,
      grant_id: grantId,
      grant_revision: 1,
      request_hash: requestHash,
      attribute_id: 'owner_note',
      base_revision: 0,
      payload: proposalState === 'committed' ? payload : payload,
      expires_at: expiresAt,
      created_at: now - 60,
      state: proposalState,
      storage_version: 2,
      target_origin: origin,
      target_vault_id: vaultId,
      target_collection_id: 'personal',
      target_record_id: 'owner_note',
      target_kind: 'owner_note',
      target_ciphertext_sha256: null,
      target_deleted: 0,
      target_key_generation: 1,
      target_owner_key_revision: 1,
      delegate: 'writer',
      provider: 'test-provider',
      operation_id: committedCandidate ? (commits[0]?.operation ?? null) : null,
      candidate: committedCandidate ? JSON.stringify(committedCandidate) : null,
      result_revision: proposalState === 'committed' ? 1 : null,
      target: target(),
      authority,
      destination: 'owner-vault-record',
      untrusted_content: true,
    });
    const status = () => ({
      grants: [grant()],
      audit: [],
      proposals: [],
      drafts: [],
      storage_version: 2,
      record_proposals: [proposal()],
      recipient: {
        public_jwk: recipientJwk,
        key_id: recipientKeyId,
        resource: 'https://agent.test/mcp',
        enabled: true,
      },
    });

    await context.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const path = url.pathname;
      if (path === '/vault/agents/record-status') {
        statusReads++;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(status()),
        });
        return;
      }
      if (path === '/vault/agents/record-decide' && request.method() === 'POST') {
        const body = request.postData()!;
        decisionBodies.push(body);
        assert.deepEqual(JSON.parse(body), {
          proposal_id: proposalId,
          request_hash: requestHash,
          approve: true,
        });
        proposalState = 'approved';
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            proposal_id: proposalId,
            request_hash: requestHash,
            state: 'approved',
            target: target(),
            authority,
            expires_at: expiresAt,
            destination: 'owner-vault-record',
            untrusted_content: true,
          }),
        });
        return;
      }
      if (path === '/vault/agents/record-prepare' && request.method() === 'POST') {
        const body = request.postData()!;
        const input = JSON.parse(body) as { candidate: string; operation_id: string };
        prepares.push({ body, operation: request.headers()['x-operation-id'] });
        committedCandidate = JSON.parse(input.candidate) as Record<string, unknown>;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            proposal_id: proposalId,
            operation_id: input.operation_id,
            candidate_sha256: createHash('sha256').update(input.candidate).digest('base64url'),
          }),
        });
        return;
      }
      if (path === '/vault/records/personal/owner_note/approved' && request.method() === 'POST') {
        const body = request.postData()!;
        const operation = request.headers()['x-operation-id'];
        commits.push({
          body,
          operation,
          fence: request.headers()['if-none-match'] ?? request.headers()['if-match'],
        });
        assert.equal(body, JSON.stringify(committedCandidate));
        assert.equal(request.headers()['x-attribute-proposal'], proposalId);
        assert.equal(request.headers()['x-proposal-hash'], requestHash);
        assert.equal(request.headers()['if-none-match'], '*');
        committedRecord = {
          format_version: 2,
          owner_id: 'owner',
          origin,
          vault_id: vaultId,
          key_generation: 1,
          owner_key_revision: 1,
          collection_id: 'personal',
          record_id: 'owner_note',
          kind: 'owner_note',
          revision: 1,
          ciphertext: committedCandidate!.ciphertext,
          key_envelope: committedCandidate!.key_envelope,
        };
        proposalState = 'committed';
        if (loseCommitResponse) {
          loseCommitResponse = false;
          await route.abort();
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: '{"revision":1,"deleted":false}',
        });
        return;
      }
      if (
        path === '/vault/records/personal/owner_note' &&
        request.method() === 'GET' &&
        committedRecord
      ) {
        await route.fulfill({
          status: 200,
          headers: { etag: '"1"', 'cache-control': 'no-store' },
          contentType: 'application/json',
          body: JSON.stringify(committedRecord),
        });
        return;
      }

      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: { ...(await request.allHeaders()), cookie: `__Host-op-sso=${secret}` },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      const responseBody = Buffer.from(await response.arrayBuffer());
      if (path === '/vault/owner-key' && request.method() === 'GET' && response.ok) {
        const key = JSON.parse(responseBody.toString('utf8')) as { vault_id: string };
        vaultId = key.vault_id;
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: responseBody,
      });
    });

    const page = await context.newPage();
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('dialog', (dialog) => void dialog.accept());
    await page.goto(`${origin}/vault?lang=en`);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toBeEnabled();
    await expect(page.locator('#owner-note-title')).toBeEnabled();
    assert.equal(
      await page.evaluate(() =>
        (window as unknown as { readOwnerNoteCeremonies: () => number }).readOwnerNoteCeremonies(),
      ),
      1,
    );
    await page.locator('#name').fill('Current owner');
    await page.locator('#save').click();
    await expect(page.locator('#status')).toHaveText('Saved.');
    await expect(page.locator('#save')).toBeEnabled();

    assert.equal(statusReads, 0, 'Opening the Vault does not fetch agent proposals');
    await page.locator('#owner-note-proposals summary').click();
    await expect(page.locator('#owner-note-proposal-' + proposalId)).toContainText(
      'Untrusted self-asserted note.',
    );
    assert.equal(statusReads, 1, 'Proposal status is fetched only after explicit expansion');
    await expect(page.locator('#owner-note-proposals-current-heading')).toBeVisible();
    await expect(page.locator('#owner-note-proposals')).toContainText(
      'No owner note has been saved yet.',
    );
    await expect(page.locator('#owner-note-proposal-' + proposalId)).toContainText('writer');

    await page.locator('#owner-note-title').fill('Unsent owner draft');
    await page.locator('#owner-note-proposal-approve-' + proposalId).click();
    await expect(page.locator('#owner-note-proposals-status')).toHaveText(
      'Unsaved changes. Save before leaving this page.',
    );
    assert.equal(decisionBodies.length, 0, 'A parent draft prevents even proposal approval');
    await page.locator('#owner-note-reload').click();
    await expect(page.locator('#owner-note-title')).toHaveValue('');
    await expect(page.locator('#owner-note-save')).toBeEnabled();

    await page.locator('#owner-note-proposal-approve-' + proposalId).click();
    await expect(page.locator('#owner-note-proposal-' + proposalId)).toContainText(
      'You approved this proposal. The Vault has not changed yet.',
    );
    assert.equal(decisionBodies.length, 1);
    await expect(page.locator('#owner-note-proposal-save-' + proposalId)).toBeVisible();
    await expect(page.locator('#owner-note-title')).toHaveValue('');

    loseCommitResponse = true;
    await page.locator('#owner-note-proposal-save-' + proposalId).click();
    await expect(page.locator('#owner-note-proposals-retry')).toBeEnabled();
    await expect(page.locator('#owner-note-title')).toBeDisabled();
    await expect(page.locator('#name')).toBeDisabled();
    assert.equal(prepares.length, 1);
    assert.equal(commits.length, 1);
    await page.locator('#owner-note-proposals-retry').click();
    await expect(page.locator('#owner-note-proposals-retry')).toHaveCount(0);
    await expect(page.locator('#owner-note-title')).toHaveValue('Suggested profile');
    await expect(page.locator('#owner-note-text')).toHaveValue('Untrusted self-asserted note.');
    await expect(page.locator('#owner-note-proposals-status')).toContainText('revision 1');
    assert.equal(prepares.length, 1, 'Retry does not repeat acknowledged record-prepare');
    assert.equal(commits.length, 2);
    assert.equal(
      commits[0]!.body,
      commits[1]!.body,
      'Retry sends the identical encrypted candidate',
    );
    assert.equal(commits[0]!.operation, commits[1]!.operation, 'Retry uses the same operation ID');
    assert.equal(
      commits[0]!.fence,
      commits[1]!.fence,
      'Retry keeps the exact revision precondition',
    );
    assert.equal(
      await page.evaluate(() =>
        (window as unknown as { readOwnerNoteCeremonies: () => number }).readOwnerNoteCeremonies(),
      ),
      1,
      'Proposal review and save do not trigger another PRF',
    );
    const width = await page.evaluate(() => ({
      client: document.documentElement.clientWidth,
      scroll: document.documentElement.scrollWidth,
    }));
    assert.ok(
      width.scroll <= width.client,
      `mobile layout overflows horizontally: ${JSON.stringify(width)}`,
    );
    await auditAccessibility(page, 'owner-note-proposals-mobile');
    assert.deepEqual(errors, []);
  } finally {
    await browser?.close();
    await harness.close();
  }
});
