import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';
import { agentKeyId } from '../../crates/worker/ui/agent-crypto.ts';
import { encodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';

test('OwnerWorkspace grants one selected encrypted record, separately allows note proposals, and revokes', async () => {
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
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Owner Agent grants UI' });

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

    const recipientPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt'],
    );
    const recipientJwk = await crypto.subtle.exportKey('jwk', recipientPair.publicKey);
    const recipientKeyId = await agentKeyId(recipientJwk);
    const resource = 'https://agent.example/mcp';
    let vaultId: string | null = null;
    let grantRow: Record<string, unknown> | null = null;
    let capabilityReceipt: Record<string, unknown> | null = null;
    const capabilityReceipts: Record<string, unknown>[] = [];
    let loseGrantResponse = false;
    let statusReads = 0;
    let ceremonies = 0;
    const grantBodies: string[] = [];
    const capabilityBodies: string[] = [];
    const revokeBodies: string[] = [];
    const errors: string[] = [];

    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    await context.exposeFunction('recordAgentGrantCeremony', () => {
      ceremonies++;
    });
    await context.addInitScript(
      ({ credentialBytes }) => {
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
              await (
                window as unknown as { recordAgentGrantCeremony: () => Promise<void> }
              ).recordAgentGrantCeremony();
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

    const status = () => ({
      grants: grantRow ? [grantRow] : [],
      audit: [],
      proposals: [],
      drafts: [],
      storage_version: 2,
      record_proposals: [],
      recipient: { public_jwk: recipientJwk, key_id: recipientKeyId, resource, enabled: true },
    });
    const currentTarget = () => ({
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
    const currentAuthority = { key_generation: 1, owner_key_revision: 1 };

    await context.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const path = url.pathname;
      if (path === '/vault/agents/record-status' && request.method() === 'GET') {
        statusReads++;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(status()),
        });
        return;
      }
      if (path === '/vault/agents/grants' && request.method() === 'POST') {
        const body = request.postData()!;
        grantBodies.push(body);
        const input = JSON.parse(body) as Record<string, any>;
        assert.equal(input.storage_version, 2);
        assert.equal(input.resource, resource);
        assert.equal(input.recipient_key_id, recipientKeyId);
        assert.deepEqual(input.operations, ['list', 'search', 'read', 'propose']);
        assert.deepEqual(input.document_ids, ['name']);
        assert.equal(input.source.revision, 1);
        assert.equal(input.source.record_id, 'name');
        assert.equal(input.authority.key_generation, 1);
        assert.doesNotMatch(
          body,
          /Current owner|private note/i,
          'source text is not sent in plaintext',
        );
        const source = input.source as Record<string, any>;
        grantRow = {
          grant_id: input.grant_id,
          account_id: 'owner',
          delegate: input.delegate,
          provider: input.provider,
          resource: input.resource,
          source_revision: source.revision,
          operations: JSON.stringify(input.operations),
          document_ids: JSON.stringify(input.document_ids),
          created_at: now,
          expires_at: input.expires_at,
          revoked: 0,
          revision: 1,
          recipient_key_id: input.recipient_key_id,
          storage_version: 2,
          source_origin: source.origin,
          source_vault_id: source.vault_id,
          source_collection_id: source.collection_id,
          source_record_id: source.record_id,
          source_kind: source.kind,
          source_ciphertext_sha256: source.ciphertext_sha256,
          source_key_generation: input.authority.key_generation,
          source_owner_key_revision: input.authority.owner_key_revision,
          active: 1,
        };
        if (loseGrantResponse) {
          loseGrantResponse = false;
          await route.abort();
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ grant_id: input.grant_id, expires_at: input.expires_at }),
        });
        return;
      }
      if (path === '/vault/agents/record-capability' && request.method() === 'POST') {
        const body = request.postData()!;
        capabilityBodies.push(body);
        const input = JSON.parse(body) as Record<string, any>;
        assert.equal(input.grant_id, grantRow?.grant_id);
        assert.deepEqual(input.target, currentTarget());
        assert.deepEqual(input.authority, currentAuthority);
        const expiresAt = Math.min(
          Number(grantRow!.expires_at),
          Math.floor(Date.now() / 1000) + 3600,
        );
        capabilityReceipt = {
          grant_id: input.grant_id,
          target: input.target,
          authority: input.authority,
          expires_at: expiresAt,
        };
        capabilityReceipts.push(capabilityReceipt);
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(capabilityReceipt),
        });
        return;
      }
      if (path === '/vault/agents/revoke' && request.method() === 'POST') {
        const body = request.postData()!;
        revokeBodies.push(body);
        const input = JSON.parse(body) as { grant_id: string };
        assert.equal(input.grant_id, grantRow?.grant_id);
        grantRow = { ...grantRow!, revoked: 1, active: 0 };
        capabilityReceipt = null;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ revoked: true }),
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
    assert.equal(statusReads, 0, 'Agent status remains lazy while the Vault is merely unlocked');
    await page.locator('#name').fill('Current owner');
    await page.locator('#save').click();
    await expect(page.locator('#status')).toHaveText('Saved.');
    await expect(page.locator('#save')).toBeEnabled();
    assert.equal(ceremonies, 1);

    await page.locator('#owner-agent-grants summary').click();
    await expect(page.locator('#owner-agent-grants-source')).toHaveValue('name');
    await expect(page.locator('#owner-agent-grants')).toContainText('Current owner');
    await expect(page.locator('#owner-agent-grants')).toContainText(resource);
    await expect(page.locator('#owner-agent-grants')).toContainText(recipientKeyId);
    assert.equal(statusReads, 1, 'Configured recipient and grants load only on explicit expansion');

    await page.locator('#owner-agent-grants-delegate').fill('researcher');
    await page.locator('#owner-agent-grants-provider').fill('Example assistant');
    await page.locator('#owner-agent-grants-lifetime').selectOption('3600');
    await page.locator('#owner-agent-grants-propose-permission').check();
    await page.locator('#owner-agent-grants-consent').check();
    loseGrantResponse = true;
    await page.locator('#owner-agent-grants-issue').click();
    await expect(page.locator('#owner-agent-grants-retry')).toBeEnabled();
    await expect(page.locator('#name')).toBeDisabled();
    assert.equal(grantBodies.length, 1);
    await page.locator('#owner-agent-grants-retry').click();
    await expect(page.locator('#owner-agent-grant-token')).toBeVisible();
    assert.equal(grantBodies.length, 2);
    assert.equal(
      grantBodies[0],
      grantBodies[1],
      'Ambiguous grant result retries the identical body/token hash',
    );
    await expect(page.locator('#owner-agent-grant-token')).toContainText('mag_');
    await expect(page.locator('#owner-agent-grants')).toContainText(
      'No execution permission is issued.',
    );
    assert.equal(
      ceremonies,
      1,
      'Grant creation uses the unlocked Owner Vault key without another PRF ceremony',
    );

    const grantId = String(grantRow!.grant_id);
    await page.locator('#owner-agent-grant-token-dismiss').click();
    await expect(page.locator('#owner-agent-grant-token')).toHaveCount(0);
    await expect(page.locator(`#owner-agent-capability-consent-${grantId}`)).toBeVisible();
    await page.locator(`#owner-agent-capability-consent-${grantId}`).check();
    await page.locator(`#owner-agent-capability-allow-${grantId}`).click();
    await expect(page.locator('#owner-agent-grants-status')).toContainText('active through');
    assert.equal(capabilityBodies.length, 1);
    assert.deepEqual(JSON.parse(capabilityBodies[0]!).target, currentTarget());
    assert.ok(capabilityReceipts[0]);
    assert.ok(Number(capabilityReceipts[0].expires_at) <= Math.floor(Date.now() / 1000) + 3600);
    assert.ok(Number(capabilityReceipts[0].expires_at) <= Number(grantRow!.expires_at));

    await page.locator(`#owner-agent-grant-revoke-${grantId}`).click();
    await expect(page.locator(`#owner-agent-grant-${grantId}`)).toContainText(
      'Inactive or expired.',
    );
    await expect(page.locator('#owner-agent-grant-token')).toHaveCount(0);
    assert.deepEqual(revokeBodies, [JSON.stringify({ grant_id: grantId })]);
    assert.equal(ceremonies, 1);
    const dimensions = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    assert.ok(
      dimensions.scrollWidth <= dimensions.clientWidth,
      `mobile layout overflows horizontally: ${JSON.stringify(dimensions)}`,
    );
    await auditAccessibility(page, 'owner-agent-grants-mobile');
    assert.deepEqual(errors, []);
  } finally {
    await browser?.close();
    await harness.close();
  }
});
