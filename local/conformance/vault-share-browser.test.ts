import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chromium } from '@playwright/test';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { createTestHarness } from 'wrangler';
import { decodeBase64Url, sealAttribute } from '../../crates/worker/ui/vault-crypto.ts';

test('Vault screen shares an unlocked name and revokes it with explicit owner actions', async () => {
  const credential = new TextEncoder().encode('credential');
  const prfOutput = new Uint8Array(32).fill(0x31);
  const saved = await sealAttribute(
    new TextEncoder().encode('Browser owner'),
    prfOutput,
    credential,
    new Uint8Array(32).fill(0x51),
    'https://mikaki.test',
    'name',
    1,
  );
  const keys = ml_kem768.keygen(new Uint8Array(64).fill(0x71));
  const keyId = createHash('sha256').update(keys.publicKey).digest('base64url');
  const directory = {
    service_id: 'userinfo',
    algorithm: 'ML-KEM-768',
    envelope_suite: 'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1',
    key_id: keyId,
    public_key: Buffer.from(keys.publicKey).toString('base64url'),
    generation: 1,
    revision: 2,
  };
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      { configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname },
    ],
  });
  let browser;
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    const script = await worker.fetch('https://mikaki.test/vault/vault.js');
    assert.equal(script.status, 200);
    const bundle = await script.text();
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const pageErrors: string[] = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    await page.addInitScript(
      ({ credentialBytes, prfBytes }) => {
        class MockPublicKeyCredential {
          rawId = Uint8Array.from(credentialBytes).buffer;
          getClientExtensionResults() {
            return { prf: { results: { first: Uint8Array.from(prfBytes).buffer } } };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockPublicKeyCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: { get: async () => new MockPublicKeyCredential() },
        });
      },
      { credentialBytes: [...credential], prfBytes: [...prfOutput] },
    );
    let active = false;
    let sharedBody: unknown;
    let shareHeaders: Record<string, string> | undefined;
    let revokeHeaders: Record<string, string> | undefined;
    let releaseActive = false;
    let releaseVersion = 0;
    let releaseBody: unknown;
    let releaseHeaders: Record<string, string> | undefined;
    await page.route('https://mikaki.test/**', async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (path === '/vault') {
        await route.fulfill({
          contentType: 'text/html; charset=utf-8',
          body: '<!doctype html><html lang="en"><body><div id="app"></div><script type="module" src="/vault/vault.js"></script></body></html>',
        });
      } else if (path === '/vault/vault.js') {
        await route.fulfill({ contentType: 'text/javascript; charset=utf-8', body: bundle });
      } else if (path === '/vault/session') {
        await route.fulfill({
          json: {
            account_id: 'owner',
            credential_id: Buffer.from(credential).toString('base64url'),
          },
        });
      } else if (path === '/vault/attributes/name') {
        await route.fulfill({ json: { ...saved, revision: 1 } });
      } else if (path === '/vault/recipient-keys/userinfo') {
        await route.fulfill({ json: directory });
      } else if (path === '/vault/shares/userinfo/name' && request.method() === 'GET') {
        await route.fulfill({
          json: {
            enabled: true,
            grant_ttl_seconds: 3600,
            active,
            grant_version: active ? 1 : null,
            expires_at: active ? Math.floor(Date.now() / 1000) + 3600 : null,
          },
        });
      } else if (path === '/vault/shares/userinfo/name' && request.method() === 'POST') {
        sharedBody = request.postDataJSON();
        shareHeaders = request.headers();
        active = true;
        await route.fulfill({ json: { grant_version: 1, attribute_revision: 1 } });
      } else if (path === '/vault/shares/userinfo/name' && request.method() === 'DELETE') {
        revokeHeaders = request.headers();
        active = false;
        releaseActive = false;
        await route.fulfill({ json: { grant_version: 2, attribute_revision: 1 } });
      } else if (path === '/vault/releases/name' && request.method() === 'GET') {
        await route.fulfill({
          json: {
            enabled: true,
            ttl_seconds: 3600,
            policy_revision: 2,
            share_active: active,
            share_grant_version: active ? 1 : null,
            clients: [
              {
                client_id: 'rp',
                sector_identifier: 'rp.example',
                client_revision: 3,
                connection_grant_version: 4,
                release_active: releaseActive,
                release_version: releaseVersion || null,
                expires_at: releaseActive ? Math.floor(Date.now() / 1000) + 3600 : null,
              },
            ],
          },
        });
      } else if (path === '/vault/releases/name' && request.method() === 'POST') {
        releaseBody = request.postDataJSON();
        releaseHeaders = request.headers();
        releaseActive = true;
        releaseVersion++;
        await route.fulfill({
          json: { client_id: 'rp', release_version: releaseVersion, active: true },
        });
      } else if (path === '/vault/releases/name' && request.method() === 'DELETE') {
        releaseHeaders = request.headers();
        releaseActive = false;
        releaseVersion++;
        await route.fulfill({
          json: { client_id: 'rp', release_version: releaseVersion, active: false },
        });
      } else {
        await route.fulfill({ status: 404 });
      }
    });

    await page.goto('https://mikaki.test/vault');
    await page.getByRole('button', { name: 'Unlock with passkey' }).click();
    await page.getByRole('button', { name: 'Share saved name with UserInfo service' }).click();
    await page.getByText('Your saved name is shared with the UserInfo service.').waitFor();
    assert.deepEqual(pageErrors, []);
    assert.ok(shareHeaders);
    assert.equal(shareHeaders['if-match'], '"1"');
    assert.equal(shareHeaders['content-type'], 'application/json');
    assert.match(shareHeaders['x-operation-id'], /^[A-Za-z0-9_-]{43}$/);
    assert.ok(sharedBody && typeof sharedBody === 'object');
    const body = sharedBody as Record<string, unknown>;
    assert.equal(body.key_id, keyId);
    assert.equal(body.generation, 1);
    assert.equal(body.directory_revision, 2);
    assert.equal(
      body.ciphertext_sha256,
      createHash('sha256').update(decodeBase64Url(saved.ciphertext)).digest('base64url'),
    );
    assert.equal(decodeBase64Url(String(body.frame)).length, 1187);

    await page.getByRole('button', { name: 'Allow this app to receive my name' }).click();
    await page.getByText('Name permission granted to this app.').waitFor();
    assert.deepEqual(releaseBody, {
      client_id: 'rp',
      client_revision: 3,
      connection_grant_version: 4,
      policy_revision: 2,
    });
    assert.equal(releaseHeaders?.['if-match'], '"1"');
    await page.getByRole('button', { name: 'Withdraw name permission' }).click();
    await page.getByText('Name permission withdrawn.').waitFor();
    assert.equal(releaseHeaders?.['if-match'], '"1"');

    await page.getByRole('button', { name: 'Stop sharing with UserInfo service' }).click();
    await page.getByText('Sharing stopped.').waitFor();
    assert.ok(revokeHeaders);
    assert.equal(revokeHeaders['if-match'], '"1"');
    assert.match(revokeHeaders['x-operation-id'], /^[A-Za-z0-9_-]{43}$/);
    assert.deepEqual(pageErrors, []);
  } finally {
    await browser?.close();
    await harness.close();
  }
});
