import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createTestHarness } from 'wrangler';

const configPath = fileURLToPath(
  new URL('../../crates/userinfo-claim-worker/wrangler.local.jsonc', import.meta.url),
);
const root = fileURLToPath(new URL('../..', import.meta.url));

test('claim Worker requires ClaimStore even when the retired local-test flag is set', async () => {
  const config = JSON.parse((await readFile(configPath, 'utf8')).replace(/,\s*([}\]])/g, '$1'));
  config.main = `${root}/crates/userinfo-claim-worker/build/worker/shim.mjs`;
  config.services = [];
  config.vars.MIKAKI_LEGACY_CLAIM_STORE = 'local-test';
  const harness = createTestHarness({ root, workers: [{ config }] });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-userinfo-claim-worker');
    const env = await worker.getEnv();
    assert.equal('DB' in env, false);
    assert.equal('VAULT_BLOBS' in env, false);
    const keyId = createHash('sha256').update('key').digest('base64url');
    assert.equal((await worker.fetch('https://internal.invalid/internal/ready')).status, 503);
    const response = await worker.fetch(
      `https://internal.invalid/internal/recipient-keys/${keyId}/verify`,
    );
    assert.equal(response.status, 503);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    const rejected = await worker.fetch(
      `https://internal.invalid/internal/recipient-keys/${keyId}/validate-envelope`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          origin: 'https://mikaki.test',
          account_id: 'owner',
          revision: 1,
          ciphertext: 'AA',
          frame: 'AA',
        }),
      },
    );
    assert.equal(rejected.status, 404);
    const absent = await worker.fetch('https://internal.invalid/internal/claims/name', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        access_hash: createHash('sha256').update('unused').digest('base64url'),
      }),
    });
    assert.equal(absent.status, 503, 'missing authority cannot be mistaken for absent consent');
    const malformed = await worker.fetch('https://internal.invalid/internal/claims/name', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ access_hash: 'short' }),
    });
    assert.equal(malformed.status, 503);
    const unknown = await worker.fetch('https://internal.invalid/');
    assert.equal(unknown.status, 404);
  } finally {
    await harness.close();
  }
});
