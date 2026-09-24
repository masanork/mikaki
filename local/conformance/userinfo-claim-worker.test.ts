import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createTestHarness } from 'wrangler';

const configPath = fileURLToPath(
  new URL('../../crates/userinfo-claim-worker/wrangler.local.jsonc', import.meta.url),
);
const root = fileURLToPath(new URL('../..', import.meta.url));

test('claim Worker fails closed without its Secrets Store binding', async () => {
  const harness = createTestHarness({ root, workers: [{ configPath }] });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-userinfo-claim-worker');
    await worker.applyD1Migrations('DB');
    const env = await worker.getEnv();
    const publicKey = Buffer.alloc(1184, 7);
    const keyId = createHash('sha256').update(publicKey).digest('base64url');
    await env.DB.prepare(
      `INSERT INTO vault_recipient_key
      (key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at)
      VALUES(?,'userinfo','ML-KEM-768',?,'VAULT_USERINFO_MLKEM_TEST',1,'staged',1,?)`,
    )
      .bind(keyId, publicKey, Math.floor(Date.now() / 1000))
      .run();
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
    assert.equal(rejected.status, 503);
    assert.equal(rejected.headers.get('Cache-Control'), 'no-store');
    const unknown = await worker.fetch('https://internal.invalid/');
    assert.equal(unknown.status, 404);
  } finally {
    await harness.close();
  }
});
