import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';

test('retired v1 Vault resource, sharing, release and attribute URLs are absent', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      { configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const retired: [string, string][] = [
      ['GET', '/vault/recipient-keys/userinfo'],
      ['GET', '/vault/shares/userinfo/name'],
      ['POST', '/vault/shares/userinfo/name'],
      ['DELETE', '/vault/shares/userinfo/name'],
      ['GET', '/vault/releases/name'],
      ['POST', '/vault/releases/name'],
      ['DELETE', '/vault/releases/name'],
      ['GET', '/vault/attributes/name'],
      ['PUT', '/vault/attributes/name'],
      ['DELETE', '/vault/attributes/name'],
      ['POST', '/vault/attributes/name/transfer'],
      ['POST', '/vault/attributes/name/approved'],
      ['GET', '/vault-api/attributes/name'],
    ];
    for (const [method, path] of retired) {
      const response = await worker.fetch(`https://mikaki.test${path}`, { method });
      assert.equal(response.status, 404, `${method} ${path} must stay retired`);
    }
  } finally {
    await harness.close();
  }
});
