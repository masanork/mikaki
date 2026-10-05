import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';

const issuer = 'https://issuer.example';

test('fresh baseline omits retired Vault OAuth tables and consent endpoints return 404', async () => {
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.vars = { MIKAKI_ISSUER: issuer, MIKAKI_NATIVE_VAULT_OAUTH: 'preview' };
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [{ config }],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const page = await worker.fetch(`${issuer}/vault/oauth/consent?tx=historical`);
    assert.equal(page.status, 404);
    const post = await worker.fetch(`${issuer}/vault/oauth/consent`, {
      method: 'POST',
      headers: { Origin: issuer, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx: 'historical', decision: 'approve' }).toString(),
    });
    assert.equal(post.status, 404);
    const tables = await DB.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
    assert.equal(
      tables.results.some((row: { name: string }) => row.name.startsWith('vault_oauth_')),
      false,
    );
  } finally {
    await harness.close();
  }
});
