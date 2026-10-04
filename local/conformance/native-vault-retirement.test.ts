import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';

const issuer = 'https://issuer.example';

test('retired native Vault consent endpoints return 404 even for historical transactions', async () => {
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
    assert.equal(await DB.prepare('SELECT count(*) AS n FROM vault_oauth_consent').first('n'), 0);
    assert.equal(await DB.prepare('SELECT count(*) AS n FROM vault_oauth_grant').first('n'), 0);
  } finally {
    await harness.close();
  }
});
