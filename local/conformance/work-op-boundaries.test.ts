import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';

test('production Rust shim and named OP facade refuse public/raw administration and unenrolled changes', async () => {
  const root = new URL('../..', import.meta.url).pathname;
  const main = `${root}crates/worker/service/entrypoint.ts`;
  const harness = createTestHarness({
    root,
    workers: [
      {
        config: {
          name: 'work-op-boundary',
          main,
          compatibility_date: '2026-10-08',
          vars: { MIKAKI_ISSUER: 'https://work.test' },
          d1_databases: [
            {
              binding: 'DB',
              database_name: 'work-op-boundary',
              database_id: '00000000-0000-0000-0000-000000000001',
              migrations_dir: `${root}crates/worker/migrations`,
            },
          ],
        },
      },
      {
        config: {
          name: 'work-boundary-caller',
          main,
          compatibility_date: '2026-10-08',
          services: [
            { binding: 'OP_PUBLIC', service: 'work-op-boundary' },
            {
              binding: 'OP_AUTHORITY_ADMIN',
              service: 'work-op-boundary',
              entrypoint: 'OpAuthorityAdmin',
            },
          ],
        },
      },
    ],
  });
  try {
    await harness.listen();
    const op = harness.getWorker('work-op-boundary');
    await op.applyD1Migrations('DB');
    const caller = await harness.getWorker('work-boundary-caller').getEnv();
    for (const binding of [caller.OP_PUBLIC, caller.OP_AUTHORITY_ADMIN]) {
      assert.equal((await binding.administer_op_authority()).status, 404);
    }
    assert.equal(
      (await caller.OP_PUBLIC.fetch('https://work.test/authority', { method: 'POST', body: '{}' }))
        .status,
      404,
    );
    const response = await caller.OP_AUTHORITY_ADMIN.fetch('https://private.invalid/authority', {
      method: 'POST',
      body: JSON.stringify({
        action: 'revoke-account',
        account: 'owner',
        expected_epoch: 0,
        actor: 'fixture',
        reason: 'unenrolled authority',
      }),
    });
    assert.equal(response.status, 409);
    const { DB } = await op.getEnv();
    assert.equal(await DB.prepare('SELECT count(*) AS n FROM account_security').first('n'), 0);
    assert.equal(
      await DB.prepare(
        "SELECT count(*) AS n FROM sqlite_master WHERE name='work_authority_checkpoint'",
      ).first('n'),
      0,
    );
  } finally {
    await harness.close();
  }
});
