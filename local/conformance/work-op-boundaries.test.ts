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
            { binding: 'WORK_GIT_STORE', service: 'work-op-boundary', entrypoint: 'WorkGitStore' },
            {
              binding: 'WORK_MINT_STORE',
              service: 'work-op-boundary',
              entrypoint: 'WorkMintStore',
            },
            {
              binding: 'WORK_EFFECT_STORE',
              service: 'work-op-boundary',
              entrypoint: 'WorkEffectStore',
            },
          ],
        },
      },
    ],
  });
  try {
    await harness.listen();
    const op = harness.getWorker('work-op-boundary');
    for (const path of [
      '/work/session',
      '/work/source-review',
      '/work/source-review.js',
      '/work/source-review.css',
      '/work/preparations',
      '/work/preparation-review',
      '/work/preparation-review.js',
      '/work/preparation-review.css',
    ]) {
      assert.equal((await op.fetch(`https://work.test${path}`)).status, 404);
    }
    await op.applyD1Migrations('DB');
    const caller = await harness.getWorker('work-boundary-caller').getEnv();
    for (const binding of [
      caller.OP_PUBLIC,
      caller.OP_AUTHORITY_ADMIN,
      caller.WORK_EFFECT_STORE,
      caller.WORK_MINT_STORE,
      caller.WORK_GIT_STORE,
    ]) {
      assert.equal((await binding.administer_op_authority()).status, 404);
      assert.equal((await binding.administer_work_effect()).status, 404);
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
    assert.equal(
      (await caller.OP_PUBLIC.fetch('https://work.test/effect', { method: 'POST', body: '{}' }))
        .status,
      404,
    );
    assert.equal(
      (
        await caller.WORK_EFFECT_STORE.fetch('https://private.invalid/effect', {
          method: 'POST',
          body: JSON.stringify({ action: 'initial-plan', attempt_id: 'a'.repeat(43) }),
        })
      ).status,
      409,
    );
    for (const input of [
      { action: 'git-plan', attempt_id: 'a'.repeat(43) },
      { action: 'preparation-verify', preparation_id: 'a'.repeat(43) },
      { action: 'git-execute', attempt_id: 'a'.repeat(43), plan: {} },
    ])
      assert.equal(
        (
          await caller.WORK_EFFECT_STORE.fetch('https://private.invalid/effect', {
            method: 'POST',
            body: JSON.stringify(input),
          })
        ).status,
        409,
      );
    for (const binding of [caller.OP_PUBLIC, caller.WORK_EFFECT_STORE, caller.WORK_MINT_STORE]) {
      assert.equal(
        (await binding.fetch('https://private.invalid/git-effect', { method: 'POST', body: '{}' }))
          .status,
        404,
      );
    }
    for (const binding of [caller.OP_PUBLIC, caller.WORK_EFFECT_STORE, caller.WORK_GIT_STORE]) {
      assert.equal(
        (await binding.fetch('https://private.invalid/mint-effect', { method: 'POST', body: '{}' }))
          .status,
        404,
      );
    }
    assert.equal(
      (
        await caller.WORK_GIT_STORE.fetch('https://private.invalid/git-effect', {
          method: 'POST',
          body: '{}',
        })
      ).status,
      409,
    );
    assert.equal(
      (
        await caller.WORK_GIT_STORE.fetch('https://private.invalid/effect', {
          method: 'POST',
          body: '{}',
        })
      ).status,
      404,
    );
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
