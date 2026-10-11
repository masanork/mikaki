import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import type { D1Database } from '@cloudflare/workers-types';
import { OWNER_MIGRATIONS } from '../../scripts/production-owner-schema.ts';
import { WORK_MIGRATIONS } from '../../scripts/production-work-schema.ts';
import { productionWorkMigrationStore } from '../../scripts/production-work-migration.ts';
import {
  captureProductionWorkSnapshot,
  productionBootstrapStore,
  productionWorkInitialTip,
  PRODUCTION_WORK_TARGET,
  releaseProductionWorkFence,
} from '../../scripts/production-work-adoption.ts';
import type { BootstrapPlan } from '../../crates/work-checkpoint-worker/bootstrap.ts';
import { assertWorkAdministrationPolicy } from '../../scripts/work-administration-policy.ts';

async function fixture() {
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'migration',
          modules: true,
          script: 'export default {fetch(){return new Response(null,{status:404})}}',
          compatibilityDate: '2026-10-11',
          d1Databases: { DB: 'migration' },
        },
      ],
    }),
  );
  try {
    const DB = (await mf.getD1Database('DB')) as unknown as D1Database;
    const owner = await Promise.all(
      OWNER_MIGRATIONS.map(async ({ name }) => ({
        name,
        sql: await readFile('crates/worker/migrations/' + name, 'utf8'),
      })),
    );
    const work = await Promise.all(
      WORK_MIGRATIONS.map(async ({ name }) => ({
        name,
        sql: await readFile('crates/worker/work-migrations/' + name, 'utf8'),
      })),
    );
    await DB.prepare(
      'CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE)',
    ).run();
    for (const [index, migration] of owner.entries())
      await DB.batch([
        ...splitSqlQuery(migration.sql).map((sql) => DB.prepare(sql)),
        DB.prepare('INSERT INTO d1_migrations VALUES(?,?)').bind(index + 1, migration.name),
      ]);
    await DB.prepare("INSERT INTO account_security VALUES('existing-owner',3,1)").run();
    const store = productionWorkMigrationStore(DB, owner, work);
    return { DB, owner, work, store, close: () => mf.dispose() };
  } catch (error) {
    await mf.dispose();
    throw error;
  }
}
test('optional operator policy permits one owner while required policy refuses the same identity', () => {
  const operators = { primary: 'same-owner', checkpoint: 'same-owner' };
  assert.equal(
    assertWorkAdministrationPolicy(
      { format_version: 1, operator_separation: 'optional' },
      operators,
    ).checkpoint_required,
    true,
  );
  assert.throws(
    () =>
      assertWorkAdministrationPolicy(
        { format_version: 1, operator_separation: 'required' },
        operators,
      ),
    /separate_operators_required/,
  );
  assert.equal(
    assertWorkAdministrationPolicy(
      { format_version: 1, operator_separation: 'required' },
      { ...operators, checkpoint: 'other-owner' },
    ).control_plane_separation_verified,
    false,
  );
});
test('atomic additive migration fences old app and named-service SQL, preserves owner rows, then opens only a matched initial checkpoint', async () => {
  const f = await fixture();
  try {
    assert.equal((await f.store.inspect()).phase, 'owner');
    await f.store.apply();
    assert.equal((await f.store.inspect()).phase, 'work-fenced');
    for (const sql of [
      "INSERT INTO account_security VALUES('new-owner',1,1)",
      "UPDATE account_security SET epoch=4 WHERE account_id='existing-owner'",
      "DELETE FROM account_security WHERE account_id='existing-owner'",
      'UPDATE bootstrap_state SET closed=1',
      'DELETE FROM work_schema_migrations WHERE id=12',
    ])
      await assert.rejects(f.DB.prepare(sql).run());
    const snapshot = await captureProductionWorkSnapshot(f.DB, f.owner, f.work, { fenced: true });
    const plan: BootstrapPlan = {
      format_version: 1,
      packet_sha256: '1'.repeat(64),
      allocation_sha256: '2'.repeat(64),
      ownership_review_sha256: '3'.repeat(64),
      quiescence_review_sha256: '4'.repeat(64),
      account_id: PRODUCTION_WORK_TARGET.account,
      database_id: PRODUCTION_WORK_TARGET.database,
      checkpoint_namespace_id: '5'.repeat(32),
      checkpoint_object_id: '6'.repeat(64),
      checkpoint_version_id: '22222222-2222-4222-8222-222222222222',
      initial: {
        authority: PRODUCTION_WORK_TARGET.authority,
        epoch: '7'.repeat(64),
        sequence: 0,
        tip: productionWorkInitialTip(snapshot),
      },
      release_floor: 1,
    };
    const primary = productionBootstrapStore(f.DB, snapshot, f.owner, f.work, { fenced: true });
    assert.equal((await primary.inspect(plan)).pristine, true);
    await primary.insert(plan);
    assert.equal((await primary.inspect(plan)).initial_only, true);
    const inspection = {
      authority: plan.initial.authority,
      object_id: plan.checkpoint_object_id,
      enrollment: plan,
      state: {
        checkpoint: plan.initial,
        pending: null,
        last: null,
        frozen: false,
        release_floor: 1,
      },
      ledger_entries: 0,
    };
    const checkpoint = {
      inspect: async () => inspection,
      enroll: async () => {
        throw new Error('No replay');
      },
    };
    await assert.rejects(
      releaseProductionWorkFence(f.DB, snapshot, plan, f.owner, f.work, {
        ...checkpoint,
        inspect: async () => ({ ...inspection, state: { ...inspection.state, frozen: true } }),
      }),
      /checkpoint_not_matched/,
    );
    await assert.rejects(
      f.DB.prepare("INSERT INTO account_security VALUES('new-owner',1,1)").run(),
    );
    await releaseProductionWorkFence(f.DB, snapshot, plan, f.owner, f.work, checkpoint);
    assert.equal((await f.store.inspect()).phase, 'work');
    assert.equal(
      await f.DB.prepare(
        "SELECT epoch FROM account_security WHERE account_id='existing-owner'",
      ).first('epoch'),
      3,
    );
    // Covered security writes still need OP frames after removing the temporary fence.
    await assert.rejects(
      f.DB.prepare("UPDATE account_security SET epoch=4 WHERE account_id='existing-owner'").run(),
    );
    await f.DB.prepare(
      'INSERT INTO auth_request_window(key_hash,window_start,attempts) VALUES(?,?,?)',
    )
      .bind('synthetic-test', 1, 1)
      .run();
    await assert.rejects(f.store.apply(), /not_admitted/);
  } finally {
    await f.close();
  }
});
test('a schema race rolls back the whole migration; a lost reply is inspected without migration replay', async () => {
  const f = await fixture();
  try {
    await f.store.inspect();
    await f.DB.prepare('CREATE TABLE unreviewed_race(value TEXT)').run();
    await assert.rejects(f.store.apply());
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) AS n FROM sqlite_schema WHERE name='work_schema_migrations'",
      ).first('n'),
      0,
    );
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM account_security').first('n'), 1);
    await assert.rejects(f.store.apply(), /not_admitted/);
  } finally {
    await f.close();
  }
  const g = await fixture();
  try {
    const lost = new Proxy(g.DB, {
      get(target, key) {
        if (key === 'batch')
          return async (statements: Parameters<D1Database['batch']>[0]) => {
            await target.batch(statements);
            throw new Error('lost');
          };
        const value = Reflect.get(target, key);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const store = productionWorkMigrationStore(lost, g.owner, g.work);
    await store.inspect();
    await assert.rejects(store.apply(), /lost/);
    assert.equal((await store.inspect()).phase, 'work-fenced');
    await assert.rejects(store.apply(), /not_admitted/);
  } finally {
    await g.close();
  }
});

test('a partial fence is refused and pre-enrollment safety opening preserves schema and owner data', async () => {
  const f = await fixture();
  try {
    await f.store.inspect();
    await f.store.apply();
    const { name, sql } = (await f.DB.prepare(
      "SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND name LIKE 'work_adoption_fence_%' LIMIT 1",
    ).first<{ name: string; sql: string }>())!;
    await f.DB.prepare(`DROP TRIGGER ${name}`).run();
    await assert.rejects(f.store.inspect(), /schema differs/);
    await f.DB.prepare(sql).run();
    await f.store.openUnenrolledFence();
    assert.equal((await f.store.inspect()).phase, 'work');
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').first('n'),
      0,
    );
    await f.DB.prepare(
      "UPDATE account_security SET epoch=4 WHERE account_id='existing-owner'",
    ).run();
    assert.equal(
      await f.DB.prepare(
        "SELECT epoch FROM account_security WHERE account_id='existing-owner'",
      ).first('epoch'),
      4,
    );
    await assert.rejects(f.store.openUnenrolledFence(), /temporary fence/);
  } finally {
    await f.close();
  }
});
