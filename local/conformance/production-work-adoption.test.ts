import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import type { D1Database } from '@cloudflare/workers-types';
import type { BootstrapPlan } from '../../crates/work-checkpoint-worker/bootstrap.ts';
import { OWNER_MIGRATIONS } from '../../scripts/production-owner-schema.ts';
import { WORK_MIGRATIONS, WORK_LEDGER_SQL } from '../../scripts/production-work-schema.ts';
import {
  captureProductionWorkSnapshot,
  productionBootstrapStore,
  productionWorkInitialTip,
  PRODUCTION_WORK_TARGET,
  validateProductionBootstrapPlan,
} from '../../scripts/production-work-adoption.ts';
import { validateIsolatedBootstrapPlan } from '../../scripts/work-authority-bootstrap.ts';

/** Synthetic provider IDs in disposable local D1; never remote allocation evidence. */
async function fixture() {
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'local-production-adoption',
          modules: true,
          script: 'export default {fetch(){return new Response(null,{status:404})}}',
          compatibilityDate: '2026-10-10',
          d1Databases: { DB: 'local-production-adoption' },
        },
      ],
    }),
  );
  const DB = await mf.getD1Database('DB');
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
  try {
    await DB.prepare(
      'CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE)',
    ).run();
    for (const [index, migration] of owner.entries())
      await DB.batch([
        ...splitSqlQuery(migration.sql).map((sql) => DB.prepare(sql)),
        DB.prepare('INSERT INTO d1_migrations VALUES(?,?)').bind(index + 1, migration.name),
      ]);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('existing-admin',3,1)"),
      DB.prepare("INSERT INTO credential VALUES('existing-passkey','existing-admin',1)"),
      DB.prepare(
        "INSERT INTO passkey_credential VALUES('existing-passkey','synthetic-public-key','synthetic-user-handle',7,1,1,1)",
      ),
      DB.prepare(
        "INSERT INTO sso_session VALUES('existing-session','existing-admin','existing-passkey',3,9999999999,0)",
      ),
      DB.prepare('UPDATE bootstrap_state SET closed=1'),
      DB.prepare(
        "INSERT INTO vault_recipient_key(key_id,service_id,algorithm,public_key,secret_ref,state,generation,revision,created_at,activated_at,retired_at) VALUES(?,?,?,?,?,'staged',1,1,1,NULL,NULL)",
      ).bind(
        'k'.repeat(43),
        'userinfo',
        'ML-KEM-768',
        Array.from({ length: 1184 }, (_, i) => i % 256),
        'synthetic-secret-reference',
      ),
      DB.prepare('INSERT INTO enrollment_waitlist VALUES(?,?,?,?,NULL,?,?,?,NULL)').bind(
        'w'.repeat(43),
        'synthetic@example.invalid',
        'ja',
        1,
        'h'.repeat(43),
        1000,
        1,
      ),
    ]);
    await DB.prepare(WORK_LEDGER_SQL).run();
    for (const [index, migration] of work.entries())
      await DB.batch([
        ...splitSqlQuery(migration.sql).map((sql) => DB.prepare(sql)),
        DB.prepare('INSERT INTO work_schema_migrations VALUES(?,?,?)').bind(
          index + 1,
          migration.name,
          WORK_MIGRATIONS[index]!.sha256,
        ),
      ]);
    const db = DB as unknown as D1Database;
    const snapshot = await captureProductionWorkSnapshot(db, owner, work);
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
      release_floor: 1,
      initial: {
        authority: PRODUCTION_WORK_TARGET.authority,
        epoch: '7'.repeat(64),
        sequence: 0,
        tip: productionWorkInitialTip(snapshot),
      },
    };
    const store = productionBootstrapStore(db, snapshot, owner, work);
    return { DB, db, snapshot, plan, store, owner, work, close: () => mf.dispose() };
  } catch (error) {
    await mf.dispose();
    throw error;
  }
}

test('populated production snapshot preserves every owner row and typed BLOB while inserting one marker', async () => {
  const f = await fixture();
  try {
    assert.throws(() => validateIsolatedBootstrapPlan(f.plan), /scope_denied|production_denied/);
    const key = f.snapshot.tables.find(({ name }) => name === 'vault_recipient_key')!.rows[0]!;
    assert.equal(typeof key.public_key, 'object');
    assert.equal((await f.store.inspect(f.plan)).pristine, true);
    await f.store.insert(f.plan);
    assert.equal((await f.store.inspect(f.plan)).initial_only, true);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM account_security').first('n'), 1);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_source_version').first('n'), 0);
    for (const table of f.snapshot.tables) {
      if (table.name === 'work_authority_checkpoint') continue;
      const rows = (await f.DB.prepare(`SELECT * FROM "${table.name}"`).all()).results;
      const { bootstrapRow } = await import('../../scripts/work-authority-bootstrap.ts');
      assert.deepEqual(rows.map(bootstrapRow), table.rows, table.name);
    }
    await assert.rejects(f.store.insert(f.plan), /primary_not_admitted/);
    await assert.rejects(captureProductionWorkSnapshot(f.db, f.owner, f.work), /already_enrolled/);
  } finally {
    await f.close();
  }
});

test('atomic insertion refuses concurrent account, BLOB, schema and separate-ledger changes', async () => {
  for (const sql of [
    'UPDATE account_security SET epoch=epoch+1',
    'blob-restore',
    'CREATE TABLE substituted_authority(value TEXT)',
    'DELETE FROM work_schema_migrations WHERE id=12',
    'DELETE FROM d1_migrations WHERE id=3',
  ]) {
    const f = await fixture();
    try {
      assert.equal((await f.store.inspect(f.plan)).pristine, true);
      if (sql === 'blob-restore') {
        // Model a privileged restore with exactly the original final schema.
        const names = ['vault_recipient_key_immutable', 'vault_recipient_key_transition'];
        await f.DB.batch([
          ...names.map((name) => f.DB.prepare(`DROP TRIGGER ${name}`)),
          f.DB.prepare('UPDATE vault_recipient_key SET public_key=zeroblob(1184)'),
          ...names.map((name) =>
            f.DB.prepare(f.snapshot.schema.find((row) => row.name === name)!.sql),
          ),
        ]);
      } else await f.DB.prepare(sql).run();
      await assert.rejects(f.store.insert(f.plan));
      assert.equal(
        await f.DB.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').first('n'),
        0,
      );
      assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM atomic_guard').first('n'), 0);
      await assert.rejects(f.store.insert(f.plan), /primary_not_admitted/);
    } finally {
      await f.close();
    }
  }
});

test('changed preflight does not admit insertion and a lost primary reply cannot be replayed', async () => {
  const f = await fixture();
  try {
    await f.DB.prepare('UPDATE account_security SET epoch=4').run();
    assert.equal((await f.store.inspect(f.plan)).pristine, false);
    await assert.rejects(f.store.insert(f.plan), /primary_not_admitted/);
    await f.DB.prepare('UPDATE account_security SET epoch=3').run();
    assert.equal((await f.store.inspect(f.plan)).pristine, true);
    await assert.rejects(
      (async () => {
        await f.store.insert(f.plan);
        throw new Error('lost-reply');
      })(),
      /lost-reply/,
    );
    assert.equal((await f.store.inspect(f.plan)).initial_only, true);
    await assert.rejects(f.store.insert(f.plan), /primary_not_admitted/);
  } finally {
    await f.close();
  }
});

test('substituted scope, initial snapshot, omitted tables and partial migration bytes are refused', async () => {
  const f = await fixture();
  try {
    for (const plan of [
      { ...f.plan, account_id: '0'.repeat(32) },
      { ...f.plan, database_id: '11111111-1111-4111-8111-111111111111' },
      { ...f.plan, initial: { ...f.plan.initial, authority: 'isolated' } },
      { ...f.plan, initial: { ...f.plan.initial, tip: '0'.repeat(64) } },
      { ...f.plan, checkpoint_namespace_id: '0'.repeat(32) },
      { ...f.plan, checkpoint_version_id: '00000000-0000-0000-0000-000000000000' },
    ])
      assert.throws(() => validateProductionBootstrapPlan(plan, f.snapshot));
    assert.throws(
      () =>
        productionBootstrapStore(
          f.db,
          {
            ...f.snapshot,
            tables: f.snapshot.tables.filter(({ name }) => name !== 'account_security'),
          },
          f.owner,
          f.work,
        ),
      /snapshot_tables_denied/,
    );
    assert.throws(
      () => productionBootstrapStore(f.db, f.snapshot, f.owner, f.work.slice(1)),
      /migration files/,
    );
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').first('n'),
      0,
    );
  } finally {
    await f.close();
  }
});

test('bounded capture refuses oversized primary tables instead of omitting their rows', async () => {
  const f = await fixture();
  try {
    await f.DB.batch(
      Array.from({ length: 64 }, (_, i) =>
        f.DB.prepare('INSERT INTO account_security VALUES(?,0,1)').bind('bounded-owner-' + i),
      ),
    );
    await assert.rejects(
      captureProductionWorkSnapshot(f.db, f.owner, f.work),
      /snapshot_row_bound/,
    );
  } finally {
    await f.close();
  }
});

test('oversized SQL guards are refused before any independent or primary write can start', async () => {
  const f = await fixture();
  try {
    const snapshot = structuredClone(f.snapshot);
    for (const name of ['sso_session', 'passkey_credential', 'credential']) {
      const table = snapshot.tables.find((table) => table.name === name)!;
      const seed = table.rows[0]!;
      const key = name === 'sso_session' ? 'sso_id' : 'credential_id';
      table.rows = Array.from({ length: 64 }, (_, i) => ({ ...seed, [key]: `${seed[key]}-${i}` }));
    }
    assert.throws(
      () => productionBootstrapStore(f.db, snapshot, f.owner, f.work),
      /query_too_large/,
    );
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').first('n'),
      0,
    );
  } finally {
    await f.close();
  }
});
