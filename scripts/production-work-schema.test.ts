import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { BASELINE_SCHEMA_QUERY, type SchemaRow } from './production-baseline.ts';
import { assertProductionOwnerSchema, OWNER_MIGRATIONS } from './production-owner-schema.ts';
import { productionWorkSchema } from './deploy-production.ts';
import { WORK_MIGRATIONS, WORK_LEDGER_SQL, workLedger } from './production-work-schema.ts';

const owner = OWNER_MIGRATIONS.map(({ name }) => ({
  name,
  sql: readFileSync('crates/worker/migrations/' + name, 'utf8'),
}));
const work = WORK_MIGRATIONS.map(({ name }) => ({
  name,
  sql: readFileSync('crates/worker/work-migrations/' + name, 'utf8'),
}));
const ownerLedger = owner.map(({ name }) => ({ name }));
function fixture(through = work.length) {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const { sql } of owner) db.exec(sql);
  db.exec(`INSERT INTO account_security VALUES('existing-admin',3,1);
    INSERT INTO credential VALUES('existing-passkey','existing-admin',1);
    INSERT INTO sso_session VALUES('existing-session','existing-admin','existing-passkey',3,9999999999,0);
    INSERT INTO bootstrap_state(id,closed) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET closed=1;`);
  const before = ownerRows(db);
  db.exec(WORK_LEDGER_SQL);
  for (const [index, { name, sql }] of work.slice(0, through).entries()) {
    db.exec(sql);
    db.prepare('INSERT INTO work_schema_migrations VALUES(?,?,?)').run(
      index + 1,
      name,
      WORK_MIGRATIONS[index]!.sha256,
    );
  }
  return { db, before, schema: () => db.prepare(BASELINE_SCHEMA_QUERY).all() as SchemaRow[] };
}
function ownerRows(db: DatabaseSync, names?: string[]) {
  return (
    names ??
    (db.prepare(BASELINE_SCHEMA_QUERY).all() as SchemaRow[])
      .filter(({ type }) => type === 'table')
      .map(({ name }) => name)
  ).map((name) => ({ name, rows: db.prepare(`SELECT * FROM ${name}`).all() }));
}

test('complete separate Work ledger is accepted only by explicit additive schema selection', () => {
  const f = fixture();
  try {
    assert.throws(
      () => assertProductionOwnerSchema(owner, ownerLedger, f.schema()),
      /schema differs/,
    );
    assertProductionOwnerSchema(owner, ownerLedger, f.schema(), {
      migrations: work,
      ledger: workLedger(),
    });
    assert.deepEqual(
      ownerRows(
        f.db,
        f.before.map(({ name }) => name),
      ),
      f.before,
    );
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').get()!.n, 0);
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM work_source_version').get()!.n, 0);
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM work_copy_job').get()!.n, 0);
    // Existing OP still works before enrollment; additive DDL grants no authority.
    f.db.exec('UPDATE sso_session SET revoked=1');
    assert.deepEqual(f.db.prepare('PRAGMA foreign_key_check').all(), []);
  } finally {
    f.db.close();
  }
});

test('each incomplete Work migration prefix is refused by production promotion', () => {
  for (let through = 0; through < work.length; through++) {
    const f = fixture(through);
    try {
      assert.throws(
        () =>
          assertProductionOwnerSchema(owner, ownerLedger, f.schema(), {
            migrations: work,
            ledger: workLedger().slice(0, through),
          }),
        /Work migration ledger differs/,
      );
      assert.throws(
        () =>
          assertProductionOwnerSchema(owner, ownerLedger, f.schema(), {
            migrations: work,
            ledger: workLedger(),
          }),
        /schema differs/,
      );
      assert.deepEqual(
        ownerRows(
          f.db,
          f.before.map(({ name }) => name),
        ),
        f.before,
      );
    } finally {
      f.db.close();
    }
  }
});

test('migration byte, ledger and actual schema substitutions remain refused', () => {
  const f = fixture();
  try {
    for (let index = 0; index < work.length; index++) {
      const changed = work.map((migration, i) =>
        i === index ? { ...migration, sql: migration.sql + '\n' } : migration,
      );
      assert.throws(
        () =>
          assertProductionOwnerSchema(owner, ownerLedger, f.schema(), {
            migrations: changed,
            ledger: workLedger(),
          }),
        /Work migration bytes differ/,
      );
      const ledger = workLedger();
      ledger[index]!.sha256 = '0'.repeat(64);
      assert.throws(
        () =>
          assertProductionOwnerSchema(owner, ownerLedger, f.schema(), {
            migrations: work,
            ledger,
          }),
        /Work migration ledger differs/,
      );
    }
    for (const ledger of [workLedger().reverse(), [...workLedger(), workLedger()[0]!]])
      assert.throws(
        () =>
          assertProductionOwnerSchema(owner, ownerLedger, f.schema(), {
            migrations: work,
            ledger,
          }),
        /Work migration ledger differs/,
      );
    f.db.exec('DROP TRIGGER work_source_access_insert');
    assert.throws(
      () =>
        assertProductionOwnerSchema(owner, ownerLedger, f.schema(), {
          migrations: work,
          ledger: workLedger(),
        }),
      /schema differs/,
    );
  } finally {
    f.db.close();
  }
});

test('deployment refuses Work capabilities without explicit schema adoption', () => {
  assert.equal(productionWorkSchema({}), false);
  assert.equal(productionWorkSchema({ WORK_SCHEMA_ENABLED: 'false' }), false);
  assert.equal(productionWorkSchema({ WORK_SCHEMA_ENABLED: 'true' }), true);
  assert.equal(
    productionWorkSchema({ WORK_SCHEMA_ENABLED: 'true', WORK_OWNER_API_ENABLED: 'true' }),
    true,
  );
  assert.throws(() => productionWorkSchema({ WORK_OWNER_API_ENABLED: 'true' }), /require/);
  assert.throws(() => productionWorkSchema({ WORK_SCHEMA_ENABLED: 'yes' }), /Invalid/);
  assert.throws(
    () => productionWorkSchema({ WORK_SCHEMA_ENABLED: 'true', WORK_OWNER_API_ENABLED: 'yes' }),
    /Invalid/,
  );
});
