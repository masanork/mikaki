import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { BASELINE_SCHEMA_QUERY, type SchemaRow } from './production-baseline.ts';
import { assertProductionOwnerSchema, OWNER_MIGRATIONS } from './production-owner-schema.ts';

test('owner promotion pins bytes, full schema and ordered complete feature ledger', () => {
  const migrations = OWNER_MIGRATIONS.map(({ name }) => ({
    name,
    sql: readFileSync('crates/worker/migrations/' + name, 'utf8'),
  }));
  const ledger = OWNER_MIGRATIONS.map(({ name }) => ({ name }));
  const db = new DatabaseSync(':memory:');
  try {
    for (const { sql } of migrations) db.exec(sql);
    const schema = db.prepare(BASELINE_SCHEMA_QUERY).all() as SchemaRow[];
    assertProductionOwnerSchema(migrations, ledger, schema);
    for (const bad of [
      ledger.slice(1),
      ledger.slice(0, 1),
      [...ledger].reverse(),
      [...ledger, ledger[1]!],
      [...ledger, { name: '0003_unknown.sql' }],
    ])
      assert.throws(() => assertProductionOwnerSchema(migrations, bad, schema), /ledger differs/);
    assert.throws(
      () => assertProductionOwnerSchema(migrations.slice(0, 1), ledger, schema),
      /migration files/,
    );
    assert.throws(
      () =>
        assertProductionOwnerSchema(
          migrations.map((migration, index) =>
            index === 0 ? { ...migration, sql: migration.sql + '\n' } : migration,
          ),
          ledger,
          schema,
        ),
      /bytes differ/,
    );
    assert.throws(
      () =>
        assertProductionOwnerSchema(
          migrations.map((migration, index) =>
            index === 1 ? { ...migration, sql: migration.sql + '\n' } : migration,
          ),
          ledger,
          schema,
        ),
      /bytes differ/,
    );
    const changed = structuredClone(schema);
    changed.find((row) => row.name === 'vault_owner_key_wrap_operation_no_update')!.sql =
      'CREATE TRIGGER changed AFTER INSERT ON credential BEGIN SELECT 1; END';
    assert.throws(() => assertProductionOwnerSchema(migrations, ledger, changed), /schema differs/);
    db.exec('CREATE TABLE old_vault_token(token TEXT)');
    assert.throws(
      () =>
        assertProductionOwnerSchema(
          migrations,
          ledger,
          db.prepare(BASELINE_SCHEMA_QUERY).all() as SchemaRow[],
        ),
      /schema differs/,
    );
  } finally {
    db.close();
  }
});
