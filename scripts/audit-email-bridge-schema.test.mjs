import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import {
  assertProductionConfig,
  auditBridgeSchema,
  parseAuditArgs,
} from './audit-email-bridge-schema.mjs';
import { OWNER_MIGRATIONS } from './production-owner-schema.ts';
import { WORK_LEDGER_SQL, WORK_MIGRATIONS } from './production-work-schema.ts';
import { MESSAGING_LEDGER_SQL, MESSAGING_MIGRATIONS } from './production-messaging-schema.ts';

test('accepts only the three exact Owner prefixes with the full Work and Messaging schema', async () => {
  const root = process.cwd(),
    feature = root;
  const db = new DatabaseSync(':memory:');
  const query = async (sql) =>
    db
      .prepare(sql)
      .all()
      .map((row) => ({ ...row }));
  const sql = (base, dir, name) => readFileSync(join(base, 'crates/worker', dir, name), 'utf8');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    db.exec('CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY,name TEXT UNIQUE)');
    for (const [i, { name }] of OWNER_MIGRATIONS.slice(0, 8).entries()) {
      db.exec(sql(root, 'migrations', name));
      db.prepare('INSERT INTO d1_migrations VALUES(?,?)').run(i + 1, name);
    }
    db.exec(WORK_LEDGER_SQL);
    for (const [i, { name, sha256 }] of WORK_MIGRATIONS.entries()) {
      db.exec(sql(root, 'work-migrations', name));
      db.prepare('INSERT INTO work_schema_migrations VALUES(?,?,?)').run(i + 1, name, sha256);
    }
    db.exec(MESSAGING_LEDGER_SQL);
    for (const [i, { name }] of MESSAGING_MIGRATIONS.entries()) {
      db.exec(sql(root, 'messaging-migrations', name));
      db.prepare('INSERT INTO messaging_schema_migrations(id,name) VALUES(?,?)').run(i + 1, name);
    }
    for (const [stage, name] of [
      [8, null],
      [9, '0009_client_secret_rotation.sql'],
      [10, '0010_verified_email.sql'],
    ]) {
      if (name) {
        db.exec(
          readFileSync(join(feature, 'scripts/fixtures/owner-email-migrations', name), 'utf8'),
        );
        db.prepare('INSERT INTO d1_migrations VALUES(?,?)').run(stage, name);
      }
      assert.equal((await auditBridgeSchema({ root, feature, stage, query })).stage, stage);
      await assert.rejects(
        auditBridgeSchema({ root, feature, stage: stage === 8 ? 9 : 8, query }),
        /Owner ledger differs/,
      );
    }
    let ledgerReads = 0;
    const changedLedger = async (statement) => {
      const rows = await query(statement);
      if (statement === 'SELECT id,name FROM d1_migrations ORDER BY id' && ++ledgerReads === 2)
        return [...rows, { id: 11, name: '0011_unexpected.sql' }];
      return rows;
    };
    await assert.rejects(
      auditBridgeSchema({ root, feature, stage: 10, query: changedLedger }),
      /Owner ledger changed during audit/,
    );
    db.exec('CREATE TABLE unexpected_schema(id INTEGER)');
    await assert.rejects(
      auditBridgeSchema({ root, feature, stage: 10, query }),
      /Combined schema differs/,
    );
  } finally {
    db.close();
  }
});

test('CLI requires an explicit reviewed stage and remote target', () => {
  for (const stage of [8, 9, 10])
    assert.equal(parseAuditArgs(['--remote', '--stage', String(stage)]), stage);
  for (const args of [
    [],
    ['--remote', '--stage', '11'],
    ['--local', '--stage', '8'],
    ['--remote', '--stage', '08'],
    ['--remote', '--stage', '8', '--extra'],
  ])
    assert.throws(() => parseAuditArgs(args));
});

test('production target configuration is byte-pinned', () => {
  const config = readFileSync('crates/worker/wrangler.production.jsonc');
  assert.doesNotThrow(() => assertProductionConfig(config));
  assert.throws(
    () => assertProductionConfig(Buffer.concat([config, Buffer.from(' ')])),
    /Production target config differs/,
  );
});
