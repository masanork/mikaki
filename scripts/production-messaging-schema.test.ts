import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { BASELINE_SCHEMA_QUERY, type SchemaRow } from './production-baseline.ts';
import { assertProductionOwnerSchema, OWNER_MIGRATIONS } from './production-owner-schema.ts';
import {
  assertMessagingMigrationConfig,
  assertMessagingMigrationFiles,
  assertMessagingLedger,
  MESSAGING_LEDGER_SQL,
  MESSAGING_MIGRATIONS,
  MESSAGING_MIGRATION_CONFIG,
} from './production-messaging-schema.ts';
import { WORK_LEDGER_SQL, WORK_MIGRATIONS, workLedger } from './production-work-schema.ts';
import { checkProductionChatSchema, chatSchemaArguments } from './check-production-chat-schema.ts';
import { inspectProductionMessaging } from './production-messaging-audit.ts';

const root = process.cwd();
const load = (directory: string, names: readonly { name: string }[]) =>
  names.map(({ name }) => ({ name, sql: readFileSync(`${directory}/${name}`, 'utf8') }));
const owner = load('crates/worker/migrations', OWNER_MIGRATIONS);
const messaging = load('crates/worker/messaging-migrations', MESSAGING_MIGRATIONS);
const work = load('crates/worker/work-migrations', WORK_MIGRATIONS);
const ownerLedger = owner.map(({ name }) => ({ name }));
const ledger = (through: number) =>
  MESSAGING_MIGRATIONS.slice(0, through).map(({ name }, index) => ({ id: index + 1, name }));

function fixture(through: number | null, withWork = false) {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const { sql } of owner) db.exec(sql);
  db.exec('CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY,name TEXT UNIQUE)');
  for (const [index, { name }] of owner.entries())
    db.prepare('INSERT INTO d1_migrations VALUES(?,?)').run(index + 1, name);
  db.exec(`INSERT INTO account_security VALUES('existing-owner',3,1);
    INSERT INTO credential VALUES('existing-passkey','existing-owner',1);
    INSERT INTO sso_session VALUES('existing-session','existing-owner','existing-passkey',3,9999999999,0)`);
  if (withWork) {
    db.exec(WORK_LEDGER_SQL);
    for (const [index, { name, sql }] of work.entries()) {
      db.exec(sql);
      db.prepare('INSERT INTO work_schema_migrations VALUES(?,?,?)').run(
        index + 1,
        name,
        WORK_MIGRATIONS[index]!.sha256,
      );
    }
  }
  const before = db.prepare('SELECT * FROM credential').all();
  if (through !== null) {
    db.exec(MESSAGING_LEDGER_SQL);
    for (const [index, { name, sql }] of messaging.slice(0, through).entries()) {
      db.exec(sql);
      db.prepare('INSERT INTO messaging_schema_migrations(id,name) VALUES(?,?)').run(
        index + 1,
        name,
      );
    }
  }
  return {
    db,
    before,
    schema: () => db.prepare(BASELINE_SCHEMA_QUERY).all() as SchemaRow[],
    // Wrangler JSON serializes SQLite's null-prototype row objects.
    query: async (sql: string) => JSON.parse(JSON.stringify(db.prepare(sql).all())),
    work: withWork ? { migrations: work, ledger: workLedger() } : undefined,
  };
}

test('dedicated migration config pins the target and cannot acquire deploy/runtime authority', () => {
  const config = JSON.parse(readFileSync(MESSAGING_MIGRATION_CONFIG, 'utf8'));
  const op = JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));
  assertMessagingMigrationConfig(config, op);
  for (const field of ['account_id', 'name', 'compatibility_date'])
    assert.throws(() => assertMessagingMigrationConfig({ ...config, [field]: 'different' }, op));
  for (const [field, value] of Object.entries({
    database_id: '00000000-0000-4000-8000-000000000000',
    database_name: 'other',
    binding: 'OTHER',
    migrations_dir: 'migrations',
    migrations_table: 'd1_migrations',
    remote: true,
  })) {
    const changed = structuredClone(config);
    changed.d1_databases[0][field] = value;
    assert.throws(() => assertMessagingMigrationConfig(changed, op));
  }
  for (const field of ['main', 'vars', 'secrets', 'routes'])
    assert.throws(() => assertMessagingMigrationConfig({ ...config, [field]: {} }, op));
  for (const args of [[], ['--remote', '--local'], ['--remote', '--apply'], ['--apply']])
    assert.throws(() => chatSchemaArguments(args), /Usage/);
  assert.equal(chatSchemaArguments(['--local']), '--local');
  assert.equal(chatSchemaArguments(['--remote']), '--remote');
});

test('each Chat SQL byte and the complete ordered ledger are pinned', () => {
  assertMessagingMigrationFiles(messaging);
  assertMessagingLedger(ledger(3));
  for (const index of [0, 1, 2]) {
    assert.throws(
      () =>
        assertMessagingMigrationFiles(
          messaging.map((file, i) => (i === index ? { ...file, sql: file.sql + '\n' } : file)),
        ),
      /bytes differ/,
    );
    assert.throws(() => assertMessagingLedger(ledger(index)), /ledger differs/);
  }
  for (const bad of [messaging.slice(1), [...messaging].reverse(), [...messaging, messaging[0]!]])
    assert.throws(() => assertMessagingMigrationFiles(bad), /migration files/);
  for (const bad of [
    [...ledger(3)].reverse(),
    [ledger(3)[1]!],
    [...ledger(3), ledger(3)[0]!],
    ledger(3).map((row) => ({ ...row, id: row.id + 1 })),
    ledger(3).map((row, i) => (i === 1 ? { ...row, name: '0002_unreviewed.sql' } : row)),
  ])
    assert.throws(() => assertMessagingLedger(bad, true));
});

test('absent Chat schema still pins every SQL byte without querying Chat tables', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-chat-absent-'));
  try {
    cpSync(
      'crates/worker/messaging-migrations',
      join(directory, 'crates/worker/messaging-migrations'),
      { recursive: true },
    );
    for (const path of [MESSAGING_MIGRATION_CONFIG, 'crates/worker/wrangler.production.jsonc'])
      cpSync(path, join(directory, path));
    const query = async () => {
      assert.fail('Absent Chat must not need a Chat database query');
    };
    assert.equal(await inspectProductionMessaging(directory, [], query), undefined);
    for (const { name, sql } of messaging) {
      const path = join(directory, 'crates/worker/messaging-migrations', name);
      writeFileSync(path, sql + '\n');
      await assert.rejects(
        inspectProductionMessaging(directory, [], query),
        /Chat migration bytes differ/,
      );
      rmSync(path);
      await assert.rejects(
        inspectProductionMessaging(directory, [], query),
        /Unexpected Chat migration files/,
      );
      writeFileSync(path, sql);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('read-only preflight accepts exact prefixes; ordinary promotion requires all three migrations', async () => {
  for (const withWork of [false, true])
    for (const through of [null, 0, 1, 2, 3]) {
      const f = fixture(through, withWork);
      try {
        const result = await checkProductionChatSchema(root, f.query);
        assert.equal(result.applied, through ?? 0);
        assert.equal(result.complete, through === 3);
        assert.equal(result.mutations, false);
        const chat =
          through === null ? undefined : { migrations: messaging, ledger: ledger(through) };
        const promote = () =>
          assertProductionOwnerSchema(owner, ownerLedger, f.schema(), f.work, chat);
        if (through === null || through === 3) promote();
        else assert.throws(promote, /Chat migration ledger differs/);
        assert.deepEqual(f.db.prepare('SELECT * FROM credential').all(), f.before);
        assert.deepEqual(
          f.db
            .prepare('SELECT name FROM d1_migrations ORDER BY id')
            .all()
            .map(({ name }) => name),
          ownerLedger.map(({ name }) => name),
        );
      } finally {
        f.db.close();
      }
    }
});

test('unledgered, partial and substituted schema objects are rejected instead of filtered out', async () => {
  const changes = [
    'DROP TABLE messaging_schema_migrations',
    'DELETE FROM messaging_schema_migrations WHERE id=2',
    "UPDATE messaging_schema_migrations SET name='0002_unknown.sql' WHERE id=2",
    'DROP INDEX messaging_beta_one_device',
    'ALTER TABLE messaging_mail ADD COLUMN plaintext TEXT',
    'CREATE TABLE unrelated_secret(value TEXT)',
    'CREATE TRIGGER messaging_forged AFTER INSERT ON messaging_account BEGIN SELECT 1; END',
    'DELETE FROM messaging_beta_schema',
    'DELETE FROM messaging_resource_policy',
    'UPDATE messaging_resource_policy SET source_per_minute=601',
  ];
  for (const sql of changes) {
    const f = fixture(3, true);
    try {
      f.db.exec(sql);
      await assert.rejects(checkProductionChatSchema(root, f.query));
      assert.deepEqual(f.db.prepare('SELECT * FROM credential').all(), f.before);
    } finally {
      f.db.close();
    }
  }
  const f = fixture(1);
  try {
    f.db.exec(messaging[1]!.sql); // A forged complete ledger cannot replace absent ingress DDL.
    f.db.exec(
      "INSERT INTO messaging_schema_migrations(id,name) VALUES(2,'0002_beta_profile.sql'),(3,'0003_ingress_budget.sql')",
    );
    await assert.rejects(checkProductionChatSchema(root, f.query));
  } finally {
    f.db.close();
  }
});

test('preflight refuses multiple existing devices without mutating their rows or credentials', async () => {
  for (const count of [1, 2]) {
    const f = fixture(1);
    try {
      f.db.exec(
        "INSERT INTO messaging_account VALUES('existing-owner','11111111-1111-4111-8111-111111111111')",
      );
      for (let i = 0; i < count; i++)
        f.db
          .prepare('INSERT INTO messaging_device_head VALUES(?,?,1,1)')
          .run('11111111-1111-4111-8111-111111111111', `device-${i}`);
      const heads = f.db.prepare('SELECT * FROM messaging_device_head ORDER BY device_id').all();
      if (count === 1) {
        await checkProductionChatSchema(root, f.query);
        for (const [index, { name, sql }] of messaging.slice(1).entries()) {
          f.db.exec(sql);
          f.db
            .prepare('INSERT INTO messaging_schema_migrations(id,name) VALUES(?,?)')
            .run(index + 2, name);
        }
        assert.equal((await checkProductionChatSchema(root, f.query)).complete, true);
      } else
        await assert.rejects(checkProductionChatSchema(root, f.query), /multiple Chat devices/);
      assert.deepEqual(
        f.db.prepare('SELECT * FROM messaging_device_head ORDER BY device_id').all(),
        heads,
      );
      assert.deepEqual(f.db.prepare('SELECT * FROM credential').all(), f.before);
    } finally {
      f.db.close();
    }
  }
});

test('local platform metadata is accepted only locally with its exact definition', async () => {
  const f = fixture(3);
  try {
    f.db.exec('CREATE TABLE _cf_METADATA (key INTEGER PRIMARY KEY, value BLOB)');
    assert.equal((await checkProductionChatSchema(root, f.query, true)).complete, true);
    await assert.rejects(checkProductionChatSchema(root, f.query), /schema differs/);
    f.db.exec('ALTER TABLE _cf_METADATA ADD COLUMN extra TEXT');
    await assert.rejects(checkProductionChatSchema(root, f.query, true), /local D1 metadata/);
  } finally {
    f.db.close();
  }
});

test('live foreign-key violations fail the audit even when the schema and ledger match', async () => {
  const f = fixture(3);
  try {
    f.db.exec(
      "PRAGMA foreign_keys=OFF; INSERT INTO messaging_account VALUES('missing-owner','11111111-1111-4111-8111-111111111111'); PRAGMA foreign_keys=ON",
    );
    await assert.rejects(
      inspectProductionMessaging(root, f.schema(), f.query),
      /foreign keys failed/,
    );
  } finally {
    f.db.close();
  }
});
