import assert from 'node:assert/strict';
import {
  readFileSync,
  readdirSync,
  mkdtempSync,
  rmSync,
  mkdirSync,
  copyFileSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import test, { after } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  APPROVED,
  CONFIRMATION,
  LEDGER_SQL,
  SCHEMA_SQL,
  applicationGate,
  applyOnly0031,
  bookmarkAt,
  expectedInputs,
  inspect,
  inspectState,
  resultRows,
} from './reconcile-production-0031.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
// This one-off production gate intentionally becomes obsolete at 0032. Keep its
// supported-state fixtures stable so later migrations do not break normal CI.
const fixture = mkdtempSync(join(tmpdir(), 'mikaki-reviewed-0031-'));
const fixtureMigrations = join(fixture, 'crates/worker/migrations');
mkdirSync(fixtureMigrations, { recursive: true });
for (const name of readdirSync(join(root, 'crates/worker/migrations')).sort().slice(0, 31)) {
  copyFileSync(join(root, 'crates/worker/migrations', name), join(fixtureMigrations, name));
}
after(() => rmSync(fixture, { recursive: true, force: true }));
const inputs = expectedInputs(fixture);
const ledger = (count = 30) =>
  inputs.names.slice(0, count).map((name, index) => ({ id: index + 1, name }));
const response = (rows: unknown[]) => JSON.stringify([{ success: true, results: rows }]);
const bookmark = '00000085-0000024c-00004c6d-8e61117bf38d7adb71b934ebbf891683';

test('exact reviewed migration is the only pending candidate, or safely already applied', () => {
  const plan = inspectState(inputs, ledger(), inputs.before);
  assert.deepEqual(plan.pending, [APPROVED.migration]);
  assert.match(plan.plan_sha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(inspectState(inputs, ledger(31), inputs.after).pending, []);
  applicationGate(plan, plan.plan_sha256, CONFIRMATION);
  assert.throws(() => applicationGate(plan, plan.plan_sha256, ''), /confirmation/);
  assert.throws(() => applicationGate(plan, 'a'.repeat(64), CONFIRMATION), /reviewed plan/);
  const done = inspectState(inputs, ledger(31), inputs.after);
  assert.throws(() => applicationGate(done, done.plan_sha256, CONFIRMATION), /exactly 0031/);
});

test('missing, unknown, duplicate, reordered or malformed ledger never becomes an apply plan', () => {
  for (const count of [0, 29])
    assert.throws(() => inspectState(inputs, ledger(count), inputs.before), /prefix/);
  for (const rows of [
    [...ledger(), { id: 31, name: '0032_unreviewed.sql' }],
    ledger().map((row, i) => (i === 29 ? { ...row, name: inputs.names[0] } : row)),
    ledger().reverse(),
    ledger().map((row, i) => (i === 29 ? { ...row, id: 0 } : row)),
  ])
    assert.throws(() => inspectState(inputs, rows, inputs.before));
});

test('absent ledger, preexisting/partial tables, altered STRICT schema and extra triggers fail closed', () => {
  assert.throws(() => inspectState(inputs, ledger(), []), /schema/);
  assert.throws(() => inspectState(inputs, ledger(), inputs.after), /schema/);
  assert.throws(() => inspectState(inputs, ledger(31), inputs.before), /schema/);
  assert.throws(
    () =>
      inspectState(
        inputs,
        ledger(31),
        inputs.after.filter((row) => row.name !== 'vault_owner_key_wrap'),
      ),
    /schema/,
  );
  assert.throws(
    () =>
      inspectState(
        inputs,
        ledger(31),
        inputs.after.map((row) => ({
          ...row,
          sql: typeof row.sql === 'string' ? row.sql.replace(' STRICT', '') : row.sql,
        })),
      ),
    /schema/,
  );
  assert.throws(
    () =>
      inspectState(inputs, ledger(), [
        ...inputs.before,
        { type: 'trigger', name: 'extra', tbl_name: 'd1_migrations', sql: 'CREATE TRIGGER extra' },
      ]),
    /schema/,
  );
});

test('default inspection executes SELECT only and rejects unsuccessful or ambiguous JSON', () => {
  const commands: string[][] = [];
  inspect((args) => {
    commands.push(args);
    return response(args.at(-1) === LEDGER_SQL ? ledger() : inputs.before);
  }, inputs);
  assert.equal(commands.length, 2);
  for (const args of commands) {
    assert.deepEqual(args.slice(0, 8), [
      'd1',
      'execute',
      APPROVED.database,
      '--remote',
      '--config',
      APPROVED.config,
      '--json',
      '--command',
    ]);
    assert.match(args.at(-1)!, /^SELECT /);
    assert.ok(!args.includes('migrations'));
  }
  for (const bad of [
    'not JSON secret',
    '[]',
    '{}',
    response([1]),
    '[{"success":false,"results":[]}]',
    '[{"success":true,"results":[]},{"success":true,"results":[]}]',
  ]) {
    assert.throws(() => resultRows(bad));
  }
});

test('bookmark is a strict validated timestamp lookup, never a restore', () => {
  const timestamp = '2026-10-03T10:00:00.000Z';
  assert.equal(
    bookmarkAt((args) => {
      assert.deepEqual(args, [
        'd1',
        'time-travel',
        'info',
        APPROVED.database,
        '--config',
        APPROVED.config,
        '--timestamp',
        timestamp,
        '--json',
      ]);
      return JSON.stringify({ bookmark });
    }, timestamp),
    bookmark,
  );
  for (const bad of ['{}', '{"bookmark":"secret\\n::error::bad"}', '[]'])
    assert.throws(() => bookmarkAt(() => bad, timestamp), /bookmark/);
});

test('application exposes only pinned 0031; local SQL rehearsal preserves existing data and verifies post-state', () => {
  const temp = mkdtempSync(join(tmpdir(), 'mikaki-0031-test-'));
  const db = new DatabaseSync(':memory:');
  try {
    for (const name of inputs.names.slice(0, 30))
      db.exec(readFileSync(join(root, 'crates/worker/migrations', name), 'utf8'));
    db.exec(
      'CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)',
    );
    for (const row of ledger())
      db.prepare('INSERT INTO d1_migrations(name) VALUES(?)').run(row.name);
    db.exec("INSERT INTO account_security VALUES ('test-owner', 1, 1)");
    const owner = db.prepare('SELECT * FROM account_security').all();
    assert.deepEqual(
      inspectState(inputs, db.prepare(LEDGER_SQL).all(), db.prepare(SCHEMA_SQL).all()).pending,
      [APPROVED.migration],
    );
    let calls = 0;
    applyOnly0031(
      (args) => {
        calls++;
        assert.deepEqual(args.slice(0, 6), [
          'd1',
          'migrations',
          'apply',
          APPROVED.database,
          '--remote',
          '--config',
        ]);
        assert.equal(args.length, 7);
        const path = args.at(-1)!;
        const config = JSON.parse(readFileSync(path, 'utf8'));
        assert.equal(config.account_id, APPROVED.account);
        assert.equal(config.d1_databases[0].database_id, APPROVED.database_id);
        assert.equal(config.d1_databases[0].migrations_table, 'd1_migrations');
        const directory = join(path, '..', config.d1_databases[0].migrations_dir);
        assert.deepEqual(readdirSync(directory), [APPROVED.migration]);
        const sql = readFileSync(join(directory, APPROVED.migration), 'utf8');
        assert.equal(sql, inputs.migration);
        db.exec('BEGIN');
        db.exec(sql);
        db.prepare('INSERT INTO d1_migrations(name) VALUES(?)').run(APPROVED.migration);
        db.exec('COMMIT');
        return 'raw Wrangler output must not be logged';
      },
      inputs.migration,
      temp,
    );
    assert.equal(calls, 1);
    assert.deepEqual(readdirSync(temp), []);
    assert.deepEqual(db.prepare('SELECT * FROM account_security').all(), owner);
    assert.deepEqual(
      inspectState(inputs, db.prepare(LEDGER_SQL).all(), db.prepare(SCHEMA_SQL).all()).pending,
      [],
    );
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
    assert.equal(db.prepare('PRAGMA integrity_check').get()!.integrity_check, 'ok');
    assert.throws(
      () =>
        applyOnly0031(
          () => {
            throw new Error('must not run');
          },
          inputs.migration + '\n',
          temp,
        ),
      /hash/,
    );
  } finally {
    db.close();
    rmSync(temp, { recursive: true, force: true });
  }
});

test('failed application cleans temporary material and propagates without retry', () => {
  const temp = mkdtempSync(join(tmpdir(), 'mikaki-0031-test-'));
  let calls = 0;
  try {
    assert.throws(
      () =>
        applyOnly0031(
          () => {
            calls++;
            throw new Error('uncertain operation');
          },
          inputs.migration,
          temp,
        ),
      /uncertain/,
    );
    assert.equal(calls, 1);
    assert.deepEqual(readdirSync(temp), []);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('workflow keeps manual/default-read-only production gate and durable preflight before apply', () => {
  const workflow = readFileSync(
    join(root, '.github/workflows/reconcile-production-0031.yml'),
    'utf8',
  );
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /default: plan/);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /group: production-deployment/);
  assert.match(workflow, /name: production/);
  assert.match(workflow, /ref: fd55932eee716c2c623cbbb45d1c8b68ec8c354e/);
  assert.ok(
    workflow.indexOf('if-no-files-found: error') <
      workflow.indexOf('run: node scripts/reconcile-production-0031.ts apply'),
  );
  assert.doesNotMatch(
    workflow,
    /OP_PRIVATE_JWK|MIKAKI_READY_TOKEN|workflow_call:|pull_request:|push:|contents: write/,
  );
});

test('production input loader rejects a later 0032 without breaking the stable test fixture', () => {
  const later = join(fixtureMigrations, '0032_unreviewed.sql');
  try {
    writeFileSync(later, 'CREATE TABLE later(id INTEGER);');
    assert.throws(() => expectedInputs(fixture), /exactly the reviewed/);
  } finally {
    rmSync(later);
  }
  assert.deepEqual(expectedInputs(fixture).names, inputs.names);
});
