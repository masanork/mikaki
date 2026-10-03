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
  CURSOR_SQL,
  SCHEMA_SQL,
  applicationGate,
  applyApprovedSuffix,
  bookmarkAt,
  expectedInputs,
  inspect,
  inspectState,
  resultRows,
} from './reconcile-production-0031.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
// This one-off production gate intentionally becomes obsolete at 0033. Keep its
// supported-state fixtures stable so later migrations do not break normal CI.
const fixture = mkdtempSync(join(tmpdir(), 'mikaki-reviewed-0031-'));
const fixtureMigrations = join(fixture, 'crates/worker/migrations');
mkdirSync(fixtureMigrations, { recursive: true });
for (const name of readdirSync(join(root, 'crates/worker/migrations')).sort().slice(0, 32)) {
  copyFileSync(join(root, 'crates/worker/migrations', name), join(fixtureMigrations, name));
}
after(() => rmSync(fixture, { recursive: true, force: true }));
const inputs = expectedInputs(fixture);
const approvedNames = APPROVED.migrations.map((item) => item.name);
const ledger = (count = 30) =>
  inputs.names.slice(0, count).map((name, index) => ({ id: index + 1, name }));
const response = (rows: unknown[]) => JSON.stringify([{ success: true, results: rows }]);
const bookmark = '00000085-0000024c-00004c6d-8e61117bf38d7adb71b934ebbf891683';

test('only the reviewed missing suffix is a pending candidate, or safely already applied', () => {
  const plan = inspectState(inputs, ledger(), inputs.schemas[30]!);
  assert.deepEqual(plan.pending, approvedNames);
  assert.match(plan.plan_sha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(inspectState(inputs, ledger(32), inputs.schemas[32]!).pending, []);
  applicationGate(plan, plan.plan_sha256, CONFIRMATION);
  const partial = inspectState(inputs, ledger(31), inputs.schemas[31]!);
  assert.deepEqual(partial.pending, [approvedNames[1]]);
  applicationGate(partial, partial.plan_sha256, CONFIRMATION);
  assert.notEqual(partial.plan_sha256, plan.plan_sha256);
  assert.throws(() => applicationGate(partial, plan.plan_sha256, CONFIRMATION), /reviewed plan/);
  assert.throws(
    () => applicationGate(plan, plan.plan_sha256, 'APPLY 0031 TO mikaki-auth'),
    /confirmation/,
  );
  assert.throws(() => applicationGate(plan, plan.plan_sha256, ''), /confirmation/);
  assert.throws(() => applicationGate(plan, 'a'.repeat(64), CONFIRMATION), /reviewed plan/);
  const done = inspectState(inputs, ledger(32), inputs.schemas[32]!);
  assert.throws(() => applicationGate(done, done.plan_sha256, CONFIRMATION), /nonempty approved/);
});

test('missing, unknown, duplicate, reordered or malformed ledger never becomes an apply plan', () => {
  for (const count of [0, 29])
    assert.throws(() => inspectState(inputs, ledger(count), inputs.schemas[30]!), /prefix/);
  for (const rows of [
    [...ledger(), { id: 31, name: '0032_unreviewed.sql' }],
    [...ledger(32), { id: 33, name: '0033_unreviewed.sql' }],
    ledger().map((row, i) => (i === 29 ? { ...row, name: inputs.names[0] } : row)),
    ledger().reverse(),
    ledger().map((row, i) => (i === 29 ? { ...row, id: 0 } : row)),
  ])
    assert.throws(() => inspectState(inputs, rows, inputs.schemas[30]!));
});

test('absent ledger, preexisting/partial tables, altered STRICT schema and extra triggers fail closed', () => {
  assert.throws(() => inspectState(inputs, ledger(), []), /schema/);
  assert.throws(() => inspectState(inputs, ledger(), inputs.schemas[32]!), /schema/);
  assert.throws(() => inspectState(inputs, ledger(31), inputs.schemas[30]!), /schema/);
  assert.throws(
    () =>
      inspectState(
        inputs,
        ledger(32),
        inputs.schemas[32]!.filter((row) => row.name !== 'vault_owner_key_wrap'),
      ),
    /schema/,
  );
  assert.throws(
    () =>
      inspectState(
        inputs,
        ledger(32),
        inputs.schemas[32]!.map((row) => ({
          ...row,
          sql: typeof row.sql === 'string' ? row.sql.replace(' STRICT', '') : row.sql,
        })),
      ),
    /schema/,
  );
  assert.throws(
    () =>
      inspectState(inputs, ledger(), [
        ...inputs.schemas[30]!,
        { type: 'trigger', name: 'extra', tbl_name: 'd1_migrations', sql: 'CREATE TRIGGER extra' },
      ]),
    /schema/,
  );
});

test('default inspection executes SELECT only and rejects unsuccessful or ambiguous JSON', () => {
  const commands: string[][] = [];
  inspect((args) => {
    commands.push(args);
    return response(args.at(-1) === LEDGER_SQL ? ledger() : inputs.schemas[30]!);
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

test('application exposes only pinned missing suffix; local SQL rehearsal preserves data and exact post-state', () => {
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
      approvedNames,
    );
    let calls = 0;
    applyApprovedSuffix(
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
        assert.deepEqual(readdirSync(directory), approvedNames);
        for (const name of approvedNames) {
          const sql = readFileSync(join(directory, name), 'utf8');
          assert.equal(sql, inputs.migrations[name]);
          db.exec('BEGIN');
          db.exec(sql);
          db.prepare('INSERT INTO d1_migrations(name) VALUES(?)').run(name);
          db.exec('COMMIT');
        }
        return 'raw Wrangler output must not be logged';
      },
      inputs,
      approvedNames,
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
        applyApprovedSuffix(
          () => {
            throw new Error('must not run');
          },
          {
            ...inputs,
            migrations: {
              ...inputs.migrations,
              [approvedNames[1]!]: inputs.migrations[approvedNames[1]!] + '\n',
            },
          },
          approvedNames,
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
        applyApprovedSuffix(
          () => {
            calls++;
            throw new Error('uncertain operation');
          },
          inputs,
          approvedNames,
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
  assert.match(workflow, /ref: 7473da7f5c4c1a336499907d6858dcd893fdbf5b/);
  assert.ok(
    workflow.indexOf('if-no-files-found: error') <
      workflow.indexOf('run: node scripts/reconcile-production-0031.ts apply'),
  );
  assert.doesNotMatch(
    workflow,
    /OP_PRIVATE_JWK|MIKAKI_READY_TOKEN|workflow_call:|pull_request:|push:|contents: write/,
  );
});

test('production input loader rejects a later 0033 without breaking the stable test fixture', () => {
  const later = join(fixtureMigrations, '0033_unreviewed.sql');
  try {
    writeFileSync(later, 'CREATE TABLE later(id INTEGER);');
    assert.throws(() => expectedInputs(fixture), /exactly the reviewed/);
  } finally {
    rmSync(later);
  }
  assert.deepEqual(expectedInputs(fixture).names, inputs.names);
});

test('partial success keeps 0031 and a new plan exposes only 0032; never retries automatically', () => {
  const temp = mkdtempSync(join(tmpdir(), 'mikaki-partial-test-'));
  const db = new DatabaseSync(':memory:');
  try {
    for (const name of inputs.names.slice(0, 30))
      db.exec(readFileSync(join(fixtureMigrations, name), 'utf8'));
    db.exec(
      'CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)',
    );
    for (const row of ledger())
      db.prepare('INSERT INTO d1_migrations(name) VALUES(?)').run(row.name);
    const original = inspectState(
      inputs,
      db.prepare(LEDGER_SQL).all(),
      db.prepare(SCHEMA_SQL).all(),
    );
    let calls = 0;
    assert.throws(
      () =>
        applyApprovedSuffix(
          () => {
            calls++;
            // Wrangler commits each migration separately. Simulate 0031 success then
            // a 0032 transaction failure; no automatic application retry follows.
            db.exec('BEGIN');
            db.exec(inputs.migrations[approvedNames[0]!]!);
            db.prepare('INSERT INTO d1_migrations(name) VALUES(?)').run(approvedNames[0]!);
            db.exec('COMMIT');
            db.exec('BEGIN');
            db.exec(inputs.migrations[approvedNames[1]!]!);
            db.exec('ROLLBACK');
            throw new Error('second migration failed');
          },
          inputs,
          original.pending,
          temp,
        ),
      /second migration failed/,
    );
    assert.equal(calls, 1);
    const partial = inspectState(
      inputs,
      db.prepare(LEDGER_SQL).all(),
      db.prepare(SCHEMA_SQL).all(),
    );
    assert.deepEqual(partial.pending, [approvedNames[1]]);
    assert.throws(
      () => applicationGate(partial, original.plan_sha256, CONFIRMATION),
      /reviewed plan/,
    );
    applicationGate(partial, partial.plan_sha256, CONFIRMATION);
    applyApprovedSuffix(
      (args) => {
        const configPath = args.at(-1)!;
        const config = JSON.parse(readFileSync(configPath, 'utf8'));
        const directory = join(configPath, '..', config.d1_databases[0].migrations_dir);
        assert.deepEqual(readdirSync(directory), [approvedNames[1]]);
        return '';
      },
      inputs,
      partial.pending,
      temp,
    );
    for (const invalid of [
      [],
      [approvedNames[0]!],
      ['0033_unreviewed.sql'],
      approvedNames.slice().reverse(),
    ]) {
      assert.throws(
        () =>
          applyApprovedSuffix(
            () => {
              throw new Error('must not run');
            },
            inputs,
            invalid,
            temp,
          ),
        /approved suffix/,
      );
    }
  } finally {
    db.close();
    rmSync(temp, { recursive: true, force: true });
  }
});

test('0032 requires exactly its initialized GC cursor id without reading the cursor value', () => {
  for (const rows of [[], [{ id: 2 }], [{ id: 1 }, { id: 2 }]]) {
    assert.throws(
      () =>
        inspect((args) => {
          const sql = args.at(-1);
          if (sql === LEDGER_SQL) return response(ledger(32));
          if (sql === SCHEMA_SQL) return response(inputs.schemas[32]!);
          assert.equal(sql, CURSOR_SQL);
          assert.equal(sql, 'SELECT id FROM vault_owner_record_gc_cursor ORDER BY id');
          return response(rows);
        }, inputs),
      /cursor initialization/,
    );
  }
  assert.deepEqual(
    inspect(
      (args) =>
        response(
          args.at(-1) === LEDGER_SQL
            ? ledger(32)
            : args.at(-1) === SCHEMA_SQL
              ? inputs.schemas[32]!
              : [{ id: 1 }],
        ),
      inputs,
    ).pending,
    [],
  );
});
