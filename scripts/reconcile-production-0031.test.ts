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
  POLICY_SQL,
  DORMANT_POLICY,
  COMPATIBILITY_TARGET,
  inspectComplete,
  SCHEMA_SQL,
  applicationGate,
  applyApprovedSuffix,
  assertFreshBookmark,
  bookmarkAt,
  canonicalSql,
  expectedInputs,
  inspect,
  inspectState,
  resultRows,
} from './reconcile-production-0031.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
// This one-off production gate intentionally becomes obsolete at 0036. Keep its
// supported-state fixtures stable so later migrations do not break normal CI.
const fixture = mkdtempSync(join(tmpdir(), 'mikaki-reviewed-0033-0035-'));
const fixtureMigrations = join(fixture, 'crates/worker/migrations');
mkdirSync(fixtureMigrations, { recursive: true });
for (const name of readdirSync(join(root, 'crates/worker/migrations')).sort().slice(0, 35)) {
  copyFileSync(join(root, 'crates/worker/migrations', name), join(fixtureMigrations, name));
}
after(() => rmSync(fixture, { recursive: true, force: true }));
const inputs = expectedInputs(fixture);
const approvedNames = APPROVED.migrations.map((item) => item.name);
const ledger = (count = 32) =>
  inputs.names.slice(0, count).map((name, index) => ({ id: index + 1, name }));
const response = (rows: unknown[]) => JSON.stringify([{ success: true, results: rows }]);
const bookmark = '00000085-0000024c-00004c6d-8e61117bf38d7adb71b934ebbf891683';

test('only approved 0033–0035 suffixes are candidates, or safely already applied', () => {
  const plan = inspectState(inputs, ledger(), inputs.schemas[32]!);
  assert.deepEqual(plan.pending, approvedNames);
  assert.match(plan.plan_sha256, /^[a-f0-9]{64}$/);
  applicationGate(plan, plan.plan_sha256, CONFIRMATION);
  for (const old of [
    '',
    'APPLY 0031 TO mikaki-auth',
    'APPLY 0031 AND 0032 TO mikaki-auth',
    'APPLY 0033 TO mikaki-auth',
  ])
    assert.throws(() => applicationGate(plan, plan.plan_sha256, old), /confirmation/);
  assert.throws(() => applicationGate(plan, 'a'.repeat(64), CONFIRMATION), /reviewed plan/);
  for (const count of [33, 34]) {
    const partial = inspectState(inputs, ledger(count), inputs.schemas[count]!);
    assert.deepEqual(partial.pending, approvedNames.slice(count - 32));
    applicationGate(partial, partial.plan_sha256, CONFIRMATION);
    assert.throws(() => applicationGate(partial, plan.plan_sha256, CONFIRMATION), /reviewed plan/);
  }
  const done = inspectState(inputs, ledger(35), inputs.schemas[35]!);
  assert.deepEqual(done.pending, []);
  assert.notEqual(done.plan_sha256, plan.plan_sha256);
  assert.throws(() => applicationGate(done, done.plan_sha256, CONFIRMATION), /nonempty approved/);
  assert.throws(() => applicationGate(done, plan.plan_sha256, CONFIRMATION), /reviewed plan/);
});

test('missing, unknown, duplicate, reordered or malformed ledger never becomes an apply plan', () => {
  for (const count of [0, 29, 30, 31])
    assert.throws(() => inspectState(inputs, ledger(count), inputs.schemas[32]!), /prefix/);
  for (const rows of [
    [...ledger(), { id: 33, name: '0033_unreviewed.sql' }],
    [...ledger(35), { id: 36, name: '0036_unreviewed.sql' }],
    ledger().map((row, i) => (i === 29 ? { ...row, name: inputs.names[0] } : row)),
    ledger().reverse(),
    ledger().map((row, i) => (i === 29 ? { ...row, id: 0 } : row)),
  ])
    assert.throws(() => inspectState(inputs, rows, inputs.schemas[32]!));
});

test('absent ledger, preexisting/partial tables, altered STRICT schema and extra triggers fail closed', () => {
  assert.throws(() => inspectState(inputs, ledger(), []), /schema/);
  assert.throws(() => inspectState(inputs, ledger(), inputs.schemas[33]!), /schema/);
  assert.throws(() => inspectState(inputs, ledger(33), inputs.schemas[32]!), /schema/);
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
        ...inputs.schemas[32]!,
        { type: 'trigger', name: 'extra', tbl_name: 'd1_migrations', sql: 'CREATE TRIGGER extra' },
      ]),
    /schema/,
  );
});

test('default inspection executes SELECT only and rejects unsuccessful or ambiguous JSON', () => {
  const commands: string[][] = [];
  inspect((args) => {
    commands.push(args);
    return response(
      args.at(-1) === LEDGER_SQL
        ? ledger()
        : args.at(-1) === SCHEMA_SQL
          ? inputs.schemas[32]!
          : [{ id: 1 }],
    );
  }, inputs);
  assert.equal(commands.length, 3);
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
  const temp = mkdtempSync(join(tmpdir(), 'mikaki-0033-test-'));
  const db = new DatabaseSync(':memory:');
  try {
    for (const name of inputs.names.slice(0, 32))
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
      new Date().toISOString(),
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
              [approvedNames[0]!]: inputs.migrations[approvedNames[0]!] + '\n',
            },
          },
          approvedNames,
          temp,
          new Date().toISOString(),
        ),
      /hash/,
    );
  } finally {
    db.close();
    rmSync(temp, { recursive: true, force: true });
  }
});

test('failed application cleans temporary material and propagates without retry', () => {
  const temp = mkdtempSync(join(tmpdir(), 'mikaki-0033-test-'));
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
          new Date().toISOString(),
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
  assert.match(
    workflow,
    /github.ref == 'refs\/heads\/main' && github.repository == 'masanork\/mikaki'/,
  );
  assert.match(workflow, /cancel-in-progress: false/);
  assert.match(workflow, /APPLY 0033 THROUGH 0035 TO mikaki-auth/);
  assert.match(workflow, /migration-0033-0035-plan\.json/);
  assert.match(workflow, /ref: af0b89963761b4ecda2adbf3ed7fb77bfda507d4/);
  assert.ok(
    workflow.indexOf('if-no-files-found: error') <
      workflow.indexOf('run: node scripts/reconcile-production-0031.ts apply'),
  );
  assert.doesNotMatch(
    workflow,
    /OP_PRIVATE_JWK|MIKAKI_READY_TOKEN|workflow_call:|pull_request:|push:|contents: write/,
  );
});

test('production input loader rejects a later 0036 without breaking the stable test fixture', () => {
  const later = join(fixtureMigrations, '0036_unreviewed.sql');
  try {
    writeFileSync(later, 'CREATE TABLE later(id INTEGER);');
    assert.throws(() => expectedInputs(fixture), /exactly the reviewed/);
  } finally {
    rmSync(later);
  }
  assert.deepEqual(expectedInputs(fixture).names, inputs.names);
});

test('uncertain completed 0033–0035 is inspected as complete, never reapplied or restored', () => {
  const temp = mkdtempSync(join(tmpdir(), 'mikaki-uncertain-test-'));
  const db = database32();
  let calls = 0;
  try {
    const before = inspectState(inputs, db.prepare(LEDGER_SQL).all(), db.prepare(SCHEMA_SQL).all());
    assert.throws(
      () =>
        applyApprovedSuffix(
          () => {
            calls++;
            applyLocal(db);
            throw new Error('response lost after commit');
          },
          inputs,
          before.pending,
          temp,
          new Date().toISOString(),
        ),
      /response lost/,
    );
    assert.equal(calls, 1);
    const done = inspectState(inputs, db.prepare(LEDGER_SQL).all(), db.prepare(SCHEMA_SQL).all());
    assert.deepEqual(done.pending, []);
    assert.throws(() => applicationGate(done, before.plan_sha256, CONFIRMATION), /reviewed plan/);
    assert.throws(() => applicationGate(done, done.plan_sha256, CONFIRMATION), /nonempty/);
    for (const invalid of [
      [],
      ['0031_vault_owner_keys.sql'],
      ['0032_vault_owner_records.sql'],
      ['0036_unreviewed.sql'],
      [...approvedNames, ...approvedNames],
    ])
      assert.throws(
        () =>
          applyApprovedSuffix(
            () => {
              throw new Error('must not run');
            },
            inputs,
            invalid,
            temp,
            new Date().toISOString(),
          ),
        /approved suffix/,
      );
  } finally {
    db.close();
    rmSync(temp, { recursive: true, force: true });
  }
});

test('all supported states require the initialized GC cursor id without reading its value', () => {
  for (const count of [32, 33, 34, 35]) {
    for (const rows of [[], [{ id: 2 }], [{ id: 1 }, { id: 2 }]]) {
      assert.throws(
        () =>
          inspect((args) => {
            const sql = args.at(-1);
            if (sql === LEDGER_SQL) return response(ledger(count));
            if (sql === SCHEMA_SQL) return response(inputs.schemas[count]!);
            if (sql === POLICY_SQL) return response(DORMANT_POLICY);
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
              ? ledger(count)
              : args.at(-1) === SCHEMA_SQL
                ? inputs.schemas[count]!
                : args.at(-1) === POLICY_SQL
                  ? DORMANT_POLICY
                  : [{ id: 1 }],
          ),
        inputs,
      ).pending,
      approvedNames.slice(count - 32),
    );
  }
});

function database32() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const name of inputs.names.slice(0, 32))
    db.exec(readFileSync(join(fixtureMigrations, name), 'utf8'));
  db.exec(
    'CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)',
  );
  for (const row of ledger()) db.prepare('INSERT INTO d1_migrations(name) VALUES(?)').run(row.name);
  return db;
}
function applyLocal(db: DatabaseSync, count = approvedNames.length) {
  for (const name of approvedNames.slice(0, count)) {
    db.exec('BEGIN');
    db.exec(inputs.migrations[name]!);
    db.prepare('INSERT INTO d1_migrations(name) VALUES(?)').run(name);
    db.exec('COMMIT');
  }
}
function seedLegacy(db: DatabaseSync) {
  db.exec(`INSERT INTO account_security VALUES('owner',1,1);
    INSERT INTO credential VALUES('key','owner',1);
    INSERT INTO agent_recipient_key VALUES('recipient','active');`);
  for (const [id, revoked] of [
    ['legacy', 0],
    ['already-revoked', 1],
  ] as const)
    db.prepare(
      `INSERT INTO agent_grant(grant_id,account_id,owner_epoch,credential_id,delegate,provider,resource,source_revision,recipient_key_id,operations,document_ids,encrypted_snapshot,token_hash,request_hash,created_at,expires_at,revoked)
    VALUES(?,'owner',1,'key','fixture','fixture','https://agent.test/mcp',1,'recipient','["read"]','["name"]','synthetic-envelope',?,'synthetic-request',100,200,?)`,
    ).run(id, id, revoked);
  db.exec(`INSERT INTO vault_attribute_head VALUES('owner','name',1,1,'legacy-object','legacy-hash','legacy-envelope',0,100);
    INSERT INTO agent_attribute_capability VALUES('legacy','owner_note',0,1,100,200);
    INSERT INTO agent_attribute_proposal(proposal_id,grant_id,grant_revision,request_hash,attribute_id,base_revision,payload,expires_at,created_at)
    VALUES('proposal','legacy',1,'hash','owner_note',0,'synthetic-payload',200,100);`);
  db.exec(`UPDATE agent_attribute_proposal SET state='approved' WHERE proposal_id='proposal';
    INSERT INTO agent_attribute_commit VALUES('proposal','owner','operation','{"format_version":1}','synthetic-candidate-hash','https://owner.test',100,NULL);
    INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'https://rp.test');
    INSERT INTO app_connection VALUES('owner','rp',1,1);
    INSERT INTO vault_claim_release VALUES('owner','rp','name',1,1,1,1,1,'revoked',200,100);
    INSERT INTO vault_claim_disclosure_audit VALUES(1,'owner','rp','name',1,1,100);`);
  db.prepare(
    "INSERT INTO vault_claim_release_audit VALUES('owner',?,?,'rp','name','revoke',1,100)",
  ).run('x'.repeat(43), 'y'.repeat(43));
  db.prepare(
    `INSERT INTO vault_owner_key_head VALUES('owner','vault','https://owner.test',1,1,2,'fixture',?,?,100)`,
  ).run('o'.repeat(43), 'q'.repeat(43));
  for (const id of ['name', 'owner_note'])
    db.prepare(
      `INSERT INTO vault_owner_record_head VALUES('owner','vault','personal',?,?,1,1,2,?,?,?,0,100)`,
    ).run(id, id, `object:${id}`, 'a'.repeat(43), 'k'.repeat(82));
}
function seedV2(db: DatabaseSync) {
  for (const id of ['name', 'owner_note'])
    db.prepare(
      `INSERT INTO agent_grant(grant_id,account_id,owner_epoch,credential_id,delegate,provider,resource,source_revision,recipient_key_id,operations,document_ids,encrypted_snapshot,token_hash,request_hash,created_at,expires_at,storage_version,source_origin,source_vault_id,source_collection_id,source_record_id,source_kind,source_ciphertext_sha256,source_key_generation,source_owner_key_revision)
      VALUES(?,'owner',1,'key','fixture','fixture','https://agent.test/mcp',1,'recipient','["read"]',?,'synthetic-v2',?,'synthetic-request',100,200,2,'https://owner.test','vault','personal',?,?,?,1,1)`,
    ).run(`v2:${id}`, JSON.stringify([id]), `token:${id}`, id, id, 'a'.repeat(43));
}

test('0033–0035 preserve all existing rows and authority, defaulting existing grants to v1', () => {
  const db = database32();
  try {
    seedLegacy(db);
    const snapshots = db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence','d1_migrations') ORDER BY name",
      )
      .all()
      .map(({ name }) => ({
        name: String(name),
        columns: db
          .prepare(`PRAGMA table_info("${name}")`)
          .all()
          .map((r) => `"${r.name}"`)
          .join(','),
        rows: db.prepare(`SELECT * FROM "${name}"`).all(),
      }));
    applyLocal(db);
    for (const { name, columns, rows } of snapshots)
      assert.deepEqual(db.prepare(`SELECT ${columns} FROM "${name}"`).all(), rows, name);
    const grants = db
      .prepare(
        'SELECT storage_version,source_origin,source_vault_id,source_collection_id,source_record_id,source_kind,source_ciphertext_sha256,source_key_generation,source_owner_key_revision FROM agent_grant',
      )
      .all();
    assert.equal(grants.length, 2);
    for (const grant of grants) {
      assert.equal(grant.storage_version, 1);
      assert.ok(
        Object.entries(grant)
          .filter(([key]) => key !== 'storage_version')
          .every(([, value]) => value === null),
      );
    }
    assert.deepEqual(
      inspectState(inputs, db.prepare(LEDGER_SQL).all(), db.prepare(SCHEMA_SQL).all()).pending,
      [],
    );
    assert.deepEqual(
      db
        .prepare(POLICY_SQL)
        .all()
        .map((row) => ({ ...row })),
      DORMANT_POLICY,
    );
    for (const table of [
      'agent_attribute_capability',
      'agent_attribute_proposal',
      'agent_attribute_commit',
    ])
      assert.ok(
        db
          .prepare(`SELECT storage_version FROM ${table}`)
          .all()
          .every((row) => row.storage_version === 1),
        table,
      );
    for (const table of [
      'vault_claim_release',
      'vault_claim_release_audit',
      'vault_claim_disclosure_audit',
    ])
      assert.ok(
        db
          .prepare(`SELECT source_storage_version FROM ${table}`)
          .all()
          .every((row) => row.source_storage_version === 1),
        table,
      );
    for (const table of [
      'vault_record_recipient_envelope',
      'vault_record_grant',
      'vault_record_share_audit',
      'vault_record_share_guard',
    ])
      assert.equal(db.prepare(`SELECT count(*) n FROM ${table}`).get()!.n, 0, table);
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
    assert.equal(db.prepare('PRAGMA integrity_check').get()!.integrity_check, 'ok');
    db.exec("UPDATE agent_grant SET revoked=1 WHERE grant_id='legacy'");
    assert.equal(
      db.prepare("SELECT encrypted_snapshot FROM agent_grant WHERE grant_id='legacy'").get()!
        .encrypted_snapshot,
      null,
    );
    assert.throws(
      () => db.exec("UPDATE agent_grant SET revoked=0 WHERE grant_id='legacy'"),
      /cannot be restored/,
    );
    assert.throws(
      () => db.exec("UPDATE agent_grant SET encrypted_snapshot='restored' WHERE grant_id='legacy'"),
      /cannot be restored/,
    );
  } finally {
    db.close();
  }
});

test('v2 record changes revoke only their exact selected source; key changes revoke only v2', () => {
  for (const mutation of [
    "UPDATE vault_owner_record_head SET revision=2 WHERE record_id='name'",
    "UPDATE vault_owner_record_head SET ciphertext_sha256=replace(ciphertext_sha256,'a','b') WHERE record_id='name'",
    "UPDATE vault_owner_record_head SET key_generation=2 WHERE record_id='name'",
    "UPDATE vault_owner_record_head SET deleted=1,object_key=NULL,ciphertext_sha256=NULL,key_envelope=NULL WHERE record_id='name'",
    "DELETE FROM vault_owner_record_head WHERE record_id='name'",
    "UPDATE vault_owner_record_head SET collection_id='other' WHERE record_id='name'",
    "UPDATE vault_owner_record_head SET kind='changed' WHERE record_id='name'",
    'UPDATE vault_owner_key_head SET revision=2',
    'UPDATE vault_owner_key_head SET key_generation=2',
    "UPDATE vault_owner_key_head SET suite='changed'",
    'DELETE FROM vault_owner_key_head',
    "UPDATE vault_owner_key_head SET origin='https://changed.test'",
  ]) {
    const db = database32();
    try {
      seedLegacy(db);
      applyLocal(db);
      // For the root-delete case, keep only the root before creating synthetic grants,
      // so record-delete triggers cannot satisfy the assertion on behalf of root deletion.
      if (mutation === 'DELETE FROM vault_owner_key_head')
        db.exec('DELETE FROM vault_owner_record_head');
      seedV2(db);
      db.exec(mutation);
      const rows = db.prepare('SELECT grant_id,revoked,encrypted_snapshot FROM agent_grant').all();
      for (const row of rows) {
        const expected =
          row.grant_id === 'already-revoked' ||
          row.grant_id === 'v2:name' ||
          (mutation.includes('vault_owner_key_head') && row.grant_id === 'v2:owner_note');
        assert.equal(row.revoked, Number(expected), `${mutation}: ${row.grant_id}`);
        if (String(row.grant_id).startsWith('v2:') && expected)
          assert.equal(row.encrypted_snapshot, null);
      }
      assert.throws(() =>
        db.exec("UPDATE agent_grant SET encrypted_snapshot='restored' WHERE grant_id='v2:name'"),
      );
    } finally {
      db.close();
    }
  }
});

test('literal-preserving SQL canonicalization accepts layout/comments, never changed literal bytes or token boundaries', () => {
  const sql =
    "SELECT 'per sonal', 'it''s -- /* literal */', \"quoted name\", `column name`, [other name] FROM t WHERE x IS NOT NULL;";
  assert.deepEqual(
    canonicalSql(sql),
    canonicalSql('/* before */\n' + sql.replace(' FROM ', '\t/* layout */ FROM\n') + ' -- end'),
  );
  for (const changed of [
    sql.replace('per sonal', 'personal'),
    sql.replace('IS NOT', 'ISNOT'),
    sql.replace("it''s", 'its'),
    sql.replace('quoted name', 'quotedname'),
    sql.replace('column name', 'columnname'),
    sql.replace('other name', 'othername'),
  ])
    assert.notDeepEqual(canonicalSql(sql), canonicalSql(changed));
  assert.notDeepEqual(canonicalSql("SELECT X'AB'"), canonicalSql("SELECT X 'AB'"));
  assert.notDeepEqual(canonicalSql('SELECT 1_000'), canonicalSql('SELECT 1 _000'));
  assert.notDeepEqual(canonicalSql('SELECT 0xAB_CD'), canonicalSql('SELECT 0xAB _CD'));
  assert.notDeepEqual(canonicalSql('SELECT x - - y'), canonicalSql('SELECT x -- y'));
  for (const bad of [
    "SELECT 'unterminated",
    'SELECT /* unterminated',
    'SELECT [unterminated',
    'SELECT ?',
  ])
    assert.throws(() => canonicalSql(bad));
  const schema = inputs.schemas[33]!;
  const changed = schema.map((row) => ({
    ...row,
    sql: typeof row.sql === 'string' ? row.sql.replace("='personal'", "='per sonal'") : row.sql,
  }));
  assert.notDeepEqual(changed, schema);
  assert.throws(() => inspectState(inputs, ledger(33), changed), /schema/);
  const formatted = schema.map((row) => ({
    ...row,
    sql:
      typeof row.sql === 'string'
        ? '/* layout */\n' + row.sql.replace('CREATE ', 'CREATE\n/* layout */ ') + '; -- end'
        : row.sql,
  }));
  assert.deepEqual(
    inspectState(inputs, ledger(33), formatted),
    inspectState(inputs, ledger(33), schema),
  );
});

test('every affected table/index/trigger is captured, and each missing definition fails closed', () => {
  const required = [
    'agent_grant',
    'agent_attribute_capability',
    'agent_attribute_proposal',
    'vault_attribute_head',
    'vault_owner_record_head',
    'vault_owner_key_head',
  ];
  for (const table of required)
    assert.ok(
      inputs.schemas[33]!.some((r) => r.type === 'table' && r.name === table),
      table,
    );
  for (const count of [32, 33, 34, 35]) {
    for (const row of inputs.schemas[count]!)
      assert.throws(
        () =>
          inspectState(
            inputs,
            ledger(count),
            inputs.schemas[count]!.filter((r) => r !== row),
          ),
        /schema/,
        String(row.name),
      );
  }
});

test('legacy source changes revoke only v1 grants; unrelated record metadata leaves v2 grants live', () => {
  for (const mutation of [
    "UPDATE vault_attribute_head SET revision=2 WHERE attribute_id='name'",
    "UPDATE vault_attribute_head SET deleted=1,object_key=NULL,ciphertext_sha256=NULL,owner_envelope=NULL WHERE attribute_id='name'",
    "DELETE FROM vault_attribute_head WHERE attribute_id='name'",
  ]) {
    const db = database32();
    try {
      seedLegacy(db);
      applyLocal(db);
      seedV2(db);
      db.exec(mutation);
      assert.equal(
        db.prepare("SELECT revoked FROM agent_grant WHERE grant_id='legacy'").get()!.revoked,
        1,
      );
      assert.equal(
        db.prepare("SELECT encrypted_snapshot FROM agent_grant WHERE grant_id='legacy'").get()!
          .encrypted_snapshot,
        null,
      );
      assert.equal(
        db
          .prepare(
            'SELECT count(*) n FROM agent_grant WHERE storage_version=2 AND revoked=0 AND encrypted_snapshot IS NOT NULL',
          )
          .get()!.n,
        2,
      );
    } finally {
      db.close();
    }
  }
  const db = database32();
  try {
    seedLegacy(db);
    applyLocal(db);
    seedV2(db);
    db.exec(
      "UPDATE vault_owner_record_head SET updated_at=101,object_key=object_key || ':changed'; UPDATE vault_owner_key_head SET created_at=101",
    );
    assert.equal(
      db.prepare('SELECT count(*) n FROM agent_grant WHERE storage_version=2 AND revoked=0').get()!
        .n,
      2,
    );
    // Remove parent-dependent records before deleting the root; unrelated legacy grants survive.
    db.exec('DELETE FROM vault_owner_record_head; DELETE FROM vault_owner_key_head');
    assert.equal(
      db.prepare("SELECT revoked FROM agent_grant WHERE grant_id='legacy'").get()!.revoked,
      0,
    );
    assert.equal(
      db
        .prepare(
          'SELECT count(*) n FROM agent_grant WHERE storage_version=2 AND revoked=1 AND encrypted_snapshot IS NULL',
        )
        .get()!.n,
      2,
    );
  } finally {
    db.close();
  }
});

test('0033 rollback leaves the original schema/ledger and no implicit retry', () => {
  const db = database32();
  const temp = mkdtempSync(join(tmpdir(), 'mikaki-rollback-test-'));
  let calls = 0;
  try {
    seedLegacy(db);
    const before = inspectState(inputs, db.prepare(LEDGER_SQL).all(), db.prepare(SCHEMA_SQL).all());
    assert.throws(
      () =>
        applyApprovedSuffix(
          () => {
            calls++;
            db.exec('BEGIN');
            db.exec(inputs.migrations[approvedNames[0]!]!);
            db.exec('ROLLBACK');
            throw new Error('transaction failed');
          },
          inputs,
          before.pending,
          temp,
          new Date().toISOString(),
        ),
      /transaction failed/,
    );
    assert.equal(calls, 1);
    assert.deepEqual(
      inspectState(inputs, db.prepare(LEDGER_SQL).all(), db.prepare(SCHEMA_SQL).all()),
      before,
    );
  } finally {
    db.close();
    rmSync(temp, { recursive: true, force: true });
  }
});

test('bookmark freshness rejects invalid, future and boundary-expired timestamps', () => {
  const now = Date.parse('2026-10-03T10:00:00.000Z');
  for (const age of [0, 119_999]) assertFreshBookmark(new Date(now - age).toISOString(), now);
  for (const timestamp of [
    'invalid',
    new Date(now + 1).toISOString(),
    new Date(now - 120_000).toISOString(),
  ])
    assert.throws(() => assertFreshBookmark(timestamp, now), /stale/);
});

test('bookmark expiring during remote inspection/readback cannot reach the migration command', (t) => {
  const now = Date.parse('2026-10-03T10:00:00.000Z');
  t.mock.timers.enable({ apis: ['Date'], now });
  const capturedAt = new Date(now - 119_000).toISOString();
  const temp = mkdtempSync(join(tmpdir(), 'mikaki-expired-test-'));
  let mutations = 0;
  const run = (args: string[]) => {
    if (args[1] === 'migrations') {
      mutations++;
      return '';
    }
    t.mock.timers.tick(500);
    if (args[1] === 'time-travel') return JSON.stringify({ bookmark });
    return response(
      args.at(-1) === LEDGER_SQL
        ? ledger()
        : args.at(-1) === SCHEMA_SQL
          ? inputs.schemas[32]!
          : [{ id: 1 }],
    );
  };
  try {
    assertFreshBookmark(capturedAt);
    const state = inspect(run, inputs);
    assert.equal(bookmarkAt(run, capturedAt), bookmark);
    assert.equal(Date.now() - Date.parse(capturedAt), 121_000);
    assert.throws(() => applyApprovedSuffix(run, inputs, state.pending, temp, capturedAt), /stale/);
    assert.equal(mutations, 0);
    assert.deepEqual(readdirSync(temp), []);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('0034/0035 require exact disabled policy initialization and never repair it', () => {
  for (const count of [34, 35])
    for (const mutation of [
      'DELETE FROM vault_record_share_policy',
      'UPDATE vault_record_share_policy SET enabled=1,revision=2',
      'UPDATE vault_record_share_policy SET grant_ttl_seconds=600,revision=2',
      'UPDATE vault_record_share_policy SET revision=2',
    ]) {
      const db = database32();
      try {
        applyLocal(db, count - 32);
        const run = (args: string[]) => response(db.prepare(args.at(-1)!).all());
        assert.deepEqual(inspect(run, inputs).pending, approvedNames.slice(count - 32));
        db.exec(mutation);
        assert.throws(() => inspect(run, inputs), /disabled initialization/);
      } finally {
        db.close();
      }
    }
});

test('partial success leaves only a reviewed suffix and requires a new digest', () => {
  for (const committed of [1, 2]) {
    const db = database32();
    const temp = mkdtempSync(join(tmpdir(), 'mikaki-partial-0035-'));
    let calls = 0;
    try {
      seedLegacy(db);
      const initial = inspectState(
        inputs,
        db.prepare(LEDGER_SQL).all(),
        db.prepare(SCHEMA_SQL).all(),
      );
      assert.throws(
        () =>
          applyApprovedSuffix(
            () => {
              calls++;
              applyLocal(db, committed);
              db.exec('BEGIN');
              db.exec(inputs.migrations[approvedNames[committed]!]!);
              db.exec('ROLLBACK');
              throw new Error('later migration failed');
            },
            inputs,
            initial.pending,
            temp,
            new Date().toISOString(),
          ),
        /later migration failed/,
      );
      assert.equal(calls, 1);
      const partial = inspectState(
        inputs,
        db.prepare(LEDGER_SQL).all(),
        db.prepare(SCHEMA_SQL).all(),
      );
      assert.deepEqual(partial.pending, approvedNames.slice(committed));
      assert.throws(
        () => applicationGate(partial, initial.plan_sha256, CONFIRMATION),
        /reviewed plan/,
      );
      applicationGate(partial, partial.plan_sha256, CONFIRMATION);
      applyApprovedSuffix(
        (args) => {
          const configPath = args.at(-1)!;
          const config = JSON.parse(readFileSync(configPath, 'utf8'));
          const directory = join(configPath, '..', config.d1_databases[0].migrations_dir);
          assert.deepEqual(readdirSync(directory).sort(), approvedNames.slice(committed));
          return '';
        },
        inputs,
        partial.pending,
        temp,
        new Date().toISOString(),
      );
      assert.deepEqual(readdirSync(temp), []);
    } finally {
      db.close();
      rmSync(temp, { recursive: true, force: true });
    }
  }
});

function compatibilityMetadata(extraService = false, advance: () => void = () => {}) {
  return async (path: string) => {
    advance();
    const target = COMPATIBILITY_TARGET;
    if (path.endsWith('/scripts'))
      return {
        success: true,
        result: [{ id: target.op }, { id: target.claim }],
      };
    const op = path.includes(`/scripts/${target.op}/`);
    const id = op ? target.versions.op : target.versions.claim;
    const bindings = [
      { name: 'DB', type: 'd1', database_id: target.database_id },
      ...(extraService ? [{ name: 'EXTRA', type: 'service', service: 'other' }] : []),
    ];
    if (path.endsWith('/settings')) return { success: true, result: { bindings } };
    if (path.includes('/deployments'))
      return {
        success: true,
        result: {
          deployments: [
            { strategy: 'percentage', versions: [{ version_id: id, percentage: 100 }] },
          ],
        },
      };
    assert.ok(path.endsWith(`/versions/${id}`));
    return {
      success: true,
      result: {
        id,
        resources: { bindings },
        annotations: {
          'workers/tag': target.qualified_source.slice(0, 12),
          'workers/message': `main CI ${target.qualified_source}`,
        },
      },
    };
  };
}
function dbRead(count = 32) {
  return (args: string[]) =>
    response(
      args.at(-1) === LEDGER_SQL
        ? ledger(count)
        : args.at(-1) === SCHEMA_SQL
          ? inputs.schemas[count]!
          : args.at(-1) === POLICY_SQL
            ? DORMANT_POLICY
            : [{ id: 1 }],
    );
}

test('plan digest binds live metadata and rechecks dormant policy and ledger', async () => {
  const first = await inspectComplete(dbRead(), inputs, compatibilityMetadata());
  const changed = await inspectComplete(dbRead(), inputs, compatibilityMetadata(true));
  assert.notEqual(first.plan_sha256, changed.plan_sha256);
  assert.throws(() => applicationGate(changed, first.plan_sha256, CONFIRMATION), /reviewed plan/);
  assert.deepEqual(
    (await inspectComplete(dbRead(35), inputs, compatibilityMetadata())).pending,
    [],
  );
  let queries = 0;
  await assert.rejects(
    inspectComplete(
      () => {
        queries++;
        return '';
      },
      inputs,
      async () => ({ success: false }),
    ),
    /metadata/,
  );
  assert.equal(queries, 0);
});

test('slow metadata inventory cannot outlive the original retained bookmark before mutation', async (t) => {
  const now = Date.parse('2026-10-03T10:00:00.000Z');
  t.mock.timers.enable({ apis: ['Date'], now });
  const capturedAt = new Date(now - 119_000).toISOString();
  assertFreshBookmark(capturedAt);
  const state = await inspectComplete(
    dbRead(),
    inputs,
    compatibilityMetadata(false, () => t.mock.timers.tick(1000)),
  );
  assert.ok(Date.now() - Date.parse(capturedAt) > 120_000);
  const temp = mkdtempSync(join(tmpdir(), 'mikaki-slow-inventory-'));
  let mutations = 0;
  try {
    assert.throws(
      () =>
        applyApprovedSuffix(
          () => {
            mutations++;
            return '';
          },
          inputs,
          state.pending,
          temp,
          capturedAt,
        ),
      /stale/,
    );
    assert.equal(mutations, 0);
    assert.deepEqual(readdirSync(temp), []);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
