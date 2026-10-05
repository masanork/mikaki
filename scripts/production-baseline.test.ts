import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import {
  assertProductionBaseline,
  BASELINE_NAME,
  BASELINE_SCHEMA_QUERY,
  canonicalSql,
} from './production-baseline.ts';

test('promotion requires the exact reset schema and singleton ledger', () => {
  const baseline = readFileSync('crates/worker/migrations/' + BASELINE_NAME, 'utf8');
  const db = new DatabaseSync(':memory:');
  try {
    db.exec(baseline);
    const schema = db.prepare(BASELINE_SCHEMA_QUERY).all() as Parameters<
      typeof assertProductionBaseline
    >[2];
    assertProductionBaseline(baseline, [{ name: BASELINE_NAME }], schema);
    assert.throws(
      () =>
        assertProductionBaseline(baseline, [{ name: '0035_agent_record_approvals.sql' }], schema),
      /single reset baseline ledger/,
    );
    assert.throws(
      () =>
        assertProductionBaseline(
          baseline,
          [{ name: BASELINE_NAME }, { name: '0035_agent_record_approvals.sql' }],
          schema,
        ),
      /single reset baseline ledger/,
    );
    db.exec('CREATE TABLE vault_oauth_token_context (access_hash TEXT)');
    assert.throws(
      () =>
        assertProductionBaseline(
          baseline,
          [{ name: BASELINE_NAME }],
          db.prepare(BASELINE_SCHEMA_QUERY).all() as typeof schema,
        ),
      /schema differs/,
    );
    const changed = structuredClone(schema);
    const trigger = changed.find((row) => row.type === 'trigger');
    assert.ok(trigger);
    trigger.sql = 'CREATE TRIGGER altered AFTER INSERT ON client BEGIN SELECT 1; END';
    assert.throws(
      () => assertProductionBaseline(baseline, [{ name: BASELINE_NAME }], changed),
      /schema differs/,
    );
  } finally {
    db.close();
  }
});

test('schema comparison preserves literals and SQL token boundaries', () => {
  assert.deepEqual(canonicalSql("CHECK( x = 'a b' ) -- comment"), canonicalSql("CHECK(x='a b')"));
  assert.notDeepEqual(canonicalSql("CHECK(x='a b')"), canonicalSql("CHECK(x='ab')"));
  assert.notDeepEqual(canonicalSql('x IS NOT NULL'), canonicalSql('x ISNOT NULL'));
  assert.notDeepEqual(canonicalSql("X'AB'"), canonicalSql("X 'AB'"));
  assert.throws(() => canonicalSql("CHECK(x='unfinished)"));
});

test('a separate RP baseline must use its own exact ledger and schema', () => {
  const sql = 'CREATE TABLE rp_session(token_hash TEXT PRIMARY KEY);';
  const db = new DatabaseSync(':memory:');
  try {
    db.exec(sql);
    const schema = db.prepare(BASELINE_SCHEMA_QUERY).all() as Parameters<
      typeof assertProductionBaseline
    >[2];
    assertProductionBaseline(sql, [{ name: '0001_initial.sql' }], schema, '0001_initial.sql');
    assert.throws(
      () => assertProductionBaseline(sql, [{ name: BASELINE_NAME }], schema, '0001_initial.sql'),
      /single reset baseline ledger/,
    );
    db.exec('CREATE TABLE old_ticket(id TEXT);');
    assert.throws(
      () =>
        assertProductionBaseline(
          sql,
          [{ name: '0001_initial.sql' }],
          db.prepare(BASELINE_SCHEMA_QUERY).all() as typeof schema,
          '0001_initial.sql',
        ),
      /schema differs/,
    );
  } finally {
    db.close();
  }
});
