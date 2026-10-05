import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

const queries = readFileSync(
  new URL('../crates/worker/src/auth_backlog.sql', import.meta.url),
  'utf8',
)
  .split(';')
  .map((sql) => sql.trim())
  .filter(Boolean);

function openDb() {
  const db = new DatabaseSync(':memory:');
  // Keep exact cutoff fixtures deterministic across a wall-clock second boundary.
  db.function('unixepoch', () => 1_800_000_000);
  db.exec(`
    CREATE TABLE login_transaction(expires_at INTEGER NOT NULL);
    CREATE TABLE authorization_code(expires_at INTEGER NOT NULL);
    CREATE TABLE token_issue(access_expires_at INTEGER NOT NULL);
    CREATE TABLE sso_session(expires_at INTEGER NOT NULL);
    CREATE TABLE sso_logout_event(deadline INTEGER NOT NULL);
    CREATE TABLE dpop_proof_use(retain_until INTEGER NOT NULL);
  `);
  return db;
}

test('auth GC backlog returns all six independent buckets and preserves retention cutoffs', () => {
  const db = openDb();
  try {
    const now = db.prepare('SELECT unixepoch() AS now').get()?.now as number;
    const fixtures = [
      ['login', 'login_transaction', 'expires_at', 86400],
      ['codes', 'authorization_code', 'expires_at', 7776000],
      ['tokens', 'token_issue', 'access_expires_at', 7776000],
      ['sso', 'sso_session', 'expires_at', 7776000],
      ['logout', 'sso_logout_event', 'deadline', 7776000],
      ['dpop', 'dpop_proof_use', 'retain_until', 0],
    ] as const;
    for (const [, table, column, retention] of fixtures) {
      const insert = db.prepare(`INSERT INTO ${table}(${column}) VALUES(?)`);
      insert.run(now - retention - 20);
      insert.run(now - retention - 10);
      insert.run(now - retention);
      insert.run(now - retention + 1);
    }

    const rows = queries.map((sql) => ({ ...db.prepare(sql).get() }));
    assert.deepEqual(
      rows,
      fixtures.map(([kind, , , retention]) => ({
        kind,
        expired: 2,
        oldest: now - retention - 20,
      })),
    );
  } finally {
    db.close();
  }
});

test('auth GC backlog reports empty buckets with zero count and null oldest', () => {
  const db = openDb();
  try {
    assert.deepEqual(
      queries.map((sql) => ({ ...db.prepare(sql).get() })),
      ['login', 'codes', 'tokens', 'sso', 'logout', 'dpop'].map((kind) => ({
        kind,
        expired: 0,
        oldest: null,
      })),
    );
  } finally {
    db.close();
  }
});
