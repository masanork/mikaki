/** SQLite contract checks for the exact SQL used by Worker authorization issuance. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

const REDIRECT = 'https://client.example/callback';
const COOKIE_HASH = 'C'.repeat(43);
const migration = (name: string) =>
  readFileSync(new URL(`../crates/worker/migrations/${name}`, import.meta.url), 'utf8');
const sql = (name: string) =>
  readFileSync(new URL(`../crates/worker/sql/${name}`, import.meta.url), 'utf8');
const scalar = (db: DatabaseSync, statement: string) =>
  Object.values(db.prepare(statement).get()!)[0];

function seededDb() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const name of [
    '0001_oidc_initial.sql',
    '0003_client_administration.sql',
    '0004_client_redirect_lifecycle.sql',
  ])
    db.exec(migration(name));
  const now = Math.floor(Date.now() / 1000);
  db.exec("INSERT INTO account_security VALUES('account',0,1)");
  db.exec("INSERT INTO credential VALUES('cred','account',1)");
  db.exec(
    "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('client',1,1,'sector.example')",
  );
  db.prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)').run(
    'client',
    REDIRECT,
  );
  db.exec("INSERT INTO app_connection VALUES('account','client',1,1)");
  db.prepare("INSERT INTO sso_session VALUES('sso','account','cred',0,?,0)").run(now + 600);
  db.prepare('INSERT INTO sso_context VALUES(?,?,?)').run('sso', COOKIE_HASH, now - 10);
  return db;
}

type Options = {
  redirect?: string;
  cookieHash?: string;
  revision?: number;
  failAfter?: number;
  sid?: string;
  codeHash?: string;
  nonce?: string;
  candidateSub?: string;
};
function runBatch(db: DatabaseSync, options: Options = {}) {
  const {
    redirect = REDIRECT,
    cookieHash = COOKIE_HASH,
    revision = 1,
    failAfter,
    sid = 'S'.repeat(43),
    codeHash = 'A'.repeat(43),
    nonce = 'test-nonce',
    candidateSub = 'Z'.repeat(43),
  } = options;
  const now = Math.floor(Date.now() / 1000);
  const commands: Array<[string, Array<string | number>]> = [
    ['insert-pairwise-subject.sql', ['account', 'sector.example', candidateSub]],
    [
      'insert-authorization-client-session.sql',
      [sid, 'sso', cookieHash, 'client', revision, redirect, now],
    ],
    [
      'insert-authorization-code.sql',
      [codeHash, 'client', sid, revision, redirect, 'P'.repeat(43), now + 60, now],
    ],
    ['insert-authorization-code-context.sql', [codeHash, nonce]],
    ['guard-authorization-code.sql', [codeHash, 'client', redirect, nonce, now]],
    ['delete-authorization-code-guard.sql', [codeHash]],
  ];
  db.exec('BEGIN IMMEDIATE');
  try {
    commands.forEach(([name, parameters], index) => {
      db.prepare(sql(name)).run(...parameters);
      if (failAfter === index) throw new Error('injected failure');
    });
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}
function counts(db: DatabaseSync) {
  return [
    'pairwise_subject',
    'client_session',
    'authorization_code',
    'code_context',
    'atomic_guard',
  ].map((table) => scalar(db, `SELECT count(*) FROM ${table}`));
}

test('issues code and stable pairwise subject together', () => {
  const db = seededDb();
  try {
    runBatch(db);
    const firstSub = scalar(db, 'SELECT sub FROM client_session');
    runBatch(db, { sid: 'T'.repeat(43), codeHash: 'B'.repeat(43), candidateSub: 'Y'.repeat(43) });
    assert.deepEqual(counts(db), [1, 2, 2, 2, 0]);
    assert.deepEqual(
      db
        .prepare('SELECT DISTINCT sub FROM client_session')
        .all()
        .map((row) => row.sub),
      [firstSub],
    );
  } finally {
    db.close();
  }
});

test('unregistered redirect rolls back pairwise and session', () => {
  const db = seededDb();
  try {
    assert.throws(() => runBatch(db, { redirect: 'https://evil.example/callback' }));
    assert.deepEqual(counts(db), [0, 0, 0, 0, 0]);
  } finally {
    db.close();
  }
});

test('retired redirect cannot issue code', () => {
  const db = seededDb();
  try {
    db.prepare('UPDATE client_redirect_uri SET active=0 WHERE client_id=?').run('client');
    assert.throws(() => runBatch(db));
    assert.deepEqual(counts(db), [0, 0, 0, 0, 0]);
  } finally {
    db.close();
  }
});

test('wrong cookie or stale client revision cannot issue', () => {
  const db = seededDb();
  try {
    for (const options of [{ cookieHash: 'X'.repeat(43) }, { revision: 2 }]) {
      assert.throws(() => runBatch(db, options));
      assert.deepEqual(counts(db), [0, 0, 0, 0, 0]);
    }
  } finally {
    db.close();
  }
});

test('each batch failure rolls back every insert', () => {
  const db = seededDb();
  try {
    for (let index = 0; index < 6; index++) {
      assert.throws(
        () =>
          runBatch(db, { codeHash: String.fromCharCode(65 + index).repeat(43), failAfter: index }),
        /injected failure/,
      );
      assert.deepEqual(counts(db), [0, 0, 0, 0, 0]);
    }
  } finally {
    db.close();
  }
});
