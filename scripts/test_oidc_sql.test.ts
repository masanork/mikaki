/** SQLite atomic-operation design tests, separate from D1, signing, and HTTP tests. */
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';

type Parameters = Record<string, string | number>;
const source = (name: string) =>
  readFileSync(new URL(`../design/sql/${name}`, import.meta.url), 'utf8');
const statements = (name: string) =>
  source(name)
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('--'))
    .join('\n')
    .split(';')
    .map((statement) => statement.trim())
    .filter(Boolean);
const scalar = (db: DatabaseSync, sql: string) => Object.values(db.prepare(sql).get()!)[0];

function batch(db: DatabaseSync, name: string, parameters: Parameters, failAfter?: number) {
  db.exec('BEGIN IMMEDIATE');
  try {
    statements(name).forEach((statement, index) => {
      const bindings = Object.fromEntries(
        [...statement.matchAll(/:([a-z_]+)/g)].map((match) => [match[1], parameters[match[1]]]),
      );
      db.prepare(statement).run(bindings);
      if (failAfter === index) throw new Error('injected storage failure');
    });
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function seed(db: DatabaseSync) {
  db.exec(source('oidc-critical-schema.sql'));
  const now = Math.floor(Date.now() / 1000);
  db.exec(`
    INSERT INTO account_security VALUES('a',0,1);
    INSERT INTO credential VALUES('cred','a',1);
    INSERT INTO client VALUES('c',1,1);
    INSERT INTO client_key VALUES('c','ck',1,1);
    INSERT INTO signing_key VALUES('opk',1,1);
    INSERT INTO app_connection VALUES('a','c',1,1);
  `);
  db.prepare('INSERT INTO sso_session VALUES(?,?,?,?,?,?)').run(
    'sso',
    'a',
    'cred',
    0,
    now + 3600,
    0,
  );
  db.prepare('INSERT INTO client_session VALUES(?,?,?,?,?,?,?)').run(
    'c',
    'sid',
    'sso',
    'a',
    'sub',
    1,
    0,
  );
  db.prepare('INSERT INTO authorization_code VALUES(?,?,?,?,?,?,?,?,?)').run(
    'codehash',
    'c',
    'sid',
    1,
    'https://app.example/cb',
    'challenge',
    now + 600,
    null,
    null,
  );
}

function params(operation = 'exchange', jti = 'assertion'): Parameters {
  return {
    client_id: 'c',
    client_kid: 'ck',
    client_key_revision: 1,
    jti,
    endpoint: 'https://login.example/token',
    operation_id: operation,
    assertion_operation_id: `assertion-${operation}`,
    retain_until: Math.floor(Date.now() / 1000) + 300,
    code_hash: 'codehash',
    redirect_uri: 'https://app.example/cb',
    pkce_challenge: 'challenge',
    signing_kid: 'opk',
    signing_generation: 1,
    access_hash: `access-${operation}`,
    access_expires_at: Math.floor(Date.now() / 1000) + 300,
  };
}

function withDb(run: (db: DatabaseSync) => void) {
  const db = new DatabaseSync(':memory:');
  try {
    seed(db);
    run(db);
  } finally {
    db.close();
  }
}
function accept(db: DatabaseSync, p: Parameters) {
  batch(db, 'accept-assertion.sql', p);
}
function unchangedCode(db: DatabaseSync) {
  assert.equal(scalar(db, 'SELECT consumed_by FROM authorization_code'), null);
  assert.equal(scalar(db, 'SELECT count(*) FROM token_issue'), 0);
}

if (!isMainThread) {
  const { path, index } = workerData as { path: string; index: number };
  const db = new DatabaseSync(path);
  db.exec('PRAGMA busy_timeout=5000');
  const p = params(`parallel-${index}`, `jti-${index}`);
  try {
    accept(db, p);
    parentPort!.postMessage('ready');
    parentPort!.once('message', () => {
      try {
        batch(db, 'exchange-code.sql', p);
        parentPort!.postMessage(true);
      } catch {
        parentPort!.postMessage(false);
      } finally {
        db.close();
      }
    });
  } catch (error) {
    db.close();
    throw error;
  }
}

if (isMainThread) {
  test('success and reuse', () =>
    withDb((db) => {
      const p = params();
      accept(db, p);
      assert.equal(scalar(db, 'SELECT count(*) FROM valid_client_session'), 0);
      batch(db, 'exchange-code.sql', p);
      assert.equal(scalar(db, 'SELECT count(*) FROM token_issue'), 1);
      assert.equal(scalar(db, 'SELECT count(*) FROM valid_client_session'), 1);
      const other = params('again', 'again');
      accept(db, other);
      assert.throws(() => batch(db, 'exchange-code.sql', other));
      assert.equal(scalar(db, 'SELECT consumed_by FROM authorization_code'), 'exchange');
    }));

  test('assertion reuse and endpoint binding', () =>
    withDb((db) => {
      const p = params();
      accept(db, p);
      assert.throws(() => accept(db, params('other', 'assertion')));
      p.endpoint = 'https://login.example/session/check';
      assert.throws(() => batch(db, 'exchange-code.sql', p));
      unchangedCode(db);
    }));

  test('zero-row guard leaves separately consumed assertion', () =>
    withDb((db) => {
      const p = params();
      accept(db, p);
      p.pkce_challenge = 'wrong';
      assert.throws(() => batch(db, 'exchange-code.sql', p));
      unchangedCode(db);
      assert.equal(scalar(db, 'SELECT count(*) FROM assertion_use'), 1);
    }));

  test('failure at every exchange statement rolls back', () =>
    withDb((db) => {
      const p = params();
      accept(db, p);
      for (let pos = 0; pos < statements('exchange-code.sql').length; pos++) {
        assert.throws(() => batch(db, 'exchange-code.sql', p, pos), /injected storage failure/);
        unchangedCode(db);
        assert.equal(scalar(db, 'SELECT count(*) FROM atomic_guard'), 0);
      }
    }));

  test('failed insert rolls back consumption', () =>
    withDb((db) => {
      db.exec(
        "CREATE TRIGGER fail_issue BEFORE INSERT ON token_issue BEGIN SELECT RAISE(ABORT,'injected'); END",
      );
      const p = params();
      accept(db, p);
      assert.throws(() => batch(db, 'exchange-code.sql', p));
      unchangedCode(db);
    }));

  test('expiry boundary', () =>
    withDb((db) => {
      db.exec("UPDATE authorization_code SET expires_at=CAST(strftime('%s','now') AS INTEGER)");
      const p = params();
      accept(db, p);
      assert.throws(() => batch(db, 'exchange-code.sql', p));
      unchangedCode(db);
    }));

  test('invalidations reject exchange', () => {
    for (const mutation of [
      'UPDATE account_security SET epoch=1',
      'UPDATE credential SET active=0',
      'UPDATE app_connection SET grant_version=2',
      'UPDATE app_connection SET active=0',
      'UPDATE sso_session SET revoked=1',
      'UPDATE client_session SET revoked=1',
      'UPDATE client SET revision=2',
      'UPDATE client SET active=0',
      'UPDATE client_key SET active=0',
      'UPDATE signing_key SET active=0',
    ])
      withDb((db) => {
        const p = params();
        accept(db, p);
        db.exec(mutation);
        assert.throws(() => batch(db, 'exchange-code.sql', p), mutation);
        assert.equal(scalar(db, 'SELECT consumed_by FROM authorization_code'), null);
      });
  });

  test('new epoch session survives old event', () =>
    withDb((db) => {
      const p = params();
      accept(db, p);
      batch(db, 'exchange-code.sql', p);
      batch(db, 'revoke-all.sql', { account_id: 'a', expected_epoch: 0, operation_id: 'logout' });
      assert.equal(scalar(db, 'SELECT count(*) FROM valid_client_session'), 0);
      db.exec(
        "INSERT INTO sso_session SELECT 'new-sso',account_id,credential_id,1,expires_at,0 FROM sso_session WHERE sso_id='sso'",
      );
      db.exec("INSERT INTO client_session VALUES('c','new-sid','new-sso','a','sub',1,0)");
      db.exec(
        "INSERT INTO authorization_code SELECT 'new-code',client_id,'new-sid',client_revision,redirect_uri,pkce_challenge,expires_at,NULL,NULL FROM authorization_code WHERE code_hash='codehash'",
      );
      const next = params('new-exchange', 'new-jti');
      next.code_hash = 'new-code';
      accept(db, next);
      batch(db, 'exchange-code.sql', next);
      assert.deepEqual(
        db
          .prepare('SELECT sid FROM valid_client_session')
          .all()
          .map((row) => row.sid),
        ['new-sid'],
      );
      assert.equal(scalar(db, 'SELECT through_epoch FROM revocation_event'), 0);
    }));

  test('stale expected epoch cannot create new event', () =>
    withDb((db) => {
      batch(db, 'revoke-all.sql', { account_id: 'a', expected_epoch: 0, operation_id: 'first' });
      assert.throws(() =>
        batch(db, 'revoke-all.sql', { account_id: 'a', expected_epoch: 0, operation_id: 'stale' }),
      );
      assert.equal(scalar(db, 'SELECT count(*) FROM revocation_event'), 1);
      assert.equal(scalar(db, 'SELECT epoch FROM account_security'), 1);
    }));

  test('failure at every revoke statement rolls back', () =>
    withDb((db) => {
      const p = { account_id: 'a', expected_epoch: 0, operation_id: 'logout' };
      for (let pos = 0; pos < statements('revoke-all.sql').length; pos++) {
        assert.throws(() => batch(db, 'revoke-all.sql', p, pos), /injected storage failure/);
        assert.equal(scalar(db, 'SELECT epoch FROM account_security'), 0);
        assert.equal(scalar(db, 'SELECT count(*) FROM revocation_event'), 0);
      }
    }));

  test('expired access candidate does not consume code', () =>
    withDb((db) => {
      const p = params();
      accept(db, p);
      p.access_expires_at = 1;
      assert.throws(() => batch(db, 'exchange-code.sql', p));
      unchangedCode(db);
    }));

  test('access expiry does not end session but issue revocation does', () =>
    withDb((db) => {
      const p = params();
      accept(db, p);
      batch(db, 'exchange-code.sql', p);
      db.exec('UPDATE token_issue SET access_expires_at=1');
      assert.equal(scalar(db, 'SELECT count(*) FROM valid_client_session'), 1);
      db.exec('UPDATE token_issue SET revoked=1');
      assert.equal(scalar(db, 'SELECT count(*) FROM valid_client_session'), 0);
    }));

  test('parallel exchange has one winner across two SQLite connections', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'mikaki-sql-'));
    const path = join(directory, 'test.sqlite');
    const db = new DatabaseSync(path);
    try {
      seed(db);
      const workers = [0, 1].map(
        (index) =>
          new Worker(new URL(import.meta.url), { workerData: { path, index }, execArgv: [] }),
      );
      try {
        const outcomes = workers.map(
          (worker) =>
            new Promise<boolean>((resolve, reject) => {
              worker.once('error', reject);
              worker.once('exit', (code) => {
                if (code !== 0) reject(new Error(`worker exited ${code}`));
              });
              worker.once('message', (message) => {
                if (message !== 'ready') return reject(new Error('worker did not reach barrier'));
                worker.once('message', (value) => resolve(value as boolean));
              });
            }),
        );
        // Each worker sends ready after accepting its assertion. Release both only then.
        await Promise.all(
          workers.map(
            (worker) =>
              new Promise<void>((resolve, reject) => {
                worker.once('error', reject);
                worker.once('message', () => resolve());
              }),
          ),
        );
        workers.forEach((worker) => worker.postMessage('go'));
        assert.deepEqual((await Promise.all(outcomes)).sort(), [false, true]);
        assert.equal(scalar(db, 'SELECT count(*) FROM token_issue'), 1);
      } finally {
        await Promise.all(workers.map((worker) => worker.terminate()));
      }
    } finally {
      db.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
