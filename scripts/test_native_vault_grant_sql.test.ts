import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

const migrationDir = new URL('../crates/worker/migrations/', import.meta.url);
const resource = 'https://mikaki.tossa.app/vault-api/';
const now = Math.floor(Date.now() / 1000);

function seededDb() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const name of readdirSync(migrationDir)
    .filter((value) => /^\d{4}_.+\.sql$/.test(value))
    .sort())
    db.exec(readFileSync(new URL(name, migrationDir), 'utf8'));
  db.exec("INSERT INTO account_security VALUES('owner',0,1),('other',0,1)");
  db.exec("INSERT INTO credential VALUES('passkey','owner',1)");
  db.exec(
    "INSERT INTO client(client_id,revision,active,client_type,auth_method,sector_identifier) VALUES('native',1,1,'native','none','mikaki.tossa.app')",
  );
  db.exec(
    "INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES('native','https://mikaki.tossa.app/oidc/native/callback')",
  );
  db.exec("INSERT INTO app_connection VALUES('owner','native',1,1)");
  db.prepare("INSERT INTO sso_session VALUES('sso','owner','passkey',0,?,0)").run(now + 600);
  db.prepare("INSERT INTO sso_context VALUES('sso',?,?)").run('B'.repeat(43), now);
  db.prepare(
    "INSERT INTO client_session(client_id,sid,sso_id,account_id,sub,grant_version,revoked) VALUES('native','sid','sso','owner','sub',1,0)",
  ).run();
  db.prepare(
    "INSERT INTO authorization_code(code_hash,client_id,sid,client_revision,redirect_uri,pkce_challenge,expires_at) VALUES(?,'native','sid',1,'https://mikaki.tossa.app/oidc/native/callback',?,?)",
  ).run('C'.repeat(43), 'P'.repeat(43), now + 120);
  return db;
}

function consent(db: DatabaseSync, id = 'T'.repeat(43), sessionHash = 'B'.repeat(43)) {
  db.prepare(
    "INSERT INTO vault_oauth_consent(tx_id,sso_secret_hash,sso_id,account_id,client_id,client_revision,authorization_url,redirect_uri,state,attribute_id,resource,expires_at,created_at) VALUES(?,?,'sso','owner','native',1,?,'https://mikaki.tossa.app/oidc/native/callback','state','owner_note',?,?,?)",
  ).run(
    id,
    sessionHash,
    'https://mikaki.tossa.app/authorize?client_id=native',
    resource,
    now + 300,
    now,
  );
}

function approve(db: DatabaseSync, id = 'T'.repeat(43)) {
  db.prepare("UPDATE vault_oauth_consent SET decision='approved' WHERE tx_id=?").run(id);
  db.prepare("UPDATE vault_oauth_consent SET decision='consumed' WHERE tx_id=?").run(id);
}

function grant(db: DatabaseSync, account = 'owner', id = 'G'.repeat(43), tx = 'T'.repeat(43)) {
  db.prepare(
    "INSERT INTO vault_oauth_grant(grant_id,consent_tx_id,account_id,client_id,client_revision,attribute_id,resource,action,version,expires_at,created_at) VALUES(?,?,?,'native',1,'owner_note',?,'read_ciphertext',1,?,?)",
  ).run(id, tx, account, resource, now + 300, now);
}

test('Vault grant stays specific to owner, client, and attribute', () => {
  const db = seededDb();
  try {
    consent(db);
    approve(db);
    grant(db);
    db.prepare('INSERT INTO vault_oauth_code_context VALUES(?, ?, 1, ?, ?)').run(
      'C'.repeat(43),
      'G'.repeat(43),
      resource,
      'owner_note',
    );
    assert.throws(() =>
      db
        .prepare("UPDATE vault_oauth_grant SET attribute_id='name',version=2 WHERE grant_id=?")
        .run('G'.repeat(43)),
    );
    db.prepare('UPDATE client SET revision=2 WHERE client_id=?').run('native');
    assert.deepEqual(
      { ...db.prepare('SELECT revoked,version FROM vault_oauth_grant').get() },
      { revoked: 1, version: 2 },
    );
  } finally {
    db.close();
  }
});

test('code context rejects another owner, target, or grant version', () => {
  for (const [account, version, attribute] of [
    ['other', 1, 'owner_note'],
    ['owner', 2, 'owner_note'],
    ['owner', 1, 'name'],
  ] as const) {
    const db = seededDb();
    try {
      consent(db);
      approve(db);
      if (account === 'other') {
        assert.throws(() => grant(db, account));
        continue;
      }
      grant(db, account);
      assert.throws(() =>
        db
          .prepare('INSERT INTO vault_oauth_code_context VALUES(?, ?, ?, ?, ?)')
          .run('C'.repeat(43), 'G'.repeat(43), version, resource, attribute),
      );
    } finally {
      db.close();
    }
  }
});

test('grant preconditions reject broad or stale authority', () => {
  const db = seededDb();
  try {
    consent(db);
    assert.throws(() => grant(db));
    approve(db);
    grant(db);
    assert.throws(() => grant(db, 'owner', 'H'.repeat(43)));
    assert.throws(() =>
      db
        .prepare("UPDATE vault_oauth_consent SET decision='approved' WHERE tx_id=?")
        .run('T'.repeat(43)),
    );
  } finally {
    db.close();
  }
});

test('consent must follow pending approval and a live SSO', () => {
  const db = seededDb();
  try {
    assert.throws(() => consent(db, 'X'.repeat(43), 'Z'.repeat(43)));
    consent(db);
    assert.throws(() =>
      db
        .prepare("UPDATE vault_oauth_consent SET decision='consumed' WHERE tx_id=?")
        .run('T'.repeat(43)),
    );
    db.prepare("UPDATE vault_oauth_consent SET decision='approved' WHERE tx_id=?").run(
      'T'.repeat(43),
    );
    db.exec("UPDATE sso_session SET revoked=1 WHERE sso_id='sso'");
    assert.throws(() =>
      db
        .prepare("UPDATE vault_oauth_consent SET decision='consumed' WHERE tx_id=?")
        .run('T'.repeat(43)),
    );
    assert.throws(() => grant(db));
  } finally {
    db.close();
  }
});
