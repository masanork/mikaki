import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

function seededDb(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  db.exec(`
    CREATE TABLE account_security(account_id TEXT PRIMARY KEY,active INTEGER,epoch INTEGER) STRICT;
    CREATE TABLE client(client_id TEXT PRIMARY KEY,revision INTEGER,active INTEGER,auth_method TEXT) STRICT;
    CREATE TABLE app_connection(
      account_id TEXT,client_id TEXT,grant_version INTEGER,active INTEGER,
      PRIMARY KEY(account_id,client_id)) STRICT;
  `);
  for (const name of [
    '0002_vault_attribute_storage.sql',
    '0007_vault_recipient_keys.sql',
    '0008_vault_attribute_sharing.sql',
    '0009_vault_recipient_disable_grants.sql',
    '0010_vault_claim_release.sql',
  ]) {
    db.exec(readFileSync(new URL(`../crates/worker/migrations/${name}`, import.meta.url), 'utf8'));
  }
  const now = Math.floor(Date.now() / 1000);
  db.exec("INSERT INTO account_security VALUES('owner',1,1)");
  db.exec("INSERT INTO client VALUES('rp',1,1,'private_key_jwt')");
  db.exec("INSERT INTO app_connection VALUES('owner','rp',1,1)");
  db.prepare(
    `INSERT INTO vault_attribute_head
     (account_id,attribute_id,revision,format_version,object_key,ciphertext_sha256,
      owner_envelope,deleted,updated_at)
     VALUES('owner','name',1,1,'blob',?,'owner-wrap',0,?)`,
  ).run('d'.repeat(43), now);
  db.prepare(
    `INSERT INTO vault_recipient_key
     (key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at)
     VALUES(?,'userinfo','ML-KEM-768',zeroblob(1184),'TEST_SEED',1,'staged',1,?)`,
  ).run('k'.repeat(43), now - 2);
  db.prepare(
    "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=? WHERE key_id=?",
  ).run(now - 1, 'k'.repeat(43));
  db.prepare(
    `INSERT INTO vault_attribute_recipient_envelope
     (envelope_id,account_id,attribute_id,attribute_revision,recipient_service,
      recipient_key_id,recipient_generation,suite,ciphertext_sha256,frame,created_at)
     VALUES(?,'owner','name',1,'userinfo',?,1,
      'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1',?,zeroblob(1187),?)`,
  ).run('e'.repeat(43), 'k'.repeat(43), 'd'.repeat(43), now);
  db.exec('UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1');
  db.prepare(
    `INSERT INTO vault_attribute_grant
     (account_id,attribute_id,recipient_service,purpose,envelope_id,attribute_revision,
      version,status,expires_at,updated_at)
     VALUES('owner','name','userinfo','oidc.userinfo.name',?,1,1,'active',?,?)`,
  ).run('e'.repeat(43), now + 3000, now);
  return db;
}

function grantRelease(db: DatabaseSync): void {
  const now = Math.floor(Date.now() / 1000);
  db.prepare(
    `INSERT INTO vault_claim_release
     (account_id,client_id,claim,attribute_revision,system_grant_version,client_revision,
      connection_grant_version,version,status,expires_at,updated_at)
     VALUES('owner','rp','name',1,1,1,1,1,'active',?,?)`,
  ).run(now + 1000, now);
}

function state(db: DatabaseSync): unknown {
  return { ...db.prepare('SELECT status,version FROM vault_claim_release').get() };
}

test('RP release needs its own enabled policy and a current system Grant', () => {
  const db = seededDb();
  try {
    assert.throws(() => grantRelease(db));
    db.exec('UPDATE vault_claim_release_policy SET enabled=1,revision=2 WHERE id=1');
    grantRelease(db);
    assert.deepEqual(state(db), { status: 'active', version: 1 });
  } finally {
    db.close();
  }
});

for (const [label, change] of [
  [
    'system Grant',
    "UPDATE vault_attribute_grant SET status='revoked',version=2 WHERE account_id='owner'",
  ],
  ['RP registration', "UPDATE client SET revision=2 WHERE client_id='rp'"],
  [
    'app connection',
    "UPDATE app_connection SET active=0 WHERE account_id='owner' AND client_id='rp'",
  ],
  ['release policy', 'UPDATE vault_claim_release_policy SET enabled=0,revision=3 WHERE id=1'],
  ['release policy revision', 'UPDATE vault_claim_release_policy SET revision=3 WHERE id=1'],
  ['account state', "UPDATE account_security SET epoch=2 WHERE account_id='owner'"],
  [
    'recipient key',
    `UPDATE vault_recipient_key SET state='disabled',revision=3,
    retired_at=CAST(strftime('%s','now') AS INTEGER) WHERE key_id='${'k'.repeat(43)}'`,
  ],
] as const) {
  test(`${label} change revokes RP release`, () => {
    const db = seededDb();
    try {
      db.exec('UPDATE vault_claim_release_policy SET enabled=1,revision=2 WHERE id=1');
      grantRelease(db);
      db.exec(change);
      assert.deepEqual(state(db), { status: 'revoked', version: 2 });
    } finally {
      db.close();
    }
  });
}

test('conformance secret clients and expired system Grants cannot receive releases', () => {
  const db = seededDb();
  try {
    db.exec('UPDATE vault_claim_release_policy SET enabled=1,revision=2 WHERE id=1');
    db.exec("UPDATE client SET auth_method='client_secret_basic' WHERE client_id='rp'");
    assert.throws(() => grantRelease(db));
    db.exec("UPDATE client SET auth_method='private_key_jwt' WHERE client_id='rp'");
    db.exec("UPDATE vault_attribute_grant SET expires_at=1,version=2 WHERE account_id='owner'");
    assert.throws(() => grantRelease(db));
  } finally {
    db.close();
  }
});
