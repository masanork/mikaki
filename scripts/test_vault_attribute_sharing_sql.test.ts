/** Exercise the sharing migration's fail-closed D1 constraints with SQLite. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

function seededDb() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  db.exec('CREATE TABLE account_security(account_id TEXT PRIMARY KEY)');
  for (const name of [
    '0002_vault_attribute_storage.sql',
    '0007_vault_recipient_keys.sql',
    '0008_vault_attribute_sharing.sql',
  ]) {
    db.exec(readFileSync(new URL(`../crates/worker/migrations/${name}`, import.meta.url), 'utf8'));
  }
  db.exec("INSERT INTO account_security(account_id) VALUES('owner')");
  db.prepare(
    `INSERT INTO vault_attribute_head
    (account_id,attribute_id,revision,format_version,object_key,ciphertext_sha256,owner_envelope,deleted,updated_at)
    VALUES('owner','name',1,1,'blob',?,'owner-wrap',0,100)`,
  ).run('d'.repeat(43));
  db.prepare(
    `INSERT INTO vault_recipient_key
    (key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at)
    VALUES(?,'userinfo','ML-KEM-768',zeroblob(1184),'TEST_SEED',1,'staged',1,100)`,
  ).run('k'.repeat(43));
  db.prepare(
    "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=101 WHERE key_id=?",
  ).run('k'.repeat(43));
  db.prepare(
    `INSERT INTO vault_attribute_recipient_envelope
    (envelope_id,account_id,attribute_id,attribute_revision,recipient_service,recipient_key_id,
     recipient_generation,suite,ciphertext_sha256,frame,created_at)
    VALUES(?,'owner','name',1,'userinfo',?,1,
      'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1',?,zeroblob(1187),102)`,
  ).run('e'.repeat(43), 'k'.repeat(43), 'd'.repeat(43));
  return db;
}
const grant = (db: DatabaseSync) =>
  db
    .prepare(
      `INSERT INTO vault_attribute_grant
  (account_id,attribute_id,recipient_service,purpose,envelope_id,attribute_revision,
   version,status,expires_at,updated_at)
  VALUES('owner','name','userinfo','oidc.userinfo.name',?,1,1,'active',604902,102)`,
    )
    .run('e'.repeat(43));
const grantState = (db: DatabaseSync) => ({
  ...db.prepare('SELECT status,version FROM vault_attribute_grant').get(),
});

test('disabled by default and policy revision', () => {
  const db = seededDb();
  try {
    assert.throws(() => grant(db));
    assert.throws(() => db.exec('UPDATE vault_share_policy SET enabled=1 WHERE id=1'));
    db.exec('UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1');
    grant(db);
  } finally {
    db.close();
  }
});

test('head update revokes grant', () => {
  const db = seededDb();
  try {
    db.exec('UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1');
    grant(db);
    db.prepare(
      `UPDATE vault_attribute_head SET revision=2,ciphertext_sha256=?,
      updated_at=103 WHERE account_id='owner' AND attribute_id='name'`,
    ).run('x'.repeat(43));
    assert.deepEqual(grantState(db), { status: 'revoked', version: 2 });
    assert.throws(() =>
      db.exec(
        "UPDATE vault_attribute_grant SET status='active',version=3 WHERE account_id='owner'",
      ),
    );
  } finally {
    db.close();
  }
});

test('key state and digest must match', () => {
  const db = seededDb();
  try {
    db.exec('UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1');
    db.prepare(
      "UPDATE vault_recipient_key SET state='disabled',revision=3,retired_at=103 WHERE key_id=?",
    ).run('k'.repeat(43));
    assert.throws(() => grant(db));
  } finally {
    db.close();
  }
});

test('disabling policy revokes active grants', () => {
  const db = seededDb();
  try {
    db.exec('UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1');
    grant(db);
    db.exec('UPDATE vault_share_policy SET enabled=0,revision=3 WHERE id=1');
    assert.deepEqual(grantState(db), { status: 'revoked', version: 2 });
  } finally {
    db.close();
  }
});

test('changing TTL revokes existing grants', () => {
  const db = seededDb();
  try {
    db.exec('UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1');
    grant(db);
    db.exec('UPDATE vault_share_policy SET grant_ttl_seconds=60,revision=3 WHERE id=1');
    assert.deepEqual(grantState(db), { status: 'revoked', version: 2 });
  } finally {
    db.close();
  }
});
