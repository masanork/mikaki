/** SQLite upgrade rehearsal with existing Vault data; not a production D1 restore. */
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

const directory = new URL('../crates/worker/migrations/', import.meta.url);
async function migrations() {
  const names = (await readdir(directory)).filter((name) => name.endsWith('.sql')).sort();
  assert.equal(
    new Set(names.map((name) => name.slice(0, 4))).size,
    names.length,
    'migration numbers must be unique across identity and existing features',
  );
  return Promise.all(
    names.map(async (name) => ({ name, sql: await readFile(new URL(name, directory), 'utf8') })),
  );
}
function apply(db: DatabaseSync, sql: string) {
  db.exec('BEGIN IMMEDIATE');
  try {
    db.exec(sql);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}
function integrity(db: DatabaseSync) {
  assert.equal(db.prepare('PRAGMA integrity_check').get()!.integrity_check, 'ok');
  assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
}
function seedExistingOwner(db: DatabaseSync) {
  db.exec(
    "INSERT INTO account_security VALUES('owner',1,1); INSERT INTO credential VALUES('passkey','owner',1)",
  );
  db.prepare('INSERT INTO vault_owner_key_head VALUES(?,?,?,?,?,?,?,?,?,?)').run(
    'owner',
    'existing-vault',
    'https://issuer.example',
    1,
    1,
    2,
    'fixture-cipher-suite',
    'a'.repeat(43),
    'b'.repeat(43),
    1,
  );
  db.prepare('INSERT INTO vault_owner_key_wrap VALUES(?,?,?,?)').run(
    'owner',
    1,
    'passkey',
    'existing-ciphertext-wrapper',
  );
  db.prepare('INSERT INTO vault_owner_record_head VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(
    'owner',
    'existing-vault',
    'notes',
    'existing-record',
    'note',
    1,
    1,
    2,
    'existing-object',
    'c'.repeat(43),
    'd'.repeat(82),
    0,
    1,
  );
}
test('identity migrations append to current main without renumbering or changing existing Vault data', async () => {
  const items = await migrations();
  const base = items.filter((item) => !item.name.includes('_identity_'));
  const identity = items.filter((item) => item.name.includes('_identity_'));
  assert.equal(base.at(-1)!.name, '0035_agent_record_approvals.sql');
  assert.equal(identity.length, 9);
  assert.equal(identity[0].name, '0036_identity_documents.sql');
  assert.equal(identity.at(-1)!.name, '0044_identity_attester_enrollment.sql');
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    for (const item of base) apply(db, item.sql);
    seedExistingOwner(db);
    const schema = db
      .prepare("SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
      .all();
    const tables = [
      'account_security',
      'credential',
      'vault_owner_key_head',
      'vault_owner_key_wrap',
      'vault_owner_record_head',
    ];
    const rows = tables.map((table) => db.prepare(`SELECT * FROM ${table}`).all());
    for (const item of identity) apply(db, item.sql);
    integrity(db);
    tables.forEach((table, index) =>
      assert.deepEqual(db.prepare(`SELECT * FROM ${table}`).all(), rows[index]),
    );
    for (const entry of schema)
      assert.equal(
        db.prepare('SELECT sql FROM sqlite_master WHERE name=?').get(entry.name as string)!.sql,
        entry.sql,
      );
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM identity_document').get()!.n, 0);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM identity_wallet_grant').get()!.n, 0);
  } finally {
    db.close();
  }
});

test('intermediate identity grants retain their budget and failed issuance cannot consume a nonce', async () => {
  const items = await migrations();
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    for (const item of items.filter((item) => Number(item.name.slice(0, 4)) <= 40))
      apply(db, item.sql);
    seedExistingOwner(db);
    const now = Math.floor(Date.now() / 1000);
    db.prepare(
      "INSERT INTO identity_transaction(tx_id,poll_hash,holder_json,document_json,policy_hash,created_at,expires_at,state,account_id,epoch) VALUES('document','poll','{}','{}','policy',?,?,'approved','owner',1)",
    ).run(now, now + 600);
    db.prepare(
      "INSERT INTO identity_document VALUES('document','owner',1,'{}','policy',?,?,0)",
    ).run(now, now + 600);
    db.prepare(
      "INSERT INTO identity_wallet_par(request_hash,client_id,client_policy_hash,request_json,expires_at,used) VALUES('par','wallet','client-policy',?,?,0)",
    ).run(
      JSON.stringify({ redirect_uri: 'https://wallet.example/cb', state: 'original-state' }),
      now + 600,
    );
    for (const [grant, state] of [
      ['active', 'token'],
      ['completed', 'issued'],
    ]) {
      db.prepare(
        "INSERT INTO identity_wallet_grant(grant_id,document_id,account_id,epoch,session_hash,client_id,client_policy_hash,policy_hash,redirect_uri,code_challenge,configuration,state,expires_at,access_hash,token_expires_at) VALUES(?,'document','owner',1,'session','wallet','client-policy','policy','https://wallet.example/cb','pkce','linked_document',?,?,?,?)",
      ).run(grant, state, now + 600, grant, now + 120);
    }
    for (const item of items.filter((item) => Number(item.name.slice(0, 4)) > 40))
      apply(db, item.sql);
    integrity(db);
    assert.deepEqual(
      { ...db.prepare('SELECT redirect_uri,wallet_state,used FROM identity_wallet_par').get() },
      { redirect_uri: 'https://wallet.example/cb', wallet_state: 'original-state', used: 0 },
    );
    assert.deepEqual(
      {
        ...db
          .prepare(
            "SELECT issuance_limit,issuance_count,authorization_dpop_jkt FROM identity_wallet_grant WHERE grant_id='active'",
          )
          .get(),
      },
      { issuance_limit: 1, issuance_count: 0, authorization_dpop_jkt: null },
    );
    assert.equal(
      db
        .prepare("SELECT issuance_count FROM identity_wallet_grant WHERE grant_id='completed'")
        .get()!.issuance_count,
      1,
    );
    db.prepare("INSERT INTO identity_nonce VALUES('nonce',?,0)").run(now + 120);
    const issue = db.prepare(
      "UPDATE identity_wallet_grant SET issuance_count=issuance_count+1,state='issued',access_hash=NULL,holder_json='{}',proof_nonce_hash=? WHERE grant_id='active'",
    );
    assert.throws(
      () => issue.run('missing-nonce'),
      /identity wallet issuance preconditions failed/,
    );
    assert.equal(
      db.prepare("SELECT issuance_count FROM identity_wallet_grant WHERE grant_id='active'").get()!
        .issuance_count,
      0,
    );
    assert.equal(
      db.prepare("SELECT used FROM identity_nonce WHERE nonce_hash='nonce'").get()!.used,
      0,
    );
    issue.run('nonce');
    assert.equal(
      db.prepare("SELECT used FROM identity_nonce WHERE nonce_hash='nonce'").get()!.used,
      1,
    );
    assert.throws(() => issue.run('nonce'));
    db.exec("UPDATE identity_document SET revoked=1 WHERE document_id='document'");
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM identity_wallet_grant').get()!.n, 0);
    assert.equal(
      db.prepare("SELECT document_json FROM identity_transaction WHERE tx_id='document'").get()!
        .document_json,
      '{}',
    );
    integrity(db);
  } finally {
    db.close();
  }
});
