/** Migration-only SQLite checks. No Worker, remote database, keys or recipients. */
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { test } from 'node:test';

const migrationDir = new URL('../crates/worker/migrations/', import.meta.url);
function fixture() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const name of readdirSync(migrationDir)
    .filter((n) => /^\d{4}_.+\.sql$/.test(n) && Number(n.slice(0, 4)) <= 33)
    .sort())
    db.exec(readFileSync(new URL(name, migrationDir), 'utf8'));
  db.exec(
    "INSERT INTO account_security VALUES('owner',1,1); INSERT INTO credential VALUES('key','owner',1)",
  );
  return db;
}
const fields: Record<string, SQLInputValue> = {
  grant_id: 'synthetic-grant',
  account_id: 'owner',
  owner_epoch: 1,
  credential_id: 'key',
  delegate: 'fixture',
  provider: 'fixture',
  resource: 'https://agent.test/mcp',
  source_revision: 1,
  recipient_key_id: 'synthetic-recipient',
  operations: '["read"]',
  document_ids: '["name"]',
  encrypted_snapshot: 'synthetic-envelope',
  token_hash: 'synthetic-token-hash',
  request_hash: 'synthetic-request-hash',
  created_at: 100,
  expires_at: 200,
  storage_version: 2,
  source_origin: 'https://owner.test',
  source_vault_id: 'vault',
  source_collection_id: 'personal',
  source_record_id: 'name',
  source_kind: 'name',
  source_ciphertext_sha256: 'a'.repeat(43),
  source_key_generation: 1,
  source_owner_key_revision: 1,
};
function insert(db: DatabaseSync, overrides: Record<string, SQLInputValue> = {}) {
  const value = { ...fields, ...overrides };
  db.prepare(
    `INSERT INTO agent_grant(${Object.keys(value).join(',')}) VALUES(${Object.keys(value)
      .map(() => '?')
      .join(',')})`,
  ).run(...Object.values(value));
}

test('v2 source rows reject missing, mixed and multi-record identities at the database boundary', () => {
  const db = fixture();
  try {
    for (const field of [
      'source_origin',
      'source_vault_id',
      'source_collection_id',
      'source_record_id',
      'source_kind',
      'source_ciphertext_sha256',
      'source_key_generation',
      'source_owner_key_revision',
    ])
      assert.throws(() => insert(db, { [field]: null }), field);
    for (const changes of [
      { storage_version: 1 },
      { source_collection_id: 'other' },
      { source_record_id: 'other' },
      { source_kind: 'owner_note' },
      { source_ciphertext_sha256: 'short' },
      { source_key_generation: 0 },
      { source_owner_key_revision: 0 },
      { document_ids: '["name","owner_note"]' },
      { document_ids: '["owner_note"]' },
      { document_ids: '{}' },
      { document_ids: 'null' },
      { document_ids: '[null]' },
      { source_revision: 1.5 },
      { source_key_generation: 1.5 },
      { source_owner_key_revision: 1.5 },
    ] as Record<string, SQLInputValue>[])
      assert.throws(() => insert(db, changes));
    insert(db);
    assert.equal(db.prepare('SELECT count(*) n FROM agent_grant').get()!.n, 1);
  } finally {
    db.close();
  }
});

test('source identity, selection and cleared snapshots cannot be rewritten or restored', () => {
  const db = fixture();
  try {
    insert(db);
    for (const field of [
      'storage_version',
      'account_id',
      'source_revision',
      'source_origin',
      'source_vault_id',
      'source_collection_id',
      'source_record_id',
      'source_kind',
      'source_ciphertext_sha256',
      'source_key_generation',
      'source_owner_key_revision',
      'document_ids',
    ])
      assert.throws(
        () =>
          db
            .prepare(`UPDATE agent_grant SET ${field}=?`)
            .run(typeof fields[field] === 'number' ? (fields[field] === 2 ? 1 : 2) : 'changed'),
        field,
      );
    db.exec('UPDATE agent_grant SET revoked=1');
    assert.equal(
      db.prepare('SELECT encrypted_snapshot FROM agent_grant').get()!.encrypted_snapshot,
      null,
    );
    assert.throws(() => db.exec('UPDATE agent_grant SET revoked=0'));
    assert.throws(() => db.exec("UPDATE agent_grant SET encrypted_snapshot='restored'"));
  } finally {
    db.close();
  }
});

test('legacy attribute mutation capabilities cannot be issued to a v2 record grant', () => {
  const db = fixture();
  try {
    insert(db);
    assert.throws(() =>
      db.exec(
        "INSERT INTO agent_attribute_capability VALUES('synthetic-grant','owner_note',0,1,100,200)",
      ),
    );
    assert.throws(() =>
      db.exec(`INSERT INTO agent_attribute_proposal(proposal_id,grant_id,grant_revision,request_hash,attribute_id,base_revision,payload,expires_at,created_at)
      VALUES('proposal','synthetic-grant',1,'hash','owner_note',0,'untrusted',200,100)`),
    );
  } finally {
    db.close();
  }
});
