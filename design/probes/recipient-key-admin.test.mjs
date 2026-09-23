import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { getPlatformProxy } from 'wrangler';
import { disableKey, stageKey, validatePublicRecord } from '../../scripts/recipient-key-admin.mjs';

const configPath = fileURLToPath(new URL('wrangler.jsonc', import.meta.url));
const migration = await readFile(
  new URL('../../crates/worker/migrations/0007_vault_recipient_keys.sql', import.meta.url),
  'utf8',
);
const vector = JSON.parse(
  await readFile(new URL('pqc/hpke-pq-draft05-vector.json', import.meta.url)),
);
const publicKey = Buffer.from(vector.pkRm, 'hex');
const record = {
  key_id: createHash('sha256').update(publicKey).digest('base64url'),
  service_id: 'userinfo',
  algorithm: 'ML-KEM-768',
  public_key: publicKey.toString('base64url'),
  secret_ref: 'VAULT_USERINFO_MLKEM_TEST',
  generation: 1,
};

test('stage and emergency disable are audited in local D1', async () => {
  const proxy = await getPlatformProxy({
    configPath,
    persist: false,
    remoteBindings: false,
    envFiles: [],
  });
  try {
    const db = proxy.env.DB;
    const statements = migration.match(
      /CREATE TABLE[\s\S]*?STRICT;|CREATE UNIQUE INDEX[\s\S]*?;|CREATE TRIGGER[\s\S]*?END;/g,
    );
    assert.equal(statements.length, 7);
    for (const statement of statements) await db.prepare(statement).run();
    validatePublicRecord(record);
    await stageKey(db, record, 'test-operator', 'stage test key', 100);
    let row = await db
      .prepare('SELECT state,revision FROM vault_recipient_key WHERE key_id=?')
      .bind(record.key_id)
      .first();
    assert.deepEqual(row, { state: 'staged', revision: 1 });
    await disableKey(db, record.key_id, 'test-operator', 'emergency stop', 101);
    row = await db
      .prepare('SELECT state,revision,retired_at FROM vault_recipient_key WHERE key_id=?')
      .bind(record.key_id)
      .first();
    assert.deepEqual(row, { state: 'disabled', revision: 2, retired_at: 101 });
    assert.equal(
      (await db.prepare('SELECT count(*) AS count FROM vault_recipient_key_audit').first()).count,
      2,
    );
    await assert.rejects(disableKey(db, record.key_id, 'test-operator', 'repeat', 102));
    assert.throws(() => validatePublicRecord({ ...record, key_id: 'x'.repeat(43) }));
  } finally {
    await proxy.dispose();
  }
});
