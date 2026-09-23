import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { getPlatformProxy } from 'wrangler';
import {
  activateKey,
  disableKey,
  rotateKey,
  stageKey,
  validatePublicRecord,
} from '../../scripts/recipient-key-admin.ts';

const configPath = fileURLToPath(new URL('wrangler.jsonc', import.meta.url));
const migration = await readFile(
  new URL('../../crates/worker/migrations/0007_vault_recipient_keys.sql', import.meta.url),
  'utf8',
);
const vector = JSON.parse(
  await readFile(new URL('pqc/hpke-pq-draft05-vector.json', import.meta.url), 'utf8'),
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
  const proxy = await getPlatformProxy<{ DB: any }>({
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
    assert.equal(statements.length, 8);
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

test('activation and rotation require verified bindings and update both keys atomically', async () => {
  const proxy = await getPlatformProxy<{ DB: any }>({
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
    for (const statement of statements) await db.prepare(statement).run();
    await stageKey(db, record, 'operator', 'initial stage', 100);
    const unavailable = { fetch: async () => ({ status: 503 }) };
    await assert.rejects(activateKey(db, unavailable, record.key_id, 'operator', 'activate', 101));
    assert.equal(
      (
        await db
          .prepare('SELECT state FROM vault_recipient_key WHERE key_id=?')
          .bind(record.key_id)
          .first()
      ).state,
      'staged',
    );
    const verifiedIds = [];
    const verified = {
      fetch: async (url) => {
        verifiedIds.push(url.split('/').at(-2));
        return { status: 204 };
      },
    };
    await activateKey(db, verified, record.key_id, 'operator', 'activate', 102);
    const secondPublic = Buffer.alloc(1184, 9);
    const second = {
      ...record,
      key_id: createHash('sha256').update(secondPublic).digest('base64url'),
      public_key: secondPublic.toString('base64url'),
      secret_ref: 'VAULT_USERINFO_MLKEM_TEST_2',
      generation: 2,
    };
    await stageKey(db, second, 'operator', 'rotation stage', 103);
    await rotateKey(db, verified, second.key_id, 'operator', 'rotation', 104);
    const rows = await db
      .prepare('SELECT key_id,state,revision FROM vault_recipient_key ORDER BY generation')
      .all();
    assert.deepEqual(rows.results, [
      { key_id: record.key_id, state: 'decrypt_only', revision: 3 },
      { key_id: second.key_id, state: 'active', revision: 2 },
    ]);
    assert.deepEqual(verifiedIds, [record.key_id, record.key_id, second.key_id]);
    assert.equal(
      (await db.prepare('SELECT count(*) AS count FROM vault_recipient_key_audit').first()).count,
      5,
    );
    assert.equal(
      (await db.prepare('SELECT count(*) AS count FROM vault_recipient_atomic_guard').first())
        .count,
      0,
    );
    const thirdPublic = Buffer.alloc(1184, 11);
    const third = {
      ...record,
      key_id: createHash('sha256').update(thirdPublic).digest('base64url'),
      public_key: thirdPublic.toString('base64url'),
      secret_ref: 'VAULT_USERINFO_MLKEM_TEST_3',
      generation: 3,
    };
    await stageKey(db, third, 'operator', 'race stage', 105);
    let checks = 0;
    const concurrentStop = {
      fetch: async () => {
        checks += 1;
        if (checks === 2) await disableKey(db, third.key_id, 'operator', 'emergency stop', 106);
        return { status: 204 };
      },
    };
    await assert.rejects(rotateKey(db, concurrentStop, third.key_id, 'operator', 'race', 107));
    assert.deepEqual(
      (
        await db
          .prepare('SELECT state FROM vault_recipient_key WHERE key_id=?')
          .bind(second.key_id)
          .first()
      ).state,
      'active',
    );
    assert.equal(
      (await db.prepare('SELECT count(*) AS count FROM vault_recipient_key_audit').first()).count,
      7,
    );
  } finally {
    await proxy.dispose();
  }
});
