/** Exercise the D1 recipient-key lifecycle constraints with SQLite. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

const migration = readFileSync(
  new URL('../crates/worker/migrations/0007_vault_recipient_keys.sql', import.meta.url),
  'utf8',
);
const db = () => {
  const database = new DatabaseSync(':memory:');
  database.exec(migration);
  return database;
};
const stage = (database: DatabaseSync, suffix: string, generation: number) =>
  database
    .prepare(
      `INSERT INTO vault_recipient_key
    (key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at)
    VALUES(?,?,?,?,?,?,'staged',1,100)`,
    )
    .run(
      suffix.repeat(43),
      'userinfo',
      'ML-KEM-768',
      Buffer.alloc(1184, generation),
      `VAULT_USERINFO_MLKEM_${suffix}`,
      generation,
    );
const scalar = (database: DatabaseSync, sql: string) =>
  Object.values(database.prepare(sql).get()!)[0];

test('promotion, rotation, and emergency stop', () => {
  const database = db();
  try {
    stage(database, 'a', 1);
    stage(database, 'b', 2);
    database
      .prepare(
        "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=101 WHERE key_id=?",
      )
      .run('a'.repeat(43));
    assert.throws(() =>
      database
        .prepare(
          "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=102 WHERE key_id=?",
        )
        .run('b'.repeat(43)),
    );
    database.exec('BEGIN IMMEDIATE');
    try {
      database
        .prepare(
          "UPDATE vault_recipient_key SET state='decrypt_only',revision=3,retired_at=103 WHERE key_id=?",
        )
        .run('a'.repeat(43));
      database
        .prepare(
          "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=103 WHERE key_id=?",
        )
        .run('b'.repeat(43));
      database.exec('COMMIT');
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
    database
      .prepare("UPDATE vault_recipient_key SET state='disabled',revision=4 WHERE key_id=?")
      .run('a'.repeat(43));
    assert.throws(() =>
      database
        .prepare(
          "UPDATE vault_recipient_key SET state='active',revision=5,retired_at=NULL WHERE key_id=?",
        )
        .run('a'.repeat(43)),
    );
    database
      .prepare(
        "UPDATE vault_recipient_key SET state='disabled',revision=3,retired_at=104 WHERE key_id=?",
      )
      .run('b'.repeat(43));
    assert.equal(
      scalar(database, "SELECT count(*) FROM vault_recipient_key WHERE state='active'"),
      0,
    );
  } finally {
    database.close();
  }
});

test('immutable identity and monotonic revision', () => {
  const database = db();
  try {
    stage(database, 'c', 1);
    for (const change of [
      'public_key=zeroblob(1184),revision=2',
      "secret_ref='different',revision=2",
      'generation=2,revision=2',
      "revision=1,state='active',activated_at=101",
      "revision=2,state='decrypt_only',activated_at=101,retired_at=102",
    ])
      assert.throws(
        () =>
          database
            .prepare(`UPDATE vault_recipient_key SET ${change} WHERE key_id=?`)
            .run('c'.repeat(43)),
        change,
      );
    assert.throws(() =>
      database.prepare('DELETE FROM vault_recipient_key WHERE key_id=?').run('c'.repeat(43)),
    );
  } finally {
    database.close();
  }
});

test('invalid key and staged stop', () => {
  const database = db();
  try {
    assert.throws(() =>
      database
        .prepare(
          `INSERT INTO vault_recipient_key
      (key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at)
      VALUES(?,?,?,?,?,1,'staged',1,100)`,
        )
        .run('x'.repeat(43), 'userinfo', 'ML-KEM-768', Buffer.from('short'), 'binding'),
    );
    stage(database, 'd', 1);
    database
      .prepare(
        "UPDATE vault_recipient_key SET state='disabled',revision=2,retired_at=101 WHERE key_id=?",
      )
      .run('d'.repeat(43));
    assert.throws(() =>
      database
        .prepare(
          `INSERT INTO vault_recipient_key
      (key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at,activated_at)
      VALUES(?,?,?,?,?,2,'active',1,100,101)`,
        )
        .run(
          'e'.repeat(43),
          'userinfo',
          'ML-KEM-768',
          Buffer.alloc(1184, 2),
          'VAULT_USERINFO_MLKEM_E',
        ),
    );
  } finally {
    database.close();
  }
});

test('activation and retirement times are fixed', () => {
  const database = db();
  try {
    stage(database, 'f', 1);
    database
      .prepare(
        "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=101 WHERE key_id=?",
      )
      .run('f'.repeat(43));
    assert.throws(() =>
      database
        .prepare(
          `UPDATE vault_recipient_key SET state='decrypt_only',revision=3,
      activated_at=102,retired_at=103 WHERE key_id=?`,
        )
        .run('f'.repeat(43)),
    );
    database
      .prepare(
        "UPDATE vault_recipient_key SET state='decrypt_only',revision=3,retired_at=103 WHERE key_id=?",
      )
      .run('f'.repeat(43));
    assert.throws(() =>
      database
        .prepare(
          "UPDATE vault_recipient_key SET state='disabled',revision=4,retired_at=104 WHERE key_id=?",
        )
        .run('f'.repeat(43)),
    );
  } finally {
    database.close();
  }
});
