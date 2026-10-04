/**
 * Execute the checked-in owner-record SQL across the full migration history.
 * SQLite transactions model a D1 batch, including sequential competing CAS
 * transactions. This is not workerd, R2, or concurrent D1 execution coverage.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

const migrationDir = new URL('../crates/worker/migrations/', import.meta.url);
const sql = (name: string) =>
  readFileSync(new URL(`../crates/worker/sql/${name}.sql`, import.meta.url), 'utf8');
const authoritySql = sql('select-owner-record-authority');
const headSql = sql('commit-owner-record-head');
const mutationSql = sql('commit-owner-record-mutation');
const origin = 'https://mikaki.example';
const suite = 'PRF-HKDF-SHA256-AES256GCM-v2';
const token = (value: string) => createHash('sha256').update(value).digest('base64url');
const ownerCookie = token('owner-cookie');
const otherCookie = token('other-cookie');
const secondCookie = token('second-cookie');
const envelope = Buffer.alloc(61, 2).toString('base64url');
let operationSequence = 0;

function databaseTime(db: DatabaseSync): number {
  return db.prepare('SELECT unixepoch() AS now').get()!.now as number;
}

function fixture(liveClock = false) {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const name of readdirSync(migrationDir)
    .filter((value) => /^\d{4}_.+\.sql$/.test(value))
    .sort()) {
    db.exec(readFileSync(new URL(name, migrationDir), 'utf8'));
  }
  // Pin the database function, not the application clock or the checked-in SQL,
  // so exact deadline/window boundaries do not depend on wall-clock scheduling.
  const clock = { now: 1_800_000_000 };
  if (!liveClock) db.function('unixepoch', () => clock.now);
  const now = databaseTime(db);
  db.exec("INSERT INTO account_security VALUES('owner',0,1),('other',0,1)");
  db.exec(
    "INSERT INTO credential VALUES('passkey','owner',1),('second','owner',1),('foreign','other',1)",
  );
  for (const [account, credential, session, cookie] of [
    ['owner', 'passkey', 'sso', ownerCookie],
    ['owner', 'second', 'second-sso', secondCookie],
    ['other', 'foreign', 'other-sso', otherCookie],
  ]) {
    db.prepare('INSERT INTO sso_session VALUES(?,?,?,0,?,0)').run(
      session,
      account,
      credential,
      now + 3600,
    );
    db.prepare('INSERT INTO sso_context VALUES(?,?,?)').run(session, cookie, now);
  }
  for (const [account, vault, credential] of [
    ['owner', 'vault', 'passkey'],
    ['other', 'other-vault', 'foreign'],
  ]) {
    db.prepare(
      `INSERT INTO vault_owner_key_head
       (account_id,vault_id,origin,key_generation,revision,format_version,suite,operation_id,request_hash,created_at)
       VALUES(?,?,?,1,1,2,?,?,?,?)`,
    ).run(account, vault, origin, suite, token(`${account}-bootstrap`), token(account), now);
    db.prepare('INSERT INTO vault_owner_key_wrap VALUES(?,1,?,?)').run(
      account,
      credential,
      '{"encrypted":"synthetic-wrapper"}',
    );
  }
  return { db, clock };
}

type Fixture = ReturnType<typeof fixture>;
function withFixture(run: (value: Fixture) => void, liveClock = false) {
  const value = fixture(liveClock);
  try {
    run(value);
  } finally {
    value.db.close();
  }
}

type Mutation = {
  account: string;
  vault: string;
  collection: string;
  record: string;
  kind: string;
  revision: number;
  generation: number;
  objectKey: string | null;
  ciphertextHash: string | null;
  keyEnvelope: string | null;
  deleted: 0 | 1;
  expectedRevision: number;
  cookie: string;
  credential: string;
  registryRevision: number;
  origin: string;
  suite: string;
  observedAt: number;
  operationId: string;
  requestHash: string;
};

function request(db: DatabaseSync, overrides: Partial<Mutation> = {}): Mutation {
  const operationId = overrides.operationId ?? token(`operation-${++operationSequence}`);
  return {
    account: 'owner',
    vault: 'vault',
    collection: 'notes',
    record: 'record',
    kind: 'note',
    revision: 1,
    generation: 1,
    objectKey: `owner-records/${operationId}`,
    ciphertextHash: token(`ciphertext-${operationId}`),
    keyEnvelope: envelope,
    deleted: 0,
    expectedRevision: -1,
    cookie: ownerCookie,
    credential: 'passkey',
    registryRevision: 1,
    origin,
    suite,
    observedAt: databaseTime(db),
    operationId,
    requestHash: token(`request-${operationId}`),
    ...overrides,
  };
}

function tombstone(db: DatabaseSync, overrides: Partial<Mutation> = {}): Mutation {
  return request(db, {
    expectedRevision: 1,
    revision: 2,
    deleted: 1,
    objectKey: null,
    ciphertextHash: null,
    keyEnvelope: null,
    ...overrides,
  });
}

function commit(db: DatabaseSync, value: Mutation) {
  if (value.objectKey)
    db.prepare(
      'INSERT OR IGNORE INTO vault_gc_candidate(object_key,eligible_at) VALUES(?,unixepoch()+86400)',
    ).run(value.objectKey);
  db.exec('BEGIN IMMEDIATE');
  try {
    const head = db
      .prepare(headSql)
      .run(
        value.account,
        value.vault,
        value.collection,
        value.record,
        value.kind,
        value.revision,
        value.generation,
        value.objectKey,
        value.ciphertextHash,
        value.keyEnvelope,
        value.deleted,
        value.expectedRevision,
        value.cookie,
        value.credential,
        value.registryRevision,
        value.origin,
        value.suite,
        value.observedAt,
        value.operationId,
      );
    // Keep these statements adjacent: changes() is the checked-in ledger guard.
    const mutation = db
      .prepare(mutationSql)
      .run(value.account, value.operationId, value.requestHash, value.revision, value.deleted);
    db.exec('COMMIT');
    return { head: Number(head.changes), mutation: Number(mutation.changes) };
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function snapshot(db: DatabaseSync) {
  return {
    heads: db
      .prepare(
        'SELECT * FROM vault_owner_record_head ORDER BY account_id,vault_id,collection_id,record_id',
      )
      .all(),
    mutations: db
      .prepare('SELECT * FROM vault_owner_record_mutation ORDER BY account_id,operation_id')
      .all(),
  };
}

function assertCommitted(db: DatabaseSync, value: Mutation) {
  assert.deepEqual(commit(db, value), { head: 1, mutation: 1 });
}

function assertSuppressed(db: DatabaseSync, value: Mutation) {
  const before = snapshot(db);
  assert.deepEqual(commit(db, value), { head: 0, mutation: 0 });
  assert.deepEqual(snapshot(db), before);
}

function authority(
  db: DatabaseSync,
  account = 'owner',
  cookie = ownerCookie,
  credential = 'passkey',
) {
  return db.prepare(authoritySql).get(account, cookie, credential);
}

function seedMutations(db: DatabaseSync, count: number, age = 0, account = 'owner') {
  const statement = db.prepare('INSERT INTO vault_owner_record_mutation VALUES(?,?,?,1,0,?)');
  for (let i = 0; i < count; i++) {
    statement.run(
      account,
      token(`seed-${account}-${i}`),
      token(`seed-request-${i}`),
      databaseTime(db) - age,
    );
  }
}

function seedHeads(db: DatabaseSync, count: number, deleted = 0, account = 'owner') {
  const statement = db.prepare(
    `INSERT INTO vault_owner_record_head
     (account_id,vault_id,collection_id,record_id,kind,revision,key_generation,format_version,object_key,ciphertext_sha256,key_envelope,deleted,updated_at)
     VALUES(?,?,'seeded',?,'note',1,1,2,?,?,?,?,?)`,
  );
  for (let i = 0; i < count; i++) {
    statement.run(
      account,
      account === 'owner' ? 'vault' : 'other-vault',
      `seed-${i}`,
      deleted ? null : `seeded/${account}/${i}`,
      deleted ? null : token(`seeded-${i}`),
      deleted ? null : envelope,
      deleted,
      databaseTime(db),
    );
  }
}

test('authority observation and commit timestamps use the actual SQLite clock', () => {
  withFixture(({ db }) => {
    const before = databaseTime(db);
    const selected = authority(db)!;
    const value = request(db, { observedAt: selected.observed_at as number });
    assertCommitted(db, value);
    const after = databaseTime(db);
    assert.ok(Number(selected.observed_at) >= before && Number(selected.observed_at) <= after);
    for (const row of [...snapshot(db).heads, ...snapshot(db).mutations]) {
      const timestamp = Number(row.updated_at ?? row.created_at);
      assert.ok(timestamp >= before && timestamp <= after);
    }
    assert.equal(selected.vault_id, 'vault');
    assert.equal(selected.key_generation, 1);
    assert.equal(selected.revision, 1);
    assert.equal(selected.format_version, 2);
    assert.equal(selected.suite, suite);
  }, true);
});

test('create, update, and delete atomically pair each head with its mutation receipt', () => {
  withFixture(({ db, clock }) => {
    const create = request(db);
    assertCommitted(db, create);
    const update = request(db, { expectedRevision: 1, revision: 2 });
    assertCommitted(db, update);
    const remove = tombstone(db, { expectedRevision: 2, revision: 3 });
    assertCommitted(db, remove);
    assert.deepEqual(
      { ...snapshot(db).heads[0] },
      {
        account_id: 'owner',
        vault_id: 'vault',
        collection_id: 'notes',
        record_id: 'record',
        kind: 'note',
        revision: 3,
        key_generation: 1,
        format_version: 2,
        object_key: null,
        ciphertext_sha256: null,
        key_envelope: null,
        deleted: 1,
        updated_at: clock.now,
      },
    );
    for (const value of [create, update, remove]) {
      assert.deepEqual(
        {
          ...db
            .prepare('SELECT * FROM vault_owner_record_mutation WHERE operation_id=?')
            .get(value.operationId),
        },
        {
          account_id: 'owner',
          operation_id: value.operationId,
          request_hash: value.requestHash,
          result_revision: value.revision,
          deleted: value.deleted,
          created_at: clock.now,
        },
      );
    }
  });
});

for (const mode of ['create', 'update', 'delete', 'recreate'] as const) {
  test(`a failing ledger insertion rolls back the ${mode} head and permits exact retry`, () => {
    withFixture(({ db }) => {
      if (mode !== 'create') assertCommitted(db, request(db));
      if (mode === 'recreate') assertCommitted(db, tombstone(db));
      const value =
        mode === 'delete'
          ? tombstone(db)
          : request(
              db,
              mode === 'recreate'
                ? { expectedRevision: 2, revision: 3 }
                : mode === 'update'
                  ? { expectedRevision: 1, revision: 2 }
                  : {},
            );
      const before = snapshot(db);
      db.exec(`CREATE TRIGGER inject_record_mutation_failure
        BEFORE INSERT ON vault_owner_record_mutation
        BEGIN SELECT RAISE(ABORT,'injected ledger failure'); END`);
      assert.throws(() => commit(db, value), /injected ledger failure/);
      assert.deepEqual(snapshot(db), before);
      db.exec('DROP TRIGGER inject_record_mutation_failure');
      assertCommitted(db, value);
    });
  });
}

test('a head constraint failure leaves no receipt and preserves the previous head', () => {
  withFixture(({ db }) => {
    assertCommitted(db, request(db));
    const before = snapshot(db);
    assert.throws(
      () =>
        commit(
          db,
          request(db, {
            expectedRevision: 1,
            revision: 2,
            ciphertextHash: 'short',
          }),
        ),
      /CHECK constraint failed/,
    );
    assert.deepEqual(snapshot(db), before);
  });
});

for (const mode of [
  'create/create',
  'update/update',
  'update/delete',
  'delete/update',
  'delete/delete',
] as const) {
  test(`sequential competing ${mode} transactions allow only one CAS winner`, () => {
    withFixture(({ db }) => {
      const [firstMode, secondMode] = mode.split('/');
      const options = firstMode === 'create' ? {} : { expectedRevision: 1, revision: 2 };
      if (firstMode !== 'create') assertCommitted(db, request(db));
      // Both contenders are prepared before either commits, sharing one observed revision.
      const first = firstMode === 'delete' ? tombstone(db) : request(db, options);
      const second = secondMode === 'delete' ? tombstone(db) : request(db, options);
      assertCommitted(db, first);
      assertSuppressed(db, second);
      assert.equal(snapshot(db).heads[0].revision, first.revision);
      assert.equal(snapshot(db).heads[0].object_key, first.objectKey);
      assert.equal(snapshot(db).heads[0].deleted, first.deleted);
    });
  });
}

test('operation reuse cannot mutate the same or a different record, even with a current CAS', () => {
  withFixture(({ db }) => {
    const original = request(db);
    assertCommitted(db, original);
    assertSuppressed(db, original);
    for (const overrides of [
      { expectedRevision: 1, revision: 2 },
      { record: 'different-record' },
      { collection: 'different-collection' },
      {
        expectedRevision: 1,
        revision: 2,
        deleted: 1 as const,
        objectKey: null,
        ciphertextHash: null,
        keyEnvelope: null,
      },
    ]) {
      assertSuppressed(
        db,
        request(db, {
          ...overrides,
          operationId: original.operationId,
          requestHash: token('changed-request'),
        }),
      );
    }
    assert.equal(snapshot(db).mutations.length, 1);
    assert.equal(snapshot(db).mutations[0].request_hash, original.requestHash);
  });
});

test('operation IDs are scoped to the authenticated account', () => {
  withFixture(({ db }) => {
    const original = request(db);
    assertCommitted(db, original);
    const other = request(db, {
      account: 'other',
      vault: 'other-vault',
      cookie: otherCookie,
      credential: 'foreign',
      operationId: original.operationId,
      objectKey: 'owner-records/other',
    });
    assertCommitted(db, other);
    assert.equal(snapshot(db).mutations.length, 2);
  });
});

for (const [label, overrides] of [
  ['owner', { account: 'other' }],
  ['Vault', { vault: 'other-vault' }],
  ['collection', { collection: 'different-collection' }],
  ['record', { record: 'different-record' }],
  ['kind', { kind: 'different-kind' }],
  ['future expected revision', { expectedRevision: 2, revision: 3 }],
  ['skipped revision', { revision: 3 }],
  ['unchanged revision', { revision: 1 }],
  ['zero expected revision', { expectedRevision: 0 }],
  ['generation', { generation: 2 }],
  ['registry revision', { registryRevision: 2 }],
  ['origin', { origin: 'https://other.example' }],
  ['suite', { suite: 'unsupported-suite' }],
  ['session secret', { cookie: token('unknown-cookie') }],
  ['another owner session', { cookie: otherCookie }],
  ['another credential', { credential: 'second' }],
  ['another credential session', { cookie: secondCookie }],
] satisfies Array<[string, Partial<Mutation>]>) {
  test(`commit rejects mismatched ${label} without a head or ledger change`, () => {
    withFixture(({ db }) => {
      assertCommitted(db, request(db));
      assertSuppressed(db, request(db, { expectedRevision: 1, revision: 2, ...overrides }));
    });
  });
}

for (const [label, change] of [
  ['inactive account', "UPDATE account_security SET active=0 WHERE account_id='owner'"],
  ['account epoch', "UPDATE account_security SET epoch=1 WHERE account_id='owner'"],
  ['inactive credential', "UPDATE credential SET active=0 WHERE credential_id='passkey'"],
  ['revoked SSO', "UPDATE sso_session SET revoked=1 WHERE sso_id='sso'"],
  ['expired SSO', "UPDATE sso_session SET expires_at=unixepoch()-1 WHERE sso_id='sso'"],
  ['SSO at exact expiry', "UPDATE sso_session SET expires_at=unixepoch() WHERE sso_id='sso'"],
  ['missing session context', "DELETE FROM sso_context WHERE sso_id='sso'"],
  ['missing credential wrapper', "DELETE FROM vault_owner_key_wrap WHERE account_id='owner'"],
] as const) {
  test(`both authority selection and post-upload commit reject ${label}`, () => {
    withFixture(({ db }) => {
      assert.ok(authority(db));
      assertCommitted(db, request(db));
      const pending = request(db, { expectedRevision: 1, revision: 2 });
      db.exec(change);
      assert.equal(authority(db), undefined);
      assertSuppressed(db, pending);
    });
  });
}

test('authority requires the exact owner, secret, session credential, and that credential wrapper', () => {
  withFixture(({ db }) => {
    assert.equal(authority(db, 'other'), undefined);
    assert.equal(authority(db, 'owner', otherCookie), undefined);
    assert.equal(authority(db, 'owner', ownerCookie, 'second'), undefined);
    assert.equal(authority(db, 'owner', secondCookie, 'passkey'), undefined);
    assert.equal(authority(db, 'owner', secondCookie, 'second'), undefined);
    assertSuppressed(db, request(db, { cookie: secondCookie, credential: 'second' }));
    db.prepare('INSERT INTO vault_owner_key_wrap VALUES(?,1,?,?)').run('owner', 'second', '{}');
    assert.ok(authority(db, 'owner', secondCookie, 'second'));
    assert.equal(authority(db, 'owner', ownerCookie, 'second'), undefined);
    assertCommitted(db, request(db, { cookie: secondCookie, credential: 'second' }));
    assert.ok(authority(db, 'other', otherCookie, 'foreign'));
  });
});

for (const [label, offset, allowed] of [
  ['future admission', 1, false],
  ['exact admission', 0, true],
  ['last admitted second', -300, true],
  ['expired admission', -301, false],
] as const) {
  test(`database-clock admission guard handles ${label}`, () => {
    withFixture(({ db, clock }) => {
      const value = request(db, { observedAt: clock.now + offset });
      if (allowed) assertCommitted(db, value);
      else assertSuppressed(db, value);
    });
  });
}

test('an upload crossing the admission deadline cannot commit using the earlier authority read', () => {
  withFixture(({ db, clock }) => {
    const observed = authority(db)!.observed_at as number;
    const pending = request(db, { observedAt: observed });
    clock.now += 301;
    assertSuppressed(db, pending);
    assertCommitted(db, request(db));
  });
});

test('database clock rollback before admission suppresses the pending mutation', () => {
  withFixture(({ db, clock }) => {
    const pending = request(db);
    clock.now--;
    assertSuppressed(db, pending);
  });
});

test('the 20th mutation commits and the 21st is suppressed across collections and records', () => {
  withFixture(({ db }) => {
    seedMutations(db, 19);
    const first = request(db);
    const competing = request(db, { collection: 'another', record: 'another' });
    assertCommitted(db, first);
    assert.equal(snapshot(db).mutations.length, 20);
    assertSuppressed(db, competing);
    assertSuppressed(db, request(db, { expectedRevision: 1, revision: 2 }));
    assertSuppressed(db, tombstone(db));
  });
});

for (const [age, allowed] of [
  [59, false],
  [60, true],
  [61, true],
] as const) {
  test(`mutation rate window treats a receipt aged ${age} seconds correctly`, () => {
    withFixture(({ db }) => {
      seedMutations(db, 20, age);
      const value = request(db);
      if (allowed) assertCommitted(db, value);
      else assertSuppressed(db, value);
    });
  });
}

test('a pending upload rechecks the mutation window at commit time', () => {
  withFixture(({ db, clock }) => {
    seedMutations(db, 20);
    const pending = request(db);
    assertSuppressed(db, pending);
    clock.now += 60;
    assertCommitted(db, pending);
  });
});

test("another owner cannot consume this account's mutation or slot limits", () => {
  withFixture(({ db }) => {
    seedMutations(db, 20, 0, 'other');
    seedHeads(db, 256, 0, 'other');
    assertCommitted(db, request(db));
  });
});

test('the 256th lifetime record slot commits, the 257th cannot, and updates still work', () => {
  withFixture(({ db }) => {
    seedHeads(db, 255);
    const first = request(db);
    const competing = request(db, { record: 'overflow' });
    assertCommitted(db, first);
    assert.equal(snapshot(db).heads.length, 256);
    assertSuppressed(db, competing);
    assertSuppressed(db, request(db, { collection: 'another-collection' }));
    assertCommitted(db, request(db, { expectedRevision: 1, revision: 2 }));
    assertCommitted(db, tombstone(db, { expectedRevision: 2, revision: 3 }));
    assertSuppressed(db, request(db, { record: 'after-delete' }));
  });
});

test('retained tombstones keep their slots and explicit CAS recreation reuses that slot', () => {
  withFixture(({ db }) => {
    seedHeads(db, 255, 1);
    const original = request(db);
    assertCommitted(db, original);
    assertCommitted(db, tombstone(db));
    db.exec('DELETE FROM vault_owner_record_mutation');
    assert.equal(snapshot(db).heads.length, 256);
    assertSuppressed(db, request(db, { record: 'new-record' }));
    assertSuppressed(db, original);
    assertSuppressed(db, tombstone(db, { expectedRevision: 2, revision: 3 }));
    assertCommitted(db, request(db, { expectedRevision: 2, revision: 3 }));
    assert.equal(snapshot(db).heads.find((row) => row.record_id === 'record')!.deleted, 0);
    assert.equal(snapshot(db).heads.length, 256);
    assertSuppressed(db, request(db, { record: 'still-no-new-slot' }));
  });
});

test('delete cannot create a tombstone for a nonexistent record or bypass create preconditions', () => {
  withFixture(({ db }) => {
    assertSuppressed(db, tombstone(db));
    assertSuppressed(db, tombstone(db, { expectedRevision: -1, revision: 1 }));
    assertSuppressed(db, request(db, { revision: 2 }));
    assertSuppressed(db, request(db, { expectedRevision: 0 }));
  });
});

test('a same-generation registry revision change preserves content while rejecting stale authority', () => {
  withFixture(({ db }) => {
    const original = request(db);
    assertCommitted(db, original);
    const before = snapshot(db);
    const pending = request(db, { expectedRevision: 1, revision: 2 });
    db.exec("UPDATE vault_owner_key_head SET revision=2 WHERE account_id='owner'");
    assert.deepEqual(snapshot(db), before);
    assert.equal(authority(db)!.revision, 2);
    assert.equal(authority(db)!.key_generation, 1);
    assertSuppressed(db, pending);
    assertCommitted(db, request(db, { expectedRevision: 1, revision: 2, registryRevision: 2 }));
    assert.equal(snapshot(db).heads[0].key_generation, 1);
  });
});

for (const field of ['objectKey', 'ciphertextHash', 'keyEnvelope'] as const) {
  test(`live rows reject NULL ${field} rather than passing a nullable CHECK`, () => {
    withFixture(({ db }) => {
      const before = snapshot(db);
      assert.throws(() => commit(db, request(db, { [field]: null })), /CHECK constraint failed/);
      assert.deepEqual(snapshot(db), before);
    });
  });
}

for (const field of ['objectKey', 'ciphertextHash', 'keyEnvelope'] as const) {
  test(`tombstones reject retained ${field}`, () => {
    withFixture(({ db }) => {
      assertCommitted(db, request(db));
      const before = snapshot(db);
      const retained = request(db)[field];
      assert.throws(
        () => commit(db, tombstone(db, { [field]: retained })),
        /CHECK constraint failed/,
      );
      assert.deepEqual(snapshot(db), before);
    });
  });
}

test('object identities cannot be reused by another live record', () => {
  withFixture(({ db }) => {
    const first = request(db);
    assertCommitted(db, first);
    const before = snapshot(db);
    assert.throws(
      () =>
        commit(
          db,
          request(db, {
            record: 'another',
            objectKey: first.objectKey,
          }),
        ),
      /UNIQUE constraint failed/,
    );
    assert.deepEqual(snapshot(db), before);
  });
});

test('tombstones require explicit current CAS recreation even after receipts expire', () => {
  withFixture(({ db }) => {
    const original = request(db);
    assertCommitted(db, original);
    const remove = tombstone(db);
    assertCommitted(db, remove);
    assertSuppressed(
      db,
      request(db, {
        expectedRevision: 2,
        revision: 3,
        operationId: original.operationId,
      }),
    );
    db.exec('DELETE FROM vault_owner_record_mutation');
    assert.equal(snapshot(db).heads.length, 1);
    assertSuppressed(db, original);
    assertSuppressed(db, request(db));
    assertSuppressed(db, request(db, { expectedRevision: 1, revision: 2 }));
    assertSuppressed(db, request(db, { expectedRevision: 3, revision: 4 }));
    assertSuppressed(db, request(db, { expectedRevision: 2, revision: 3, kind: 'other-kind' }));
    assertSuppressed(db, tombstone(db, { expectedRevision: 2, revision: 3 }));
    const recreate = request(db, { expectedRevision: 2, revision: 3 });
    assertCommitted(db, recreate);
    assertSuppressed(db, original);
    assertSuppressed(db, remove);
    assert.equal(snapshot(db).heads[0].object_key, recreate.objectKey);
    assert.equal(snapshot(db).heads[0].revision, 3);
    assert.equal(snapshot(db).heads[0].deleted, 0);
    assertCommitted(db, request(db, { record: 'separate-record' }));
  });
});

for (const order of ['recreate-first', 'delete-first'] as const) {
  test(`competing delete and explicit recreation preserve new content (${order})`, () => {
    withFixture(({ db }) => {
      assertCommitted(db, request(db));
      assertCommitted(db, tombstone(db));
      const recreate = request(db, { expectedRevision: 2, revision: 3 });
      const competingDelete = tombstone(db, { expectedRevision: 2, revision: 3 });
      if (order === 'delete-first') {
        // A fresh DELETE cannot advance an existing tombstone.
        assertSuppressed(db, competingDelete);
        assertCommitted(db, recreate);
      } else {
        assertCommitted(db, recreate);
        // After recreation, that DELETE no longer holds the current revision.
        assertSuppressed(db, competingDelete);
      }
      assert.equal(snapshot(db).heads[0].object_key, recreate.objectKey);
      assert.equal(snapshot(db).heads[0].revision, 3);
      assert.equal(snapshot(db).heads[0].deleted, 0);
    });
  });
}

test('competing explicit recreations allow only one tombstone CAS winner', () => {
  withFixture(({ db }) => {
    assertCommitted(db, request(db));
    assertCommitted(db, tombstone(db));
    const first = request(db, { expectedRevision: 2, revision: 3 });
    const competing = request(db, { expectedRevision: 2, revision: 3 });
    assertCommitted(db, first);
    assertSuppressed(db, competing);
    assert.equal(snapshot(db).heads[0].object_key, first.objectKey);
    assert.equal(snapshot(db).heads[0].revision, 3);
  });
});

test('reusing an operation on another existing record leaves both heads and receipts intact', () => {
  withFixture(({ db }) => {
    const original = request(db);
    assertCommitted(db, original);
    const another = request(db, { record: 'another-record' });
    assertCommitted(db, another);
    assertSuppressed(
      db,
      request(db, {
        record: another.record,
        expectedRevision: 1,
        revision: 2,
        operationId: original.operationId,
        requestHash: token('changed-target-and-body'),
      }),
    );
    assert.equal(snapshot(db).heads.length, 2);
    assert.equal(snapshot(db).mutations.length, 2);
  });
});

test('generation changes reject both stale admission and relabeling a prior-generation record', () => {
  withFixture(({ db }) => {
    assertCommitted(db, request(db));
    const before = snapshot(db);
    const pending = request(db, { expectedRevision: 1, revision: 2 });
    // Simulate a future authority transition only; this slice has no rotation API.
    db.exec("DELETE FROM vault_owner_key_wrap WHERE account_id='owner'");
    db.exec("UPDATE vault_owner_key_head SET key_generation=2,revision=2 WHERE account_id='owner'");
    db.prepare('INSERT INTO vault_owner_key_wrap VALUES(?,2,?,?)').run('owner', 'passkey', '{}');
    assert.equal(authority(db)!.key_generation, 2);
    assert.deepEqual(snapshot(db), before);
    assertSuppressed(db, pending);
    assertSuppressed(
      db,
      request(db, {
        expectedRevision: 1,
        revision: 2,
        generation: 2,
        registryRevision: 2,
      }),
    );
    assertCommitted(
      db,
      request(db, {
        record: 'new-generation-record',
        generation: 2,
        registryRevision: 2,
      }),
    );
  });
});

test('content revision cannot advance beyond the maximum safe integer', () => {
  withFixture(({ db }) => {
    assertCommitted(db, request(db));
    db.exec('UPDATE vault_owner_record_head SET revision=9007199254740991');
    const before = snapshot(db);
    assert.throws(
      () =>
        commit(
          db,
          request(db, {
            expectedRevision: Number.MAX_SAFE_INTEGER,
            revision: Number.MAX_SAFE_INTEGER + 1,
          }),
        ),
      /CHECK constraint failed/,
    );
    assert.deepEqual(snapshot(db), before);
  });
});
