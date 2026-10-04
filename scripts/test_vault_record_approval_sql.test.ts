/** Exact Rust-approved-commit SQL in native SQLite; no claim of workerd/R2 coverage. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

const folder = new URL('../crates/worker/migrations/', import.meta.url);
const sql = (name: string) =>
  readFileSync(new URL(`../crates/worker/sql/${name}.sql`, import.meta.url), 'utf8');
const readySql = sql('select-owner-record-approval');
const consumeSql = `UPDATE agent_attribute_proposal SET state='committed',payload=NULL WHERE proposal_id=?1 AND EXISTS(${readySql})`;
const headSql = sql('commit-owner-record-head');
const ledgerSql = sql('commit-owner-record-mutation');
const finishSql = sql('finish-owner-record-approval');
const guardSql = sql('guard-owner-record-approval');
const hash = (s: string) => createHash('sha256').update(s).digest('base64url');
const origin = 'https://mikaki.example';
const suite = 'PRF-HKDF-SHA256-AES256GCM-v2';
const frame = Buffer.alloc(61, 2).toString('base64url');
type Value = string | number | null;
type Row = Record<string, Value>;
function insert(db: DatabaseSync, table: string, row: Row) {
  db.prepare(
    `INSERT INTO ${table}(${Object.keys(row).join(',')}) VALUES(${Object.keys(row)
      .map(() => '?')
      .join(',')})`,
  ).run(...Object.values(row));
}
function migrations(db: DatabaseSync) {
  db.exec(readFileSync(new URL('0001_owner_vault_initial.sql', folder), 'utf8'));
}
function fixture(base = 0, deleted = 0, source = 'name') {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  migrations(db);
  const clock = { now: 1_800_000_000 };
  db.function('unixepoch', () => clock.now);
  db.exec(
    "INSERT INTO account_security VALUES('owner',0,1),('other',0,1); INSERT INTO credential VALUES('key','owner',1),('foreign','other',1);",
  );
  db.prepare('INSERT INTO sso_session VALUES(?,?,?,0,?,0)').run(
    'session',
    'owner',
    'key',
    clock.now + 3600,
  );
  db.prepare('INSERT INTO sso_context VALUES(?,?,?)').run('session', 'cookie', clock.now);
  insert(db, 'vault_owner_key_head', {
    account_id: 'owner',
    vault_id: 'vault',
    origin,
    key_generation: 1,
    revision: 1,
    format_version: 2,
    suite,
    operation_id: hash('bootstrap'),
    request_hash: hash('bootstrap-body'),
    created_at: clock.now,
  });
  db.exec(
    "INSERT INTO vault_owner_key_wrap VALUES('owner',1,'key','{}'); INSERT INTO agent_recipient_key VALUES('recipient','active');",
  );
  function record(id: string, revision: number, deleted = 0) {
    insert(db, 'vault_owner_record_head', {
      account_id: 'owner',
      vault_id: 'vault',
      collection_id: 'personal',
      record_id: id,
      kind: id,
      revision,
      key_generation: 1,
      format_version: 2,
      object_key: deleted ? null : `blob/${id}`,
      ciphertext_sha256: deleted ? null : hash(id),
      key_envelope: deleted ? null : frame,
      deleted,
      updated_at: clock.now,
    });
  }
  if (base > 0) record('owner_note', base, deleted);
  if (source !== 'owner_note') record(source, 1);
  const grant: Row = {
    grant_id: 'grant',
    account_id: 'owner',
    owner_epoch: 0,
    credential_id: 'key',
    delegate: 'agent',
    provider: 'test',
    resource: 'https://agent.test/mcp',
    source_revision: source === 'owner_note' ? base : 1,
    recipient_key_id: 'recipient',
    operations: '["propose"]',
    document_ids: JSON.stringify([source]),
    encrypted_snapshot: 'opaque',
    token_hash: hash('token'),
    request_hash: hash('grant'),
    created_at: clock.now,
    expires_at: clock.now + 3600,
    storage_version: 2,
    source_origin: origin,
    source_vault_id: 'vault',
    source_collection_id: 'personal',
    source_record_id: source,
    source_kind: source,
    source_ciphertext_sha256: hash(source),
    source_key_generation: 1,
    source_owner_key_revision: 1,
  };
  const target: Row = {
    storage_version: 2,
    target_origin: origin,
    target_vault_id: 'vault',
    target_collection_id: 'personal',
    target_record_id: 'owner_note',
    target_kind: 'owner_note',
    target_ciphertext_sha256: base && !deleted ? hash('owner_note') : null,
    target_deleted: deleted,
    target_key_generation: 1,
    target_owner_key_revision: 1,
  };
  const capability: Row = {
    grant_id: 'grant',
    attribute_id: 'owner_note',
    base_revision: base,
    grant_revision: 1,
    created_at: clock.now,
    expires_at: clock.now + 600,
    ...target,
  };
  const proposal: Row = {
    proposal_id: hash('proposal'),
    grant_id: 'grant',
    grant_revision: 1,
    request_hash: hash('approved-value'),
    attribute_id: 'owner_note',
    base_revision: base,
    payload: 'approved note',
    created_at: clock.now,
    expires_at: clock.now + 600,
    ...target,
  };
  const candidate = JSON.stringify({
    format_version: 2,
    vault_id: 'vault',
    key_generation: 1,
    owner_key_revision: 1,
    kind: 'owner_note',
    revision: base + 1,
    ciphertext: frame,
    key_envelope: frame,
  });
  const prepared: Row = {
    proposal_id: proposal.proposal_id!,
    account_id: 'owner',
    operation_id: hash('operation'),
    candidate,
    candidate_sha256: hash(candidate),
    origin,
    prepared_at: clock.now,
    storage_version: 2,
  };
  function setup() {
    insert(db, 'agent_grant', grant);
    insert(db, 'agent_attribute_capability', capability);
    insert(db, 'agent_attribute_proposal', proposal);
    db.exec("UPDATE agent_attribute_proposal SET state='approved'");
    insert(db, 'agent_attribute_commit', prepared);
  }
  const identity: Value[] = [
    proposal.proposal_id!,
    proposal.request_hash!,
    base,
    'owner',
    prepared.operation_id!,
    hash(candidate),
    origin,
    'cookie',
    'key',
    'vault',
    1,
    1,
    candidate,
  ];
  const values = [...identity, base + 1, hash('V2-APPROVED/exact-request')];
  function commit(
    overrides: {
      identity?: Value[];
      values?: Value[];
      head?: Value[];
      skipConsume?: boolean;
      ledgerHash?: string;
    } = {},
  ) {
    const objectKey = overrides.head?.[7] ?? 'blob/new';
    if (typeof objectKey === 'string')
      db.prepare(
        'INSERT OR IGNORE INTO vault_gc_candidate(object_key,eligible_at) VALUES(?,unixepoch()+86400)',
      ).run(objectKey);
    db.exec('BEGIN IMMEDIATE');
    try {
      if (!overrides.skipConsume) db.prepare(consumeSql).run(...(overrides.identity ?? identity));
      db.prepare(headSql).run(
        ...(overrides.head ?? [
          'owner',
          'vault',
          'personal',
          'owner_note',
          'owner_note',
          base + 1,
          1,
          'blob/new',
          hash('new-body'),
          frame,
          0,
          base === 0 ? -1 : base,
          'cookie',
          'key',
          1,
          origin,
          suite,
          clock.now,
          prepared.operation_id!,
        ]),
      );
      db.prepare(ledgerSql).run(
        'owner',
        prepared.operation_id!,
        overrides.ledgerHash ?? values[14]!,
        base + 1,
        0,
      );
      db.prepare(finishSql).run(...(overrides.values ?? values));
      db.prepare(guardSql).run(...(overrides.values ?? values));
      db.prepare('DELETE FROM agent_attribute_commit_guard WHERE operation_id=?').run(
        prepared.operation_id!,
      );
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }
  const ready = (v = identity) => !!db.prepare(readySql).get(...v);
  return {
    db,
    clock,
    grant,
    capability,
    proposal,
    prepared,
    identity,
    values,
    setup,
    commit,
    ready,
  };
}
type Fixture = ReturnType<typeof fixture>;
function withFixture(fn: (f: Fixture) => void, base = 0, deleted = 0, source = 'name') {
  const f = fixture(base, deleted, source);
  try {
    f.setup();
    fn(f);
  } finally {
    f.db.close();
  }
}
function snapshot(db: DatabaseSync) {
  return [
    'vault_owner_record_head',
    'vault_owner_record_mutation',
    'agent_attribute_proposal',
    'agent_attribute_commit',
    'agent_audit',
    'agent_grant',
    'agent_attribute_commit_guard',
  ].map((t) => db.prepare(`SELECT * FROM ${t} ORDER BY rowid`).all());
}
function rejected(f: Fixture, overrides: Parameters<Fixture['commit']>[0] = {}) {
  const before = snapshot(f.db);
  assert.throws(() => f.commit(overrides));
  assert.deepEqual(snapshot(f.db), before);
}

for (const [base, deleted, source] of [
  [0, 0, 'name'],
  [2, 0, 'name'],
  [2, 1, 'name'],
  [1, 0, 'owner_note'],
] as const) {
  test(`atomic exact approved commit base=${base} deleted=${deleted} source=${source}`, () =>
    withFixture(
      (f) => {
        assert.equal(f.ready(), true);
        f.commit();
        assert.equal(
          f.db.prepare('SELECT state FROM agent_attribute_proposal').get()!.state,
          'committed',
        );
        assert.equal(
          f.db.prepare('SELECT payload FROM agent_attribute_proposal').get()!.payload,
          null,
        );
        assert.equal(
          f.db.prepare('SELECT result_revision FROM agent_attribute_commit').get()!.result_revision,
          base + 1,
        );
        assert.equal(
          f.db.prepare('SELECT count(*) n FROM vault_owner_record_mutation').get()!.n,
          1,
        );
        assert.equal(
          f.db.prepare("SELECT count(*) n FROM agent_audit WHERE outcome='committed'").get()!.n,
          1,
        );
        assert.equal(
          f.db.prepare('SELECT count(*) n FROM agent_attribute_commit_guard').get()!.n,
          0,
        );
        if (source === 'owner_note')
          assert.equal(f.db.prepare('SELECT revoked FROM agent_grant').get()!.revoked, 1);
        // A second serialized competing transaction cannot apply another mutation.
        const before = snapshot(f.db);
        f.commit();
        assert.deepEqual(snapshot(f.db), before);
      },
      base,
      deleted,
      source,
    ));
}
for (const [label, action] of Object.entries({
  audit:
    "CREATE TRIGGER fault BEFORE INSERT ON agent_audit WHEN NEW.outcome='committed' BEGIN SELECT RAISE(ABORT,'audit failure'); END",
  head: "CREATE TRIGGER fault BEFORE INSERT ON vault_owner_record_head BEGIN SELECT RAISE(ABORT,'head failure'); END",
  ledger:
    "CREATE TRIGGER fault BEFORE INSERT ON vault_owner_record_mutation BEGIN SELECT RAISE(ABORT,'ledger failure'); END",
  result:
    "CREATE TRIGGER fault BEFORE UPDATE ON agent_attribute_commit BEGIN SELECT RAISE(ABORT,'result failure'); END",
  guard:
    "CREATE TRIGGER fault BEFORE INSERT ON agent_attribute_commit_guard BEGIN SELECT RAISE(ABORT,'guard failure'); END",
}))
  test(`injected ${label} failure rolls back plaintext, proposal, head, ledger and audit`, () =>
    withFixture((f) => {
      f.db.exec(action);
      rejected(f);
      f.db.exec('DROP TRIGGER fault');
      assert.equal(f.ready(), true);
      f.commit();
    }));

test('ordinary owner write cannot mark an approval or satisfy the final assertion', () =>
  withFixture((f) => rejected(f, { skipConsume: true })));
test('substituted ledger request hash rolls every D1 change back', () =>
  withFixture((f) => rejected(f, { ledgerHash: hash('ordinary-put') })));
for (const [index, value] of [
  [0, hash('other-proposal')],
  [1, hash('other-approval')],
  [2, 1],
  [3, 'other'],
  [4, hash('other-operation')],
  [5, hash('other-candidate')],
  [6, 'https://foreign.test'],
  [7, 'other-cookie'],
  [8, 'foreign'],
  [9, 'other-vault'],
  [10, 2],
  [11, 2],
  [12, '{}'],
] as [number, Value][]) {
  test(`exact preparation/owner binding rejects identity index ${index}`, () =>
    withFixture((f) => {
      const identity = [...f.identity];
      identity[index] = value;
      assert.equal(f.ready(identity), false);
      rejected(f, { identity });
    }));
}
for (const [label, statement] of Object.entries({
  'session revoked': 'UPDATE sso_session SET revoked=1',
  'session expired': 'UPDATE sso_session SET expires_at=unixepoch()',
  'account inactive': "UPDATE account_security SET active=0 WHERE account_id='owner'",
  'owner epoch changed': "UPDATE account_security SET epoch=1 WHERE account_id='owner'",
  'credential inactive': "UPDATE credential SET active=0 WHERE credential_id='key'",
  'owner wrapper removed': 'DELETE FROM vault_owner_key_wrap',
  'recipient retired': "UPDATE agent_recipient_key SET state='disabled'",
  'grant expired': 'UPDATE agent_grant SET created_at=unixepoch()-1,expires_at=unixepoch()',
  'grant shortened below capability': 'UPDATE agent_grant SET expires_at=unixepoch()+300',
  'grant revoked': 'UPDATE agent_grant SET revoked=1,revision=revision+1',
  'grant operation removed': 'UPDATE agent_grant SET operations=\'["read"]\'',
  'snapshot cleared': 'UPDATE agent_grant SET encrypted_snapshot=NULL',
  'source digest changed':
    "UPDATE vault_owner_record_head SET ciphertext_sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE record_id='name'",
  'source revision changed': "UPDATE vault_owner_record_head SET revision=2 WHERE record_id='name'",
  'source kind changed':
    "UPDATE vault_owner_record_head SET kind='owner_note' WHERE record_id='name'",
  'source deleted': "DELETE FROM vault_owner_record_head WHERE record_id='name'",
  'registry revision changed': 'UPDATE vault_owner_key_head SET revision=2',
  'root suite unsupported': "UPDATE vault_owner_key_head SET suite='unsupported'",
  'root origin changed': "UPDATE vault_owner_key_head SET origin='https://foreign.test'",
}))
  test(`live ${label} blocks ready and transactional consumption`, () =>
    withFixture((f) => {
      f.db.exec(statement);
      assert.equal(f.ready(), false);
      rejected(f);
    }));

test('database-clock proposal/capability deadline is absolute and exclusive', () =>
  withFixture((f) => {
    f.clock.now += 600;
    assert.equal(f.ready(), false);
    rejected(f);
  }));
test('approved mutation admission deadline rolls consumed proposal back', () =>
  withFixture((f) => {
    const head: Value[] = [
      'owner',
      'vault',
      'personal',
      'owner_note',
      'owner_note',
      1,
      1,
      'blob/new',
      hash('new-body'),
      frame,
      0,
      -1,
      'cookie',
      'key',
      1,
      origin,
      suite,
      f.clock.now - 301,
      f.prepared.operation_id!,
    ];
    rejected(f, { head });
  }));
test('changed target digest at same revision invalidates approval', () =>
  withFixture((f) => {
    f.db
      .prepare(
        "UPDATE vault_owner_record_head SET ciphertext_sha256=? WHERE record_id='owner_note'",
      )
      .run(hash('changed'));
    assert.equal(f.ready(), false);
    rejected(f);
  }, 1));
test('target tombstone cannot masquerade as never-created or previous live revision', () =>
  withFixture(
    (f) => {
      for (const base of [0, 1, 3]) {
        const identity = [...f.identity];
        identity[2] = base;
        assert.equal(f.ready(identity), false);
        rejected(f, { identity });
      }
    },
    2,
    1,
  ));
test('historical receipt remains unchanged after newer edit, expiry, recipient retirement and metadata cleanup', () =>
  withFixture((f) => {
    f.commit();
    const receipt = f.db.prepare('SELECT * FROM vault_owner_record_mutation').get();
    f.db.exec(
      "UPDATE vault_owner_record_head SET revision=2 WHERE record_id='owner_note'; UPDATE agent_recipient_key SET state='disabled'; DELETE FROM agent_attribute_proposal",
    );
    f.clock.now += 3601;
    assert.deepEqual(f.db.prepare('SELECT * FROM vault_owner_record_mutation').get(), receipt);
    assert.equal(
      f.db
        .prepare("SELECT revision FROM vault_owner_record_head WHERE record_id='owner_note'")
        .get()!.revision,
      2,
    );
  }));

for (const [field, value] of [
  ['target_origin', null],
  ['target_vault_id', null],
  ['target_collection_id', null],
  ['target_record_id', null],
  ['target_kind', null],
  ['target_deleted', null],
  ['target_key_generation', null],
  ['target_owner_key_revision', null],
  ['target_key_generation', 1.5],
  ['target_owner_key_revision', 1.5],
  ['base_revision', 0.5],
  ['target_deleted', 1],
  ['target_ciphertext_sha256', hash('unexpected')],
  ['storage_version', 1],
] as [string, Value][]) {
  test(`schema rejects invalid capability ${field}=${String(value)}`, () => {
    const f = fixture();
    try {
      insert(f.db, 'agent_grant', f.grant);
      assert.throws(() =>
        insert(f.db, 'agent_attribute_capability', { ...f.capability, [field]: value }),
      );
    } finally {
      f.db.close();
    }
  });
}
for (const field of [
  'target_origin',
  'target_vault_id',
  'target_collection_id',
  'target_record_id',
  'target_kind',
  'target_ciphertext_sha256',
  'target_deleted',
  'target_key_generation',
  'target_owner_key_revision',
  'storage_version',
  'base_revision',
]) {
  test(`frozen proposal ${field} cannot be substituted or mutated`, () =>
    withFixture((f) => {
      const old = f.proposal[field];
      const value = typeof old === 'number' ? old + 1 : 'substituted';
      assert.throws(() =>
        f.db.prepare(`UPDATE agent_attribute_proposal SET ${field}=?`).run(value),
      );
      assert.throws(() =>
        insert(f.db, 'agent_attribute_proposal', {
          ...f.proposal,
          proposal_id: hash('substitute'),
          [field]: value,
        }),
      );
    }));
}
for (const [field, value] of [
  ['storage_version', 1],
  ['account_id', 'other'],
  ['origin', 'https://foreign.test'],
  ['result_revision', 1],
  [
    'candidate',
    JSON.stringify({
      format_version: 2,
      vault_id: 'other',
      key_generation: 1,
      owner_key_revision: 1,
      kind: 'owner_note',
      revision: 1,
    }),
  ],
] as [string, Value][]) {
  test(`prepared immutable source rejects ${field} substitution`, () =>
    withFixture((f) => {
      f.db.exec('DELETE FROM agent_attribute_commit');
      assert.throws(() =>
        insert(f.db, 'agent_attribute_commit', { ...f.prepared, [field]: value }),
      );
    }));
}
test('a legacy proposal cannot be attached to a v2 record grant', () =>
  withFixture((f) => {
    assert.throws(() =>
      insert(f.db, 'agent_attribute_proposal', {
        proposal_id: hash('legacy-on-v2'),
        grant_id: 'grant',
        grant_revision: 1,
        request_hash: 'hash',
        attribute_id: 'owner_note',
        base_revision: 0,
        payload: 'old',
        created_at: f.clock.now,
        expires_at: f.clock.now + 60,
      }),
    );
  }));

test('historical retry SQL accepts only live same-owner database-clock scope independently of root/grant', () =>
  withFixture((f) => {
    const retry = () =>
      !!f.db.prepare(sql('select-owner-record-retry-owner')).get('cookie', 'owner', 'key');
    assert.equal(retry(), true);
    f.commit();
    f.db.exec("DELETE FROM vault_owner_key_wrap; UPDATE agent_recipient_key SET state='disabled'");
    f.clock.now += 600;
    assert.equal(retry(), true);
    assert.equal(
      f.db.prepare(sql('select-owner-record-retry-owner')).get('cookie', 'other', 'key'),
      undefined,
    );
    assert.equal(
      f.db.prepare(sql('select-owner-record-retry-owner')).get('cookie', 'owner', 'foreign'),
      undefined,
    );
    f.clock.now += 3000;
    assert.equal(retry(), false);
  }));

test('present capabilities cannot omit their exact digest or downgrade to missing selection', () => {
  const f = fixture(1);
  try {
    insert(f.db, 'agent_grant', f.grant);
    for (const patch of [
      { target_ciphertext_sha256: null },
      { target_ciphertext_sha256: '!'.repeat(43) },
      { target_deleted: 1, target_ciphertext_sha256: hash('retained') },
      { base_revision: 0 },
    ] as Row[])
      assert.throws(() =>
        insert(f.db, 'agent_attribute_capability', { ...f.capability, ...patch }),
      );
  } finally {
    f.db.close();
  }
});
