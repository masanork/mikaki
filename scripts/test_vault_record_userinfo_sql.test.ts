/** Checked-in D1 statements on SQLite. Real Worker/Secrets Store tests remain separate. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
const directory = new URL('../crates/worker/migrations/', import.meta.url);
const sql = (name: string) =>
  readFileSync(new URL(`../crates/worker/sql/${name}.sql`, import.meta.url), 'utf8');
const claimSql = (name: string) =>
  readFileSync(new URL(`../crates/userinfo-claim-worker/src/${name}.sql`, import.meta.url), 'utf8');
const token = (s: string) => createHash('sha256').update(s).digest('base64url');
const origin = 'https://mikaki.example',
  digest = token('ciphertext'),
  keyId = token('recipient'),
  suite = 'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-record-v2';
const live = sql('select-record-share-source');
const shareSql = sql('commit-record-recipient-envelope')
  .replace('{LIVE_SOURCE}', live)
  .replace('{SUITE}', suite);
const consentSql = sql('commit-record-claim-release').replace('{LIVE_SOURCE}', live);
const preflight = `SELECT v.account_id,ac.client_id,h.revision,r.version AS release_version,h.ciphertext_sha256,e.recipient_key_id,g.origin,g.vault_id,g.collection_id,g.record_id,g.kind,g.key_generation,g.owner_key_revision,g.version AS grant_version,k.generation,e.envelope_id ${claimSql('active_name_record_release')}`;
const finalAudit = claimSql('audit_name_record_release').replace(
  '{ACTIVE_NAME_RELEASE}',
  claimSql('active_name_record_release'),
);
function fixture() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const name of readdirSync(directory)
    .filter((n) => /^\d{4}_.+\.sql$/.test(n))
    .sort()) {
    db.exec(readFileSync(new URL(name, directory), 'utf8'));
  }
  const now = Number(db.prepare('SELECT unixepoch() AS t').get()!.t);
  db.exec(
    "INSERT INTO account_security VALUES('owner',1,1); INSERT INTO credential VALUES('credential','owner',1); INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'https://rp.example');INSERT INTO app_connection VALUES('owner','rp',1,1);INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES('rp','https://rp.example/callback');",
  );
  db.prepare("INSERT INTO sso_session VALUES('sso','owner','credential',1,?,0)").run(now + 3600);
  db.prepare("INSERT INTO sso_context VALUES('sso',?,?)").run(token('cookie'), now);
  db.prepare(
    "INSERT INTO vault_owner_key_head VALUES('owner','vault',?,1,1,2,'PRF-HKDF-SHA256-AES256GCM-v2',?,?,?)",
  ).run(origin, token('root'), token('root-body'), now);
  db.exec(
    "INSERT INTO vault_owner_key_wrap VALUES('owner',1,'credential','synthetic-owner-envelope')",
  );
  db.prepare(
    "INSERT INTO vault_owner_record_head VALUES('owner','vault','personal','name','name',1,1,2,'blob',?,?,0,?)",
  ).run(digest, Buffer.alloc(61, 2).toString('base64url'), now);
  db.prepare(
    "INSERT INTO vault_recipient_key(key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at) VALUES(?,'userinfo','ML-KEM-768',zeroblob(1184),'VAULT_USERINFO_MLKEM_TEST',1,'staged',1,?)",
  ).run(keyId, now - 2);
  db.prepare(
    "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=? WHERE key_id=?",
  ).run(now - 1, keyId);
  db.exec("INSERT INTO client_session VALUES('rp','sid','sso','owner','pairwise',1,0)");
  db.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256',?)").run('{}');
  db.prepare(
    "INSERT INTO authorization_code(code_hash,client_id,sid,client_revision,redirect_uri,pkce_challenge,expires_at,consumed_by,consumed_at) VALUES(?,'rp','sid',1,'https://rp.example/callback','',?,'issue',?)",
  ).run(token('code'), now + 60, now);
  db.prepare("INSERT INTO code_context(code_hash,nonce,scope) VALUES(?,NULL,'openid profile')").run(
    token('code'),
  );
  db.prepare(
    "INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked) VALUES(?,'issue',?,?,'op',?,0)",
  ).run(token('code'), token('access'), now + 3600, now);
  return db;
}
const params = () =>
  [
    'owner',
    origin,
    'vault',
    'personal',
    'name',
    'name',
    1,
    digest,
    1,
    1,
    'credential',
    token('cookie'),
  ] as (string | number | Uint8Array)[];
const frame = Buffer.concat([Buffer.from('MKVR'), Buffer.from([2]), Buffer.alloc(1182)]);
function enable(db: DatabaseSync) {
  db.exec(
    'UPDATE vault_record_share_policy SET enabled=1,revision=2; UPDATE vault_claim_release_policy SET enabled=1,revision=2',
  );
}
function share(
  db: DatabaseSync,
  id = token('share'),
  overrides: Record<number, string | number | Uint8Array> = {},
) {
  const values = [...params(), id, keyId, 1, 2, 2, frame, 0];
  for (const [i, v] of Object.entries(overrides)) values[Number(i)] = v;
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare(shareSql).run(...values);
    db.prepare(
      'INSERT INTO vault_record_share_guard VALUES(?,?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
    ).run('owner', id + ':envelope');
    db.prepare(sql('commit-record-recipient-grant')).run('owner', id, 600);
    db.prepare(
      'INSERT INTO vault_record_share_guard VALUES(?,?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
    ).run('owner', id + ':grant');
    db.prepare(sql('commit-record-share-audit')).run('owner', id, token('body'));
    db.prepare(
      'INSERT INTO vault_record_share_guard VALUES(?,?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
    ).run('owner', id + ':audit');
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}
function consent(db: DatabaseSync, overrides: Record<number, string | number | Uint8Array> = {}) {
  const values = [...params(), 'rp', 1, 1, 2, 1, 0];
  for (const [i, v] of Object.entries(overrides)) values[Number(i)] = v;
  return db.prepare(consentSql).run(...values).changes;
}
function snapshot(db: DatabaseSync) {
  return db.prepare(preflight).get(token('access'));
}
function disclose(db: DatabaseSync, row: Record<string, any>) {
  return db
    .prepare(finalAudit)
    .all(
      token('access'),
      row.account_id,
      row.client_id,
      row.revision,
      row.release_version,
      row.ciphertext_sha256,
      row.recipient_key_id,
      row.origin,
      row.vault_id,
      row.collection_id,
      row.record_id,
      row.kind,
      row.key_generation,
      row.owner_key_revision,
      row.grant_version,
      row.generation,
      row.envelope_id,
    );
}
function ready() {
  const db = fixture();
  enable(db);
  share(db);
  assert.equal(consent(db), 1);
  return db;
}

const shareStatus = sql('select-record-share-status').replace(
  '{CURRENT_RECORD_SHARE}',
  sql('select-current-record-share'),
);
const releaseStatus = sql('select-record-claim-release-status').replace(
  '{CURRENT_RECORD_SHARE}',
  sql('select-current-record-share'),
);
function displayedAuthority(db: DatabaseSync, time?: number) {
  const at = (query: string) =>
    time === undefined ? query : query.replaceAll('unixepoch()', String(time));
  return {
    share: db.prepare(at(shareStatus)).get('owner'),
    rp: db.prepare(at(releaseStatus)).get('owner'),
  };
}
test('sharing status distinguishes encrypted preparation from current RP permission', () => {
  const db = fixture();
  try {
    assert.equal(displayedAuthority(db).share, undefined);
    assert.equal(displayedAuthority(db).rp!.authority_current, 0);
    enable(db);
    share(db);
    const prepared = displayedAuthority(db);
    assert.equal(prepared.share!.authority_current, 1);
    assert.equal(prepared.share!.recipient_key_id, keyId);
    assert.equal(prepared.share!.recipient_generation, 1);
    assert.equal(prepared.share!.directory_revision, 2);
    assert.equal(prepared.share!.policy_revision, 2);
    assert.equal(prepared.rp!.authority_current, 0);
    assert.equal(consent(db), 1);
    assert.equal(displayedAuthority(db).rp!.authority_current, 1);
  } finally {
    db.close();
  }
});
test('sharing status expires permissions without waiting for stored active rows to be revoked', () => {
  const db = fixture();
  try {
    enable(db);
    db.exec('UPDATE vault_claim_release_policy SET ttl_seconds=60,revision=3');
    share(db);
    assert.equal(consent(db, { 15: 3 }), 1);
    const current = displayedAuthority(db);
    const afterRp = Number(current.rp!.expires_at) + 1;
    const partiallyExpired = displayedAuthority(db, afterRp);
    assert.equal(partiallyExpired.share!.status, 'active');
    assert.equal(partiallyExpired.share!.authority_current, 1);
    assert.equal(partiallyExpired.rp!.release_status, 'active');
    assert.equal(partiallyExpired.rp!.authority_current, 0);
    const afterShare = Number(current.share!.expires_at) + 1;
    assert.equal(displayedAuthority(db, afterShare).share!.authority_current, 0);
  } finally {
    db.close();
  }
});

test('v2 policy defaults disabled and system sharing alone never creates RP consent', () => {
  const db = fixture();
  try {
    assert.throws(() => share(db));
    assert.equal(db.prepare('SELECT enabled FROM vault_record_share_policy').get()!.enabled, 0);
    enable(db);
    share(db);
    assert.equal(snapshot(db), undefined);
    assert.equal(consent(db), 1);
    assert.ok(snapshot(db));
  } finally {
    db.close();
  }
});
for (const [label, index, value] of [
  ['origin', 1, 'https://other.example'],
  ['vault', 2, 'other'],
  ['collection', 3, 'other'],
  ['record', 4, 'other'],
  ['kind', 5, 'other'],
  ['revision', 6, 2],
  ['digest', 7, token('different')],
  ['generation', 8, 2],
  ['root registry', 9, 2],
  ['credential', 10, 'other'],
  ['session', 11, 'other'],
  ['recipient', 13, token('other')],
  ['recipient generation', 14, 2],
  ['directory revision', 15, 1],
  ['policy revision', 16, 1],
  ['grant CAS', 18, 1],
] as const)
  test(`share CAS rejects ${label} substitution and rolls back envelope`, () => {
    const db = fixture();
    try {
      enable(db);
      assert.throws(() => share(db, token('bad'), { [index]: value }));
      assert.equal(
        db.prepare('SELECT count(*) AS n FROM vault_record_recipient_envelope').get()!.n,
        0,
      );
    } finally {
      db.close();
    }
  });
for (const table of ['vault_record_grant', 'vault_record_share_audit'])
  test(`failed ${table} rolls back share batch`, () => {
    const db = fixture();
    try {
      enable(db);
      db.exec(
        `CREATE TRIGGER injected_failure BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'injected');END;`,
      );
      assert.throws(() => share(db));
      assert.equal(
        db.prepare('SELECT count(*) AS n FROM vault_record_recipient_envelope').get()!.n,
        0,
      );
      db.exec('DROP TRIGGER injected_failure');
      share(db);
    } finally {
      db.close();
    }
  });
for (const [label, change] of [
  [
    'source edit',
    "UPDATE vault_owner_record_head SET revision=2,ciphertext_sha256='" + token('new') + "'",
  ],
  [
    'source delete',
    'UPDATE vault_owner_record_head SET deleted=1,revision=2,object_key=NULL,ciphertext_sha256=NULL,key_envelope=NULL',
  ],
  ['root authority', 'UPDATE vault_owner_key_head SET revision=2'],
  ['system grant', "UPDATE vault_record_grant SET status='revoked',version=version+1"],
  ['RP withdrawal', "UPDATE vault_claim_release SET status='revoked',version=version+1"],
  ['RP registration', 'UPDATE client SET revision=2'],
  ['app connection', 'UPDATE app_connection SET active=0,grant_version=2'],
  [
    'recipient retirement',
    "UPDATE vault_recipient_key SET state='decrypt_only',revision=3,retired_at=unixepoch()",
  ],
  ['share policy revision', 'UPDATE vault_record_share_policy SET revision=3'],
  ['release policy revision', 'UPDATE vault_claim_release_policy SET revision=3'],
  ['account epoch', 'UPDATE account_security SET epoch=2'],
  ['account disabled', 'UPDATE account_security SET active=0'],
] as const)
  test(`postdecrypt ${label} prevents audit and irreversibly invalidates consent`, () => {
    const db = ready();
    try {
      const selected = snapshot(db)!;
      assert.ok(selected);
      assert.equal(displayedAuthority(db).rp!.authority_current, 1);
      db.exec(change);
      assert.equal(disclose(db, selected).length, 0);
      assert.equal(snapshot(db), undefined);
      assert.equal(db.prepare('SELECT status FROM vault_claim_release').get()!.status, 'revoked');
      assert.equal(displayedAuthority(db).rp?.authority_current ?? 0, 0);
    } finally {
      db.close();
    }
  });
test('exact source audit succeeds and audit insertion failure discloses nothing', () => {
  const db = ready();
  try {
    const row = snapshot(db)!;
    assert.equal(disclose(db, row).length, 1);
    db.exec(
      "CREATE TRIGGER audit_failure BEFORE INSERT ON vault_claim_disclosure_audit BEGIN SELECT RAISE(ABORT,'injected');END;",
    );
    assert.throws(() => disclose(db, row));
    assert.equal(db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').get()!.n, 1);
  } finally {
    db.close();
  }
});
test('token revocation stops disclosure even after preflight', () => {
  const db = ready();
  try {
    const row = snapshot(db)!;
    db.exec('UPDATE token_issue SET revoked=1');
    assert.equal(disclose(db, row).length, 0);
    assert.equal(snapshot(db), undefined);
  } finally {
    db.close();
  }
});
test('full tuple foreign key rejects transplanted revoked grant', () => {
  const db = ready();
  try {
    assert.throws(() =>
      db.exec(
        "UPDATE vault_record_grant SET ciphertext_sha256='" +
          token('other') +
          "',status='revoked',version=version+1",
      ),
    );
    assert.throws(() => db.exec('UPDATE vault_record_recipient_envelope SET frame=zeroblob(1187)'));
  } finally {
    db.close();
  }
});
test('historical share operation cannot be replayed as a new grant after source invalidation', () => {
  const db = ready();
  try {
    db.exec('UPDATE vault_owner_key_head SET revision=2');
    assert.throws(() => share(db));
    assert.equal(db.prepare('SELECT status FROM vault_record_grant').get()!.status, 'revoked');
    assert.equal(db.prepare('SELECT count(*) AS n FROM vault_record_share_audit').get()!.n, 1);
  } finally {
    db.close();
  }
});
test('invalid nullable source selector cannot bypass check triggers', () => {
  const db = ready();
  try {
    assert.throws(() =>
      db.exec("UPDATE vault_claim_release SET source_kind=NULL,status='revoked',version=version+1"),
    );
  } finally {
    db.close();
  }
});

test('RP consent CAS rejects stale replacement and withdrawal races in the single ledger', () => {
  const db = ready();
  try {
    assert.equal(consent(db), 0, 'new operation cannot replay the initial consent version');
    assert.equal(consent(db, { 17: 1 }), 1, 'matching consent version can be renewed');
    assert.equal(consent(db, { 17: 1 }), 0, 'concurrent old source selection loses');
    db.exec("UPDATE vault_claim_release SET status='revoked',version=version+1");
    assert.equal(consent(db, { 17: 2 }), 0, 'withdrawal fences an in-flight consent');
    assert.equal(snapshot(db), undefined);
    assert.equal(consent(db, { 17: 3 }), 1, 'fresh explicit consent is permitted');
    assert.ok(snapshot(db));
  } finally {
    db.close();
  }
});

for (const [label, index, value] of [
  ['origin', 1, 'https://other.example'],
  ['vault', 2, 'other'],
  ['collection', 3, 'other'],
  ['record', 4, 'other'],
  ['kind', 5, 'other'],
  ['content revision', 6, 2],
  ['digest', 7, token('different')],
  ['root generation', 8, 2],
  ['current registry fence', 9, 2],
  ['credential', 10, 'other'],
  ['session', 11, 'other'],
  ['RP', 12, 'other'],
  ['RP revision', 13, 2],
  ['connection revision', 14, 2],
  ['policy revision', 15, 1],
  ['system grant revision', 16, 2],
  ['consent revision', 17, 1],
] as const) {
  test(`record consent rejects stale ${label} without modifying the ledger`, () => {
    const db = fixture();
    try {
      enable(db);
      share(db);
      assert.equal(consent(db, { [index]: value }), 0);
      assert.equal(db.prepare('SELECT count(*) AS n FROM vault_claim_release').get()!.n, 0);
    } finally {
      db.close();
    }
  });
}

for (const [label, change] of [
  ['SSO revocation', 'UPDATE sso_session SET revoked=1'],
  ['SSO expiry', 'UPDATE sso_session SET expires_at=unixepoch()-1'],
  ['credential disabled', 'UPDATE credential SET active=0'],
  ['client-session revocation', 'UPDATE client_session SET revoked=1'],
  ['token expiry', 'UPDATE token_issue SET access_expires_at=unixepoch()-1'],
  [
    'system grant expiry',
    "UPDATE vault_record_grant SET expires_at=unixepoch()-1,status='revoked',version=version+1",
  ],
  [
    'consent expiry',
    "UPDATE vault_claim_release SET expires_at=unixepoch()-1,status='revoked',version=version+1",
  ],
] as const) {
  test(`postdecrypt ${label} prevents the disclosure audit`, () => {
    const db = ready();
    try {
      const selected = snapshot(db)!;
      db.exec(change);
      assert.equal(disclose(db, selected).length, 0);
      assert.equal(snapshot(db), undefined);
    } finally {
      db.close();
    }
  });
}

test('profile scope is required by preflight and final disclosure authority', () => {
  const db = ready();
  try {
    // Simulate a token issued without profile; scope itself is immutable after issuance.
    db.exec('DROP TRIGGER code_context_scope_immutable');
    const selected = snapshot(db)!;
    db.exec("UPDATE code_context SET scope='openid'");
    assert.equal(disclose(db, selected).length, 0);
    assert.equal(snapshot(db), undefined);
  } finally {
    db.close();
  }
});
