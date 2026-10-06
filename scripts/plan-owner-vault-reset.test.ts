import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import {
  BASELINE_NAME,
  assertFreshBaselineTarget,
  createResetPlan,
  readMigrations,
  rehearseSchema,
} from './plan-owner-vault-reset.ts';

const root = fileURLToPath(new URL('../', import.meta.url));

test('reset planning rehearses the complete main schema and records source/config/SQL digests', () => {
  const plan = createResetPlan(root);
  assert.equal(plan.mode, 'offline-review-only');
  assert.equal(
    plan.source.commit,
    execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
  );
  const op = plan.schemas.find((schema) => schema.database === 'mikaki-auth-owner')!;
  assert.ok(op.tables.includes('vault_owner_key_head'));
  assert.ok(op.tables.includes('vault_owner_key_wrap'));
  assert.ok(op.tables.includes('vault_owner_record_head'));
  assert.ok(op.tables.includes('auth_resource_policy'));
  assert.ok(
    op.objects.some((item) => item.type === 'view' && item.name === 'valid_client_session'),
  );
  assert.ok(
    op.objects.some((item) => item.type === 'trigger' && item.table === 'vault_owner_record_head'),
  );
  assert.deepEqual(
    op.migrations.map((item) => item.name),
    readMigrations(`${root}/crates/worker/migrations`).map((item) => item.name),
  );
  for (const item of plan.configs)
    assert.equal(
      item.sha256,
      createHash('sha256')
        .update(readFileSync(`${root}/${item.path}`))
        .digest('hex'),
    );
  assert.deepEqual(op.missing_identity_tables, []);
  assert.deepEqual(op.legacy_tables, []);
  assert.deepEqual(op.legacy_dependencies, []);
  assert.equal(op.tables.includes('vault_attribute_head'), false);
  assert.equal(op.tables.includes('vault_share_policy'), false);
  assert.equal(op.tables.includes('vault_oauth_token_context'), false);
  assert.ok(op.tables.includes('vault_record_share_policy'));
  assert.ok(op.tables.includes('agent_attribute_proposal'));
  assert.ok(op.tables.includes('identity_claim_release'));
  assert.ok(op.tables.includes('identity_wallet_attestation_replay'));
  assert.ok(!plan.blockers.includes('identity-not-integrated'));
  assert.ok(!plan.blockers.includes('legacy-vault-still-present'));
  // The feature chain cannot be mistaken for a freshly consolidated reset baseline.
  assert.ok(plan.blockers.includes('baseline-not-consolidated'));
  assert.ok(plan.blockers.includes('faq-production-registration-required'));
});

test('inventory separates OP storage, service-bound claims, and retiring demo resources', () => {
  const plan = createResetPlan(root);
  assert.deepEqual(
    plan.databases.map((db) => [db.name, db.id, db.disposition]),
    [
      ['mikaki-auth-owner', 'd0258938-0d27-4110-8aa9-c82e20f3885b', 'reset'],
      ['mikaki-demo-rp', 'ce11d383-758b-4574-8bcc-7febc505a408', 'retire-after-client-revocation'],
    ],
  );
  assert.equal(
    plan.workers.find((worker) => worker.name === 'mikaki-auth-claims')!.services[0].entrypoint,
    'ClaimStore',
  );
  assert.equal(
    plan.databases.some((db) => db.worker === 'mikaki-auth-claims'),
    false,
  );
  assert.deepEqual(
    plan.buckets.map((bucket) => bucket.bucket_name),
    ['mikaki-auth-vault'],
  );
  assert.equal(
    plan.preserve_secret_names.find(
      (secret) => 'name' in secret && secret.name === 'OP_PRIVATE_JWK',
    )!.disposition,
    'preserve',
  );
  assert.equal(
    plan.preserve_secret_names.find(
      (secret) => 'name' in secret && secret.name === 'RP_PRIVATE_JWK',
    )!.disposition,
    'retire-with-demo-worker',
  );
  assert.equal(
    plan.preserve_secret_names.some(
      (secret) => 'secret_name' in secret && secret.secret_name === 'VAULT_USERINFO_MLKEM_A',
    ),
    true,
  );
  assert.equal(plan.faq.configured, false);
  assert.equal(plan.faq.origin, 'https://docs.mikaki.org');
  assert.ok(!plan.faq.required.includes('origin'));
  const rp = plan.schemas.find((schema) => schema.database === 'mikaki-demo-rp')!;
  assert.equal(rp.identity_profile_required, false);
  assert.deepEqual(rp.missing_identity_tables, []);
});

test('a rewritten 0001 is rejected on old ledgers, application tables, and unknown internal-looking tables', () => {
  assertFreshBaselineTarget([]);
  assertFreshBaselineTarget([{ name: 'sqlite_sequence' }, { name: '_cf_KV' }]);
  for (const name of [
    'd1_migrations',
    'account_security',
    'vault_attribute_head',
    'vault_owner_record_head',
    '_cf_custom_state',
  ])
    assert.throws(() => assertFreshBaselineTarget([{ name }]), /fresh database/);
});

test('the frozen reset baseline installs Owner Vault and Identity only into an empty database', () => {
  const migrations = readMigrations(`${root}/crates/worker/migrations`).filter(
    (migration) => migration.name === BASELINE_NAME,
  );
  assert.deepEqual(
    migrations.map((item) => item.name),
    [BASELINE_NAME],
  );
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    db.exec(migrations[0]!.sql);
    assert.equal(db.prepare('PRAGMA integrity_check').get()!.integrity_check, 'ok');
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
    const tables = new Set(
      db
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .all()
        .map((row) => row.name),
    );
    for (const table of [
      'account_security',
      'vault_owner_key_head',
      'vault_owner_record_head',
      'vault_record_share_policy',
      'vault_claim_release',
      'agent_attribute_proposal',
      'identity_document',
      'identity_claim_release',
      'identity_wallet_grant',
      'identity_wallet_attestation_replay',
    ])
      assert.ok(tables.has(table), table);
    for (const table of [
      'd1_migrations',
      'vault_attribute_head',
      'vault_attribute_grant',
      'vault_share_policy',
      'vault_oauth_consent',
      'vault_oauth_grant',
      'vault_oauth_code_context',
      'vault_oauth_token_context',
      'vault_gc_cursor',
    ])
      assert.equal(tables.has(table), false, table);
    assert.equal(db.prepare('SELECT count(*) AS n FROM account_security').get()!.n, 0);
    assert.equal(db.prepare('SELECT count(*) AS n FROM identity_document').get()!.n, 0);
    assert.equal(db.prepare('SELECT count(*) AS n FROM identity_wallet_grant').get()!.n, 0);
    assert.equal(db.prepare('SELECT count(*) AS n FROM bootstrap_state').get()!.n, 1);
    assert.deepEqual(
      {
        ...db.prepare('SELECT enabled,ttl_seconds,revision FROM vault_claim_release_policy').get(),
      },
      { enabled: 0, ttl_seconds: 86400, revision: 1 },
    );
    assert.deepEqual(
      {
        ...db
          .prepare('SELECT enabled,grant_ttl_seconds,revision FROM vault_record_share_policy')
          .get(),
      },
      { enabled: 0, grant_ttl_seconds: 604800, revision: 1 },
    );
    const grantSql = db
      .prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='agent_grant'")
      .get()!.sql as string;
    assert.match(
      grantSql,
      /storage_version INTEGER NOT NULL DEFAULT 2 CHECK\(storage_version IN\(1,2\)\)/,
    );
    const releaseSql = db
      .prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='vault_claim_release'")
      .get()!.sql as string;
    assert.match(
      releaseSql,
      /source_storage_version INTEGER NOT NULL DEFAULT 2 CHECK\(source_storage_version=2\)/,
    );
  } finally {
    db.close();
  }
});

test('migration failures and invalid foreign keys cannot produce a successful review plan', () => {
  assert.throws(
    () =>
      rehearseSchema([
        {
          name: '0001_bad.sql',
          sha256: '',
          sql: 'CREATE TABLE example(id); INSERT INTO absent VALUES(1);',
        },
      ]),
    /Migration rehearsal failed/,
  );
  assert.throws(
    () =>
      rehearseSchema([
        {
          name: '0001_bad.sql',
          sha256: '',
          sql: 'CREATE TABLE parent(id PRIMARY KEY); CREATE TABLE child(id REFERENCES parent(id)); INSERT INTO child VALUES(1);',
        },
      ]),
    /Migration rehearsal failed/,
  );
});

test('the review CLI is read-only, rejects action flags, and exits nonzero with blockers', () => {
  const result = spawnSync(process.execPath, ['scripts/plan-owner-vault-reset.ts'], {
    cwd: root,
    encoding: 'utf8',
  });
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stdout).mode, 'offline-review-only');
  for (const flag of ['--apply', '--remote', '--reset']) {
    const invalid = spawnSync(process.execPath, ['scripts/plan-owner-vault-reset.ts', flag], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.notEqual(invalid.status, 0);
    assert.equal(invalid.stdout, '');
    assert.match(invalid.stderr, /Usage:/);
  }
});
