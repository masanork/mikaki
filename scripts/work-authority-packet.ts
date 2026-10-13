/** Offline Native/checkpoint preparation. Resource allocation and enrollment are separate. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { OWNER_MIGRATIONS } from './production-owner-schema.ts';

export const AUTHORITY_ACCOUNT = '4b749427a0c80c547e726a42aff4b6fc';
export const AUTHORITY_TARGET = {
  op: 'mikaki-work-authority-qualification',
  checkpoint: 'mikaki-work-checkpoint-qualification',
  database: 'mikaki-work-authority-qualification',
  vault: 'mikaki-work-vault-qualification',
  logout_queue: 'mikaki-work-logout-qualification',
  logout_dlq: 'mikaki-work-logout-qualification-dlq',
  authority: 'mikaki-work-authority-qualification-v1',
} as const;
export const OP_MEMBERS = [
  'index.js',
  'index_bg.wasm',
  'package.json',
  'worker/shim.mjs',
  'worker/service.mjs',
] as const;
export const AUTHORITY_INPUTS = [
  'Cargo.toml',
  'Cargo.lock',
  'package.json',
  'package-lock.json',
  'crates/worker/Cargo.toml',
  'scripts/build-op-authority.ts',
  'docs/work-authority-qualification.md',
  'docs/work-authority-checkpoint.md',
] as const;
const DATE = '2026-10-10';
const bytesLimit = 16 * 1024 * 1024;
type Digest = { bytes: number; sha256: string };
type Member = { path: string; digest: Digest };
type Source = { commit: string; clean: true };

export function digest(bytes: Uint8Array): Digest {
  assert.ok(bytes.byteLength <= bytesLimit, 'authority_packet_input_too_large');
  return { bytes: bytes.byteLength, sha256: createHash('sha256').update(bytes).digest('hex') };
}
export async function packetFile(path: string, maximum = bytesLimit): Promise<Buffer> {
  const f = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await f.stat();
    assert.ok(stat.isFile() && stat.size <= maximum, 'authority_packet_file_denied');
    const bytes = Buffer.alloc(stat.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const part = await f.read(bytes, length, bytes.length - length, null);
      if (!part.bytesRead) break;
      length += part.bytesRead;
    }
    assert.equal(length, stat.size, 'authority_packet_file_changed');
    return bytes.subarray(0, length);
  } finally {
    await f.close();
  }
}
export async function packetJson(path: string, value: unknown) {
  await writeFile(path, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}

/** Unresolved IDs/origin intentionally make this a template, never a deploy target. */
export function authorityTemplates(account: string) {
  assert.equal(account, AUTHORITY_ACCOUNT, 'authority_packet_account_denied');
  const common = {
    account_id: account,
    compatibility_date: DATE,
    workers_dev: false,
    preview_urls: false,
    observability: { enabled: true, logs: { enabled: true }, traces: { enabled: true } },
  };
  return {
    op: {
      ...common,
      name: AUTHORITY_TARGET.op,
      main: 'build/worker/service.mjs',
      no_bundle: true,
      base_dir: 'build',
      find_additional_modules: true,
      rules: [
        { type: 'ESModule', globs: ['**/*.mjs', '**/*.js'], fallthrough: true },
        { type: 'CompiledWasm', globs: ['**/*.wasm'], fallthrough: true },
      ],
      version_metadata: { binding: 'CF_VERSION_METADATA' },
      vars: {
        MIKAKI_ISSUER: '__REVIEWED_ISOLATED_HTTPS_ORIGIN_REQUIRED__',
        WORK_OWNER_API_ENABLED: 'true',
        WORK_SOURCE_API_ENABLED: 'true',
        WORK_PREPARATION_REVIEW_ENABLED: 'true',
        WORK_COPY_CONSENT_ENABLED: 'true',
        WORK_ARTIFACTS_ACCOUNT: account,
        WORK_PREPARATION_COMPOSE_ENABLED: 'false',
        WORK_COPY_EXECUTION_ENABLED: 'false',
        WORK_EFFECT_STORE_ENABLED: 'false',
        WORK_MINT_STORE_ENABLED: 'false',
        WORK_GIT_STORE_ENABLED: 'false',
      },
      secrets: { required: ['OP_PRIVATE_JWK', 'MIKAKI_READY_TOKEN'] },
      d1_databases: [
        {
          binding: 'DB',
          database_name: AUTHORITY_TARGET.database,
          database_id: '__NEW_ISOLATED_D1_ID_REQUIRED__',
          migrations_dir: '../migrations',
          remote: true,
        },
      ],
      r2_buckets: [{ binding: 'VAULT_BLOBS', bucket_name: AUTHORITY_TARGET.vault }],
      services: [
        {
          binding: 'WORK_AUTHORITY_CHECKPOINT',
          service: AUTHORITY_TARGET.checkpoint,
          entrypoint: 'WorkCheckpointService',
        },
      ],
      queues: {
        producers: [{ binding: 'LOGOUT_QUEUE', queue: AUTHORITY_TARGET.logout_queue }],
        consumers: [
          {
            queue: AUTHORITY_TARGET.logout_queue,
            max_batch_size: 1,
            max_batch_timeout: 1,
            max_retries: 3,
            max_concurrency: 1,
            dead_letter_queue: AUTHORITY_TARGET.logout_dlq,
          },
        ],
      },
      triggers: { crons: [] },
    },
    checkpoint: {
      ...common,
      name: AUTHORITY_TARGET.checkpoint,
      main: 'worker.mjs',
      no_bundle: true,
      vars: { WORK_AUTHORITY_ID: AUTHORITY_TARGET.authority },
      durable_objects: { bindings: [{ name: 'CHECKPOINTS', class_name: 'WorkCheckpoint' }] },
      migrations: [{ tag: 'authority-qualification-v1', new_sqlite_classes: ['WorkCheckpoint'] }],
    },
  };
}

export function authorityPlan(
  account: string,
  baseline: 'current' | 'waitlist' | 'retained' = 'current',
) {
  authorityTemplates(account);
  return {
    format_version: 1,
    stage: 'prepared-not-allocated-or-enrolled',
    account_id: account,
    target: AUTHORITY_TARGET,
    unresolved: {
      database_id: null,
      checkpoint_namespace_id: null,
      checkpoint_operator: null,
      op_operator: null,
      browser_origin: null,
      signing_key: null,
      initial_checkpoint: null,
      owner_account_id: null,
      source_reader: null,
      source_registration: null,
      runtime_policy_revision: null,
    },
    capabilities: {
      op_to_checkpoint: 'WorkCheckpointService',
      operator_only: ['WorkCheckpointAdmin', 'OpAuthorityAdmin'],
      bound_to_op: ['DB', 'VAULT_BLOBS', 'LOGOUT_QUEUE', 'WORK_AUTHORITY_CHECKPOINT'],
      external_effects: false,
      synthetic_verifier: false,
      imported_authority: false,
    },
    qualification: [
      'allocate-and-inventory-dedicated-resources',
      'review-independent-operator-and-release-recovery-ownership',
      baseline === 'retained'
        ? 'apply-frozen-fourteen-migrations-to-empty-isolated-d1'
        : baseline === 'waitlist'
          ? 'apply-frozen-fifteen-migrations-to-empty-isolated-d1'
          : 'apply-frozen-sixteen-migrations-to-empty-isolated-d1',
      'bootstrap-independent-checkpoint-and-primary-once-under-quiescence',
      'verify-matching-current-markers-before-opening-browser-ingress',
      'complete-actual-passkey-owner-enrollment-and-prf-vault-open',
      'register-artificial-source-with-current-owner-policy-and-private-reader',
      'review-compose-consent-without-copy-mint-or-git-effect',
      'verify-session-account-credential-source-policy-revocation',
      'verify-pending-freeze-release-floor-and-isolated-d1-restore-refusal',
    ],
    retained_history: {
      protected_artifacts_allocations: 'no-import-or-mutation',
      unknown_initial_effects: 'remain-unknown-and-charged',
      git_host_qualification: 'infrastructure-evidence-only',
    },
  };
}

/** Apply the packaged chain only to in-memory SQLite to inventory its exact schema. */
export async function authoritySchema(directory: string) {
  const names = (await readdir(directory)).sort();
  const owner = names.includes('0004_identity_age_requests.sql')
    ? OWNER_MIGRATIONS
    : names.includes('0003_enrollment_waitlist.sql')
      ? OWNER_MIGRATIONS.slice(0, 3)
      : OWNER_MIGRATIONS.slice(0, 2);
  const workNames = [
    '0003_work_delegation.sql',
    '0004_work_disclosure_budget.sql',
    '0005_work_sources.sql',
    '0006_work_registered_disclosures.sql',
    '0007_work_preparation_intents.sql',
    '0008_work_prepared_authority.sql',
    '0009_work_credential_custody.sql',
    '0010_work_candidate_payload.sql',
    '0011_work_authority_checkpoint.sql',
    '0012_op_authority_frames.sql',
    '0013_work_copy_consent.sql',
    '0014_work_copy_job.sql',
  ];
  assert.deepEqual(
    names,
    [...owner.map(({ name }) => name), ...workNames].sort(),
    'authority_packet_migrations_denied',
  );
  const db = new DatabaseSync(':memory:');
  const migrations: Member[] = [];
  try {
    db.exec('PRAGMA foreign_keys=ON');
    for (const name of names) {
      const bytes = await packetFile(join(directory, name), 2 * 1024 * 1024);
      const d = digest(bytes);
      const baseline = owner.find((migration) => migration.name === name);
      if (baseline) assert.equal(d.sha256, baseline.sha256);
      db.exec(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      migrations.push({ path: `migrations/${name}`, digest: d });
    }
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
    for (const table of [
      'account_security',
      'credential',
      'sso_session',
      'work_authority_checkpoint',
      'work_source_version',
      'work_copy_consent',
      'work_copy_job',
    ])
      assert.equal(db.prepare(`SELECT count(*) AS n FROM ${table}`).get()!.n, 0);
    const rows = db
      .prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
      )
      .all();
    return {
      migrations,
      schema: { ...digest(Buffer.from(JSON.stringify(rows))), objects: rows.length },
    };
  } finally {
    db.close();
  }
}

async function members(directory: string, prefix = ''): Promise<Member[]> {
  const files: Member[] = [];
  for (const entry of (await readdir(join(directory, prefix), { withFileTypes: true })).sort(
    (a, b) => a.name.localeCompare(b.name, 'en'),
  )) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (!prefix && entry.name === 'manifest.json') continue;
    assert.ok(entry.isDirectory() || entry.isFile(), 'authority_packet_member_denied');
    if (entry.isDirectory()) files.push(...(await members(directory, path)));
    else files.push({ path, digest: digest(await packetFile(join(directory, path))) });
    assert.ok(files.length <= 64, 'authority_packet_too_many_members');
  }
  return files;
}
export async function authorityInventory(directory: string, source: Source) {
  assert.match(source.commit, /^[a-f0-9]{40}$/);
  assert.equal(source.clean, true, 'authority_packet_source_dirty');
  const templates = authorityTemplates(AUTHORITY_ACCOUNT);
  for (const [name, value] of Object.entries(templates))
    assert.deepEqual(
      JSON.parse(
        (await packetFile(join(directory, name, 'wrangler.template.json'))).toString('utf8'),
      ),
      value,
      'authority_packet_config_changed',
    );
  const schema = await authoritySchema(join(directory, 'migrations'));
  const baseline = schema.migrations.some(
    (migration) => migration.path === 'migrations/0004_identity_age_requests.sql',
  )
    ? 'current'
    : schema.migrations.some(
          (migration) => migration.path === 'migrations/0003_enrollment_waitlist.sql',
        )
      ? 'waitlist'
      : 'retained';
  assert.deepEqual(
    JSON.parse((await packetFile(join(directory, 'plan.json'))).toString('utf8')),
    authorityPlan(AUTHORITY_ACCOUNT, baseline),
    'authority_packet_plan_changed',
  );
  const inventory = await members(directory);
  const expected = [
    'plan.json',
    'build.json',
    'build-1.log',
    'build-2.log',
    'build-3.log',
    'op/wrangler.template.json',
    'checkpoint/wrangler.template.json',
    'checkpoint/worker.mjs',
    ...OP_MEMBERS.map((name) => `op/build/${name}`),
    ...AUTHORITY_INPUTS.map((name) => `inputs/${name.replaceAll('/', '__')}`),
    ...schema.migrations.map(({ path }) => path),
  ];
  assert.deepEqual(
    inventory.map(({ path }) => path).sort(),
    expected.sort(),
    'authority_packet_members_changed',
  );
  const wasm = await packetFile(join(directory, 'op/build/index_bg.wasm'));
  assert.ok(wasm.includes(Buffer.from(source.commit)), 'authority_packet_embedded_source_changed');
  assert.ok(WebAssembly.validate(new Uint8Array(wasm)), 'authority_packet_wasm_invalid');
  return {
    format_version: 1,
    source,
    account_id: AUTHORITY_ACCOUNT,
    stage: 'prepared-not-allocated-or-enrolled',
    ...schema,
    members: inventory,
  };
}
export async function verifyAuthorityPacket(directory: string) {
  const manifest = JSON.parse(
    (await packetFile(join(directory, 'manifest.json'), 65536)).toString('utf8'),
  );
  assert.deepEqual(
    manifest,
    await authorityInventory(directory, manifest.source),
    'authority_packet_inventory_changed',
  );
  return manifest;
}
