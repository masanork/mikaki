/** Promote verified, attested upload bundles; never build or migrate in this job. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { releaseSource } from './release-inventory.ts';
import { promotionDirectory, verifyPreparedUpload } from './prepare-release-upload.ts';
import { readdirSync } from 'node:fs';
import { BASELINE_SCHEMA_QUERY } from './production-baseline.ts';
import { assertProductionOwnerSchema } from './production-owner-schema.ts';
import { inspectProductionMessaging } from './production-messaging-audit.ts';
import type { WorkLedgerRow } from './production-work-schema.ts';
import { assertProductionWorkRolloutSchema } from './production-work-migration.ts';
import { productionWorkPacketDigest } from './production-work-packet.ts';
import { cloudflareMetadataGet } from './production-worker-inventory.ts';
import { PRODUCTION_WORK_TARGET } from './production-work-adoption.ts';
import { productionWrangler } from './production-wrangler.ts';
import { assertDedicatedIdentityKey } from './identity-issuer-key.ts';
import { identityTestTrust, productionIdentityTestProfile } from './identity-test-profile.ts';
import { assertIdentityHaipSecrets } from './identity-haip-profile.ts';
import {
  assertClosedProductionCopyGraph,
  assertCopyCompanionsPresent,
  closedCopyDeployment,
} from './production-work-copy-graph.ts';

type Binding = Record<string, unknown>;
type Config = {
  name: string;
  compatibility_date: string;
  compatibility_flags?: string[];
  vars: Record<string, string>;
  d1_databases?: { binding: string; database_id: string }[];
  r2_buckets?: { binding: string; bucket_name: string }[];
  services?: { binding: string; service: string; entrypoint?: string }[];
  secrets?: { required: string[] };
  send_email?: { name: string; allowed_sender_addresses?: string[] }[];
  version_metadata?: { binding: string };
  durable_objects?: { bindings: { name: string; class_name: string }[] };
  secrets_store_secrets?: { binding: string; store_id: string; secret_name: string }[];
  assets?: { binding: string };
  ratelimits?: { name: string; namespace_id: string; simple: { limit: number; period: number } }[];
  queues?: {
    producers?: { binding: string; queue: string; delivery_delay?: number; remote?: boolean }[];
    consumers?: {
      queue: string;
      max_batch_size?: number;
      max_batch_timeout?: number;
      max_retries?: number;
      dead_letter_queue?: string;
      max_concurrency?: number | null;
      retry_delay?: number;
    }[];
  };
};

export function checkBindings(
  version: {
    resources: {
      bindings: Binding[];
      script_runtime: { compatibility_date: string; compatibility_flags?: string[] };
    };
  },
  config: Config,
) {
  assert.equal(version.resources.script_runtime.compatibility_date, config.compatibility_date);
  assert.deepEqual(
    [...(version.resources.script_runtime.compatibility_flags ?? [])].sort(),
    [...(config.compatibility_flags ?? [])].sort(),
    'Uploaded compatibility flags differ from the reviewed configuration',
  );
  const bindings = version.resources.bindings;
  const names = new Set<string>();
  for (const binding of bindings) {
    assert.equal(typeof binding.name, 'string', 'Binding is missing its name');
    assert.ok(!names.has(binding.name as string), `Duplicate binding ${String(binding.name)}`);
    names.add(binding.name as string);
    if (binding.type === 'd1')
      assert.ok(
        config.d1_databases?.some((item) => item.binding === binding.name),
        `Unexpected storage binding ${binding.name}`,
      );
    if (binding.type === 'r2_bucket')
      assert.ok(
        config.r2_buckets?.some((item) => item.binding === binding.name),
        `Unexpected storage binding ${binding.name}`,
      );
  }
  const expected = new Map<string, Binding>();
  const expect = (name: string, binding: Binding) => {
    assert.ok(!expected.has(name), `Duplicate configured binding ${name}`);
    expected.set(name, binding);
  };
  for (const [name, text] of Object.entries(config.vars))
    expect(name, { type: 'plain_text', text });
  for (const item of config.d1_databases ?? [])
    expect(item.binding, { type: 'd1', database_id: item.database_id });
  for (const item of config.r2_buckets ?? [])
    expect(item.binding, { type: 'r2_bucket', bucket_name: item.bucket_name });
  for (const item of config.services ?? [])
    expect(item.binding, {
      type: 'service',
      service: item.service,
      entrypoint: item.entrypoint,
    });
  for (const name of config.secrets?.required ?? []) expect(name, { type: 'secret_text' });
  for (const item of config.send_email ?? [])
    expect(item.name, {
      type: 'send_email',
      allowed_sender_addresses: item.allowed_sender_addresses,
    });
  if (config.version_metadata)
    expect(config.version_metadata.binding, { type: 'version_metadata' });
  for (const item of config.durable_objects?.bindings ?? [])
    expect(item.name, { type: 'durable_object_namespace', class_name: item.class_name });
  for (const item of config.secrets_store_secrets ?? [])
    expect(item.binding, {
      type: 'secrets_store_secret',
      store_id: item.store_id,
      secret_name: item.secret_name,
    });

  if (config.assets) expect(config.assets.binding, { type: 'assets' });
  for (const item of config.ratelimits ?? [])
    expect(item.name, {
      type: 'ratelimit',
      namespace_id: item.namespace_id,
      simple: item.simple,
    });
  for (const item of config.queues?.producers ?? [])
    expect(item.binding, { type: 'queue', queue_name: item.queue });

  for (const name of expected.keys()) assert.ok(names.has(name), `Missing binding ${name}`);
  for (const binding of bindings) {
    const name = binding.name as string;
    const approved = expected.get(name);
    assert.ok(approved, `Unexpected binding ${name}`);
    if (binding.type === 'durable_object_namespace') {
      assert.match(String(binding.namespace_id), /^[a-f0-9]{32}$/);
      assert.notEqual(binding.namespace_id, '0'.repeat(32));
    }
    for (const [key, value] of Object.entries(approved))
      // Cloudflare exposes rate-limit namespace IDs as either strings or numbers.
      assert.deepEqual(
        binding.type === 'ratelimit' && key === 'namespace_id'
          ? String(binding[key])
          : binding[key],
        value,
        `Binding ${name}: ${key}`,
      );
  }
  if (config.name === 'mikaki-auth') {
    assert.deepEqual(config.queues?.producers, [
      { binding: 'LOGOUT_QUEUE', queue: 'mikaki-logout-wakeups' },
    ]);
    assert.deepEqual(config.queues?.consumers, [
      {
        queue: 'mikaki-logout-wakeups',
        max_batch_size: 1,
        max_batch_timeout: 1,
        max_retries: 3,
        dead_letter_queue: 'mikaki-logout-wakeups-dlq',
        max_concurrency: 2,
        retry_delay: 30,
      },
    ]);
  }
}

export function sourceIsCurrent(changedPaths: string[]) {
  // The metrics bot commits with GITHUB_TOKEN, so those descendants have no CI run.
  const metrics = new Set([
    'metrics/history.json',
    'metrics/code-size.svg',
    'metrics/coverage.svg',
    'metrics/dependency-inventory.md',
  ]);
  return changedPaths.every((path) => metrics.has(path));
}

export function checkCheckpointExposure(value: unknown) {
  assert.ok(
    value &&
      typeof value === 'object' &&
      'enabled' in value &&
      'previews_enabled' in value &&
      value.enabled === false &&
      value.previews_enabled === false,
    'Existing checkpoint must keep workers.dev and preview URLs disabled',
  );
}

export function assertWaitlistMailKey(value: unknown): asserts value is string {
  assert.ok(
    typeof value === 'string',
    'WAITLIST_MAIL_KEY must be 32 bytes encoded as unpadded base64url',
  );
  const bytes = Buffer.from(value, 'base64url');
  try {
    assert.ok(
      bytes.length === 32 && bytes.toString('base64url') === value,
      'WAITLIST_MAIL_KEY must be 32 bytes encoded as unpadded base64url',
    );
  } finally {
    bytes.fill(0);
  }
}

export function productionRuntimeSecrets(config: Config, env: Record<string, string | undefined>) {
  const base = ['OP_PRIVATE_JWK', 'MIKAKI_READY_TOKEN', 'WAITLIST_MAIL_KEY'];
  const required = config.secrets?.required ?? [];
  assert.equal(new Set(required).size, required.length, 'Duplicate runtime secret selection');
  assert.ok(
    base.every((name) => required.includes(name)),
    'Missing base runtime secret selection',
  );
  assert.ok(
    required.every((name) =>
      [
        ...base,
        'WORK_CREDENTIAL_KEY_V1',
        'IDENTITY_ISSUER_JWK',
        'IDENTITY_TRUSTED_KEYS',
        'IDENTITY_ATTESTER_SIGNING',
        'IDENTITY_CREDENTIAL_ENCRYPTION_JWK',
      ].includes(name),
    ),
    'Unreviewed runtime secret selection',
  );
  const withIdentity = required.includes('IDENTITY_ISSUER_JWK');
  const identityProfile = productionIdentityTestProfile(config);
  const withKey = required.includes('WORK_CREDENTIAL_KEY_V1');
  assert.ok(
    config.vars.WORK_CREDENTIAL_KEY_ADMIN_ENABLED !== 'true' || withKey,
    'Key administration requires reviewed secret custody',
  );
  if (withKey)
    assert.equal(
      config.vars.WORK_CREDENTIAL_KEY_FLOOR,
      '1',
      'Initial key custody requires version floor 1',
    );
  const secrets: Record<string, string> = {};
  for (const name of required) {
    const value = env[name];
    assert.ok(
      typeof value === 'string' && value.length > 0,
      'Required runtime secret is unavailable',
    );
    secrets[name] = value;
  }
  assertWaitlistMailKey(secrets.WAITLIST_MAIL_KEY);
  if (withIdentity)
    assertDedicatedIdentityKey(secrets.IDENTITY_ISSUER_JWK!, secrets.OP_PRIVATE_JWK!);
  if (
    identityProfile === 'first-party-age' ||
    identityProfile === 'operator-card-age' ||
    identityProfile === 'operator-card-haip-age'
  )
    assert.equal(
      identityTestTrust(
        secrets.IDENTITY_TRUSTED_KEYS!,
        undefined,
        config.vars.IDENTITY_OPERATOR_CARD_KEY_SHA256,
      ).policy_sha256,
      config.vars.IDENTITY_TRUST_POLICY_SHA256,
      'Identity card trust differs from the reviewed policy',
    );
  if (identityProfile === 'operator-card-haip-age') assertIdentityHaipSecrets(secrets);
  if (withKey) {
    const bytes = Buffer.from(secrets.WORK_CREDENTIAL_KEY_V1!, 'base64url');
    try {
      assert.ok(
        bytes.length === 32 && bytes.toString('base64url') === secrets.WORK_CREDENTIAL_KEY_V1,
        'Work wrapping key must be 32 bytes encoded as unpadded base64url',
      );
    } finally {
      bytes.fill(0);
    }
  }
  return secrets;
}

/** Explicit schema adoption is distinct from enabling any owner/effect capability. */
export function productionWorkSchema(vars: Record<string, string>) {
  assert.ok(
    vars.WORK_SCHEMA_ENABLED === undefined || ['true', 'false'].includes(vars.WORK_SCHEMA_ENABLED),
    'Invalid production Work schema selection',
  );
  const enabled = vars.WORK_SCHEMA_ENABLED === 'true';
  assert.ok(
    vars.WORK_SCHEMA_ADOPTION === undefined ||
      ['true', 'false'].includes(vars.WORK_SCHEMA_ADOPTION),
    'Invalid production Work schema adoption',
  );
  const adopting = vars.WORK_SCHEMA_ADOPTION === 'true';
  assert.ok(!adopting || !enabled, 'Schema adoption must finish before Work activation');
  for (const [name, value] of Object.entries(vars))
    if (name.startsWith('WORK_') && name.endsWith('_ENABLED') && name !== 'WORK_SCHEMA_ENABLED') {
      assert.ok(['true', 'false'].includes(value), 'Invalid production Work capability selection');
      assert.ok(value !== 'true' || enabled, 'Work capabilities require the reviewed Work schema');
    }
  return enabled;
}

async function main() {
  const root = fileURLToPath(new URL('../', import.meta.url));
  assert.equal(process.argv.length, 3, 'Usage: deploy-production.ts <promotion-directory>');
  const destination = await promotionDirectory(root, process.argv[2]!);
  const source = releaseSource(root);
  assert.equal(process.env.GITHUB_EVENT_NAME, 'push');
  assert.equal(process.env.GITHUB_REF, 'refs/heads/main');
  assert.equal(process.env.GITHUB_REPOSITORY, 'masanork/mikaki');
  assert.equal(source.commit, process.env.GITHUB_SHA);
  assert.ok(source.clean);
  const git = (args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8' });
  git(['fetch', 'origin', 'main']);
  git(['merge-base', '--is-ancestor', source.commit, 'origin/main']);
  const paths = git(['diff', '--name-only', source.commit, 'origin/main']).trim();
  if (!sourceIsCurrent(paths ? paths.split('\n') : [])) {
    appendFileSync(process.env.GITHUB_OUTPUT!, 'deployed=false\n');
    console.log('A newer application revision is on main; leaving deployment to its CI run.');
    return;
  }
  const manifest = JSON.parse(readFileSync(join(destination, 'upload-manifest.json'), 'utf8'));
  assert.equal(
    manifest.promotion_ready,
    true,
    'Candidate has not qualified for production promotion',
  );
  await verifyPreparedUpload(root, destination, manifest, source);
  const assets = JSON.parse(readFileSync(join(root, 'artifacts/login-assets.json'), 'utf8'));
  assert.equal(assets.profile, 'default', 'Ordinary production requires default login assets');
  assert.deepEqual(assets.source, source);
  for (const extension of ['js', 'css']) assert.match(assets.login[extension], /^[a-f0-9]{64}$/);
  const wrangler = (args: string[]) =>
    productionWrangler(args, (selected) =>
      execFileSync(join(root, 'node_modules/.bin/wrangler'), selected, {
        cwd: root,
        encoding: 'utf8',
        timeout: 120_000,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    );
  const opConfig = 'crates/worker/wrangler.production.jsonc';
  const reviewedOp = JSON.parse(readFileSync(join(root, opConfig), 'utf8')) as Config;
  const workSchemaEnabled = productionWorkSchema(reviewedOp.vars);
  const copyBindingsStaged = assertClosedProductionCopyGraph(reviewedOp);
  const adopting = reviewedOp.vars.WORK_SCHEMA_ADOPTION === 'true';
  const migrations = await wrangler([
    'd1',
    'migrations',
    'list',
    'DB',
    '--remote',
    '--config',
    opConfig,
  ]);
  assert.ok(
    migrations.includes('No migrations to apply'),
    'Pending migrations require manual reconciliation before deployment',
  );
  const schemaProbe = JSON.parse(
    await wrangler([
      'd1',
      'execute',
      'DB',
      '--remote',
      '--config',
      opConfig,
      '--command',
      `SELECT name FROM d1_migrations ORDER BY id; ${BASELINE_SCHEMA_QUERY};`,
      '--json',
    ]),
  );
  assert.equal(schemaProbe.length, 2, 'Expected ledger and schema results');
  assert.ok(schemaProbe.every((result: { success: boolean }) => result.success === true));
  const migrationDirectory = join(root, 'crates/worker/migrations');
  let workSchema;
  if (
    workSchemaEnabled ||
    (adopting &&
      schemaProbe[1].results.some((row: { name: string }) => row.name === 'work_schema_migrations'))
  ) {
    const directory = join(root, 'crates/worker/work-migrations');
    const probe = JSON.parse(
      await wrangler([
        'd1',
        'execute',
        'DB',
        '--remote',
        '--config',
        opConfig,
        '--command',
        'SELECT id,name,sha256 FROM work_schema_migrations ORDER BY id',
        '--json',
      ]),
    );
    assert.equal(probe.length, 1, 'Expected the separate Work ledger');
    assert.equal(probe[0].success, true);
    workSchema = {
      migrations: readdirSync(directory)
        .filter((name) => name.endsWith('.sql'))
        .sort()
        .map((name) => ({ name, sql: readFileSync(join(directory, name), 'utf8') })),
      ledger: probe[0].results as WorkLedgerRow[],
    };
  }
  const ownerFiles = readdirSync(migrationDirectory)
    .sort()
    .map((name) => ({ name, sql: readFileSync(join(migrationDirectory, name), 'utf8') }));
  const messagingSchema = await inspectProductionMessaging(
    root,
    schemaProbe[1].results,
    async (sql) => {
      const probe = JSON.parse(
        await wrangler([
          'd1',
          'execute',
          'DB',
          '--remote',
          '--config',
          opConfig,
          '--command',
          sql,
          '--json',
        ]),
      );
      assert.equal(probe.length, 1, 'Expected one Chat schema probe');
      assert.equal(probe[0].success, true);
      return probe[0].results;
    },
  );
  if (adopting) {
    assert.ok(!messagingSchema, 'Finish Work adoption before Chat schema changes');
    assertProductionWorkRolloutSchema(
      ownerFiles,
      workSchema?.migrations ?? [],
      schemaProbe[0].results,
      schemaProbe[1].results,
      workSchema?.ledger ?? null,
    );
    if (workSchema) {
      const marker = JSON.parse(
        await wrangler([
          'd1',
          'execute',
          'DB',
          '--remote',
          '--config',
          opConfig,
          '--command',
          'SELECT count(*) AS n FROM work_authority_checkpoint',
          '--json',
        ]),
      );
      assert.equal(
        marker[0].results[0].n,
        0,
        'Enrolled production requires its reviewed checkpoint binding; finish adoption before promotion',
      );
    }
  } else
    assertProductionOwnerSchema(
      ownerFiles,
      schemaProbe[0].results,
      schemaProbe[1].results,
      workSchema,
      messagingSchema,
    );
  const secretFile = join(process.env.RUNNER_TEMP!, 'mikaki-production-secrets.json');
  const runtimeSecrets = productionRuntimeSecrets(reviewedOp, process.env);
  writeFileSync(secretFile, JSON.stringify(runtimeSecrets), { mode: 0o600 });
  const record: { source: typeof source; workers: Record<string, unknown> } = {
    source,
    workers: {},
  };
  const evidence = join(root, 'artifacts/production-deployment.json');
  // A fresh SQLite namespace requires deploy, rather than versions upload.
  // It receives only the attested bundle; the fixed migration tag retains the
  // namespace on later deployments. Enrollment remains a separate operation.
  const checkpointConfigPath = 'crates/work-checkpoint-worker/wrangler.production.jsonc';
  const checkpointConfig = JSON.parse(
    readFileSync(join(root, checkpointConfigPath), 'utf8'),
  ) as Config;
  assert.equal(checkpointConfig.vars.WORK_BOOTSTRAP_PACKET_SHA256, productionWorkPacketDigest());
  const metadataGet = cloudflareMetadataGet(
    PRODUCTION_WORK_TARGET.account,
    process.env.CLOUDFLARE_API_TOKEN!,
  );
  const opPath = `/accounts/${PRODUCTION_WORK_TARGET.account}/workers/scripts/mikaki-auth`;
  const priorCopyVersion = copyBindingsStaged
    ? await closedCopyDeployment(metadataGet, opPath)
    : null;
  const roster = (await metadataGet(
    `/accounts/${PRODUCTION_WORK_TARGET.account}/workers/scripts`,
  )) as { result: { id: string }[] };
  assert.ok(
    Array.isArray(roster.result) && roster.result.length <= 100,
    'Bounded checkpoint resource inventory required',
  );
  if (copyBindingsStaged) assertCopyCompanionsPresent(roster.result);
  const checkpointPath = `/accounts/${PRODUCTION_WORK_TARGET.account}/workers/scripts/${PRODUCTION_WORK_TARGET.checkpoint}`;
  let priorNamespace: string | null = null;
  if (roster.result.some(({ id }) => id === PRODUCTION_WORK_TARGET.checkpoint)) {
    const settings = (await metadataGet(checkpointPath + '/settings')) as {
      result: { bindings: Binding[] };
    };
    priorNamespace = settings.result.bindings.find((binding) => binding.name === 'CHECKPOINTS')
      ?.namespace_id as string;
    assert.match(
      priorNamespace,
      /^[a-f0-9]{32}$/,
      'An existing checkpoint must retain its namespace',
    );
    const exposure = (await metadataGet(checkpointPath + '/subdomain')) as { result: unknown };
    checkCheckpointExposure(exposure.result);
  }
  if (workSchemaEnabled) {
    assert.match(reviewedOp.vars.WORK_CHECKPOINT_NAMESPACE_ID!, /^[a-f0-9]{32}$/);
    assert.equal(
      priorNamespace,
      reviewedOp.vars.WORK_CHECKPOINT_NAMESPACE_ID,
      'Enrolled production checkpoint namespace changed or absent',
    );
  }
  const uploadCheckpoint = await wrangler([
    ...(priorNamespace === null ? ['deploy'] : ['versions', 'upload']),
    join(destination, 'checkpoint/bundle/checkpoint.js'),
    '--no-bundle',
    '--config',
    checkpointConfigPath,
    ...(priorNamespace === null
      ? []
      : ['--tag', source.commit.slice(0, 12), '--message', `main CI ${source.commit}`]),
  ]);
  const checkpointId = uploadCheckpoint.match(
    /(?:Current|Worker) Version ID:\s*([a-f0-9-]{36})/,
  )?.[1];
  assert.ok(checkpointId, 'Wrangler did not return the checkpoint version identity');
  const checkpointVersion = JSON.parse(
    await wrangler(['versions', 'view', checkpointId, '--config', checkpointConfigPath, '--json']),
  );
  assert.equal(checkpointVersion.id, checkpointId);
  checkBindings(checkpointVersion, checkpointConfig);
  const namespace = checkpointVersion.resources.bindings.find(
    (binding: Binding) => binding.name === 'CHECKPOINTS',
  ).namespace_id;
  assert.ok(
    priorNamespace === null || namespace === priorNamespace,
    'Checkpoint deployment must retain its existing namespace',
  );
  if (priorNamespace !== null) {
    await wrangler([
      'versions',
      'deploy',
      `${checkpointId}@100`,
      '--yes',
      '--config',
      checkpointConfigPath,
      '--message',
      `main CI ${source.commit}`,
    ]);
  }
  record.workers.checkpoint = {
    version_id: checkpointId,
    namespace_id: namespace,
    activated: true,
  };
  writeFileSync(evidence, `${JSON.stringify(record, null, 2)}\n`);
  // Stage both versions and inspect bindings before changing any traffic.
  const staged = [];
  for (const [worker, configPath] of [
    ['op', opConfig],
    ['userinfo', 'crates/userinfo-claim-worker/wrangler.production.jsonc'],
  ]) {
    const config: Config = JSON.parse(readFileSync(join(root, configPath!), 'utf8'));
    const history = JSON.parse(
      await wrangler(['deployments', 'list', '--config', configPath!, '--json']),
    );
    const previous = history
      .sort((a: { created_on: string }, b: { created_on: string }) =>
        a.created_on.localeCompare(b.created_on),
      )
      .at(-1);
    const args = [
      'versions',
      'upload',
      join(destination, worker!, worker === 'op' ? 'bundle/service.js' : 'bundle/shim.js'),
      '--no-bundle',
      '--config',
      configPath!,
      ...(worker === 'op' && manifest.release_inventory.assets?.length
        ? ['--assets', join(destination, 'op/assets')]
        : []),
      '--tag',
      source.commit.slice(0, 12),
      '--message',
      `main CI ${source.commit}`,
    ];
    if (worker === 'op') args.push('--secrets-file', secretFile);
    const upload = await wrangler(args);
    const id = upload.match(/Worker Version ID:\s*([a-f0-9-]{36})/)?.[1];
    assert.ok(id, 'Wrangler did not return an uploaded version ID');
    record.workers[worker!] = { version_id: id, previous_deployment: previous, activated: false };
    writeFileSync(evidence, `${JSON.stringify(record, null, 2)}\n`);
    const version = JSON.parse(
      await wrangler(['versions', 'view', id, '--config', configPath!, '--json']),
    );
    assert.equal(version.id, id);
    checkBindings(version, config);
    staged.push({ worker: worker!, configPath: configPath!, config, id });
  }
  for (const item of staged) {
    if (item.worker === 'op' && priorCopyVersion)
      assert.equal(
        await closedCopyDeployment(metadataGet, opPath),
        priorCopyVersion,
        'OP changed while the ordinary promotion was staged',
      );
    console.log(
      await wrangler([
        'versions',
        'deploy',
        `${item.id}@100`,
        '--yes',
        '--config',
        item.configPath,
        '--message',
        `main CI ${source.commit}`,
      ]),
    );
    (record.workers[item.worker] as { activated: boolean }).activated = true;
    writeFileSync(evidence, `${JSON.stringify(record, null, 2)}\n`);
    console.log(await wrangler(['triggers', 'deploy', '--config', item.configPath]));
  }
  const op = staged.find((item) => item.worker === 'op')!;
  appendFileSync(
    process.env.GITHUB_OUTPUT!,
    [
      'deployed=true',
      `version_id=${op.id}`,
      `source_commit=${source.commit}`,
      `login_js_sha256=${assets.login.js}`,
      `login_css_sha256=${assets.login.css}`,
      `android_fingerprint=${op.config.vars.MIKAKI_ANDROID_SHA256_CERT_FINGERPRINT}`,
      '',
    ].join('\n'),
  );
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
