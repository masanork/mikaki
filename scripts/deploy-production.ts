/** Promote verified, attested upload bundles; never build or migrate in this job. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { releaseSource } from './release-inventory.ts';
import { verifyPreparedUpload } from './prepare-release-upload.ts';
import { readdirSync } from 'node:fs';
import { BASELINE_SCHEMA_QUERY } from './production-baseline.ts';
import { assertProductionOwnerSchema } from './production-owner-schema.ts';

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

async function main() {
  const root = fileURLToPath(new URL('../', import.meta.url));
  assert.equal(process.argv.length, 3, 'Usage: deploy-production.ts <promotion-directory>');
  const destination = resolve(process.argv[2]!);
  assert.ok(destination.startsWith(join(root, 'artifacts/promotion-')));
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
  await verifyPreparedUpload(root, destination, manifest, source);
  const assets = JSON.parse(readFileSync(join(root, 'artifacts/login-assets.json'), 'utf8'));
  assert.deepEqual(assets.source, source);
  for (const extension of ['js', 'css']) assert.match(assets.login[extension], /^[a-f0-9]{64}$/);
  const wrangler = (args: string[]) =>
    execFileSync(join(root, 'node_modules/.bin/wrangler'), args, {
      cwd: root,
      encoding: 'utf8',
      timeout: 120_000,
      maxBuffer: 4 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  const opConfig = 'crates/worker/wrangler.production.jsonc';
  const migrations = wrangler(['d1', 'migrations', 'list', 'DB', '--remote', '--config', opConfig]);
  assert.ok(
    migrations.includes('No migrations to apply'),
    'Pending migrations require manual reconciliation before deployment',
  );
  const schemaProbe = JSON.parse(
    wrangler([
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
  assertProductionOwnerSchema(
    readdirSync(migrationDirectory)
      .sort()
      .map((name) => ({ name, sql: readFileSync(join(migrationDirectory, name), 'utf8') })),
    schemaProbe[0].results,
    schemaProbe[1].results,
  );
  const secretFile = join(process.env.RUNNER_TEMP!, 'mikaki-production-secrets.json');
  assert.ok(
    process.env.OP_PRIVATE_JWK && process.env.MIKAKI_READY_TOKEN && process.env.WAITLIST_MAIL_KEY,
  );
  assertWaitlistMailKey(process.env.WAITLIST_MAIL_KEY);
  writeFileSync(
    secretFile,
    JSON.stringify({
      OP_PRIVATE_JWK: process.env.OP_PRIVATE_JWK,
      MIKAKI_READY_TOKEN: process.env.MIKAKI_READY_TOKEN,
      WAITLIST_MAIL_KEY: process.env.WAITLIST_MAIL_KEY,
    }),
    { mode: 0o600 },
  );
  const record: { source: typeof source; workers: Record<string, unknown> } = {
    source,
    workers: {},
  };
  const evidence = join(root, 'artifacts/production-deployment.json');
  // Stage both versions and inspect bindings before changing any traffic.
  const staged = [];
  for (const [worker, configPath] of [
    ['op', opConfig],
    ['userinfo', 'crates/userinfo-claim-worker/wrangler.production.jsonc'],
  ]) {
    const config: Config = JSON.parse(readFileSync(join(root, configPath!), 'utf8'));
    const history = JSON.parse(
      wrangler(['deployments', 'list', '--config', configPath!, '--json']),
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
      '--tag',
      source.commit.slice(0, 12),
      '--message',
      `main CI ${source.commit}`,
    ];
    if (worker === 'op') args.push('--secrets-file', secretFile);
    const upload = wrangler(args);
    const id = upload.match(/Worker Version ID:\s*([a-f0-9-]{36})/)?.[1];
    assert.ok(id, 'Wrangler did not return an uploaded version ID');
    record.workers[worker!] = { version_id: id, previous_deployment: previous, activated: false };
    writeFileSync(evidence, `${JSON.stringify(record, null, 2)}\n`);
    const version = JSON.parse(
      wrangler(['versions', 'view', id, '--config', configPath!, '--json']),
    );
    assert.equal(version.id, id);
    checkBindings(version, config);
    staged.push({ worker: worker!, configPath: configPath!, config, id });
  }
  for (const item of staged) {
    console.log(
      wrangler([
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
    console.log(wrangler(['triggers', 'deploy', '--config', item.configPath]));
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
