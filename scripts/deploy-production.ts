/** Promote verified, attested upload bundles; never build or migrate in this job. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { releaseSource } from './release-inventory.ts';
import { verifyPreparedUpload } from './prepare-release-upload.ts';
import {
  assertProductionBaseline,
  BASELINE_NAME,
  BASELINE_SCHEMA_QUERY,
} from './production-baseline.ts';

type Binding = Record<string, unknown>;
type Config = {
  name: string;
  compatibility_date: string;
  vars: Record<string, string>;
  d1_databases?: { binding: string; database_id: string }[];
  r2_buckets?: { binding: string; bucket_name: string }[];
  services?: { binding: string; service: string; entrypoint?: string }[];
  secrets?: { required: string[] };
  version_metadata?: { binding: string };
  secrets_store_secrets?: { binding: string; store_id: string; secret_name: string }[];
};

export function checkBindings(
  version: {
    resources: { bindings: Binding[]; script_runtime: { compatibility_date: string } };
  },
  config: Config,
) {
  assert.equal(version.resources.script_runtime.compatibility_date, config.compatibility_date);
  const bindings = version.resources.bindings;
  for (const binding of bindings) {
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
  const check = (name: string, expected: Binding) => {
    const actual = bindings.find((binding) => binding.name === name);
    assert.ok(actual, `Missing binding ${name}`);
    for (const [key, value] of Object.entries(expected))
      assert.deepEqual(actual[key], value, `Binding ${name}: ${key}`);
  };
  for (const [name, text] of Object.entries(config.vars)) check(name, { type: 'plain_text', text });
  for (const item of config.d1_databases ?? [])
    check(item.binding, { type: 'd1', database_id: item.database_id });
  for (const item of config.r2_buckets ?? [])
    check(item.binding, { type: 'r2_bucket', bucket_name: item.bucket_name });
  for (const item of config.services ?? [])
    check(item.binding, {
      type: 'service',
      service: item.service,
      ...(item.entrypoint ? { entrypoint: item.entrypoint } : {}),
    });
  for (const name of config.secrets?.required ?? []) check(name, { type: 'secret_text' });
  if (config.version_metadata) check(config.version_metadata.binding, { type: 'version_metadata' });
  for (const item of config.secrets_store_secrets ?? [])
    check(item.binding, {
      type: 'secrets_store_secret',
      store_id: item.store_id,
      secret_name: item.secret_name,
    });
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
  const migrations = wrangler([
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
  assertProductionBaseline(
    readFileSync(join(root, 'crates/worker/migrations', BASELINE_NAME), 'utf8'),
    schemaProbe[0].results,
    schemaProbe[1].results,
  );
  const secretFile = join(process.env.RUNNER_TEMP!, 'mikaki-production-secrets.json');
  assert.ok(process.env.OP_PRIVATE_JWK && process.env.MIKAKI_READY_TOKEN);
  writeFileSync(
    secretFile,
    JSON.stringify({
      OP_PRIVATE_JWK: process.env.OP_PRIVATE_JWK,
      MIKAKI_READY_TOKEN: process.env.MIKAKI_READY_TOKEN,
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
