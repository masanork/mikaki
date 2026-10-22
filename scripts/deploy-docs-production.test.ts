import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { checkDocsBindings } from './deploy-docs-production.ts';

test('Docs promotion reports an unverified or superseded release as undeployed', () => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-docs-source-'));
  const root = join(directory, 'checkout');
  const remote = join(directory, 'origin.git');
  const output = join(directory, 'workflow-output');
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Docs fixture',
    GIT_AUTHOR_EMAIL: 'docs-fixture@example.invalid',
    GIT_COMMITTER_NAME: 'Docs fixture',
    GIT_COMMITTER_EMAIL: 'docs-fixture@example.invalid',
    GITHUB_EVENT_NAME: 'push',
    GITHUB_REF: 'refs/heads/main',
    GITHUB_REPOSITORY: 'masanork/mikaki',
    GITHUB_OUTPUT: output,
  };
  for (const name of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'CLOUDFLARE_API_TOKEN'])
    delete env[name];
  const git = (...args: string[]) =>
    execFileSync('git', args, {
      cwd: root,
      env,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  const invoke = () => {
    writeFileSync(output, '');
    const module = new URL('./deploy-docs-production.ts', import.meta.url).href;
    const child = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '--eval',
        `import { deployDocsProduction } from ${JSON.stringify(module)}; await deployDocsProduction(process.argv[1]);`,
        root,
      ],
      { cwd: root, env, encoding: 'utf8', timeout: 30_000 },
    );
    assert.ifError(child.error);
    return { child, outputs: readFileSync(output, 'utf8') };
  };
  try {
    mkdirSync(root);
    git('init', '--bare', '--template=', remote);
    git('init', '--initial-branch=main', '--template=');
    writeFileSync(join(root, 'README.md'), 'Docs release fixture\n');
    git('add', 'README.md');
    git('commit', '-m', 'Initial source');
    git('remote', 'add', 'origin', remote);
    git('push', 'origin', 'main');
    const source = git('rev-parse', 'HEAD');
    env.GITHUB_SHA = source;

    // A current revision without verified release bytes must never publish success.
    const unverified = invoke();
    assert.equal(unverified.child.status, 1);
    assert.match(unverified.child.stderr, /ENOENT/);
    assert.equal(unverified.outputs, 'deployed=false\n');

    // Reproduce main advancing after OP activation but before Docs promotion.
    mkdirSync(join(root, 'docs'));
    writeFileSync(join(root, 'docs/rollout.md'), 'New main revision\n');
    git('add', 'docs/rollout.md');
    git('commit', '-m', 'Advance main before Docs activation');
    git('push', 'origin', 'main');
    git('checkout', '--detach', source);
    const superseded = invoke();
    assert.equal(superseded.child.status, 0, superseded.child.stderr);
    assert.match(superseded.child.stdout, /leaving Docs and release smoke to its CI run/);
    assert.equal(superseded.outputs, 'deployed=false\n');
    assert.equal(existsSync(join(root, 'artifacts/production-docs-deployment.json')), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('Docs requires its own database, assets, limiter and secret with no extra authority', () => {
  const config: Parameters<typeof checkDocsBindings>[1] = {
    name: 'docs-fixture',
    account_id: 'fixture',
    compatibility_date: '2026-10-03',
    vars: {
      ISSUER: 'https://op.example',
      RP_ORIGIN: 'https://docs.example',
      CLIENT_ID: 'docs-client',
    },
    d1_databases: [{ binding: 'DB', database_id: 'docs-db' }],
    secrets: { required: ['RP_PRIVATE_JWK'] },
    version_metadata: { binding: 'CF_VERSION_METADATA' },
    assets: { binding: 'DOCS_ASSETS', directory: 'dist' },
    ratelimits: [{ name: 'AUTH_LIMITER', namespace_id: '17', simple: { limit: 60, period: 60 } }],
  };
  const bindings: Record<string, unknown>[] = [
    ...Object.entries(config.vars).map(([name, text]) => ({ name, type: 'plain_text', text })),
    { name: 'DB', type: 'd1', database_id: 'docs-db' },
    { name: 'RP_PRIVATE_JWK', type: 'secret_text' },
    { name: 'CF_VERSION_METADATA', type: 'version_metadata' },
    { name: 'DOCS_ASSETS', type: 'assets' },
    {
      name: 'AUTH_LIMITER',
      type: 'ratelimit',
      namespace_id: '17',
      simple: { limit: 60, period: 60 },
    },
  ];
  const version = {
    resources: { bindings, script_runtime: { compatibility_date: config.compatibility_date } },
  };
  checkDocsBindings(version, config);
  const numericNamespace = structuredClone(version);
  numericNamespace.resources.bindings.find(
    (binding) => binding.name === 'AUTH_LIMITER',
  )!.namespace_id = 17;
  checkDocsBindings(numericNamespace, config);
  for (const extra of [
    { name: 'OP_PRIVATE_JWK', type: 'secret_text' },
    { name: 'CLAIM_STORE', type: 'service', service: 'op' },
    { name: 'OWNER_DB', type: 'd1', database_id: 'owner-db' },
    { name: 'VAULT_BLOBS', type: 'r2_bucket', bucket_name: 'owner-vault' },
  ])
    assert.throws(() =>
      checkDocsBindings(
        { resources: { ...version.resources, bindings: [...bindings, extra] } },
        config,
      ),
    );
  for (const [name, key, value] of [
    ['DB', 'database_id', 'owner-db'],
    ['AUTH_LIMITER', 'namespace_id', 'wrong-limiter'],
    ['DOCS_ASSETS', 'type', 'service'],
  ]) {
    const changed = structuredClone(version);
    changed.resources.bindings.find((binding) => binding.name === name)![key!] = value;
    assert.throws(() => checkDocsBindings(changed, config));
  }
});
