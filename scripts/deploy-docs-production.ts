/** Promote the attested, prepared Docs bytes; never build or migrate here. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkBindings, sourceIsCurrent } from './deploy-production.ts';
import { releaseSource } from './release-inventory.ts';
import { verifyDocsRelease } from './prepare-docs-release.ts';
import { assertProductionBaseline, BASELINE_SCHEMA_QUERY } from './production-baseline.ts';

type DocsConfig = Parameters<typeof checkBindings>[1] & {
  account_id: string;
  assets: { binding: string; directory: string };
  ratelimits: { name: string; namespace_id: string; simple: { limit: number; period: number } }[];
};

export function checkDocsBindings(
  version: Parameters<typeof checkBindings>[0],
  config: DocsConfig,
) {
  checkBindings(version, config);
  const bindings = version.resources.bindings;
  const names = [
    ...Object.keys(config.vars),
    ...config.d1_databases!.map((item) => item.binding),
    ...config.secrets!.required,
    config.version_metadata!.binding,
    config.assets.binding,
    ...config.ratelimits.map((item) => item.name),
  ];
  assert.deepEqual(
    bindings.map((item) => item.name).sort(),
    names.sort(),
    'Unexpected Docs authority',
  );
  assert.equal(bindings.find((item) => item.name === config.assets.binding)!.type, 'assets');
  for (const limiter of config.ratelimits) {
    const binding = bindings.find((item) => item.name === limiter.name)!;
    assert.equal(binding.type, 'ratelimit');
    assert.equal(String(binding.namespace_id), limiter.namespace_id);
    assert.deepEqual(binding.simple, limiter.simple);
  }
}

async function main() {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const source = releaseSource(root);
  assert.ok(source.clean, 'Docs promotion requires clean source');
  assert.equal(process.env.GITHUB_EVENT_NAME, 'push');
  assert.equal(process.env.GITHUB_REF, 'refs/heads/main');
  assert.equal(process.env.GITHUB_REPOSITORY, 'masanork/mikaki');
  assert.equal(source.commit, process.env.GITHUB_SHA);
  const git = (args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8' });
  git(['fetch', 'origin', 'main']);
  git(['merge-base', '--is-ancestor', source.commit, 'origin/main']);
  const changed = git(['diff', '--name-only', source.commit, 'origin/main']).trim();
  if (!sourceIsCurrent(changed ? changed.split('\n') : [])) {
    console.log('A newer application revision is on main; leaving Docs to its CI run.');
    return;
  }
  await verifyDocsRelease(root, source);
  const configPath = 'apps/mikaki-docs/wrangler.production.jsonc';
  const config: DocsConfig = JSON.parse(readFileSync(join(root, configPath), 'utf8'));
  assert.equal(config.name, 'mikaki-docs-rp');
  assert.equal(config.vars.RP_ORIGIN, 'https://docs.mikaki.org');
  assert.equal(config.vars.ISSUER, 'https://auth.mikaki.org');
  assert.equal(config.d1_databases?.length, 1);
  assert.equal(config.d1_databases[0]!.database_id, '8527823b-5417-425d-8028-0532464e39e7');
  assert.match(config.vars.CLIENT_ID!, /^[a-f0-9-]{36}$/);
  const wrangler = (args: string[]) =>
    execFileSync(join(root, 'node_modules/.bin/wrangler'), args, {
      cwd: root,
      encoding: 'utf8',
      timeout: 120_000,
      maxBuffer: 4 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  const query = (path: string, sql: string) => {
    const results = JSON.parse(
      wrangler(['d1', 'execute', 'DB', '--remote', '--config', path, '--command', sql, '--json']),
    );
    assert.ok(
      Array.isArray(results) &&
        results.length &&
        results.every((item: { success?: boolean }) => item.success === true),
    );
    return results;
  };
  assert.ok(
    wrangler(['d1', 'migrations', 'list', 'DB', '--remote', '--config', configPath]).includes(
      'No migrations to apply',
    ),
    'Pending Docs migrations require manual initialization',
  );
  const schema = query(
    configPath,
    `SELECT name FROM d1_migrations ORDER BY id; ${BASELINE_SCHEMA_QUERY};`,
  );
  assert.equal(schema.length, 2);
  assertProductionBaseline(
    readFileSync(join(root, 'apps/mikaki-docs/migrations/0001_initial.sql'), 'utf8'),
    schema[0].results,
    schema[1].results,
    '0001_initial.sql',
  );

  const secret = process.env.DOCS_RP_PRIVATE_JWK;
  assert.ok(secret, 'Dedicated Docs signing key is required');
  const jwk = JSON.parse(secret);
  assert.equal(jwk.kty, 'EC');
  assert.equal(jwk.crv, 'P-256');
  assert.equal(jwk.kid, 'mikaki-docs-20261005');
  assert.ok(jwk.d);
  const privateKey = createPrivateKey({ key: jwk, format: 'jwk' });
  const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' });
  const proof = Buffer.from('mikaki Docs deployment signing-key proof');
  assert.ok(
    verify('sha256', proof, createPublicKey(privateKey), sign('sha256', proof, privateKey)),
    'Docs key pair is inconsistent',
  );
  const publicHex = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(publicJwk.x!, 'base64url'),
    Buffer.from(publicJwk.y!, 'base64url'),
  ])
    .toString('hex')
    .toUpperCase();
  const client = config.vars.CLIENT_ID;
  const registration = query(
    'crates/worker/wrangler.production.jsonc',
    `SELECT c.client_id,c.sector_identifier,c.auth_method,c.active,k.kid,k.algorithm,k.active AS key_active,hex(k.public_key_sec1) AS public_key FROM client c JOIN client_key k ON k.client_id=c.client_id WHERE c.client_id='${client}' AND k.kid='mikaki-docs-20261005'; SELECT redirect_uri FROM client_redirect_uri WHERE client_id='${client}' AND active=1 ORDER BY redirect_uri; SELECT logout_uri FROM client_backchannel_logout_uri WHERE client_id='${client}' AND active=1;`,
  );
  assert.equal(registration.length, 3);
  assert.deepEqual(registration[0].results, [
    {
      client_id: client,
      sector_identifier: 'docs.mikaki.org',
      auth_method: 'private_key_jwt',
      active: 1,
      kid: 'mikaki-docs-20261005',
      algorithm: 'ES256',
      key_active: 1,
      public_key: publicHex,
    },
  ]);
  assert.deepEqual(registration[1].results, [{ redirect_uri: 'https://docs.mikaki.org/callback' }]);
  assert.deepEqual(registration[2].results, [
    { logout_uri: 'https://docs.mikaki.org/backchannel' },
  ]);

  const directory = mkdtempSync(join(tmpdir(), 'mikaki-docs-promotion-'));
  try {
    const secretsFile = join(directory, 'secrets.json');
    writeFileSync(secretsFile, JSON.stringify({ RP_PRIVATE_JWK: secret }), {
      mode: 0o600,
      flag: 'wx',
    });
    const upload = wrangler([
      'versions',
      'upload',
      join(root, 'artifacts/docs-promotion/bundle/worker.js'),
      '--no-bundle',
      '--config',
      configPath,
      '--secrets-file',
      secretsFile,
      '--tag',
      source.commit.slice(0, 12),
      '--message',
      `main CI ${source.commit}`,
    ]);
    const id = upload.match(/Worker Version ID:\s*([a-f0-9-]{36})/)?.[1];
    assert.ok(id, 'Wrangler did not report a staged Docs version');
    const record = { source, worker: config.name, version_id: id, activated: false };
    mkdirSync(join(root, 'artifacts'), { recursive: true });
    const evidence = join(root, 'artifacts/production-docs-deployment.json');
    const save = () => writeFileSync(evidence, JSON.stringify(record, null, 2) + '\n');
    save();
    const version = JSON.parse(
      wrangler(['versions', 'view', id, '--config', configPath, '--json']),
    );
    assert.equal(version.id, id);
    assert.equal(version.annotations['workers/tag'], source.commit.slice(0, 12));
    checkDocsBindings(version, config);
    console.log(
      wrangler([
        'versions',
        'deploy',
        `${id}@100`,
        '--yes',
        '--config',
        configPath,
        '--message',
        `main CI ${source.commit}`,
      ]),
    );
    record.activated = true;
    save();
    console.log(wrangler(['triggers', 'deploy', '--config', configPath]));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
