import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import {
  docsReleaseSourcePaths,
  recordDocsReleaseManifest,
  verifyDocsRelease,
} from './prepare-docs-release.ts';

test('Docs release manifest binds source, worker bundle, migrations and every public asset', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mikaki-docs-release-test-'));
  const source = { commit: 'a'.repeat(40), clean: true };
  try {
    const members = [
      ...docsReleaseSourcePaths,
      'artifacts/docs-promotion/bundle/worker.js',
      'apps/mikaki-docs/dist/index.html',
      'apps/mikaki-docs/dist/en/index.html',
    ];
    for (const [index, path] of members.entries()) {
      await mkdir(dirname(join(root, path)), { recursive: true });
      await writeFile(join(root, path), `fixture-${index}`);
    }
    await recordDocsReleaseManifest(root, source);
    await verifyDocsRelease(root, source);

    await writeFile(join(root, 'apps/mikaki-docs/dist/en/index.html'), 'changed-after-attestation');
    await assert.rejects(verifyDocsRelease(root, source));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('production Docs Wrangler config is strict JSON with release worker and binding names', async () => {
  const path = new URL('../apps/mikaki-docs/wrangler.production.jsonc', import.meta.url);
  const config = JSON.parse(await readFile(path, 'utf8')) as {
    name: string;
    main: string;
    assets: { binding: string };
    d1_databases: Array<{ binding: string; database_name: string }>;
    version_metadata: { binding: string };
    ratelimits: Array<{ name: string }>;
    secrets: { required: string[] };
  };

  assert.equal(config.name, 'mikaki-docs-rp');
  assert.equal(config.main, 'worker.ts');
  assert.equal(config.assets.binding, 'DOCS_ASSETS');
  assert.deepEqual(config.d1_databases, [
    {
      binding: 'DB',
      database_name: 'mikaki-docs-rp',
      database_id: '8527823b-5417-425d-8028-0532464e39e7',
      migrations_dir: 'migrations',
    },
  ]);
  assert.equal(config.version_metadata.binding, 'CF_VERSION_METADATA');
  assert.deepEqual(config.ratelimits.map(({ name }) => name), ['AUTH_LIMITER']);
  assert.deepEqual(config.secrets.required, ['RP_PRIVATE_JWK']);
});
