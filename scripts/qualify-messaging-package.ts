/** Record the complete beta service upload locally. This never uploads or deploys. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'jsonc-parser';
import { createTestHarness } from 'wrangler';
import { releaseSource } from './release-inventory.ts';
import { MESSAGING_PACKAGE_FILES, MESSAGING_PACKAGE_ENTRYPOINTS } from './release-profile.ts';
import { checkWorkerBundle, measureWorkerUpload } from './worker-bundle-size.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const flags = process.argv.slice(2);
assert.ok(flags.length === 0 || (flags.length === 1 && flags[0] === '--allow-dirty'));
const source = releaseSource(root);
assert.ok(source.clean || flags[0] === '--allow-dirty', 'Qualification requires a clean checkout');
async function packageFiles() {
  return Promise.all(
    MESSAGING_PACKAGE_FILES.map(async (path) => {
      const bytes = await readFile(join(root, path));
      assert.ok(bytes.length > 0, `Missing beta asset: ${path}`);
      return {
        path,
        bytes: bytes.length,
        sha256: createHash('sha256').update(bytes).digest('hex'),
      };
    }),
  );
}
const files = await packageFiles();
const output = join(root, 'local/generated/messaging-package');
const evidence = join(root, 'artifacts/messaging-package');
await mkdir(output, { recursive: true });
await mkdir(evidence, { recursive: true });
const config = parse(await readFile(join(root, 'crates/worker/wrangler.jsonc'), 'utf8'));
config.main = join(root, 'crates/worker/build-messaging-beta/worker/service.mjs');
config.assets.directory = join(root, 'assets');
config.d1_databases[0].migrations_dir = join(root, 'crates/worker/migrations');
const configuration = join(output, 'wrangler.jsonc');
await writeFile(configuration, JSON.stringify(config, null, 2) + '\n');
// Read the compile profile from the actual service, independently of its runtime gate.
config.vars = { ...config.vars, MESSAGING_BETA_ENABLED: 'false' };
const harness = createTestHarness({ root, workers: [{ config }] });
let runtime;
try {
  await harness.listen();
  const response = await harness.getWorker(config.name).fetch('https://mikaki.test/version');
  assert.equal(response.status, 200);
  const version = (await response.json()) as Record<string, unknown>;
  runtime = {
    build_profile: version.build_profile,
    source_commit: version.source_commit,
    source_clean: version.source_clean,
  };
  assert.deepEqual(
    runtime,
    {
      build_profile: 'messaging-beta',
      source_commit: source.commit,
      source_clean: source.clean,
    },
    'Rebuild the actual beta service for this source revision',
  );
} finally {
  await harness.close();
}
const uploadFile = join(output, 'worker.multipart');
const metadataFile = join(output, 'bundle-meta.json');
const log = execFileSync(
  join(root, 'node_modules/.bin/wrangler'),
  [
    'deploy',
    '--config',
    configuration,
    '--dry-run',
    '--outdir',
    join(output, 'bundle'),
    '--outfile',
    uploadFile,
    '--metafile',
    metadataFile,
  ],
  {
    cwd: root,
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 2 * 1024 * 1024,
  },
);
await writeFile(join(output, 'dry-run.log'), log);
const upload = await measureWorkerUpload(new Uint8Array(await readFile(uploadFile)));
assert.deepEqual(
  upload.modules
    .filter((file) => file.type === 'application/wasm')
    .map((file) => ({ bytes: file.bytes, sha256: file.sha256 })),
  [{ bytes: files[1]!.bytes, sha256: files[1]!.sha256 }],
  'Qualified upload Wasm differs from built archive member',
);
assert.deepEqual(checkWorkerBundle('messaging-beta', upload.raw), []);
const metadata = JSON.parse(await readFile(metadataFile, 'utf8')) as {
  outputs: Record<string, { exports: string[]; entryPoint?: string }>;
};
const entry = Object.values(metadata.outputs).find((item) => item.entryPoint);
assert.ok(entry, 'Missing bundled service entry');
const expected = MESSAGING_PACKAGE_ENTRYPOINTS;
assert.deepEqual(new Set(entry.exports), new Set(expected), 'Changed service entrypoints');
assert.deepEqual(await packageFiles(), files, 'Built package changed during qualification');
assert.deepEqual(releaseSource(root), source, 'Source changed while measuring the beta package');
await writeFile(
  join(evidence, 'summary.json'),
  JSON.stringify(
    {
      schema: 'mikaki-messaging-package-qualification-v2',
      source,
      // This is qualification evidence, not a promotion inventory or attestation.
      profile: 'messaging-beta',
      runtime,
      entrypoints: expected,
      upload,
      files,
    },
    null,
    2,
  ) + '\n',
);
console.log(
  `Chat service package: ${upload.raw} bytes, ${upload.modules.length} modules; source ${source.commit} (clean=${source.clean})`,
);
