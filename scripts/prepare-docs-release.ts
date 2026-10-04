import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { mkdir, open, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { releaseSource, type ReleaseSource } from './release-inventory.ts';

const configPath = 'apps/mikaki-docs/wrangler.production.jsonc';
const sourcePaths = [
  'apps/mikaki-docs/worker.ts',
  'apps/mikaki-docs/migrations/0001_initial.sql',
  configPath,
  'crates/helpdesk-rp/oidc.ts',
  'crates/helpdesk-rp/i18n.ts',
] as const;
const releaseDirectory = 'artifacts/docs-promotion';
const manifestPath = `${releaseDirectory}/manifest.json`;
const bundlePath = `${releaseDirectory}/bundle/worker.js`;
const assetsDirectory = 'apps/mikaki-docs/dist';
const maximumFileBytes = 32 * 1024 * 1024;
export const docsReleaseSourcePaths = sourcePaths;

type FileDigest = { path: string; bytes: number; sha256: string };
type DocsReleaseManifest = {
  schema_version: 1;
  source: ReleaseSource;
  worker: 'mikaki-docs-rp';
  bundle: FileDigest;
  source_files: FileDigest[];
  assets: FileDigest[];
};

async function digestFile(root: string, path: string): Promise<FileDigest> {
  const fullPath = join(root, path);
  const file = await open(
    fullPath,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = await file.stat();
    assert.ok(stat.isFile() && stat.size <= maximumFileBytes, `Expected bounded file: ${path}`);
    const bytes = Buffer.alloc(stat.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const result = await file.read(bytes, length, bytes.length - length, null);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    assert.ok(length <= stat.size, `File changed while reading: ${path}`);
    return {
      path,
      bytes: length,
      sha256: createHash('sha256').update(bytes.subarray(0, length)).digest('hex'),
    };
  } finally {
    await file.close();
  }
}

async function filesUnder(root: string, directory: string): Promise<string[]> {
  const result: string[] = [];
  async function visit(path: string): Promise<void> {
    for (const entry of await readdir(join(root, path), { withFileTypes: true })) {
      const child = `${path}/${entry.name}`;
      assert.ok(!entry.isSymbolicLink(), `Symlink is not a Docs release member: ${child}`);
      if (entry.isDirectory()) await visit(child);
      else {
        assert.ok(entry.isFile(), `Non-regular Docs release member: ${child}`);
        result.push(child);
      }
    }
  }
  await visit(directory);
  return result.sort();
}

async function manifestFor(root: string, source: ReleaseSource): Promise<DocsReleaseManifest> {
  assert.match(source.commit, /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/);
  assert.equal(source.clean, true, 'Docs release preparation requires a clean source checkout');
  const sourceFiles = await Promise.all(sourcePaths.map((path) => digestFile(root, path)));
  const assets = await Promise.all(
    (await filesUnder(root, assetsDirectory)).map((path) => digestFile(root, path)),
  );
  assert.ok(assets.length > 0, 'Docs static asset build is required before release preparation');
  return {
    schema_version: 1,
    source,
    worker: 'mikaki-docs-rp',
    bundle: await digestFile(root, bundlePath),
    source_files: sourceFiles,
    assets,
  };
}

export async function verifyDocsRelease(root: string, source: ReleaseSource): Promise<void> {
  assert.equal(source.clean, true, 'Docs promotion requires a clean source checkout');
  const manifest = JSON.parse(
    await readFile(join(root, manifestPath), 'utf8'),
  ) as DocsReleaseManifest;
  assert.equal(manifest.schema_version, 1);
  assert.equal(manifest.worker, 'mikaki-docs-rp');
  assert.deepEqual(
    manifest,
    await manifestFor(root, source),
    'Docs bundle/source/assets differ from attested inventory',
  );
}

export async function recordDocsReleaseManifest(
  root: string,
  source: ReleaseSource,
): Promise<void> {
  const manifest = await manifestFor(root, source);
  await mkdir(join(root, releaseDirectory), { recursive: true });
  await writeFile(join(root, manifestPath), `${JSON.stringify(manifest, null, 2)}\n`, {
    mode: 0o600,
  });
}

export async function createDocsRelease(root: string, source: ReleaseSource): Promise<void> {
  await rm(join(root, releaseDirectory), { recursive: true, force: true });
  await mkdir(join(root, `${releaseDirectory}/bundle`), { recursive: true });
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(
      'node_modules/.bin/wrangler',
      [
        'deploy',
        '--dry-run',
        '--outdir',
        join(root, `${releaseDirectory}/bundle`),
        '--config',
        configPath,
      ],
      { cwd: root, stdio: 'inherit' },
    );
    child.once('error', reject);
    child.once('exit', (code) =>
      code === 0
        ? resolvePromise()
        : reject(new Error(`Wrangler bundle failed (${code ?? 'signal'})`)),
    );
  });
  await recordDocsReleaseManifest(root, source);
  await verifyDocsRelease(root, source);
}

async function main(): Promise<void> {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const source = releaseSource(root);
  assert.equal(
    source.commit,
    process.env.GITHUB_SHA,
    'prepared Docs source must match the workflow commit',
  );
  assert.match(
    source.commit,
    /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/,
    'GITHUB_SHA must identify the checked-out source',
  );
  if (process.argv[2] === 'create') await createDocsRelease(root, source);
  else if (process.argv[2] === 'verify') await verifyDocsRelease(root, source);
  else throw new Error('Usage: node scripts/prepare-docs-release.ts create|verify');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
