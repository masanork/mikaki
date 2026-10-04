/** Offline byte and migration checks. Authenticity still requires trusted attestations. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { open, readdir, mkdir, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const members = ['index.js', 'index_bg.wasm', 'package.json', 'worker/shim.mjs'];
const archives = ['mikaki-worker.tar.gz', 'mikaki-userinfo-claim-worker.tar.gz'];
const limit = 64 * 1024 * 1024;
export type ReleaseSource = { commit: string; clean: boolean };
type Digest = { bytes: number; sha256: string };
export type ReleaseInventory = {
  schema_version: 1;
  source: ReleaseSource;
  archives: { name: string; digest: Digest; members: { name: string; digest: Digest }[] }[];
  migrations: { name: string; digest: Digest }[];
};
function digest(bytes: Uint8Array): Digest {
  assert.ok(bytes.length <= limit, 'Release input exceeds size limit');
  return { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
}
async function regularFile(path: string, maximum = limit): Promise<Buffer> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat();
    assert.ok(info.isFile() && info.size <= maximum, 'Expected a bounded regular release file');
    const bytes = Buffer.alloc(info.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const result = await file.read(bytes, length, bytes.length - length, null);
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    assert.ok(length <= info.size, 'Release file changed while reading');
    return bytes.subarray(0, length);
  } finally {
    await file.close();
  }
}
function tar(bytes: Buffer, args: string[]): Buffer {
  return execFileSync('tar', [args[0]!, '-f', '-', ...args.slice(1)], {
    input: bytes,
    maxBuffer: limit,
    timeout: 30_000,
  });
}
export async function collectRelease(
  root: string,
  source: ReleaseSource,
): Promise<ReleaseInventory> {
  assert.match(source.commit, /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/);
  assert.equal(typeof source.clean, 'boolean');
  const releases: ReleaseInventory['archives'] = [];
  for (const name of archives) {
    const requiredMembers =
      name === 'mikaki-worker.tar.gz' ? [...members, 'worker/service.mjs'] : members;
    const path = join(root, 'artifacts', name);
    const bytes = await regularFile(path);
    const names = tar(bytes, ['-tz']).toString('utf8').trimEnd().split('\n');
    assert.deepEqual(
      [...names].sort(),
      [...requiredMembers].sort(),
      `Unexpected/duplicate archive entries: ${name}`,
    );
    const types = tar(bytes, ['-tvz']).toString('utf8').trimEnd().split('\n');
    assert.equal(types.length, requiredMembers.length);
    assert.ok(
      types.every((line) => line.startsWith('-')),
      'Archive members must be regular files',
    );
    const archiveMembers = requiredMembers.map((entry) => ({
      name: entry,
      bytes: tar(bytes, ['-xOz', entry]),
    }));
    if (name === 'mikaki-userinfo-claim-worker.tar.gz') {
      const wasm = archiveMembers.find((entry) => entry.name === 'index_bg.wasm')!.bytes;
      assert.ok(
        !wasm.includes(Buffer.from('CONFORMANCE_GATE')) &&
          !wasm.includes(Buffer.from('https://conformance.internal/after-decrypt')),
        'Conformance pause gate must not enter a release archive',
      );
    }
    releases.push({
      name,
      digest: digest(bytes),
      members: archiveMembers.map((entry) => ({ name: entry.name, digest: digest(entry.bytes) })),
    });
  }
  const directory = join(root, 'crates/worker/migrations');
  const names = (await readdir(directory)).sort();
  assert.ok(names.length > 0);
  for (const [index, name] of names.entries()) {
    assert.match(
      name,
      new RegExp(`^${String(index + 1).padStart(4, '0')}_[a-z0-9_]+\\.sql$`),
      'Migration sequence must be complete',
    );
  }
  const migrations = await Promise.all(
    names.map(async (name) => ({ name, digest: digest(await regularFile(join(directory, name))) })),
  );
  return { schema_version: 1, source, archives: releases, migrations };
}
export async function verifyRelease(
  root: string,
  inventory: unknown,
  source: ReleaseSource,
  allowDirty = false,
): Promise<void> {
  assert.ok(source.clean || allowDirty, 'Release verification requires a clean source checkout');
  assert.deepEqual(
    inventory,
    await collectRelease(root, source),
    'Release bytes, migration set or source identity do not match',
  );
}
export function releaseSource(root: string): ReleaseSource {
  const git = (args: string[]) =>
    execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', timeout: 10_000 });
  const commit = git(['rev-parse', 'HEAD']).trim();
  const dirty = git(['status', '--porcelain=v1', '--untracked-files=all']).trim().length !== 0;
  return { commit, clean: !dirty };
}
async function main(): Promise<void> {
  const [action, ...flags] = process.argv.slice(2);
  assert.ok(
    action === 'create' || action === 'verify',
    'Usage: node scripts/release-inventory.ts create|verify [--allow-dirty]',
  );
  assert.ok(
    flags.length === 0 || (flags.length === 1 && flags[0] === '--allow-dirty'),
    'Unknown option',
  );
  const allowDirty = flags[0] === '--allow-dirty';
  const root = fileURLToPath(new URL('../', import.meta.url));
  const source = releaseSource(root);
  assert.ok(
    source.clean || allowDirty,
    'Release creation/verification requires a clean source checkout',
  );
  const path = join(root, 'artifacts/release-manifest.json');
  if (action === 'create') {
    await mkdir(join(root, 'artifacts'), { recursive: true });
    await writeFile(path, JSON.stringify(await collectRelease(root, source), null, 2) + '\n');
  } else {
    const bytes = await regularFile(path, 1024 * 1024);
    await verifyRelease(root, JSON.parse(bytes.toString('utf8')), source, allowDirty);
  }
  console.log(
    `Release ${action}: byte inventory ${source.clean ? 'clean' : 'LOCAL DIRTY'}; ${source.commit}`,
  );
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
