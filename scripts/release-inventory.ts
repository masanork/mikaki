/** Offline byte and migration checks. Authenticity still requires trusted attestations. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { open, readdir, mkdir, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  releaseProfile,
  assertCompiledProfile,
  releaseArguments,
  MESSAGING_PACKAGE_FILES,
  MESSAGING_PACKAGE_ENTRYPOINTS,
  type ReleaseProfile,
  type MessagingQualification,
} from './release-profile.ts';
import { checkWorkerBundle, workerBundleBytes } from './worker-bundle-size.ts';

const members = ['index.js', 'index_bg.wasm', 'package.json', 'worker/shim.mjs'];
const archives = [
  'mikaki-worker.tar.gz',
  'mikaki-userinfo-claim-worker.tar.gz',
  'mikaki-work-checkpoint.tar.gz',
];
const limit = 64 * 1024 * 1024;
export type ReleaseSource = { commit: string; clean: boolean };
type Digest = { bytes: number; sha256: string };
export type ReleaseInventory = {
  schema_version: 2;
  profile: ReleaseProfile;
  source: ReleaseSource;
  archives: { name: string; digest: Digest; members: { name: string; digest: Digest }[] }[];
  migrations: { name: string; digest: Digest }[];
  assets?: { name: string; digest: Digest }[];
  messaging?: MessagingQualification;
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
async function collectArchive(root: string, name: string) {
  const requiredMembers =
    name === 'mikaki-worker.tar.gz'
      ? [...members, 'worker/service.mjs']
      : name === 'mikaki-work-checkpoint.tar.gz'
        ? ['worker/checkpoint.mjs']
        : members;
  const path = join(root, 'artifacts', name);
  const bytes = await regularFile(path);
  const names = tar(bytes, ['-tz']).toString('utf8').trimEnd().split('\n');
  assert.deepEqual(
    [...names].sort((a, b) => a.localeCompare(b)),
    [...requiredMembers].sort((a, b) => a.localeCompare(b)),
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
  const wasm = archiveMembers.find((entry) => entry.name === 'index_bg.wasm')?.bytes;
  if (name === 'mikaki-userinfo-claim-worker.tar.gz') {
    assert.ok(wasm);
    assert.ok(
      !wasm.includes(Buffer.from('CONFORMANCE_GATE')) &&
        !wasm.includes(Buffer.from('https://conformance.internal/after-decrypt')),
      'Conformance pause gate must not enter a release archive',
    );
  }
  return {
    inventory: {
      name,
      digest: digest(bytes),
      members: archiveMembers.map((entry) => ({ name: entry.name, digest: digest(entry.bytes) })),
    },
    wasm,
  };
}
export async function collectRelease(
  root: string,
  source: ReleaseSource,
  profile: ReleaseProfile = 'default',
): Promise<ReleaseInventory> {
  releaseProfile(profile);
  assert.match(source.commit, /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/);
  assert.equal(typeof source.clean, 'boolean');
  const collected = await Promise.all(archives.map((name) => collectArchive(root, name)));
  const releases = collected.map(({ inventory }) => inventory);
  const opWasm = collected.find(({ inventory }) => inventory.name === 'mikaki-worker.tar.gz')!.wasm;
  assert.ok(opWasm);
  assertCompiledProfile(opWasm, profile);
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
  const config = JSON.parse(
    (await regularFile(join(root, 'crates/worker/wrangler.production.jsonc'))).toString('utf8'),
  ) as { assets?: { directory: string } };
  const assets = config.assets
    ? (await collectFontAssets(root)).filter(
        (file) => profile === 'messaging-beta' || !file.name.startsWith('chat/'),
      )
    : undefined;
  if (config.assets) assert.equal(config.assets.directory, '../../assets');
  const messaging =
    profile === 'messaging-beta'
      ? await messagingQualification(root, source, releases, assets ?? [])
      : undefined;
  return {
    schema_version: 2,
    profile,
    source,
    archives: releases,
    migrations,
    ...(assets ? { assets } : {}),
    ...(messaging ? { messaging } : {}),
  };
}

async function messagingQualification(
  root: string,
  source: ReleaseSource,
  releases: ReleaseInventory['archives'],
  assets: NonNullable<ReleaseInventory['assets']>,
): Promise<MessagingQualification> {
  const q = JSON.parse(
    (
      await regularFile(join(root, 'artifacts/messaging-package/summary.json'), 1024 * 1024)
    ).toString('utf8'),
  ) as MessagingQualification;
  assert.equal(q.schema, 'mikaki-messaging-package-qualification-v2');
  assert.deepEqual(q.source, source, 'Chat qualification source differs');
  assert.equal(q.profile, 'messaging-beta');
  assert.deepEqual(q.runtime, {
    build_profile: 'messaging-beta',
    source_commit: source.commit,
    source_clean: source.clean,
  });
  assert.deepEqual(q.entrypoints, MESSAGING_PACKAGE_ENTRYPOINTS);
  assert.deepEqual(
    assets
      .filter((file) => file.name.startsWith('chat/'))
      .map((file) => file.name)
      .sort((a, b) => a.localeCompare(b)),
    ['chat/client.js', 'chat/crypto.wasm'],
  );
  const op = releases.find((file) => file.name === 'mikaki-worker.tar.gz')!;
  const expected = MESSAGING_PACKAGE_FILES.map((path) => {
    const value = path.startsWith('assets/')
      ? assets.find((file) => file.name === path.slice(7))
      : op.members.find(
          (file) => file.name === path.slice('crates/worker/build-messaging-beta/'.length),
        );
    assert.ok(value, `Missing qualified Chat file: ${path}`);
    return { path, ...value.digest };
  });
  assert.deepEqual(q.files, expected, 'Chat archive/assets differ from qualified bytes');
  assert.equal(q.upload.raw, workerBundleBytes(q.upload.modules, q.upload.entry));
  for (const file of q.upload.modules) assert.match(file.sha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(checkWorkerBundle('messaging-beta', q.upload.raw), []);
  return q;
}

/** Inventory every static font and its accompanying license before promotion. */
export async function collectFontAssets(root: string) {
  const files: { name: string; digest: Digest }[] = [];
  async function visit(directory: string) {
    for (const entry of (
      await readdir(join(root, 'assets', directory), { withFileTypes: true })
    ).sort((a, b) => a.name.localeCompare(b.name))) {
      const name = directory ? `${directory}/${entry.name}` : entry.name;
      assert.match(name, /^[a-zA-Z0-9_./-]+$/, 'Unexpected static asset path');
      assert.ok(!entry.isSymbolicLink(), 'Static assets must not be symlinks');
      if (entry.isDirectory()) await visit(name);
      else files.push({ name, digest: digest(await regularFile(join(root, 'assets', name))) });
    }
  }
  await visit('');
  assert.ok(
    files.some((file) => file.name === 'fonts/fonts.css'),
    'Font build required',
  );
  return files;
}
export async function verifyRelease(
  root: string,
  inventory: unknown,
  source: ReleaseSource,
  allowDirty = false,
  profile: ReleaseProfile = 'default',
): Promise<void> {
  assert.ok(source.clean || allowDirty, 'Release verification requires a clean source checkout');
  assert.deepEqual(
    inventory,
    await collectRelease(root, source, profile),
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
  const { profile, allowDirty, operands } = releaseArguments(flags);
  assert.equal(operands.length, 0);
  const root = fileURLToPath(new URL('../', import.meta.url));
  const source = releaseSource(root);
  assert.ok(
    source.clean || allowDirty,
    'Release creation/verification requires a clean source checkout',
  );
  const path = join(root, 'artifacts/release-manifest.json');
  if (action === 'create') {
    await mkdir(join(root, 'artifacts'), { recursive: true });
    await writeFile(
      path,
      JSON.stringify(await collectRelease(root, source, profile), null, 2) + '\n',
    );
  } else {
    const bytes = await regularFile(path, 1024 * 1024);
    await verifyRelease(root, JSON.parse(bytes.toString('utf8')), source, allowDirty, profile);
  }
  console.log(
    `Release ${action}: byte inventory ${source.clean ? 'clean' : 'LOCAL DIRTY'}; ${source.commit}`,
  );
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
