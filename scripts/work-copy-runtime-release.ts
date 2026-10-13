/** Public CI companion bytes only. Authenticity requires the separate GitHub attestations. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { releaseSource } from './release-inventory.ts';
import { packetFile } from './work-authority-packet.ts';
import {
  COPY_PACKET_LIMITS,
  copyRuntimeInventory,
  prepareCopyRuntimePacket,
  verifyCopyRuntimePacket,
} from './work-copy-runtime-packet.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const archiveName = 'mikaki-work-copy-runtime.tar.gz';
const manifestName = 'work-copy-runtime-manifest.json';
const maximum = 70 * 1024 * 1024;
const hex = z.string().regex(/^[a-f0-9]{64}$/);
const digest = (bytes: Buffer) => ({
  bytes: bytes.length,
  sha256: createHash('sha256').update(bytes).digest('hex'),
});
const digestSchema = z.strictObject({
  bytes: z.number().int().nonnegative().max(maximum),
  sha256: hex,
});
const manifestSchema = z.strictObject({
  format_version: z.literal(1),
  kind: z.literal('mikaki-work-copy-runtime-release-candidate-v1'),
  stage: z.literal('verified-bytes-not-attestation-or-execution'),
  source_commit: z.string().regex(/^[a-f0-9]{40}$/),
  runtime: z.strictObject({
    source_commit: z.string().regex(/^[a-f0-9]{40}$/),
    manifest_sha256: hex,
  }),
  archive: z.strictObject({ name: z.literal(archiveName), digest: digestSchema }),
  members: z
    .array(z.strictObject({ path: z.string().regex(/^[A-Za-z0-9_@.\/-]+$/), digest: digestSchema }))
    .min(1)
    .max(COPY_PACKET_LIMITS.entries),
  external_effects: z.literal(false),
  execution_authorized: z.literal(false),
  ai_delegation_authorized: z.literal(false),
});
const decode = (bytes: Buffer): unknown =>
  JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
function tar(bytes: Buffer, args: string[], limit = maximum) {
  return execFileSync('tar', [args[0]!, '-f', '-', ...args.slice(1)], {
    input: bytes,
    maxBuffer: limit,
    timeout: 30_000,
  });
}
async function ignoredDirectory(input: string) {
  const directory = resolve(input);
  const inside = relative(root, directory);
  assert.ok(
    inside && !inside.startsWith('..') && !inside.startsWith('/'),
    'copy_release_output_denied',
  );
  execFileSync('git', ['check-ignore', '--quiet', directory], { cwd: root, stdio: 'pipe' });
  let ancestor = root;
  for (const part of inside.split('/')) {
    ancestor = join(ancestor, part);
    const stat = await lstat(ancestor).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error;
      return null;
    });
    if (stat)
      assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), 'copy_release_output_link_denied');
    else await mkdir(ancestor, { mode: 0o700 });
  }
  assert.equal(await realpath(directory), directory, 'copy_release_output_link_denied');
  return directory;
}
async function write(path: string, bytes: Buffer) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
}

export async function prepareCopyRuntimeRelease(output = join(root, 'artifacts')) {
  const source = releaseSource(root);
  assert.ok(source.clean, 'copy_release_source_dirty');
  const directory = await ignoredDirectory(output);
  const runtime = await prepareCopyRuntimePacket(
    join(root, 'local/generated/copy-runtime-release'),
  );
  try {
    const members = [
      {
        path: 'manifest.json',
        digest: digest(await packetFile(join(runtime.directory, 'manifest.json'), 256 * 1024)),
      },
      ...(await copyRuntimeInventory(runtime.directory)),
    ].sort((a, b) => a.path.localeCompare(b.path));
    const archive = execFileSync(
      'tar',
      ['-czf', '-', '-C', runtime.directory, '--', ...members.map((m) => m.path)],
      { maxBuffer: maximum, timeout: 30_000 },
    );
    await verifyCopyRuntimePacket(runtime.directory, runtime);
    assert.deepEqual(releaseSource(root), source, 'copy_release_source_changed');
    const manifest = manifestSchema.parse({
      format_version: 1,
      kind: 'mikaki-work-copy-runtime-release-candidate-v1',
      stage: 'verified-bytes-not-attestation-or-execution',
      source_commit: source.commit,
      runtime: { source_commit: runtime.source_commit, manifest_sha256: runtime.manifest_sha256 },
      archive: { name: archiveName, digest: digest(archive) },
      members,
      external_effects: false,
      execution_authorized: false,
      ai_delegation_authorized: false,
    });
    const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
    await write(join(directory, archiveName), archive);
    await write(join(directory, manifestName), manifestBytes);
    return {
      directory,
      ...(await verifyCopyRuntimeRelease(directory, digest(manifestBytes).sha256)),
    };
  } finally {
    await rm(runtime.directory, { recursive: true, force: true });
  }
}

export async function verifyCopyRuntimeRelease(
  directoryInput = join(root, 'artifacts'),
  expectedManifestSha256?: string,
  outputParent?: string,
) {
  const source = releaseSource(root);
  assert.ok(source.clean, 'copy_release_source_dirty');
  const directory = resolve(directoryInput);
  const manifestBytes = await packetFile(join(directory, manifestName), 256 * 1024);
  if (expectedManifestSha256)
    assert.equal(
      digest(manifestBytes).sha256,
      hex.parse(expectedManifestSha256),
      'copy_release_manifest_changed',
    );
  const manifest = manifestSchema.parse(decode(manifestBytes));
  assert.equal(manifest.source_commit, source.commit, 'copy_release_source_changed');
  assert.equal(
    manifest.runtime.source_commit,
    source.commit,
    'copy_release_runtime_source_changed',
  );
  const names = manifest.members.map((m) => m.path);
  assert.ok(
    names.every(
      (name) => !name.startsWith('/') && name.split('/').every((p) => p && p !== '.' && p !== '..'),
    ),
    'copy_release_member_path_denied',
  );
  assert.equal(new Set(names).size, names.length, 'copy_release_duplicate_member');
  assert.ok(
    manifest.members.reduce((n, m) => n + m.digest.bytes, 0) <= COPY_PACKET_LIMITS.bytes,
    'copy_release_total_limit',
  );
  const archive = await packetFile(join(directory, archiveName), maximum);
  assert.deepEqual(digest(archive), manifest.archive.digest, 'copy_release_archive_changed');
  assert.deepEqual(
    tar(archive, ['-tz'], 256 * 1024)
      .toString()
      .trim()
      .split('\n')
      .sort(),
    [...names].sort(),
    'copy_release_archive_members_changed',
  );
  assert.ok(
    tar(archive, ['-tvz'], 512 * 1024)
      .toString()
      .trim()
      .split('\n')
      .every((line) => line.startsWith('-')),
    'copy_release_archive_link_denied',
  );
  const temporary = await mkdtemp(
    join(
      await ignoredDirectory(join(root, 'local/generated/copy-runtime-release-verification')),
      'verified-',
    ),
  );
  try {
    for (const member of manifest.members) {
      const bytes = tar(archive, ['-xzO', '--', member.path], 16 * 1024 * 1024);
      assert.deepEqual(digest(bytes), member.digest, 'copy_release_member_changed');
      await write(join(temporary, member.path), bytes);
    }
    const checked = await verifyCopyRuntimePacket(temporary, manifest.runtime);
    assert.deepEqual(
      ['manifest.json', ...(await copyRuntimeInventory(temporary)).map((m) => m.path)].sort(),
      [...names].sort(),
      'copy_release_extra_member',
    );
    assert.deepEqual(releaseSource(root), source, 'copy_release_source_changed');
    let retained;
    if (outputParent) {
      assert.ok(expectedManifestSha256, 'copy_release_materialization_requires_retained_pin');
      const parent = await ignoredDirectory(outputParent);
      retained = await mkdtemp(join(parent, 'companions-'));
      await rename(temporary, retained);
    }
    return {
      ...(retained ? { directory: retained } : {}),
      manifest_sha256: digest(manifestBytes).sha256,
      source_commit: source.commit,
      runtime: manifest.runtime,
      archive: manifest.archive,
      workers: checked.modules,
      stage: manifest.stage,
      external_effects: false,
    };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [mode, expected, outputParent] = process.argv.slice(2);
    assert.ok(
      (mode === 'create' && process.argv.length === 3) ||
        (mode === 'verify' && process.argv.length <= 4) ||
        (mode === 'materialize' && process.argv.length === 5 && expected && outputParent),
    );
    console.log(
      JSON.stringify(
        mode === 'create'
          ? await prepareCopyRuntimeRelease()
          : await verifyCopyRuntimeRelease(undefined, expected, outputParent),
        null,
        2,
      ),
    );
  } catch {
    console.error(
      'Copy runtime release refused. Preserve the qualified source and externally retained manifest/attestation; no provider operation is issued.',
    );
    process.exitCode = 1;
  }
}
