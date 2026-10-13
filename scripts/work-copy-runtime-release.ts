/** Package/recheck companion bytes for CI attestation. This grants no deployment or copy authority. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { lstat, mkdir, mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { packetFile } from './work-authority-packet.ts';
import { releaseSource } from './release-inventory.ts';
import {
  COPY_PACKET_LIMITS,
  copyRuntimeInventory,
  prepareCopyRuntimePacket,
  verifyCopyRuntimePacket,
  type CopyRuntimeReceipt,
} from './work-copy-runtime-packet.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const archiveName = 'mikaki-work-copy-runtime.tar.gz';
const hex = z.string().regex(/^[a-f0-9]{64}$/);
const receiptSchema = z.strictObject({
  kind: z.literal('mikaki-work-copy-runtime-release-v1'),
  source_commit: z.string().regex(/^[a-f0-9]{40}$/),
  manifest_sha256: hex,
  archive: z.strictObject({
    name: z.literal(archiveName),
    bytes: z.number().int().positive().max(COPY_PACKET_LIMITS.bytes),
    sha256: hex,
  }),
  modules: z.literal(14),
  provenance: z.literal('release-candidate-bytes-requiring-trusted-attestation'),
  execution_authorized: z.literal(false),
});
const digest = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const decode = (bytes: Buffer): unknown =>
  JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
async function exclusiveDirectory(input: string) {
  const directory = resolve(input);
  assert.ok(
    ['artifacts', 'local/generated'].some((base) => {
      const path = relative(join(root, base), directory);
      return path && !path.startsWith('..') && !path.startsWith('/');
    }),
    'copy_release_output_denied',
  );
  let ancestor = root;
  for (const part of relative(root, dirname(directory)).split('/')) {
    ancestor = join(ancestor, part);
    const info = await lstat(ancestor).catch((e: NodeJS.ErrnoException) => {
      if (e.code !== 'ENOENT') throw e;
      return null;
    });
    if (info)
      assert.ok(info.isDirectory() && !info.isSymbolicLink(), 'copy_release_output_link_denied');
    else await mkdir(ancestor, { mode: 0o700 });
  }
  execFileSync('git', ['check-ignore', '--quiet', directory], { cwd: root, stdio: 'pipe' });
  await mkdir(directory, { mode: 0o700 });
  return directory;
}

export async function packageCopyRuntimeRelease(
  runtimeInput: string,
  expected: CopyRuntimeReceipt,
  output: string,
) {
  const runtime = resolve(runtimeInput);
  const checked = await verifyCopyRuntimePacket(runtime, expected);
  const inventory = await copyRuntimeInventory(runtime);
  const directory = await exclusiveDirectory(output);
  const archive = join(directory, archiveName);
  execFileSync(
    'tar',
    [
      '--format=ustar',
      '-czf',
      archive,
      '-C',
      runtime,
      '--',
      'manifest.json',
      ...inventory.map((member) => member.path),
    ],
    {
      env: { ...process.env, COPYFILE_DISABLE: '1' },
      stdio: 'pipe',
      timeout: 30000,
      maxBuffer: 1024 * 1024,
    },
  );
  const bytes = await packetFile(archive, COPY_PACKET_LIMITS.bytes);
  const receipt = receiptSchema.parse({
    kind: 'mikaki-work-copy-runtime-release-v1',
    ...expected,
    archive: { name: archiveName, bytes: bytes.length, sha256: digest(bytes) },
    modules: checked.modules,
    provenance: 'release-candidate-bytes-requiring-trusted-attestation',
    execution_authorized: false,
  });
  const receiptBytes = Buffer.from(JSON.stringify(receipt, null, 2) + '\n');
  await writeFile(join(directory, 'release.json'), receiptBytes, { flag: 'wx', mode: 0o600 });
  await verifyCopyRuntimeRelease(directory, digest(receiptBytes), expected.source_commit);
  return { directory, release_sha256: digest(receiptBytes), ...receipt };
}

export async function verifyCopyRuntimeRelease(
  input: string,
  expectedRelease: string,
  expectedSource: string,
) {
  const directory = resolve(input);
  assert.equal(await realpath(directory), directory, 'copy_release_directory_link_denied');
  assert.deepEqual(
    (await readdir(directory)).sort(),
    [archiveName, 'release.json'].sort(),
    'copy_release_extra_member',
  );
  for (const name of [archiveName, 'release.json']) {
    const s = await lstat(join(directory, name));
    assert.ok(s.isFile() && s.nlink === 1, 'copy_release_file_denied');
  }
  const receiptBytes = await packetFile(join(directory, 'release.json'), 16384);
  assert.equal(digest(receiptBytes), hex.parse(expectedRelease), 'copy_release_receipt_changed');
  const receipt = receiptSchema.parse(decode(receiptBytes));
  assert.equal(receipt.source_commit, expectedSource, 'copy_release_source_changed');
  const archive = await packetFile(join(directory, archiveName), COPY_PACKET_LIMITS.bytes);
  assert.equal(archive.length, receipt.archive.bytes, 'copy_release_archive_changed');
  assert.equal(digest(archive), receipt.archive.sha256, 'copy_release_archive_changed');
  const tar = gunzipSync(archive, { maxOutputLength: COPY_PACKET_LIMITS.bytes + 1024 * 1024 });
  const command = (args: string[]) =>
    execFileSync('tar', args, {
      input: tar,
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 30000,
      maxBuffer: 256 * 1024,
    });
  const names = command(['-tf', '-']).toString('utf8').trimEnd().split('\n');
  assert.ok(
    names.length > 0 &&
      names.length <= COPY_PACKET_LIMITS.entries &&
      new Set(names).size === names.length,
    'copy_release_members_denied',
  );
  for (const name of names)
    assert.ok(
      /^[A-Za-z0-9_@.\/-]+$/.test(name) &&
        !name.startsWith('/') &&
        name.split('/').every((part) => part && part !== '.' && part !== '..'),
      'copy_release_path_denied',
    );
  const types = command(['-tvf', '-']).toString('utf8').trimEnd().split('\n');
  assert.equal(types.length, names.length, 'copy_release_members_denied');
  assert.ok(
    types.every((line) => line.startsWith('-')),
    'copy_release_links_denied',
  );
  // Extraction follows bounded decompression and complete regular-member/path checks.
  const parent = join(root, 'local/generated/work-copy-release-verification');
  await mkdir(parent, { recursive: true, mode: 0o700 });
  assert.equal(await realpath(parent), parent, 'copy_release_scratch_link_denied');
  const restored = await mkdtemp(join(parent, 'runtime-'));
  try {
    command(['-xf', '-', '-C', restored, '--no-same-owner', '--no-same-permissions']);
    const checked = await verifyCopyRuntimePacket(restored, {
      source_commit: receipt.source_commit,
      manifest_sha256: receipt.manifest_sha256,
    });
    const inventory = await copyRuntimeInventory(restored);
    assert.deepEqual(
      [...names].sort(),
      ['manifest.json', ...inventory.map((member) => member.path)].sort(),
      'copy_release_members_denied',
    );
    return {
      ...checked,
      release_sha256: expectedRelease,
      archive: receipt.archive,
      authenticity_verified: false,
      execution_authorized: false,
    };
  } finally {
    await rm(restored, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [action, ...args] = process.argv.slice(2);
    let result;
    if (action === 'create' && args.length === 1) {
      const source = releaseSource(root);
      assert.equal(source.clean, true, 'copy_release_source_dirty');
      const runtime = await prepareCopyRuntimePacket(
        join(root, 'local/generated/work-copy-release-build'),
      );
      result = await packageCopyRuntimeRelease(
        runtime.directory,
        { source_commit: runtime.source_commit, manifest_sha256: runtime.manifest_sha256 },
        args[0]!,
      );
      assert.deepEqual(releaseSource(root), source, 'copy_release_source_changed');
    } else {
      assert.ok(action === 'verify' && args.length === 3);
      result = await verifyCopyRuntimeRelease(args[0]!, args[1]!, args[2]!);
    }
    console.log(JSON.stringify(result, null, 2));
  } catch {
    console.error(
      'Copy runtime release refused. Keep the exact receipt/archive/source and verify trusted CI attestation separately.',
    );
    process.exitCode = 1;
  }
}
