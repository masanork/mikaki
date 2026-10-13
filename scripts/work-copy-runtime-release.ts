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
// Accept only the regular USTAR records emitted by our packer. No archive
// interpreter applies ownership, modes, link targets, sparse maps or extensions.
function regularUstarMembers(tar: Buffer) {
  const members: { path: string; bytes: Buffer }[] = [];
  const names = new Set<string>();
  const octal = (field: Buffer) => {
    const value = field.toString('ascii').replace(/\0.*$/, '').trim();
    assert.match(value, /^[0-7]+$/, 'copy_release_header_denied');
    const number = Number.parseInt(value, 8);
    assert.ok(Number.isSafeInteger(number), 'copy_release_header_denied');
    return number;
  };
  const field = (bytes: Buffer) => {
    const end = bytes.indexOf(0);
    if (end >= 0)
      assert.ok(
        bytes.subarray(end).every((byte) => byte === 0),
        'copy_release_header_denied',
      );
    return new TextDecoder('utf-8', { fatal: true }).decode(
      end < 0 ? bytes : bytes.subarray(0, end),
    );
  };
  let offset = 0;
  for (;;) {
    assert.ok(offset + 512 <= tar.length, 'copy_release_truncated');
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      assert.ok(
        tar.length - offset >= 1024 && tar.subarray(offset).every((byte) => byte === 0),
        'copy_release_trailing_data',
      );
      break;
    }
    assert.equal(
      header.subarray(257, 265).toString('hex'),
      '7573746172003030',
      'copy_release_header_denied',
    );
    assert.ok(header[156] === 48 || header[156] === 0, 'copy_release_links_denied');
    assert.equal(
      octal(header.subarray(148, 156)),
      header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0),
      'copy_release_checksum_denied',
    );
    const prefix = field(header.subarray(345, 500));
    const name = field(header.subarray(0, 100));
    const path = prefix ? `${prefix}/${name}` : name;
    assert.ok(
      /^[A-Za-z0-9_@.\/-]+$/.test(path) &&
        !path.startsWith('/') &&
        path.split('/').every((part) => part && part !== '.' && part !== '..') &&
        path.split('/').length <= COPY_PACKET_LIMITS.depth,
      'copy_release_path_denied',
    );
    assert.ok(
      !names.has(path) && members.length < COPY_PACKET_LIMITS.entries,
      'copy_release_members_denied',
    );
    names.add(path);
    const size = octal(header.subarray(124, 136));
    assert.ok(size <= 16 * 1024 * 1024, 'copy_release_file_limit');
    const next = offset + 512 + Math.ceil(size / 512) * 512;
    assert.ok(next <= tar.length, 'copy_release_truncated');
    members.push({ path, bytes: tar.subarray(offset + 512, offset + 512 + size) });
    offset = next;
  }
  assert.ok(members.length > 0, 'copy_release_members_denied');
  return members;
}
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
  const records = regularUstarMembers(tar);
  const names = records.map((record) => record.path);
  const parent = join(root, 'local/generated/work-copy-release-verification');
  let ancestor = root;
  for (const part of relative(root, parent).split('/')) {
    ancestor = join(ancestor, part);
    const info = await lstat(ancestor).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error;
      return null;
    });
    if (info)
      assert.ok(info.isDirectory() && !info.isSymbolicLink(), 'copy_release_scratch_link_denied');
    else await mkdir(ancestor, { mode: 0o700 });
  }
  assert.equal(await realpath(parent), parent, 'copy_release_scratch_link_denied');
  const restored = await mkdtemp(join(parent, 'runtime-'));
  try {
    for (const record of records) {
      const path = join(restored, record.path);
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await writeFile(path, record.bytes, { flag: 'wx', mode: 0o600 });
    }
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
