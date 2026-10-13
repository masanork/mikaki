import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import {
  prepareCopyRuntimeRelease,
  verifyCopyRuntimeRelease,
} from './work-copy-runtime-release.ts';
import { verifyCopyRuntimePacket } from './work-copy-runtime-packet.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const hash = (b: Buffer) => createHash('sha256').update(b).digest('hex');
test('source-bound companion release preserves real bundle inputs and refuses archive/source/authority substitution', async (t) => {
  const parent = join(root, 'local/generated/copy-release-tests');
  await mkdir(parent, { recursive: true });
  const output = await mkdtemp(join(parent, 'release-'));
  try {
    const result = await prepareCopyRuntimeRelease(output);
    const manifestPath = join(output, 'work-copy-runtime-manifest.json');
    const archivePath = join(output, 'mikaki-work-copy-runtime.tar.gz');
    const original = await readFile(manifestPath);
    const archive = await readFile(archivePath);
    assert.equal(result.workers, 14);
    assert.equal(result.external_effects, false);
    const { directory: _directory, ...checked } = result;
    assert.deepEqual(await verifyCopyRuntimeRelease(output, result.manifest_sha256), checked);
    const materialized = await verifyCopyRuntimeRelease(output, result.manifest_sha256, output);
    assert.ok(materialized.directory);
    assert.equal(
      (await verifyCopyRuntimePacket(materialized.directory, materialized.runtime)).modules,
      14,
    );
    await t.test(
      'retained manifest pin and archive digest refuse changed bytes before extraction',
      async () => {
        const changed = Buffer.from(archive);
        changed[changed.length - 1] ^= 1;
        await writeFile(archivePath, changed);
        await assert.rejects(
          verifyCopyRuntimeRelease(output, result.manifest_sha256),
          /archive_changed/,
        );
        await writeFile(archivePath, archive);
        await writeFile(manifestPath, Buffer.concat([original, Buffer.from('\n')]));
        await assert.rejects(
          verifyCopyRuntimeRelease(output, result.manifest_sha256),
          /manifest_changed/,
        );
        await writeFile(manifestPath, original);
      },
    );
    await t.test(
      'changed source and relabelled execution cannot qualify even with a rewritten manifest pin',
      async () => {
        for (const patch of [
          { source_commit: '0'.repeat(40) },
          { execution_authorized: true },
          { stage: 'deployed-and-authorized' },
        ]) {
          const changed = Buffer.from(
            JSON.stringify({ ...JSON.parse(original.toString()), ...patch }),
          );
          await writeFile(manifestPath, changed);
          await assert.rejects(verifyCopyRuntimeRelease(output, hash(changed)));
        }
        await writeFile(manifestPath, original);
      },
    );
    await t.test('an archive link is refused before any file is materialized', async () => {
      const trap = await mkdtemp(join(parent, 'trap-'));
      try {
        await symlink('/etc/passwd', join(trap, 'manifest.json'));
        const linked = execFileSync('tar', ['-czf', '-', '-C', trap, 'manifest.json']);
        const manifest = JSON.parse(original.toString());
        manifest.archive.digest = { bytes: linked.length, sha256: hash(linked) };
        manifest.members = [
          { path: 'manifest.json', digest: { bytes: 0, sha256: '0'.repeat(64) } },
        ];
        const changed = Buffer.from(JSON.stringify(manifest));
        await writeFile(manifestPath, changed);
        await writeFile(archivePath, linked);
        await assert.rejects(
          verifyCopyRuntimeRelease(output, hash(changed)),
          /archive_link_denied/,
        );
      } finally {
        await rm(trap, { recursive: true, force: true });
      }
      await writeFile(manifestPath, original);
      await writeFile(archivePath, archive);
    });
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});
