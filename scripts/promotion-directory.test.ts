import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promotionDirectory } from './prepare-release-upload.ts';

test('promotion inputs reject sibling prefixes, nested paths and symlink escapes before reading manifests', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mikaki-promotion-test-'));
  try {
    const valid = join(root, 'artifacts/promotion-Ab12cd');
    await mkdir(valid, { recursive: true });
    assert.equal(await promotionDirectory(root, valid), valid);
    const alternative = join(root, 'artifacts/promotion-Kl78mn');
    await mkdir(alternative);
    assert.equal(await promotionDirectory(root, alternative), alternative);
    assert.equal(await promotionDirectory(root, valid), valid);
    await assert.rejects(
      promotionDirectory(root, join(root, 'artifacts/promotion-Zz99zz')),
      /Invalid promotion directory/,
    );
    for (const path of [
      join(root, 'artifacts/promotion-Ab12cd/checkpoint'),
      join(root, 'artifacts/promotion-Ab12cd-extra'),
      join(root, 'artifacts/promotion-Ab12cd/../outside'),
      join(root, 'artifacts/promotion-Ab12cd\n'),
      join(root, 'artifacts-elsewhere/promotion-Ab12cd'),
    ]) {
      await mkdir(path, { recursive: true });
      await assert.rejects(promotionDirectory(root, path), /Invalid promotion directory/);
    }
    await mkdir(join(root, 'outside'));
    const link = join(root, 'artifacts/promotion-Ef34gh');
    await symlink(join(root, 'outside'), link, 'dir');
    await assert.rejects(promotionDirectory(root, link), /symlinks/);
    const file = join(root, 'artifacts/promotion-Ij56kl');
    await writeFile(file, 'not a directory');
    await assert.rejects(promotionDirectory(root, file), /directory/);
    await rm(join(root, 'artifacts'), { recursive: true });
    await symlink(join(root, 'outside'), join(root, 'artifacts'), 'dir');
    await mkdir(join(root, 'outside/promotion-Ab12cd'));
    await assert.rejects(promotionDirectory(root, valid), /symlinks/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
