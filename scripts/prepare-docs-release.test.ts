import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
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
