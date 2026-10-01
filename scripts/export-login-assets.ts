/** Capture the tested Worker's UI bytes for version-matched production smoke. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { releaseSource } from './release-inventory.ts';

const root = process.cwd();
const source = releaseSource(root);
assert.ok(source.clean, 'Login asset inventory requires clean source');
const harness = createTestHarness({
  root,
  workers: [{ configPath: `${root}/crates/worker/wrangler.jsonc` }],
});
try {
  await harness.listen();
  const worker = harness.getWorker('mikaki-op-worker');
  const version = (await (await worker.fetch('https://mikaki.test/version')).json()) as Record<
    string,
    unknown
  >;
  assert.equal(version.source_commit, source.commit);
  assert.equal(version.source_clean, true);
  const login: Record<string, string> = {};
  for (const extension of ['js', 'css']) {
    const response = await worker.fetch(`https://mikaki.test/login/login.${extension}`);
    assert.equal(response.status, 200);
    login[extension] = createHash('sha256')
      .update(Buffer.from(await response.arrayBuffer()))
      .digest('hex');
  }
  await writeFile('artifacts/login-assets.json', `${JSON.stringify({ source, login }, null, 2)}\n`);
} finally {
  await harness.close();
}
