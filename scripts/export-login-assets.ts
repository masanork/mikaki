/** Capture the tested Worker's UI bytes for version-matched production smoke. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { releaseSource } from './release-inventory.ts';
import { releaseArguments } from './release-profile.ts';
import { parse } from 'jsonc-parser';

const root = process.cwd();
const source = releaseSource(root);
const { profile, allowDirty, operands } = releaseArguments(process.argv.slice(2));
assert.ok(!allowDirty && operands.length === 0);
assert.ok(source.clean, 'Login asset inventory requires clean source');
const config = parse(await readFile(`${root}/crates/worker/wrangler.jsonc`, 'utf8'));
config.main = `${root}/crates/worker/${profile === 'default' ? 'build' : 'build-messaging-beta'}/worker/service.mjs`;
config.assets.directory = `${root}/assets`;
config.d1_databases[0].migrations_dir = `${root}/crates/worker/migrations`;
const harness = createTestHarness({
  root,
  workers: [{ config }],
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
  assert.equal(version.build_profile, profile);
  const login: Record<string, string> = {};
  for (const extension of ['js', 'css']) {
    const response = await worker.fetch(`https://mikaki.test/login/login.${extension}`);
    assert.equal(response.status, 200);
    login[extension] = createHash('sha256')
      .update(Buffer.from(await response.arrayBuffer()))
      .digest('hex');
  }
  await writeFile(
    'artifacts/login-assets.json',
    `${JSON.stringify({ source, profile, login }, null, 2)}\n`,
  );
} finally {
  await harness.close();
}
