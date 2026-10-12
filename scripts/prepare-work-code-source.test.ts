import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { gitFixture } from './work-git-fixture.ts';
import { localGit, inspectCodeSource } from './work-git-disclosure.ts';
import { prepareWorkCodeSource, verifyWorkCodeSource } from './prepare-work-code-source.ts';

test('code source snapshots preserve the selected tree and independently verify one reachable commit without earlier history', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'mikaki-code-source-'));
  try {
    const fixture = await gitFixture(
      parent,
      'original',
      { 'README.md': 'Current code\n' },
      'Historical content\n',
    );
    const result = await prepareWorkCodeSource(fixture.dir, fixture.commit, parent);
    assert.deepEqual(await verifyWorkCodeSource(result.directory, fixture.dir), {
      source: result.source,
      provenance: result.provenance,
    });
    assert.equal(result.source.tree, fixture.tree);
    assert.equal(result.source.code.commits, 1);
    assert.equal(result.provenance.original_history_included, false);
    const restored = join(parent, 'independent.git');
    execFileSync('git', ['clone', '--bare', join(result.directory, 'source.bundle'), restored], {
      stdio: 'pipe',
    });
    const checked = await inspectCodeSource({
      repository: result.source.repo_name,
      gitDir: restored,
      commit: result.source.commit,
    });
    assert.deepEqual(checked.commits, [result.source.commit]);
    assert.equal(checked.object_bytes, result.source.code.object_bytes);
    assert.equal(checked.tree, fixture.tree);
    assert.throws(() => localGit(restored, ['cat-file', '-e', fixture.commit]));
    assert.throws(() => localGit(restored, ['cat-file', '-e', fixture.parentCommit!]));
    assert.equal(
      localGit(restored, ['show', `${result.source.commit}:README.md`]).toString(),
      'Current code\n',
    );
    assert.deepEqual(
      JSON.parse(await readFile(join(result.directory, 'source.json'), 'utf8')),
      result.source,
    );
    const again = await prepareWorkCodeSource(fixture.dir, fixture.commit, parent);
    assert.deepEqual(again.source, result.source);
    await assert.rejects(prepareWorkCodeSource(fixture.dir, 'main', parent));
    await writeFile(
      join(result.directory, 'source.json'),
      JSON.stringify({ ...result.source, code: { ...result.source.code, object_bytes: 0 } }),
    );
    await assert.rejects(verifyWorkCodeSource(result.directory, fixture.dir));
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
