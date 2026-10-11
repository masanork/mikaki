import assert from 'node:assert/strict';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { localGit, prepareGitDisclosure } from './work-git-disclosure.ts';
import { gitFixture } from './work-git-fixture.ts';

test('Git disclosure copies exact selected blobs into one root without source refs/history', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'mikaki-disclosure-git-'));
  try {
    const code = await gitFixture(
      parent,
      'code',
      { 'README.md': 'A bounded public code example\n' },
      'Earlier public code\n',
    );
    const personal = await gitFixture(
      parent,
      'context',
      { 'writing.md': '結論から書く。\n', 'unselected.md': 'SYNTHETIC_UNSELECTED\n' },
      'SYNTHETIC_HISTORICAL_ONLY\n',
    );
    const codeSource = { repository: 'code', gitDir: code.dir, commit: code.commit };
    const selected = {
      repository: 'personal',
      gitDir: personal.dir,
      commit: personal.commit,
      paths: ['writing.md'],
    };
    const prepared = await prepareGitDisclosure(codeSource, [selected], parent, 'snapshot');
    assert.equal(prepared.input.code.commits.length, 2);
    assert.equal(prepared.input.contexts[0]!.files[0]!.content, '結論から書く。\n');
    assert.equal(
      localGit(prepared.gitDir, ['rev-list', '--all', '--count']).toString().trim(),
      '1',
    );
    const paths = localGit(prepared.gitDir, [
      'ls-tree',
      '-r',
      '--name-only',
      prepared.input.snapshot.commit,
    ])
      .toString()
      .trim();
    assert.equal(paths, 'context/00/writing.md');
    for (const absent of [
      personal.historicalBlob!,
      personal.parentCommit!,
      personal.blobs.get('unselected.md')!,
      code.commit,
    ])
      assert.throws(() => localGit(prepared.gitDir, ['cat-file', '-e', absent]));
    const again = await prepareGitDisclosure(codeSource, [selected], parent, 'other-snapshot');
    assert.equal(again.input.snapshot.commit, prepared.input.snapshot.commit);

    await t.test('selection, version, mode and source aliases fail closed', async () => {
      for (const paths of [
        ['writing.md', 'writing.md'],
        ['../writing.md'],
        ['missing.md'],
        ['.git/config'],
      ])
        await assert.rejects(
          prepareGitDisclosure(codeSource, [{ ...selected, paths }], parent, 'snapshot'),
        );
      await assert.rejects(
        prepareGitDisclosure(
          codeSource,
          [{ ...selected, gitDir: code.dir, commit: code.commit, paths: ['README.md'] }],
          parent,
          'snapshot',
        ),
      );
      await assert.rejects(
        prepareGitDisclosure({ ...codeSource, commit: 'main' }, [selected], parent, 'snapshot'),
      );
      const blob = personal.blobs.get('writing.md')!;
      localGit(personal.dir, ['update-index', '--cacheinfo', '120000', blob, 'writing.md']);
      const tree = localGit(personal.dir, ['write-tree']).toString().trim();
      const commit = localGit(personal.dir, ['commit-tree', tree], 'Symlink fixture\n', {
        GIT_AUTHOR_NAME: 'Fixture',
        GIT_AUTHOR_EMAIL: 'fixture@mikaki.invalid',
        GIT_COMMITTER_NAME: 'Fixture',
        GIT_COMMITTER_EMAIL: 'fixture@mikaki.invalid',
      })
        .toString()
        .trim();
      await assert.rejects(
        prepareGitDisclosure(codeSource, [{ ...selected, commit }], parent, 'snapshot'),
      );
    });
    await t.test('oversize, binary and LFS files are refused before copying', async () => {
      for (const content of [
        'x'.repeat(16385),
        '\0binary',
        'version https://git-lfs.github.com/spec/v1\n',
      ]) {
        const f = await gitFixture(parent, 'unsupported', { 'file.md': content });
        await assert.rejects(
          prepareGitDisclosure(
            codeSource,
            [{ repository: 'context', gitDir: f.dir, commit: f.commit, paths: ['file.md'] }],
            parent,
            'snapshot',
          ),
        );
      }
    });
    await t.test('shallow/grafted/alternate sources cannot claim complete history', async () => {
      for (const path of ['shallow', 'info/grafts', 'objects/info/alternates']) {
        const f = await gitFixture(parent, 'boundary', { 'file.md': 'text' });
        const target = join(f.dir, path);
        await mkdir(join(target, '..'), { recursive: true });
        await writeFile(target, f.commit + '\n');
        await assert.rejects(
          prepareGitDisclosure(
            { repository: 'code', gitDir: f.dir, commit: f.commit },
            [],
            parent,
            'snapshot',
          ),
        );
      }
    });
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
