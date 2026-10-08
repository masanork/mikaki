import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { preparationFixture } from './support/work-preparation-fixture.ts';
import { gitFixture } from '../../scripts/work-git-fixture.ts';
import { localGit, prepareGitDisclosure } from '../../scripts/work-git-disclosure.ts';
import {
  objectInventory,
  probeRemote,
  probeRepositoryAbsent,
  verifyGitReadback,
} from '../../scripts/work-artifacts-git.ts';

test('actual OP runtime shutdown/restart preserves dispatched preparation and cannot dispatch again', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-preparation-restart-'));
  let f: Awaited<ReturnType<typeof preparationFixture>> | undefined;
  try {
    const code = await gitFixture(
      directory,
      'code',
      { 'README.md': 'Synthetic code\n' },
      'Synthetic previous code\n',
    );
    const context = await gitFixture(
      directory,
      'context',
      { 'writing.md': 'Synthetic selected context\n', 'other.md': 'SYNTHETIC_UNSELECTED\n' },
      'SYNTHETIC_HISTORY\n',
    );
    const selected = await prepareGitDisclosure(
      { repository: 'code', gitDir: code.dir, commit: code.commit },
      [
        {
          repository: 'personal',
          gitDir: context.dir,
          commit: context.commit,
          paths: ['writing.md'],
        },
      ],
      directory,
      'snapshot',
    );
    f = await preparationFixture(directory);
    const p = await f.initialize(selected.input);
    assert.equal((await f.call({ action: 'dispatch-preparation', id: p.id })).started, true);
    await f.close();
    f = await preparationFixture(directory);
    const restored = await f.call({ action: 'get-preparation', id: p.id });
    assert.equal(restored.body, p.body);
    assert.equal(restored.digest, p.digest);
    assert.equal(restored.state, 'dispatched');
    assert.equal((await f.call({ action: 'dispatch-preparation', id: p.id })).started, false);
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) AS n FROM work_audit WHERE action='preparation.dispatch'",
      ).first('n'),
      1,
    );
    assert.equal(
      (await f.call({ action: 'cleanup-preparation', id: p.id })).state,
      'cleanup_pending',
    );
    const expected = objectInventory(selected.gitDir, selected.input.snapshot.commit);
    const clone = join(directory, 'independent-clone');
    localGit(directory, [
      '-c',
      'protocol.file.allow=always',
      'clone',
      '--bare',
      selected.gitDir,
      clone,
    ]);
    const evidence = verifyGitReadback(
      clone,
      selected.gitDir,
      selected.input.snapshot.commit,
      selected.input.snapshot.tree,
      'snapshot',
    );
    assert.equal(evidence.inventory_sha256, expected.sha256);
    assert.equal(evidence.commits, 1);
    for (const oid of [context.historicalBlob!, context.blobs.get('other.md')!, context.commit])
      assert.throws(() => localGit(clone, ['cat-file', '-e', oid]));
    localGit(clone, ['update-ref', 'refs/heads/unreviewed', selected.input.snapshot.commit]);
    assert.throws(
      () =>
        verifyGitReadback(
          clone,
          selected.gitDir,
          selected.input.snapshot.commit,
          selected.input.snapshot.tree,
          'snapshot',
        ),
      /probe_readback_mismatch/,
    );
    for (const name of ['mikaki', '../mikaki', 'wk-other-snapshot'])
      assert.throws(() => probeRemote(name), /invalid_probe_destination/);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
  } finally {
    await f?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('remote absence requires complete bounded pagination and rejects ambiguous inventory', async () => {
  const target = `wk-${'1'.repeat(32)}-snapshot`;
  const repository = (id: string, name: string) => ({
    id,
    name,
    description: null,
    defaultBranch: 'main',
    createdAt: '2026-10-07T00:00:00Z',
    updatedAt: '2026-10-07T00:00:00Z',
    lastPushAt: null,
    source: null,
    readOnly: false,
  });
  const baseline = repository('baseline', 'mikaki');
  assert.equal(
    await probeRepositoryAbsent({ list: async () => ({ repos: [baseline], total: 1 }) }, target),
    true,
  );
  assert.equal(
    await probeRepositoryAbsent(
      { list: async () => ({ repos: [repository('target', target)], total: 1 }) },
      target,
    ),
    false,
  );
  assert.equal(
    await probeRepositoryAbsent(
      {
        list: async ({ cursor } = {}) =>
          cursor
            ? { repos: [repository('other', 'other')], total: 2 }
            : { repos: [baseline], total: 2, cursor: 'next' },
      },
      target,
    ),
    true,
  );
  for (const list of [
    async () => ({ repos: [baseline], total: 2 }),
    async ({ cursor }: { cursor?: string } = {}) =>
      cursor
        ? { repos: [repository('other', 'other')], total: 3 }
        : { repos: [baseline], total: 2, cursor: 'next' },
    async ({ cursor }: { cursor?: string } = {}) =>
      cursor
        ? { repos: [repository('baseline', 'other')], total: 2 }
        : { repos: [baseline], total: 2, cursor: 'next' },
    async () => ({ repos: [], total: 513 }),
    async () => {
      throw new Error('transport_unavailable');
    },
  ])
    await assert.rejects(probeRepositoryAbsent({ list }, target));
});
