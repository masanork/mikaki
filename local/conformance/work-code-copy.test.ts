/** Actual Native registration/composition + independently restored local Git; no provider writes. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSourceFixture } from './support/work-source-fixture.ts';
import { gitFixture } from '../../scripts/work-git-fixture.ts';
import { localGit } from '../../scripts/work-git-disclosure.ts';
import { prepareWorkCodeSource } from '../../scripts/prepare-work-code-source.ts';
import { prepareWorkCodeCopy } from '../../scripts/prepare-work-code-copy.ts';
import { loadGitRegistry } from '../../scripts/work-git-registry.ts';
import type { WorkDisclosure } from '../../crates/worker/ui/work-preparation-view.ts';

test('registered code-only Native review provisions the exact retained snapshot without original history or owner consent', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-code-copy-test-'));
  const f = await createSourceFixture(undefined, true, 'product', true, 3600, true);
  try {
    const original = await gitFixture(
      directory,
      'original',
      { 'README.md': 'Selected current code\n' },
      'Excluded historical contents\n',
    );
    const packet = await prepareWorkCodeSource(
      original.dir,
      original.commit,
      directory,
      'registered-code-snapshot',
      'physical-code-source',
    );
    const registered = await f.fixture.fetch('https://work.test/authority-fixture', {
      method: 'POST',
      body: JSON.stringify({
        action: 'register-source',
        source: packet.source,
        account: f.first.account,
        expected_epoch: 0,
        actor: 'code-copy-qualifier',
        reason: 'independently checked snapshot',
      }),
    });
    assert.equal(registered.status, 200, await registered.clone().text());
    const created = await f.http('/work/preparations', f.first, {
      method: 'POST',
      body: JSON.stringify({
        format_version: 1,
        code: { source_id: packet.source.source_id, source_revision: 1, access_revision: 1 },
        contexts: [],
        expires_at: Math.floor(Date.now() / 1000) + 600,
      }),
    });
    assert.equal(created.status, 200, await created.clone().text());
    const ack = (await created.json()) as { record: { disclosure_digest: string } };
    const projected = await f.http('/work/disclosures/' + ack.record.disclosure_digest);
    assert.equal(projected.status, 200);
    const { record: review } = (await projected.json()) as {
      record: {
        kind: 'disclosure';
        digest: string;
        manifest: WorkDisclosure;
        current_sources: true;
      };
    };
    assert.equal(review.manifest.code.repository, packet.source.source_id);
    assert.notEqual(packet.source.source_id, packet.source.repo_name);
    assert.deepEqual(review.manifest.contexts, []);

    // A mutable operator repository is not the retained source bundle. Inject
    // unrelated objects/refs there and prove they do not reach either copy.
    const injected = localGit(
      join(packet.directory, 'source.git'),
      ['hash-object', '-w', '--stdin'],
      'Unselected operator data\n',
    )
      .toString()
      .trim();
    localGit(join(packet.directory, 'source.git'), [
      'update-ref',
      'refs/heads/unselected',
      packet.source.commit,
    ]);
    const prepared = await prepareWorkCodeCopy(review, packet.directory, original.dir, directory);
    assert.deepEqual(
      JSON.parse(await readFile(join(prepared.directory, 'code-copy-receipt.json'), 'utf8')),
      prepared.codeCopyReceipt,
    );
    assert.equal(prepared.codeCopyReceipt.original_history_included, false);
    assert.equal(prepared.codeCopyReceipt.owner_consent_recorded, false);
    assert.equal(prepared.codeCopyReceipt.external_effects, 0);
    const loaded = await loadGitRegistry(prepared.directory, prepared.registry_sha256, directory);
    try {
      const [task, snapshot] = loaded.registered;
      assert.ok(task && snapshot);
      assert.equal(task.commit, packet.source.commit);
      assert.equal(
        localGit(task.gitDir, ['rev-list', '--count', task.commit]).toString().trim(),
        '1',
      );
      assert.equal(
        localGit(task.gitDir, ['show', task.commit + ':README.md']).toString(),
        'Selected current code\n',
      );
      assert.equal(localGit(snapshot.gitDir, ['ls-tree', '-r', snapshot.commit]).length, 0);
      for (const repository of [task, snapshot])
        for (const oid of [
          original.commit,
          original.parentCommit!,
          original.historicalBlob!,
          injected,
        ])
          assert.throws(() => localGit(repository.gitDir, ['cat-file', '-e', oid]));
    } finally {
      await loaded.close();
    }
    for (const table of [
      'source_reader_calls',
      'work_copy_consent',
      'work_credential_attempt',
      'work_grant',
      'work_run',
    ])
      assert.equal(Number(await f.DB.prepare('SELECT count(*) AS n FROM ' + table).first('n')), 0);

    await t.test(
      'stale or mismatched Native source facts cannot provision the packet',
      async () => {
        for (const altered of [
          { ...review, current_sources: false },
          { ...review, manifest: { ...review.manifest, expires_at: 1 } },
          {
            ...review,
            manifest: {
              ...review.manifest,
              code: { ...review.manifest.code, commit: original.commit },
            },
          },
          {
            ...review,
            manifest: {
              ...review.manifest,
              registered_sources: [
                { ...review.manifest.registered_sources[0], source_revision: 2 },
              ],
            },
          },
          {
            ...review,
            manifest: { ...review.manifest, code: { ...review.manifest.code, head_files: 0 } },
          },
        ])
          await assert.rejects(
            prepareWorkCodeCopy(altered, packet.directory, original.dir, directory),
          );
      },
    );
    await t.test(
      'a current context-bearing disclosure cannot use the code-only bridge',
      async () => {
        const response = await f.http('/work/preparations', f.first, {
          method: 'POST',
          body: JSON.stringify({
            format_version: 1,
            code: { source_id: packet.source.source_id, source_revision: 1, access_revision: 1 },
            contexts: [f.input()],
            expires_at: Math.floor(Date.now() / 1000) + 600,
          }),
        });
        assert.equal(response.status, 200, await response.clone().text());
        const ack = (await response.json()) as { record: { disclosure_digest: string } };
        const projected = await f.http('/work/disclosures/' + ack.record.disclosure_digest);
        assert.equal(projected.status, 200);
        const { record } = (await projected.json()) as { record: unknown };
        await assert.rejects(
          prepareWorkCodeCopy(record, packet.directory, original.dir, directory),
        );
      },
    );
  } finally {
    await f.close();
    await rm(directory, { recursive: true, force: true });
  }
});
