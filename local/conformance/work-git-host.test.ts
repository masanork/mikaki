/** Native projections + real Git indexing and private Linux HTTP; no provider writes. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile, readdir, writeFile, symlink, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { copyJobFixture } from './support/work-copy-job-fixture.ts';
import { materializeGitRegistry, loadGitRegistry } from '../../scripts/work-git-registry.ts';
import { prepareGitHostImage } from '../../scripts/prepare-work-git-host.ts';
import { localGit } from '../../scripts/work-git-disclosure.ts';
import { gitHostServer } from '../../scripts/work-git-host-server.ts';

test('sealed Native selection cold-starts with exact history and no unselected context', async (t) => {
  const f = await copyJobFixture({ LOCAL_COPY_TRIGGER_DISABLED: 'true' });
  try {
    const sealed = await materializeGitRegistry(f.nativeDisclosure, f.sourceBindings, f.directory);
    assert.deepEqual((await readdir(sealed.directory)).sort(), [
      'registry.json',
      'snapshot.pack',
      'task.pack',
    ]);
    for (let restart = 0; restart < 2; restart++) {
      const loaded = await loadGitRegistry(sealed.directory, sealed.registry_sha256, f.directory);
      try {
        const task = loaded.registered[0]!,
          snapshot = loaded.registered[1]!;
        assert.equal(
          localGit(task.gitDir, ['rev-list', task.commit, '--count']).toString().trim(),
          '2',
        );
        assert.equal(
          localGit(snapshot.gitDir, ['rev-list', snapshot.commit, '--count']).toString().trim(),
          '1',
        );
        assert.equal(
          localGit(snapshot.gitDir, ['ls-tree', '-r', '--name-only', snapshot.commit])
            .toString()
            .trim(),
          'context/00/selected.md',
        );
        assert.equal(
          localGit(snapshot.gitDir, [
            'show',
            snapshot.commit + ':context/00/selected.md',
          ]).toString(),
          'Selected context\n',
        );
        for (const object of [
          f.sourceObjects.personal.parentCommit!,
          f.sourceObjects.personal.historicalBlob!,
          f.sourceObjects.personal.blobs.get('private.md')!,
          f.sourceObjects.code.commit,
        ])
          assert.throws(() => localGit(snapshot.gitDir, ['cat-file', '-e', object]));
      } finally {
        await loaded.close();
      }
    }
    await t.test(
      'changed source versions, history and planned snapshot fail before registration',
      async () => {
        for (const field of [
          'tree',
          'history_digest',
          'objects',
          'object_bytes',
          'head_files',
        ] as const) {
          const changed = structuredClone(f.nativeDisclosure);
          changed.manifest.code[field] =
            typeof changed.manifest.code[field] === 'number'
              ? changed.manifest.code[field] + 1
              : '0'.repeat(changed.manifest.code[field].length);
          await assert.rejects(materializeGitRegistry(changed, f.sourceBindings, f.directory));
        }
        const changed = structuredClone(f.nativeDisclosure);
        changed.manifest.snapshot.commit = '0'.repeat(40);
        await assert.rejects(materializeGitRegistry(changed, f.sourceBindings, f.directory));
        changed.manifest.snapshot.commit = f.nativeDisclosure.manifest.snapshot.commit;
        changed.manifest.contexts[0].files[0].sha256 = '0'.repeat(64);
        await assert.rejects(materializeGitRegistry(changed, f.sourceBindings, f.directory));
        await assert.rejects(
          materializeGitRegistry(
            f.nativeDisclosure,
            f.sourceBindings.map((s) => ({ ...s, access_revision: 2 })),
            f.directory,
          ),
        );
        await assert.rejects(
          materializeGitRegistry(
            { ...f.nativeDisclosure, current_sources: false },
            f.sourceBindings,
            f.directory,
          ),
        );
        await assert.rejects(
          materializeGitRegistry(
            f.nativeDisclosure,
            [f.sourceBindings[0], f.sourceBindings[0]],
            f.directory,
          ),
        );
      },
    );
    await t.test(
      'wrong registry pin, tampered pack and symlinked source package fail closed',
      async () => {
        await assert.rejects(loadGitRegistry(sealed.directory, '0'.repeat(64), f.directory));
        const path = join(sealed.directory, 'snapshot.pack'),
          original = await readFile(path);
        const changed = Buffer.from(original);
        changed[20] = changed[20]! ^ 1;
        await writeFile(path, changed);
        await assert.rejects(
          loadGitRegistry(sealed.directory, sealed.registry_sha256, f.directory),
        );
        await writeFile(path, original);
        const other = join(f.directory, 'synthetic-linked-pack');
        await writeFile(other, original);
        await rm(path);
        await symlink(other, path);
        await assert.rejects(
          loadGitRegistry(sealed.directory, sealed.registry_sha256, f.directory),
        );
        await rm(path);
        await writeFile(path, original);
      },
    );
    await t.test(
      'private listener serves readiness and refuses public/configuration input',
      async () => {
        let exchanges = 0;
        const host = await gitHostServer(
          {
            account: 'a'.repeat(32),
            namespace: 'mikaki-dev',
            authority: 'synthetic-managed-work',
            directory: sealed.directory,
            registrySha256: sealed.registry_sha256,
            temporaryParent: f.directory,
          },
          async () => {
            exchanges++;
            throw new Error('synthetic lost Git reply');
          },
        );
        try {
          await new Promise<void>((resolve) => host.server.listen(0, '127.0.0.1', resolve));
          const address = host.server.address();
          assert.ok(address && typeof address !== 'string');
          const base = `http://127.0.0.1:${address.port}`;
          assert.deepEqual(await (await fetch(base + '/ready')).json(), {
            registry_sha256: sealed.registry_sha256,
            disclosure_digest: sealed.registry.disclosure_digest,
          });
          for (const path of ['/', '/register', '/git-execute?retry=true']) {
            const r = await fetch(base + path, { method: 'POST' });
            assert.equal(r.status, 404);
            await r.text();
          }
          for (const body of ['{}', 'x'.repeat(4097)]) {
            const r = await fetch(base + '/git-execute', {
              method: 'POST',
              headers: {
                Authorization: 'Bearer SYNTHETIC_PRIVATE_SECRET',
                'Content-Type': 'application/json',
              },
              body,
            });
            assert.equal(r.status, 409);
            assert.doesNotMatch(await r.text(), /SECRET|token|\/tmp/);
          }
          const expires = Math.floor(Date.now() / 1000) + 120;
          const p = {
            format_version: 1,
            effect: 'git.upload',
            attempt_id: 'm'.repeat(43),
            digest: 'd'.repeat(64),
            namespace: 'mikaki-dev',
            name: `wk-${'e'.repeat(32)}-code`,
            role: 'task',
            deadline: expires,
            checkpoint: {
              authority: 'synthetic-managed-work',
              epoch: 'a'.repeat(64),
              sequence: 0,
              tip: 'b'.repeat(64),
            },
            artifacts_account: 'a'.repeat(32),
            purpose: 'upload',
            scope: 'write',
            repo_id: 'repo',
            initial_attempt_id: 'i'.repeat(43),
            key_version: 1,
            key_fingerprint: 'f'.repeat(64),
            preparation_digest: 'c'.repeat(64),
            disclosure_digest: sealed.registry.disclosure_digest,
            commit: sealed.registry.entries[0].commit,
            tree: sealed.registry.entries[0].tree,
            branch: 'work',
            observation: { repo_id: 'repo', token_id: 'mint', scope: 'write', expires_at: expires },
          };
          for (const attempt_id of ['m'.repeat(43), 'm'.repeat(43), 'n'.repeat(43)]) {
            const r = await fetch(base + '/git-execute', {
              method: 'POST',
              headers: {
                Authorization: 'Bearer SYNTHETIC_PRIVATE_SECRET',
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({ ...p, attempt_id }),
            });
            assert.equal(r.status, 409);
            await r.text();
          }
          assert.equal(exchanges, 1);
        } finally {
          await host.close();
        }
      },
    );
    await t.test(
      'image context contains the trusted program while source packs stay separate',
      async () => {
        const image = await prepareGitHostImage(f.nativeDisclosure, f.sourceBindings, f.directory);
        assert.deepEqual((await readdir(image.image)).sort(), ['Dockerfile', 'host.mjs']);
        assert.equal(image.registry_sha256, sealed.registry_sha256);
        assert.ok((await readFile(join(image.image, 'host.mjs'))).length > 1000);
        assert.doesNotMatch(
          await readFile(join(image.directory, 'image-receipt.json'), 'utf8'),
          /SECRET|selected\.md|gitDir/,
        );
      },
    );
  } finally {
    await f.close();
  }
});

test('one approved Workflow copies and verifies through the sealed HTTP Git host', async () => {
  const f = await copyJobFixture({}, { sealedHost: true });
  try {
    assert.equal((await f.approve()).status, 200);
    assert.equal((await f.start()).status, 200);
    const end = await f.settled();
    assert.equal(end.job.state, 'verified');
    assert.equal(end.job.next_step, 19);
    const remote = await f.remote();
    assert.equal(remote.counts.create, 2);
    assert.equal(remote.counts.mint, 4);
    assert.ok(remote.repos.every((r: any) => r.tokens.every((t: any) => t.state !== 'active')));
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) FROM work_credential_attempt WHERE state='closed' AND confirmation='refused' AND envelope IS NULL",
      ).first('count(*)'),
      6,
    );
    assert.equal((await f.start()).status, 409);
    assert.equal((await f.copy()).body.record.job.state, 'verified');
    assert.deepEqual((await f.remote()).counts, remote.counts);
    for (const table of ['work_request', 'work_prepared_task', 'work_grant', 'work_run'])
      assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM ' + table).first('n'), 0);
  } finally {
    await f.close();
  }
});
