import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import { workStoreFixture } from './support/work-store-fixture.ts';
import { gitFixture } from '../../scripts/work-git-fixture.ts';
import { prepareGitDisclosure, localGit } from '../../scripts/work-git-disclosure.ts';
import {
  prepareCandidatePayload,
  restoreCandidatePayload,
} from '../../scripts/work-candidate-payload.ts';

const receipt = '3'.repeat(64);
async function fixture(throughMigration?: string) {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-candidate-payload-'));
  let op = await workStoreFixture(directory);
  try {
    const code = await gitFixture(
      directory,
      'code',
      { 'README.md': 'Base code\n' },
      'Retained code history\n',
    );
    const selected = await prepareGitDisclosure(
      { repository: 'code', gitDir: code.dir, commit: code.commit },
      [],
      directory,
      'snapshot',
    );
    const p = await op.initialize(selected.input, throughMigration);
    await op.call({ action: 'dispatch-preparation', id: p.id });
    await op.call({
      action: 'verify-preparation',
      id: p.id,
      preparation_evidence: {
        for_operation: p.id,
        task_repo_id: 'actual-task',
        snapshot_repo_id: 'actual-snapshot',
        payload_receipt: '1'.repeat(64),
        credential_receipt: '2'.repeat(64),
      },
    });
    await op.call({ action: 'materialize-preparation', id: p.id });
    const plan = JSON.parse(p.body).data.plan;
    const request = {
      profile: 'mikaki-managed-work-v1',
      request_id: 'payload-work',
      revision: 1,
      goal: 'Preserve candidate',
      acceptance: 'Restore exact Git graph',
      code_repository: 'code',
      base_commit: code.commit,
      disclosure_digest: plan.binding.disclosure,
      recipient: 'launcher-client',
      workload: 'managed-agent',
      task_repository: 'synthetic-task',
      adoption_repository: 'field',
      adoption_ref: 'refs/heads/trial',
      expected_head: code.commit,
      operations: ['repo.proposal.submit'],
      deadline: plan.binding.expires_at - 60,
    };
    const w = await op.call({ action: 'prepared-request', request });
    await op.call({ action: 'grant', id: 'grant', digest: w.digest });
    await op.call({ action: 'run', grant: 'grant', run: 'run' });
    const blob = localGit(code.dir, ['hash-object', '-w', '--stdin'], 'Proposed code\n')
      .toString()
      .trim();
    localGit(code.dir, ['update-index', '--cacheinfo', '100644', blob, 'README.md']);
    const tree = localGit(code.dir, ['write-tree']).toString().trim();
    const commit = localGit(code.dir, ['commit-tree', tree, '-p', code.commit], 'Candidate\n', {
      GIT_AUTHOR_NAME: 'Fixture',
      GIT_AUTHOR_EMAIL: 'fixture@mikaki.invalid',
      GIT_COMMITTER_NAME: 'Fixture',
      GIT_COMMITTER_EMAIL: 'fixture@mikaki.invalid',
    })
      .toString()
      .trim();
    const extra = localGit(
      code.dir,
      ['hash-object', '-w', '--stdin'],
      'EXCLUDED private unrelated object\n',
    )
      .toString()
      .trim();
    localGit(code.dir, ['update-ref', 'refs/tags/private-extra', extra]);
    const candidate = await op.call({
      action: 'candidate',
      grant: 'grant',
      run: 'run',
      candidate: { commit, tree, evidence: 'c'.repeat(64) },
    });
    const packed = await prepareCandidatePayload(
      { repository: 'synthetic-task', gitDir: code.dir, commit },
      tree,
      code.commit,
      directory,
    );
    const call: typeof op.call = (...args) => op.call(...args);
    const reserve = (status = 200, facts = packed.facts) =>
      call(
        { action: 'reserve-candidate-payload', digest: candidate.digest, payload: facts },
        status,
      );
    const retain = (status = 200, bytes = packed.bytes) =>
      call(
        {
          action: 'retain-candidate-payload',
          digest: candidate.digest,
          payload_bytes: bytes.toString('base64'),
        },
        status,
      );
    const read = (status = 200) =>
      call({ action: 'read-candidate-payload', digest: candidate.digest }, status);
    const cleanup = (status = 200) =>
      call({ action: 'cleanup-candidate-payloads', id: p.id }, status);
    const cleaned = (status = 200) =>
      call({ action: 'cleaned-preparation-with-payloads', id: p.id, receipt }, status);
    const row = () =>
      op.DB.prepare('SELECT * FROM work_candidate_payload WHERE candidate_digest=?')
        .bind(candidate.digest)
        .first<{
          state: string;
          revision: number;
          body: string;
          object_key: string;
          bundle_bytes: number;
        }>();
    return {
      p,
      code,
      candidate,
      packed,
      request,
      commit,
      tree,
      blob,
      extra,
      directory,
      call,
      reserve,
      retain,
      read,
      cleanup,
      cleaned,
      row,
      get DB() {
        return op.DB;
      },
      get bucket() {
        return op.bucket;
      },
      get ownerPreparation() {
        return op.ownerPreparation;
      },
      async restart() {
        await op.close();
        op = await workStoreFixture(directory);
      },
      async dispose() {
        await op.close();
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await op.close();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

test('actual candidate graph survives source deletion and OP/R2 restart, without unrelated refs or objects', async () => {
  const f = await fixture();
  try {
    const reservations = await Promise.all(Array.from({ length: 4 }, () => f.reserve()));
    assert.equal(new Set(reservations.map((r) => r.digest)).size, 1);
    const data = JSON.stringify(JSON.parse(reservations[0]!.body).data.data);
    const hash = createHash('sha256');
    for (const value of ['mikaki.work-candidate-payload.v1', data]) {
      const bytes = Buffer.from(value),
        length = Buffer.alloc(8);
      length.writeBigUInt64BE(BigInt(bytes.length));
      hash.update(length).update(bytes);
    }
    assert.equal(reservations[0]!.digest, hash.digest('hex'));
    await Promise.all(Array.from({ length: 4 }, () => f.retain()));
    assert.equal((await f.bucket.list()).objects.length, 1);
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) FROM work_audit WHERE action='candidate.payload.retain'",
      ).first('count(*)'),
      1,
    );
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    assert.equal((await f.cleanup()).payloads?.length, 1);
    await rm(f.code.dir, { recursive: true, force: true });
    await f.restart();
    const retrieved = await f.read();
    const recovered = await restoreCandidatePayload(
      Buffer.from(retrieved.bytes!, 'base64'),
      f.packed.facts,
      f.directory,
    );
    assert.equal(
      localGit(recovered.dir, ['show', `${f.commit}:README.md`]).toString(),
      'Proposed code\n',
    );
    assert.equal(
      localGit(recovered.dir, ['show', `${f.code.parentCommit}:previous-only.md`]).toString(),
      'Retained code history\n',
    );
    assert.equal(
      localGit(recovered.dir, ['for-each-ref', '--format=%(refname)']).toString().trim(),
      'refs/heads/retained-candidate',
    );
    assert.throws(() => localGit(recovered.dir, ['cat-file', '-t', f.extra]));
    await f.cleaned();
    await f.cleaned();
    assert.equal((await f.call({ action: 'get-preparation', id: f.p.id })).state, 'cleaned');
    const owner = await f.ownerPreparation(f.p.id);
    assert.doesNotMatch(
      JSON.stringify(owner.body),
      /work-candidate\/v1|bundle_digest|inventory_digest|Proposed code/,
    );
  } finally {
    await f.dispose();
  }
});

test('cleanup refuses metadata-only, incomplete or missing archives while retaining historical candidate and stopped producer', async () => {
  const f = await fixture();
  try {
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    await f.cleanup(409);
    await f.cleaned(409);
    await f.call({ action: 'cleaned-preparation', id: f.p.id, receipt }, 409);
    await f.reserve();
    await f.cleanup(409);
    await f.cleaned(409);
    await f.retain();
    const r = (await f.row())!;
    await f.bucket.delete(r.object_key);
    await f.read(409);
    await f.cleanup(409);
    await f.cleaned(409);
    assert.equal((await f.row())!.state, 'retained');
    assert.equal(await f.DB.prepare('SELECT count(*) FROM work_candidate').first('count(*)'), 1);
    assert.equal(await f.DB.prepare('SELECT count(*) FROM work_live_run').first('count(*)'), 0);
    // Exact planned bytes repair an absent object; no replacement identity.
    await f.retain();
    await f.cleaned();
  } finally {
    await f.dispose();
  }
});

test('archive and R2 substitutions, corruption and non-ancestral candidates fail independent Git/native checks', async () => {
  const f = await fixture();
  try {
    await f.reserve(409, { ...f.packed.facts, commit: f.code.commit });
    await f.reserve(409, { ...f.packed.facts, base_commit: f.commit });
    const saved = await f.reserve();
    await f.reserve(409, { ...f.packed.facts, inventory_digest: 'f'.repeat(64) });
    await f.retain(409, Buffer.from('substituted'));
    assert.equal((await f.bucket.list()).objects.length, 0);
    await f.retain();
    const row = (await f.row())!;
    await f.bucket.put(row.object_key, 'corrupt-object');
    await f.read(409);
    await f.retain(409);
    assert.equal((await f.bucket.get(row.object_key))!.size, 14);
    const changed = Buffer.from(f.packed.bytes);
    changed[changed.length - 1] ^= 1;
    await assert.rejects(
      restoreCandidatePayload(
        changed,
        { ...f.packed.facts, bundle_digest: createHash('sha256').update(changed).digest('hex') },
        f.directory,
      ),
    );
    await assert.rejects(
      restoreCandidatePayload(
        f.packed.bytes,
        { ...f.packed.facts, objects: f.packed.facts.objects + 1 },
        f.directory,
      ),
    );
    await assert.rejects(
      prepareCandidatePayload(
        { repository: 'task', gitDir: f.code.dir, commit: f.code.commit },
        f.code.tree,
        f.commit,
        f.directory,
      ),
    );
    const path = join(f.code.dir, 'shallow');
    await writeFile(path, f.code.commit + '\n');
    await assert.rejects(
      prepareCandidatePayload(
        { repository: 'task', gitDir: f.code.dir, commit: f.commit },
        f.tree,
        f.code.commit,
        f.directory,
      ),
    );
    assert.equal((await f.row())!.body, saved.body);
  } finally {
    await f.dispose();
  }
});

test('R2-first audit failure leaves a charged recoverable archive and cleanup audit rolls back completion', async () => {
  const f = await fixture();
  try {
    await f.reserve();
    await f.DB.exec(
      "CREATE TRIGGER fail_archive_audit BEFORE INSERT ON work_audit WHEN NEW.action='candidate.payload.retain' BEGIN SELECT RAISE(ABORT,'test audit failure'); END;",
    );
    await f.retain(500);
    assert.equal((await f.row())!.state, 'reserved');
    assert.equal((await f.bucket.list()).objects.length, 1);
    await f.restart();
    await f.read(409);
    await f.DB.exec('DROP TRIGGER fail_archive_audit');
    await f.retain();
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    await f.DB.exec(
      "CREATE TRIGGER fail_closed_audit BEFORE INSERT ON work_audit WHEN NEW.action='preparation.cleaned' BEGIN SELECT RAISE(ABORT,'test audit failure'); END;",
    );
    await f.cleaned(500);
    assert.equal(
      (await f.call({ action: 'get-preparation', id: f.p.id })).state,
      'cleanup_pending',
    );
    await f.DB.exec('DROP TRIGGER fail_closed_audit');
    await f.cleaned();
    assert.equal(
      await f.DB.prepare('SELECT count(*) FROM work_transition_guard').first('count(*)'),
      0,
    );
  } finally {
    await f.dispose();
  }
});

test('private archive quotas fence reservation before R2 I/O; capture and cleanup survive owner/source/policy loss', async () => {
  const f = await fixture();
  try {
    await f.DB.prepare('UPDATE work_candidate_payload_policy SET bytes_per_owner=1').run();
    await f.reserve(409);
    assert.equal((await f.bucket.list()).objects.length, 0);
    assert.equal(await f.row(), null);
    await f.DB.prepare(
      'UPDATE work_candidate_payload_policy SET bytes_per_owner=67108864,bytes_total=1',
    ).run();
    await f.reserve(409);
    await f.DB.prepare('UPDATE work_candidate_payload_policy SET bytes_total=1073741824').run();
    await f.reserve();
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    await f.DB.prepare('UPDATE account_security SET active=0,epoch=epoch+1').run();
    await f.DB.prepare('UPDATE sso_session SET revoked=1').run();
    await f.DB.prepare('UPDATE work_source_head SET active=0').run();
    await f.DB.prepare('DELETE FROM work_candidate_payload_policy').run();
    await f.DB.prepare('DELETE FROM work_resource_policy').run();
    await f.reserve();
    await f.retain();
    await f.cleaned();
    assert.equal((await f.ownerPreparation(f.p.id)).status, 409);
    assert.equal((await f.row())!.bundle_bytes, f.packed.bytes.length);
    await assert.rejects(f.DB.prepare('DELETE FROM work_candidate_payload').run());
    await assert.rejects(
      f.DB.prepare("UPDATE work_candidate_payload SET state='reserved',revision=1").run(),
    );
    await assert.rejects(
      f.DB.prepare("UPDATE work_candidate_payload SET object_key='foreign'").run(),
    );
  } finally {
    await f.dispose();
  }
});

test('0010 preserves all prior data without certifying candidate payload, and captured SQL cannot bypass cleanup guard', async () => {
  const f = await fixture('0009');
  try {
    const tables = (
      await f.DB.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name",
      ).all<{ name: string }>()
    ).results.map((r) => r.name);
    const before = await f.DB.batch(tables.map((t) => f.DB.prepare(`SELECT * FROM ${t}`)));
    const sql = await readFile(
      new URL(
        '../../crates/worker/work-migrations/0010_work_candidate_payload.sql',
        import.meta.url,
      ),
      'utf8',
    );
    await f.DB.batch(splitSqlQuery(sql).map((s) => f.DB.prepare(s)));
    const after = await f.DB.batch(tables.map((t) => f.DB.prepare(`SELECT * FROM ${t}`)));
    before.forEach((r, i) => assert.deepEqual(after[i]!.results, r.results, tables[i]));
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    const current = await f.call({ action: 'get-preparation', id: f.p.id });
    const revision = await f.DB.prepare(
      'SELECT revision FROM work_preparation WHERE operation_id=?',
    )
      .bind(f.p.id)
      .first<number>('revision');
    const transition = await readFile(
      new URL('../../crates/worker/sql/work/transition-preparation.sql', import.meta.url),
      'utf8',
    );
    const evidence = await f.DB.prepare(
      'SELECT evidence FROM work_preparation WHERE operation_id=?',
    )
      .bind(f.p.id)
      .first<string>('evidence');
    await assert.rejects(
      f.DB.prepare(transition)
        .bind(f.p.id, revision, current.body, 'cleaned', evidence, receipt)
        .run(),
      /work_preparation_guard_failed/,
    );
    assert.equal(
      await f.DB.prepare('SELECT count(*) FROM work_candidate_payload').first('count(*)'),
      0,
    );
    await f.reserve();
    await f.retain();
    await f.cleaned();
  } finally {
    await f.dispose();
  }
});

test('candidate closure set is bounded across request revisions and every accepted candidate needs its own archive', async () => {
  const f = await fixture();
  try {
    for (let n = 1; n <= 14; n++)
      await f.call({
        action: 'candidate',
        grant: 'grant',
        run: 'run',
        candidate: { commit: f.commit, tree: f.tree, evidence: n.toString(16).padStart(64, '0') },
      });
    const revised = await f.call({
      action: 'prepared-request',
      request: { ...f.request, revision: 2 },
    });
    await f.call({ action: 'grant', id: 'grant2', digest: revised.digest });
    await f.call({ action: 'run', grant: 'grant2', run: 'run2' });
    await f.call({
      action: 'candidate',
      grant: 'grant2',
      run: 'run2',
      candidate: { commit: f.commit, tree: f.tree, evidence: 'e'.repeat(64) },
    });
    assert.equal(await f.DB.prepare('SELECT count(*) FROM work_candidate').first('count(*)'), 16);
    await f.call(
      {
        action: 'candidate',
        grant: 'grant2',
        run: 'run2',
        candidate: { commit: f.commit, tree: f.tree, evidence: 'f'.repeat(64) },
      },
      409,
    );
    await f.reserve();
    await f.retain();
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    await f.cleanup(409);
    await f.cleaned(409);
    assert.equal(
      (await f.call({ action: 'get-preparation', id: f.p.id })).state,
      'cleanup_pending',
    );
    assert.equal((await f.bucket.list()).objects.length, 1);
  } finally {
    await f.dispose();
  }
});
