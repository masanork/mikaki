import assert from 'node:assert/strict';
import { test } from 'node:test';
import { effectFixture } from './support/work-effect-fixture.ts';
import { gitHttpFixture } from './support/work-git-http-fixture.ts';
import { fixedGitExecutor } from '../../scripts/work-git-executor.ts';
import type { GitPlan, GitResult } from '../../crates/work-effect-worker/protocol.ts';
type Role = 'task' | 'snapshot';
type Review = {
  id: string;
  state: string;
  destination_digest: string;
  task: { repository_id: string };
  snapshot: { repository_id: string };
};
async function fixture() {
  let executor: ((request: Request) => Promise<Response>) | undefined;
  const f = await effectFixture({}, (r) =>
    executor ? executor(r) : Promise.resolve(new Response(null, { status: 409 })),
  );
  const http = await gitHttpFixture(f.directory, async (name, token, write) => {
    const remote = await f.remote(),
      repo = remote.repos.find((r) => r.name === name),
      n = /^SYNTHETIC_MINT_SECRET_(\d+)$/.exec(token)?.[1];
    const t = repo?.tokens.find((t) => t.id === `mint-${n}`);
    return Boolean(t && t.state === 'active' && (!write || t.scope === 'write'));
  });
  const attempts = [
    { attempt_id: f.task.id, purpose: 'initial' },
    { attempt_id: f.snapshot.id, purpose: 'initial' },
  ];
  try {
    for (const id of [f.task.id, f.snapshot.id])
      assert.equal((await f.execute(id)).state, 'closed');
    const reserve = async (role: Role, purpose: 'upload' | 'readback') => {
      const a = await f.call({
        action: 'reserve-credential',
        credential: { preparation_id: f.p.id, role, purpose },
      });
      assert.equal(
        (await f.effect<{ state: string }>({ action: 'mint', input: { attempt_id: a.id } })).state,
        'custodied',
      );
      attempts.push({ attempt_id: a.id, purpose });
      return a.id;
    };
    const upload = {
      task: await reserve('task', 'upload'),
      snapshot: await reserve('snapshot', 'upload'),
    };
    const plans: GitPlan[] = [];
    for (const id of Object.values(upload))
      plans.push(
        await f.effect<GitPlan>({ action: 'plan', input: { action: 'git-plan', attempt_id: id } }),
      );
    executor = fixedGitExecutor(
      {
        account: 'a'.repeat(32),
        namespace: 'mikaki-dev',
        authority: 'synthetic-managed-work',
        temporaryDirectory: f.directory,
        registered: plans.map((p) => ({
          disclosure_digest: p.disclosure_digest,
          role: p.role,
          commit: p.commit,
          tree: p.tree,
          gitDir: p.role === 'task' ? f.gitSources.code.dir : f.gitSources.selected.gitDir,
        })),
      },
      http.http,
    );
    const git = (id: string) =>
      f.effect<{ state: string; result: GitResult | null }>({
        action: 'git',
        input: { attempt_id: id },
      });
    const closeMint = async (id: string) => {
      await f.effect({ action: 'mint-reconcile', input: { attempt_id: id } });
      const r = await f.effect<{ state: string; op_synchronized: boolean }>({
        action: 'mint-close',
        input: { attempt_id: id },
      });
      assert.equal(r.state, 'closed');
      assert.equal(r.op_synchronized, true);
    };
    const completeRole = async (role: Role) => {
      assert.equal((await git(upload[role])).state, 'completed');
      await closeMint(upload[role]);
      const read = await reserve(role, 'readback');
      assert.equal((await git(read)).state, 'completed');
      await closeMint(read);
      return read;
    };
    const state = () =>
      f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
        .bind(f.p.id)
        .first<string>('state');
    const audit = () =>
      f.DB.prepare(
        "SELECT count(*) AS n FROM work_audit WHERE action='preparation.verify'",
      ).first<number>('n');
    const verify = (status = 200, input: unknown = { preparation_id: f.p.id }) =>
      f.effect<Review>({ action: 'preparation', input }, status);
    return {
      ...f,
      get DB() {
        return f.DB;
      },
      http,
      upload,
      attempts,
      plans,
      reserve,
      git,
      closeMint,
      completeRole,
      state,
      audit,
      verify,
      async complete() {
        await completeRole('task');
        await completeRole('snapshot');
      },
      async close() {
        await http.close();
        await f.close();
      },
    };
  } catch (error) {
    await http.close();
    await f.close();
    throw error;
  }
}
test('both real Git copies and all six closed credentials compose exactly once across concurrency and restart', async () => {
  const f = await fixture();
  try {
    await f.complete();
    const remote = await f.remote(),
      counts = { ...f.http.counts };
    await f.restart();
    const concurrent = await Promise.allSettled([f.verify(), f.verify()]);
    const successful = concurrent.filter((r) => r.status === 'fulfilled');
    assert.ok(successful.length >= 1);
    const a = await f.verify();
    for (const r of successful) assert.deepEqual(r.value, a);
    for (const r of concurrent)
      if (r.status === 'rejected') {
        assert.equal(r.reason.actual, 409);
        assert.equal(r.reason.expected, 200);
      }
    assert.equal(a.state, 'verified');
    assert.equal(a.id, f.p.id);
    assert.equal(a.task.repository_id, remote.repos.find((r) => r.name === f.plans[0]!.name)!.id);
    assert.equal(
      a.snapshot.repository_id,
      remote.repos.find((r) => r.name === f.plans[1]!.name)!.id,
    );
    assert.match(a.destination_digest, /^[a-f0-9]{64}$/);
    assert.equal(await f.audit(), 1);
    const checkpoint = await f.DB.prepare(
      'SELECT sequence,tip FROM work_authority_checkpoint',
    ).first();
    const evidence = await f.DB.prepare('SELECT evidence FROM work_preparation').first<string>(
      'evidence',
    );
    await f.restart({ LOCAL_PREPARATION_EVIDENCE_FAULT: 'reverse' });
    assert.deepEqual(await f.verify(), a);
    assert.equal(
      await f.DB.prepare('SELECT evidence FROM work_preparation').first('evidence'),
      evidence,
    );
    assert.deepEqual(
      await f.DB.prepare('SELECT sequence,tip FROM work_authority_checkpoint').first(),
      checkpoint,
    );
    assert.deepEqual(f.http.counts, counts);
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_task_repository').first('n'),
      0,
    );
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_run').first('n'), 0);
    assert.doesNotMatch(JSON.stringify(a), /SYNTHETIC|token_id|key_version|envelope|plaintext/);
  } finally {
    await f.close();
  }
});
test('one verified repo or an unclosed readback credential cannot promote preparation', async () => {
  const f = await fixture();
  try {
    await f.verify(409);
    await f.completeRole('task');
    await f.verify(409);
    await f.git(f.upload.snapshot);
    await f.closeMint(f.upload.snapshot);
    const read = await f.reserve('snapshot', 'readback');
    await f.git(read);
    await f.verify(409);
    assert.equal(await f.state(), 'dispatched');
    assert.equal(await f.audit(), 0);
    await f.closeMint(read);
    assert.equal((await f.verify()).state, 'verified');
  } finally {
    await f.close();
  }
});
test('six independently closed credentials without completed Git evidence cannot verify a copy', async () => {
  const f = await fixture();
  try {
    for (const role of ['task', 'snapshot'] as const) {
      for (const purpose of ['upload', 'readback'] as const) {
        const id = purpose === 'upload' ? f.upload[role] : await f.reserve(role, purpose);
        await f.call({ action: 'credential-revoke', id });
        assert.equal(
          (await f.effect<{ state: string }>({ action: 'mint', input: { attempt_id: id } })).state,
          'outcome_unknown',
        );
        await f.closeMint(id);
      }
    }
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) AS n FROM work_credential_attempt WHERE state='closed'",
      ).first('n'),
      6,
    );
    await f.verify(409);
    assert.equal(await f.state(), 'dispatched');
    assert.equal(await f.audit(), 0);
  } finally {
    await f.close();
  }
});
test('missing, substituted, malformed and unbounded independent metadata cannot certify preparation', async () => {
  const f = await fixture();
  try {
    await f.complete();
    const counts = { ...f.http.counts };
    for (const mode of [
      'unavailable',
      'oversized',
      'duplicate-key',
      'missing',
      'duplicate',
      'repo',
      'closure',
      'inventory',
      'inventory-both',
      'receipt',
      'key',
      'initial',
      'checkpoint',
      'commit',
      'plan',
      'extra',
    ]) {
      await f.restart({ LOCAL_PREPARATION_EVIDENCE_FAULT: mode });
      await f.verify(409);
      assert.equal(await f.state(), 'dispatched', mode);
      assert.equal(await f.audit(), 0, mode);
    }
    assert.deepEqual(f.http.counts, counts);
    await f.restart();
    assert.equal((await f.verify()).state, 'verified');
  } finally {
    await f.close();
  }
});
test('an accepted upload with a lost response stays uncertain even after all credentials close', async () => {
  const f = await fixture();
  try {
    await f.completeRole('snapshot');
    f.http.setMode('push-lost');
    assert.equal((await f.git(f.upload.task)).state, 'outcome_unknown');
    await f.closeMint(f.upload.task);
    const read = await f.reserve('task', 'readback');
    await f.effect({ action: 'git', input: { attempt_id: read } }, 409);
    await f.call({ action: 'credential-revoke', id: read });
    assert.equal(
      (await f.effect<{ state: string }>({ action: 'mint', input: { attempt_id: read } })).state,
      'outcome_unknown',
    );
    await f.closeMint(read);
    const counts = { ...f.http.counts };
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) AS n FROM work_credential_attempt WHERE state='closed'",
      ).first('n'),
      6,
    );
    await f.restart();
    await f.verify(409);
    assert.equal(await f.state(), 'dispatched');
    assert.equal(await f.audit(), 0);
    assert.deepEqual(f.http.counts, counts);
  } finally {
    await f.close();
  }
});
test('closed historical evidence needs no wrapping secret and verified retries grant no current source access', async () => {
  const f = await fixture();
  try {
    await f.complete();
    const counts = { ...f.http.counts };
    await f.restart({ WORK_CREDENTIAL_KEY_FLOOR: '2', WORK_CREDENTIAL_KEY_V1: 'unavailable' });
    const review = await f.verify();
    assert.equal(review.state, 'verified');
    await f.DB.prepare(
      'UPDATE work_source_access SET active=0,access_revision=access_revision+1',
    ).run();
    assert.deepEqual(await f.verify(), review);
    assert.equal(await f.audit(), 1);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
    assert.deepEqual(f.http.counts, counts);
  } finally {
    await f.close();
  }
});
for (const pause of ['freeze', 'pending', 'floor', 'source', 'owner', 'policy'])
  test(`${pause} during evidence read denies the Native verify commit`, async () => {
    const f = await fixture();
    try {
      await f.complete();
      const counts = { ...f.http.counts };
      await f.restart({ LOCAL_PREPARATION_EVIDENCE_PAUSE: pause });
      await f.verify(409);
      assert.equal(await f.state(), 'dispatched');
      assert.equal(await f.audit(), 0);
      assert.deepEqual(f.http.counts, counts);
    } finally {
      await f.close();
    }
  });
test('lost verified acknowledgement is recovered from retained exact evidence without Git replay or another audit', async () => {
  const f = await fixture();
  try {
    await f.complete();
    const counts = { ...f.http.counts };
    await f.restart({ LOCAL_PREPARATION_VERIFY_LOST: 'true' });
    await f.verify(409);
    assert.equal(await f.state(), 'verified');
    assert.equal(await f.audit(), 1);
    await f.restart();
    assert.equal((await f.verify()).state, 'verified');
    assert.equal(await f.audit(), 1);
    assert.deepEqual(f.http.counts, counts);
  } finally {
    await f.close();
  }
});
test('primary rollback after verification stays fenced despite independent complete copy evidence', async () => {
  const f = await fixture();
  try {
    await f.complete();
    await f.backup();
    await f.verify();
    const counts = { ...f.http.counts };
    await f.restore();
    await f.verify(409);
    assert.equal(await f.state(), 'dispatched');
    assert.equal(await f.audit(), 0);
    assert.deepEqual(f.http.counts, counts);
  } finally {
    await f.close();
  }
});
test('opaque and read-only capability boundaries reject caller evidence, secrets and other actions', async () => {
  const f = await fixture();
  try {
    assert.deepEqual(await f.bindingNames('work-preparation'), [
      'OP_EFFECT_STORE',
      'WORK_PREPARATION_GATE_ENABLED',
    ]);
    for (const input of [
      { preparation_id: f.p.id, receipt: 'a'.repeat(64) },
      { preparation_id: f.p.id, token: 'SYNTHETIC' },
      { preparation_id: 'invalid' },
      { preparation_id: 'a'.repeat(43) },
    ])
      await f.verify(409, input);
    await f.effect({ action: 'preparation-public' }, 404);
    for (const method of ['claim', 'mint', 'finish', 'freeze', 'begin', 'administer_work_effect'])
      await f.effect({ action: 'preparation-evidence-call', method, args: [] }, 409);
    await f.effect({ action: 'preparation-evidence', input: { attempts: [] } }, 409);
    await f.effect(
      { action: 'preparation-evidence', input: { attempts: f.attempts }, method: 'GET' },
      404,
    );
    await f.complete();
    const input = { attempts: f.attempts };
    const e = await f.effect({ action: 'preparation-evidence', input });
    assert.doesNotMatch(JSON.stringify(e), /SYNTHETIC_MINT_SECRET|envelope|plaintext/);
    await f.effect(
      { action: 'preparation-evidence', input: { ...input, url: 'https://attacker.invalid/' } },
      409,
    );
    await f.effect(
      {
        action: 'preparation-evidence',
        input: { attempts: [...f.attempts.slice(0, 5), f.attempts[0]] },
      },
      409,
    );
    assert.equal(await f.state(), 'dispatched');
    await f.restart({ WORK_PREPARATION_VERIFY_ENABLED: 'false' });
    await f.verify(409);
    await f.restart({ WORK_PREPARATION_GATE_ENABLED: 'false' });
    await f.verify(409);
  } finally {
    await f.close();
  }
});
