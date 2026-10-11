import assert from 'node:assert/strict';
import { test } from 'node:test';
import { effectFixture } from './support/work-effect-fixture.ts';
import { gitHttpFixture } from './support/work-git-http-fixture.ts';
import { fixedGitExecutor } from '../../scripts/work-git-executor.ts';
import { localGit } from '../../scripts/work-git-disclosure.ts';
import type { GitPlan, GitResult, MintRecord } from '../../crates/work-effect-worker/protocol.ts';
async function fixture(role: 'task' | 'snapshot' = 'task') {
  let executor: ((request: Request) => Promise<Response>) | undefined;
  const f = await effectFixture({}, (request) =>
    executor ? executor(request) : Promise.resolve(new Response(null, { status: 409 })),
  );
  const http = await gitHttpFixture(f.directory, async (name, token, write) => {
    const remote = await f.remote(),
      repo = remote.repos.find((r) => r.name === name),
      n = /^SYNTHETIC_MINT_SECRET_(\d+)$/.exec(token)?.[1];
    const t = repo?.tokens.find((t) => t.id === `mint-${n}`);
    return Boolean(t && t.state === 'active' && (!write || t.scope === 'write'));
  });
  try {
    const initial = role === 'task' ? f.task : f.snapshot;
    assert.equal((await f.execute(initial.id)).state, 'closed');
    const reserve = async (purpose: 'upload' | 'readback') => {
      const a = await f.call({
        action: 'reserve-credential',
        credential: { preparation_id: f.p.id, role, purpose },
      });
      assert.equal(
        (await f.effect<{ state: string }>({ action: 'mint', input: { attempt_id: a.id } })).state,
        'custodied',
      );
      return a.id;
    };
    const id = await reserve('upload');
    const p = await f.effect<GitPlan>({
      action: 'plan',
      input: { action: 'git-plan', attempt_id: id },
    });
    const source = role === 'task' ? f.gitSources.code.dir : f.gitSources.selected.gitDir;
    executor = fixedGitExecutor(
      {
        account: 'a'.repeat(32),
        namespace: 'mikaki-dev',
        authority: 'synthetic-managed-work',
        temporaryDirectory: f.directory,
        registered: [
          {
            disclosure_digest: p.disclosure_digest,
            role,
            gitDir: source,
            commit: p.commit,
            tree: p.tree,
          },
        ],
      },
      http.http,
    );
    const ledger = (attempt = id) =>
      f.effect<MintRecord>({ action: 'mint-lookup', attempt_id: attempt });
    const git = (attempt = id, status = 200, input: unknown = { attempt_id: attempt }) =>
      f.effect<{ state: string; result: GitResult | null }>({ action: 'git', input }, status);
    const close = async (attempt = id) => {
      await f.effect({ action: 'mint-reconcile', input: { attempt_id: attempt } });
      const result = await f.effect<{ state: string; op_synchronized: boolean }>({
        action: 'mint-close',
        input: { attempt_id: attempt },
      });
      assert.equal(result.state, 'closed');
      assert.equal(result.op_synchronized, true);
    };
    return {
      ...f,
      get DB() {
        return f.DB;
      },
      id,
      p,
      preparation: f.p,
      http,
      source,
      reserve,
      ledger,
      git,
      closeMint: close,
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
for (const role of ['task', 'snapshot'] as const)
  test(`${role}: Native custody performs one exact upload, refusal closure and independent full Git readback`, async () => {
    const f = await fixture(role);
    try {
      const upload = await f.git();
      assert.equal(upload.state, 'completed');
      assert.equal(upload.result!.method, 'git_push_accepted');
      assert.equal(f.http.counts.pushes, 1);
      assert.equal((await f.ledger()).cleanup_requested, true);
      assert.equal((await f.row(f.id))!.state, 'revocation_pending');
      const counts = { ...f.http.counts };
      await f.restart();
      assert.deepEqual(await f.git(), upload);
      assert.deepEqual(f.http.counts, counts);
      await f.closeMint();
      const read = await f.reserve('readback'),
        result = await f.git(read);
      assert.equal(result.state, 'completed');
      assert.equal(result.result!.method, 'git_readback_verified');
      assert.equal(result.result!.inventory_sha256, upload.result!.inventory_sha256);
      assert.equal(result.result!.commits, role === 'task' ? 2 : 1);
      assert.equal(f.http.counts.fetches, 1);
      await f.closeMint(read);
      assert.equal((await f.ledger()).state, 'closed');
      assert.equal((await f.ledger(read)).state, 'closed');
      assert.equal(
        await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
          .bind(f.preparation.id)
          .first('state'),
        'dispatched',
      );
      assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
      const remoteDir = f.http.repository(f.p.name);
      if (role === 'snapshot') {
        const names = localGit(f.http.repository(f.p.name), [
          'ls-tree',
          '-r',
          '--name-only',
          f.p.commit,
        ]).toString();
        assert.equal(names, 'context/00/selected.md\n');
        const old = f.gitSources.personal!.historicalBlob!;
        assert.throws(() => localGit(remoteDir, ['cat-file', '-e', old]));
      }
      assert.doesNotMatch(
        JSON.stringify([upload, result, await f.ledger(), await f.row(f.id)]),
        /SYNTHETIC_MINT_SECRET|plaintext/,
      );
    } finally {
      await f.close();
    }
  });
test('lost accepted push reply survives restart and D1 restore without another send', async () => {
  const f = await fixture();
  try {
    await f.backup();
    f.http.setMode('push-lost');
    assert.equal((await f.git()).state, 'outcome_unknown');
    assert.equal(f.http.counts.pushes, 1);
    assert.equal(
      localGit(f.http.repository(f.p.name), ['rev-parse', 'refs/heads/work']).toString().trim(),
      f.p.commit,
    );
    const counts = { ...f.http.counts };
    await f.restore();
    f.http.setMode('normal');
    assert.equal((await f.git()).state, 'outcome_unknown');
    assert.deepEqual(f.http.counts, counts);
    assert.equal((await f.ledger()).git!.result, null);
  } finally {
    await f.close();
  }
});
for (const mode of ['redirect', 'unavailable'])
  test(`${mode} keeps the upload uncertain and never replays HTTP`, async () => {
    const f = await fixture();
    try {
      f.http.setMode(mode);
      assert.equal((await f.git()).state, 'outcome_unknown');
      assert.equal(f.http.counts.pushes, 0);
      const counts = { ...f.http.counts };
      await f.restart();
      f.http.setMode('normal');
      await f.git();
      assert.deepEqual(f.http.counts, counts);
    } finally {
      await f.close();
    }
  });
test('extra remote ref makes independent readback fail without preparation verification', async () => {
  const f = await fixture();
  try {
    await f.git();
    await f.closeMint();
    localGit(f.http.repository(f.p.name), ['update-ref', 'refs/heads/unexpected', f.p.commit]);
    const read = await f.reserve('readback');
    assert.equal((await f.git(read)).state, 'outcome_unknown');
    assert.equal(f.http.counts.fetches, 0);
    assert.equal((await f.ledger(read)).git!.result, null);
  } finally {
    await f.close();
  }
});
test('corrupt downloaded pack is rejected before Git indexing or a retained verification receipt', async () => {
  const f = await fixture();
  try {
    await f.git();
    await f.closeMint();
    const read = await f.reserve('readback');
    f.http.setMode('readback-corrupt');
    const r = await f.git(read);
    assert.equal(r.state, 'outcome_unknown');
    assert.equal(r.result, null);
    assert.equal(f.http.counts.fetches, 1);
    const counts = { ...f.http.counts };
    f.http.setMode('normal');
    await f.restart();
    await f.git(read);
    assert.deepEqual(f.http.counts, counts);
  } finally {
    await f.close();
  }
});
test('a successful HTTP status with malformed receive-pack report cannot certify upload', async () => {
  const f = await fixture();
  try {
    f.http.setMode('push-malformed');
    const r = await f.git();
    assert.equal(r.state, 'outcome_unknown');
    assert.equal(r.result, null);
    assert.equal(f.http.counts.pushes, 1);
    assert.equal(
      localGit(f.http.repository(f.p.name), ['rev-parse', 'refs/heads/work']).toString().trim(),
      f.p.commit,
    );
  } finally {
    await f.close();
  }
});
test('owner/source/key/frozen authority loss before Git admission denies external I/O', async () => {
  for (const loss of ['source', 'owner', 'key', 'freeze']) {
    const f = await fixture();
    try {
      if (loss === 'source')
        await f.DB.prepare(
          'UPDATE work_source_access SET active=0,access_revision=access_revision+1',
        ).run();
      if (loss === 'owner')
        assert.equal(
          (
            await f.authority({
              action: 'revoke-account',
              account: 'synthetic-delivery-owner',
              expected_epoch: 0,
              actor: 'fixture',
              reason: 'before Git admission',
            })
          ).status,
          200,
        );
      if (loss === 'key') await f.restart({ WORK_CREDENTIAL_KEY_FLOOR: '2' });
      if (loss === 'freeze') await f.checkpoint({ action: 'freeze' });
      await f.git(f.id, 409);
      assert.equal((await f.ledger()).git, undefined);
      assert.equal(f.http.counts.requests, 0);
    } finally {
      await f.close();
    }
  }
});
test('opaque/public boundaries reject request widening and dispatch replay', async () => {
  const f = await fixture();
  try {
    await f.effect({ action: 'git-public' }, 404);
    for (const extra of [
      { url: 'https://wrong.invalid' },
      { ref: 'refs/heads/other' },
      { plaintext: 'arbitrary' },
      { commit: 'e'.repeat(40) },
    ])
      await f.git(f.id, 409, { attempt_id: f.id, ...extra });
    await f.effect({ action: 'git-claim', plan: { ...f.p, branch: 'other' } }, 409);
    assert.equal(f.http.counts.requests, 0);
    await f.effect({ action: 'git-claim', plan: f.p });
    await f.effect(
      {
        action: 'plan',
        input: { action: 'git-execute', attempt_id: f.id, plan: { ...f.p, tree: 'e'.repeat(40) } },
      },
      409,
    );
    const first = await f.effect<GitResult>({
      action: 'plan',
      input: { action: 'git-execute', attempt_id: f.id, plan: f.p },
    });
    assert.equal(first.method, 'git_push_accepted');
    await f.effect(
      { action: 'plan', input: { action: 'git-execute', attempt_id: f.id, plan: f.p } },
      409,
    );
    assert.equal(f.http.counts.pushes, 1);
    for (const method of ['mint', 'bootstrap', 'freeze', 'reset', 'custody', 'env'])
      await f.effect({ action: 'git-call', method, args: [] }, 409);
  } finally {
    await f.close();
  }
});
for (const loss of ['claim', 'take', 'finish', 'native'])
  test(`lost ${loss} acknowledgement retains the Git slot without another execution`, async () => {
    const f = await fixture();
    try {
      await f.restart(
        loss === 'native' ? { LOCAL_GIT_EXECUTE_LOST: 'true' } : { LOCAL_GIT_LEDGER_LOST: loss },
      );
      await f.git(f.id, loss === 'claim' || loss === 'finish' ? 409 : 200);
      assert.equal(f.http.counts.pushes, loss === 'claim' || loss === 'take' ? 0 : 1);
      const counts = { ...f.http.counts };
      await f.restart();
      const r = await f.git();
      assert.deepEqual(f.http.counts, counts);
      assert.equal(
        r.state,
        loss === 'finish'
          ? 'completed'
          : loss === 'claim'
            ? 'admitted'
            : loss === 'take'
              ? 'dispatching'
              : 'outcome_unknown',
      );
      assert.equal((await f.ledger()).cleanup_requested, true);
    } finally {
      await f.close();
    }
  });
for (const loss of ['source', 'owner', 'freeze'])
  test(`${loss} after Git admission retains cleanup intent and denies execution`, async () => {
    const f = await fixture();
    try {
      await f.restart({ LOCAL_GIT_EXECUTE_PAUSE: loss });
      assert.equal((await f.git()).state, 'admitted');
      assert.equal(f.http.counts.requests, 0);
      assert.equal((await f.ledger()).cleanup_requested, true);
      assert.equal(
        (await f.row(f.id))!.state,
        loss === 'freeze' ? 'captured' : 'revocation_pending',
      );
    } finally {
      await f.close();
    }
  });
for (const mode of [
  'replaced-repo',
  'wrong-description',
  'incomplete-inventory',
  'mint-substitute-scope',
  'mint-substitute-expiry',
])
  test(`${mode} denies Git dispatch before host executor I/O`, async () => {
    const f = await fixture();
    try {
      await f.mode(mode);
      assert.equal((await f.git()).state, 'dispatching');
      assert.equal(f.http.counts.requests, 0);
      assert.equal((await f.ledger()).git!.result, null);
    } finally {
      await f.close();
    }
  });
test('readback needs independently completed upload and strong refusal closure', async () => {
  const f = await fixture();
  try {
    const r = await f.ledger();
    await f.effect({ action: 'mint-ledger-call', method: 'abandon', args: [f.id, r.plan.digest] });
    await f.effect({
      action: 'plan',
      input: { action: 'mint-cleanup', attempt_id: f.id, digest: r.plan.digest, ...r.observation! },
    });
    await f.closeMint();
    const read = await f.reserve('readback');
    await f.git(read, 409);
    assert.equal((await f.ledger(read)).git, undefined);
    assert.equal(f.http.counts.requests, 0);
  } finally {
    await f.close();
  }
});
test('concurrent Git calls cannot obtain two sends and retained completion cannot change', async () => {
  const f = await fixture();
  try {
    await Promise.all([f.git(), f.git()]);
    assert.ok(f.http.counts.pushes <= 1);
    const r = await f.ledger();
    assert.ok(r.git);
    const counts = { ...f.http.counts };
    await f.restart();
    await f.git();
    assert.deepEqual(f.http.counts, counts);
    if (r.git.result)
      await f.effect(
        {
          action: 'git-call',
          method: 'finish',
          args: [f.id, { ...r.git.result, receipt: 'e'.repeat(64) }],
        },
        409,
      );
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
  } finally {
    await f.close();
  }
});
