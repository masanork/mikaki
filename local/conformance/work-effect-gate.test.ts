import assert from 'node:assert/strict';
import { test } from 'node:test';
import { effectFixture as fixture } from './support/work-effect-fixture.ts';
import type { InitialPlan, EffectRecord } from '../../crates/work-effect-worker/protocol.ts';
test('initial task/snapshot create uses Native names, closes initial tokens, and never outputs or stores plaintext', async () => {
  const f = await fixture();
  try {
    for (const a of [f.task, f.snapshot]) {
      const result = await f.execute(a.id);
      assert.equal(result.state, 'closed');
      assert.equal(result.op_synchronized, true);
      const row = await f.row(a.id);
      assert.equal(row!.state, 'closed');
      assert.equal(row!.envelope, null);
      assert.equal(row!.key_version, null);
      assert.equal(row!.nonce, null);
      const ledger = await f.ledger(a.id);
      assert.equal(ledger!.closure!.receipt, row!.receipt);
      assert.equal(ledger!.repo_id, result.repo_id);
      assert.doesNotMatch(
        JSON.stringify([result, row, ledger]),
        /SYNTHETIC_INITIAL_SECRET|plaintext/,
      );
    }
    const before = await f.remote();
    assert.equal(before.counts.create, 2);
    assert.equal(before.counts.revoke, 2);
    assert.equal(before.counts.git, 2);
    assert.equal(before.counts.http, 2);
    assert.ok(before.repos.every((r) => r.state === 'revoked'));
    assert.deepEqual(before.repos.map((r) => r.defaultBranch).sort(), ['snapshot', 'work']);
    await f.restart();
    assert.equal((await f.execute()).state, 'closed');
    assert.equal((await f.execute(f.snapshot.id)).op_synchronized, true);
    assert.deepEqual((await f.remote()).counts, before.counts);
  } finally {
    await f.close();
  }
});
test('concurrent gate calls receive only one durable create admission', async () => {
  const f = await fixture();
  try {
    await f.plan();
    const results = await Promise.all([f.execute(), f.execute()]);
    assert.ok(results.some((r) => r.state === 'closed'));
    assert.ok(results.every((r) => ['closed', 'outcome_unknown'].includes(r.state)));
    assert.equal((await f.remote()).counts.create, 1);
    assert.equal((await f.execute()).state, 'closed');
  } finally {
    await f.close();
  }
});
for (const mode of [
  'create-lost',
  'get-lost',
  'revoke-lost',
  'incomplete-inventory',
  'list-lost',
  'wrong-remote',
  'unexpected-token',
  'git-active',
  'git-unavailable',
  'git-redirect',
]) {
  test(`unknown ${mode} is retained across restart without replay`, async () => {
    const f = await fixture();
    try {
      await f.mode(mode);
      assert.equal((await f.execute()).state, 'outcome_unknown');
      const before = await f.remote();
      assert.equal(before.counts.create, 1);
      if (mode === 'create-lost') {
        assert.equal(before.repos[0]!.state, 'active');
        assert.equal(before.counts.get, 0);
      } else if (mode === 'get-lost') {
        assert.equal(before.repos[0]!.state, 'active');
        assert.equal(before.counts.revoke, 0);
        assert.equal((await f.ledger())!.repo_id, before.repos[0]!.id);
      } else {
        assert.equal(before.repos[0]!.state, 'revoked');
        assert.equal(before.counts.revoke, 1);
      }
      if (mode.startsWith('git-')) {
        assert.equal(before.counts.git, 1);
        assert.equal(before.counts.http, 1);
      }
      assert.equal((await f.ledger())!.state, 'outcome_unknown');
      await f.restart();
      await f.mode('normal');
      assert.equal((await f.execute()).state, 'outcome_unknown');
      assert.deepEqual((await f.remote()).counts, before.counts);
    } finally {
      await f.close();
    }
  });
}
for (const pause of ['pending', 'freeze', 'revoke']) {
  test(`independent gate denies ${pause} between Native plan and remote I/O`, async () => {
    const f = await fixture({ LOCAL_EFFECT_PAUSE: pause });
    try {
      await f.execute(f.task.id, 409);
      assert.equal((await f.remote()).counts.create, 0);
      assert.equal(await f.ledger(), null);
      assert.equal((await f.row())!.state, 'dispatched');
    } finally {
      await f.close();
    }
  });
}
test('whole D1 restore cannot replay a known create or admit the other old attempt', async () => {
  const f = await fixture();
  try {
    await f.backup();
    assert.equal((await f.execute()).op_synchronized, true);
    const before = await f.remote();
    await f.restore();
    assert.equal((await f.row())!.state, 'reserved');
    const recovered = await f.execute();
    assert.equal(recovered.state, 'closed');
    assert.equal(recovered.op_synchronized, false);
    await f.execute(f.snapshot.id, 409);
    assert.deepEqual((await f.remote()).counts, before.counts);
    assert.equal(await f.ledger(f.snapshot.id), null);
  } finally {
    await f.close();
  }
});
test('freeze after admission permits safety recording while OP sync remains blocked', async () => {
  const f = await fixture();
  try {
    await f.mode('freeze-during-create');
    const r = await f.execute();
    assert.equal(r.state, 'closed');
    assert.equal(r.op_synchronized, false);
    assert.equal((await f.ledger())!.state, 'closed');
    assert.equal((await f.row())!.state, 'dispatched');
    const before = await f.remote();
    assert.equal(before.repos[0]!.state, 'revoked');
    await f.restart();
    assert.equal((await f.execute()).state, 'closed');
    assert.deepEqual((await f.remote()).counts, before.counts);
    await f.execute(f.snapshot.id, 409);
  } finally {
    await f.close();
  }
});
test('cold flags, wrong namespace, closed request shape and raw/public capability boundaries deny I/O', async () => {
  const f = await fixture();
  try {
    for (const action of [
      'public',
      'public-raw',
      'effect-raw',
      'effect-admin-raw',
      'admin-effect-raw',
    ])
      await f.effect({ action }, 404);
    await f.effect(
      {
        action: 'execute',
        input: { attempt_id: f.task.id, name: 'arbitrary', token: 'arbitrary' },
      },
      409,
    );
    await f.effect(
      {
        action: 'plan',
        input: { action: 'initial-plan', attempt_id: f.task.id, namespace: 'arbitrary' },
      },
      409,
    );
    await f.restart({ WORK_EFFECT_GATE_ENABLED: 'false' });
    await f.execute(f.task.id, 409);
    await f.restart({ WORK_EFFECT_STORE_ENABLED: 'false' });
    await f.execute(f.task.id, 409);
    await f.restart({ WORK_ARTIFACTS_NAMESPACE: 'wrong' });
    await f.execute(f.task.id, 409);
    await f.restart({ WORK_ARTIFACTS_ACCOUNT: 'b'.repeat(32) });
    await f.execute(f.task.id, 409);
    assert.equal((await f.remote()).counts.create, 0);
    assert.equal(await f.ledger(), null);
  } finally {
    await f.close();
  }
});
test('effect tombstone conflict, expiry and monotonic release floor deny admission', async () => {
  const f = await fixture();
  try {
    const p = await f.plan();
    await f.effect({ action: 'ledger-claim', plan: { ...p, deadline: 1 } }, 409);
    const first = await f.effect<{ started: boolean }>({ action: 'ledger-claim', plan: p });
    assert.equal(first.started, true);
    const repeat = await f.effect<{ started: boolean }>({ action: 'ledger-claim', plan: p });
    assert.equal(repeat.started, false);
    await f.effect({ action: 'ledger-claim', plan: { ...p, digest: 'f'.repeat(64) } }, 409);
    const r = await f.checkpoint({ action: 'raise-floor', floor: 2 });
    assert.equal(r.status, 200);
    await f.execute(f.snapshot.id, 409);
    assert.equal((await f.remote()).counts.create, 0);
  } finally {
    await f.close();
  }
});

test('lost durable claim reply strands the attempt without remote I/O or replay', async () => {
  const f = await fixture({ LOCAL_EFFECT_CLAIM_LOST: 'true' });
  try {
    await f.execute(f.task.id, 409);
    assert.equal((await f.ledger())!.state, 'outcome_unknown');
    assert.equal((await f.remote()).counts.create, 0);
    await f.restart({ LOCAL_EFFECT_CLAIM_LOST: 'false' });
    assert.equal((await f.execute()).state, 'outcome_unknown');
    assert.equal((await f.remote()).counts.create, 0);
  } finally {
    await f.close();
  }
});
test('lost OP closure acknowledgement reconciles exact metadata without repeating Artifacts', async () => {
  const f = await fixture({ LOCAL_EFFECT_CAPTURE_LOST: 'true' });
  try {
    const r = await f.execute();
    assert.equal(r.state, 'closed');
    assert.equal(r.op_synchronized, false);
    const before = await f.remote();
    assert.equal((await f.row())!.state, 'closed');
    await f.restart({ LOCAL_EFFECT_CAPTURE_LOST: 'false' });
    assert.equal((await f.execute()).op_synchronized, true);
    assert.deepEqual((await f.remote()).counts, before.counts);
    const c = (await f.ledger())!.closure!;
    await f.effect(
      {
        action: 'capture',
        input: { action: 'capture-closed', attempt_id: f.task.id, ...c, token_id: 'substitution' },
      },
      409,
    );
  } finally {
    await f.close();
  }
});
test('retained effect capacity fails closed and keeps existing tombstones', async () => {
  const f = await fixture();
  try {
    const p = await f.plan();
    for (let i = 0; i < 256; i++) {
      const plan = { ...p, attempt_id: i.toString(16).padStart(43, '0') };
      const r = await f.effect<{ started: boolean }>({ action: 'ledger-claim', plan });
      assert.equal(r.started, true);
    }
    await f.effect({ action: 'ledger-claim', plan: p }, 409);
    const r = await f.effect<{ started: boolean }>({
      action: 'ledger-claim',
      plan: { ...p, attempt_id: '0'.repeat(43) },
    });
    assert.equal(r.started, false);
    assert.equal((await f.remote()).counts.create, 0);
  } finally {
    await f.close();
  }
});
test('ISO fractional expiry rounds conservatively before Native closure', async () => {
  const f = await fixture();
  try {
    await f.mode('fractional-expiry');
    assert.equal((await f.execute()).op_synchronized, true);
    assert.equal(
      (await f.ledger())!.closure!.expires_at,
      Math.ceil(Date.parse('2030-01-01T00:00:00.125Z') / 1000),
    );
  } finally {
    await f.close();
  }
});

for (const lost of ['create-lost', 'get-lost', 'revoke-lost']) {
  test(`safety reconciliation after ${lost} revokes by ID and retains the unknown charge`, async () => {
    const f = await fixture();
    try {
      await f.mode(lost);
      assert.equal((await f.execute()).state, 'outcome_unknown');
      await f.restart();
      await f.mode('normal');
      const r = await f.reconcile();
      assert.equal(r.cleanup, 'initial_token_revoked');
      assert.equal(r.state, 'outcome_unknown');
      assert.equal(r.op_synchronized, true);
      const row = await f.row(),
        ledger = await f.ledger(),
        remote = await f.remote();
      assert.equal(row!.state, 'revocation_pending');
      assert.equal(row!.envelope, null);
      assert.equal(row!.receipt, null);
      assert.equal(ledger!.state, 'outcome_unknown');
      assert.equal(ledger!.closure, null);
      assert.equal(ledger!.cleanup!.token_id, `token-${remote.repos[0]!.id}`);
      assert.equal(remote.counts.create, 1);
      assert.equal(remote.counts.revoke, 1);
      assert.equal(remote.counts.git ?? 0, 0);
      assert.equal(remote.repos[0]!.state, 'revoked');
      assert.doesNotMatch(JSON.stringify([r, row, ledger]), /SYNTHETIC_INITIAL_SECRET|plaintext/);
      await f.restart();
      assert.equal((await f.reconcile()).op_synchronized, true);
      assert.deepEqual(await f.row(), row);
      assert.deepEqual((await f.ledger())!.cleanup, ledger!.cleanup);
      const before = await f.remote();
      assert.equal((await f.execute()).state, 'outcome_unknown');
      assert.deepEqual((await f.remote()).counts, before.counts);
    } finally {
      await f.close();
    }
  });
}
for (const mode of [
  'wrong-description',
  'multiple-tokens',
  'empty-inventory',
  'incomplete-inventory',
  'list-lost',
]) {
  test(`reconciliation quarantines ${mode} without guessing or revoking unrelated tokens`, async () => {
    const f = await fixture();
    try {
      await f.mode('create-lost');
      await f.execute();
      await f.mode(mode);
      const r = await f.reconcile();
      assert.equal(r.state, 'outcome_unknown');
      assert.equal(r.cleanup, undefined);
      assert.equal((await f.ledger())!.cleanup, undefined);
      assert.equal((await f.remote()).counts.create, 1);
      assert.equal((await f.remote()).counts.revoke, 0);
      assert.equal((await f.row())!.state, 'dispatched');
    } finally {
      await f.close();
    }
  });
}
test('lost revoke reply recovers fresh revoked inventory without a second revoke', async () => {
  const f = await fixture();
  try {
    await f.mode('create-lost');
    await f.execute();
    await f.mode('revoke-lost');
    assert.equal((await f.reconcile()).cleanup, undefined);
    assert.equal((await f.remote()).repos[0]!.state, 'revoked');
    await f.restart();
    await f.mode('normal');
    assert.equal((await f.reconcile()).cleanup, 'initial_token_revoked');
    assert.equal((await f.remote()).counts.revoke, 1);
    assert.equal((await f.remote()).counts.create, 1);
  } finally {
    await f.close();
  }
});
for (const safety of ['freeze', 'floor', 'pending', 'missing-key', 'restore']) {
  test(`reconciliation remains safety-only across ${safety}, independently of OP synchronization`, async () => {
    const f = await fixture();
    try {
      if (safety === 'restore') await f.backup();
      await f.mode('create-lost');
      await f.execute();
      await f.mode('normal');
      if (safety === 'restore') await f.restore();
      if (safety === 'freeze') assert.equal((await f.checkpoint({ action: 'freeze' })).status, 200);
      if (safety === 'floor')
        assert.equal((await f.checkpoint({ action: 'raise-floor', floor: 2 })).status, 200);
      if (safety === 'pending') {
        const cp = (await (await f.checkpoint({ action: 'status', release: 1 })).json()) as {
          checkpoint: unknown;
        };
        assert.equal(
          (
            await f.checkpoint({
              action: 'begin',
              release: 1,
              expected: cp.checkpoint,
              operation: 'synthetic-safety-pending',
            })
          ).status,
          200,
        );
      }
      if (safety === 'missing-key')
        await f.restart({ WORK_CREDENTIAL_KEY_V1: '', WORK_CREDENTIAL_KEY_FLOOR: '2' });
      const r = await f.reconcile();
      assert.equal(r.cleanup, 'initial_token_revoked');
      assert.equal(r.state, 'outcome_unknown');
      assert.equal(r.op_synchronized, safety === 'missing-key');
      assert.equal((await f.ledger())!.state, 'outcome_unknown');
      assert.equal((await f.remote()).counts.create, 1);
      assert.equal((await f.remote()).counts.revoke, 1);
    } finally {
      await f.close();
    }
  });
}
test('reconciliation refuses missing admission, cold/scope/public capability and substituted evidence', async () => {
  const f = await fixture();
  try {
    await f.reconcile(f.task.id, 409);
    assert.equal((await f.remote()).counts.get, 0);
    await f.effect({ action: 'reconcile-public' }, 404);
    await f.effect({ action: 'maintenance-claim', plan: await f.plan() }, 409);
    await f.effect(
      { action: 'reconcile', input: { attempt_id: f.task.id, token: 'arbitrary' } },
      409,
    );
    await f.mode('create-lost');
    await f.execute();
    await f.restart({ WORK_EFFECT_RECONCILE_ENABLED: 'false' });
    await f.reconcile(f.task.id, 409);
    await f.restart({ WORK_ARTIFACTS_NAMESPACE: 'wrong' });
    await f.reconcile(f.task.id, 409);
    await f.restart();
    await f.mode('normal');
    await f.reconcile();
    const record = (await f.ledger())!,
      { observed_at, ...e } = record.cleanup!;
    await f.effect(
      {
        action: 'maintenance-record',
        attempt_id: f.task.id,
        digest: record.plan.digest,
        value: { ...e, token_id: 'substitution' },
      },
      409,
    );
    await f.mode('replaced-repo');
    assert.equal((await f.reconcile()).cleanup, undefined);
    await f.mode('replaced-token');
    assert.equal((await f.reconcile()).cleanup, undefined);
    assert.equal((await f.remote()).counts.revoke, 1);
    assert.deepEqual((await f.ledger())!.cleanup, record.cleanup);
  } finally {
    await f.close();
  }
});
test('strongly closed effect reconciliation never reopens remote I/O', async () => {
  const f = await fixture();
  try {
    await f.execute();
    const before = await f.remote();
    const r = await f.reconcile();
    assert.equal(r.state, 'closed');
    assert.equal(r.op_synchronized, true);
    assert.deepEqual((await f.remote()).counts, before.counts);
  } finally {
    await f.close();
  }
});
test('remote removal of revoked tokens requires the retained ID-specific positive acknowledgement', async () => {
  const f = await fixture();
  try {
    await f.mode('create-lost');
    await f.execute();
    await f.mode('remove-revoked');
    assert.equal((await f.reconcile()).op_synchronized, true);
    const l = (await f.ledger())!;
    assert.equal(l.cleanup!.method, 'revoke_acknowledged');
    assert.equal(l.token_observation!.token_id, l.cleanup!.token_id);
    assert.equal(l.state, 'outcome_unknown');
    assert.equal((await f.row())!.state, 'revocation_pending');
    await f.restart();
    await f.mode('remove-revoked');
    assert.equal((await f.reconcile()).op_synchronized, true);
    assert.equal((await f.remote()).counts.revoke, 1);
    assert.equal((await f.remote()).counts.create, 1);
  } finally {
    await f.close();
  }
});
test('lost ID-revoke response followed by removed token cannot become revocation evidence from absence', async () => {
  const f = await fixture();
  try {
    await f.mode('create-lost');
    await f.execute();
    await f.mode('revoke-lost-remove');
    assert.equal((await f.reconcile()).cleanup, undefined);
    const before = await f.ledger();
    assert.ok(before!.token_observation);
    assert.equal(before!.cleanup, undefined);
    await f.restart();
    await f.mode('remove-revoked');
    assert.equal((await f.reconcile()).cleanup, undefined);
    assert.deepEqual(await f.ledger(), before);
    assert.equal((await f.row())!.state, 'dispatched');
    assert.equal((await f.remote()).counts.revoke, 1);
    assert.equal((await f.remote()).counts.create, 1);
  } finally {
    await f.close();
  }
});

test('reconciler receives only the maintenance factory and broker only the read-only ledger', async () => {
  const f = await fixture();
  try {
    const recon = await f.bindingNames('work-reconcile'),
      broker = await f.bindingNames('artifacts-maintenance');
    assert.ok(recon.includes('ARTIFACTS_MAINTENANCE'));
    assert.ok(!recon.includes('ARTIFACTS'));
    assert.ok(broker.includes('ARTIFACTS'));
    assert.ok(broker.includes('EFFECT_LOOKUP'));
    for (const name of [
      'DB',
      'WORK_GIT_PAYLOADS',
      'OP_EFFECT_STORE',
      'EFFECT_MAINTENANCE',
      'EFFECT_CHECKPOINT',
      'CHECKPOINTS',
      'CHECKPOINT_ADMIN',
      'WORK_CREDENTIAL_KEY_V1',
    ])
      assert.ok(!broker.includes(name));
    for (const method of [
      'claim',
      'close',
      'observe',
      'observeToken',
      'recordRevocation',
      'bootstrap',
      'commit',
      'freeze',
      'raiseFloor',
    ])
      await f.effect({ action: 'lookup-call', method, input: {} }, 409);
    for (const method of [
      'create',
      'get',
      'list',
      'delete',
      'fork',
      'createToken',
      'revokeToken',
      'lookup',
      'env',
      'ctx',
    ])
      await f.effect(
        { action: 'broker-factory-call', method, input: { attempt_id: f.task.id } },
        409,
      );
    await f.effect({ action: 'broker-public' }, 404);
    assert.equal((await f.remote()).counts.create, 0);
    assert.equal((await f.remote()).counts.get, 0);
  } finally {
    await f.close();
  }
});
test('maintenance factory denies unadmitted attempts, supplied destinations and cold or foreign scope before remote I/O', async () => {
  const f = await fixture();
  try {
    await f.broker('info', undefined, {}, 409);
    await f.mode('create-lost');
    await f.execute();
    await f.mode('normal');
    for (const input of [
      { attempt_id: f.task.id, name: 'arbitrary' },
      { attempt_id: f.task.id, repo_id: 'arbitrary' },
      { attempt_id: f.task.id, token: 'arbitrary' },
      { attempt_id: f.task.id, namespace: 'other' },
    ])
      await f.broker('info', undefined, { input }, 409);
    await f.restart({ WORK_ARTIFACTS_MAINTENANCE_ENABLED: 'false' });
    await f.broker('info', undefined, {}, 409);
    assert.equal((await f.reconcile()).cleanup, undefined);
    await f.restart({ WORK_MAINTENANCE_NAMESPACE: 'other' });
    await f.broker('info', undefined, {}, 409);
    assert.equal((await f.remote()).counts.get, 0);
    assert.equal((await f.remote()).counts.revoke, 0);
  } finally {
    await f.close();
  }
});
test('returned safety capability exposes metadata, hides its raw repo, and has no mint/fork/write/delete/namespace methods', async () => {
  const f = await fixture();
  try {
    await f.mode('create-lost');
    await f.execute();
    await f.mode('normal');
    const info = await f.broker('info');
    assert.deepEqual(Object.keys(info).sort(), [
      'defaultBranch',
      'description',
      'id',
      'name',
      'remote',
    ]);
    const listed = await f.broker('listTokens');
    assert.equal(listed.total, 1);
    assert.doesNotMatch(JSON.stringify([info, listed]), /SYNTHETIC_INITIAL_SECRET|plaintext/);
    for (const method of [
      'createToken',
      'fork',
      'create',
      'delete',
      'get',
      'readFile',
      'readBlob',
      'readCommit',
      'push',
      'fetch',
      'update',
      'repo',
      '#repo',
      'plan',
      '#lookup',
      'env',
      'ctx',
    ])
      await f.broker(method, {}, {}, 409);
    assert.equal((await f.remote()).counts.create, 1);
    assert.equal((await f.remote()).counts.revoke, 0);
  } finally {
    await f.close();
  }
});
test('ID revoke requires the stored token observation and rejects plaintext, an unrelated token and the other destination', async () => {
  const f = await fixture();
  try {
    await f.mode('create-lost');
    await f.execute();
    await f.execute(f.snapshot.id);
    await f.mode('normal');
    await f.broker('revokeToken', 'token-synthetic-1', {}, 409);
    await f.broker('revokeToken', 'SYNTHETIC_INITIAL_SECRET_1', { observe: true }, 409);
    await f.broker('revokeToken', 'token-synthetic-2', {}, 409);
    await f.broker('revokeToken', { token_id: 'token-synthetic-1' }, {}, 409);
    assert.equal((await f.remote()).counts.revoke, 0);
    assert.equal(
      await f.effect({
        action: 'broker-call',
        input: { attempt_id: f.task.id },
        method: 'revokeToken',
        argument: 'token-synthetic-1',
      }),
      true,
    );
    const remote = await f.remote();
    assert.equal(remote.counts.create, 2);
    assert.equal(remote.counts.revoke, 1);
    assert.equal(remote.repos[0]!.state, 'revoked');
    assert.equal(remote.repos[1]!.state, 'active');
    assert.equal((await f.ledger())!.cleanup, undefined);
  } finally {
    await f.close();
  }
});
for (const mode of [
  'multiple-tokens',
  'incomplete-inventory',
  'replaced-token',
  'fractional-expiry',
]) {
  test(`maintenance revoke rejects changed ${mode} independently of caller validation`, async () => {
    const f = await fixture();
    try {
      await f.mode('create-lost');
      await f.execute();
      await f.mode('normal');
      await f.broker('info', undefined, { observe: true });
      await f.mode(mode);
      await f.broker('revokeToken', 'token-synthetic-1', {}, 409);
      assert.equal((await f.remote()).counts.revoke, 0);
      assert.equal((await f.remote()).counts.create, 1);
    } finally {
      await f.close();
    }
  });
}
test('a held safety capability checks identity and admission again and cannot survive disposal', async () => {
  const f = await fixture();
  try {
    await f.mode('create-lost');
    await f.execute();
    await f.mode('normal');
    await f.broker('info', undefined, { pause: 'replace' }, 409);
    await f.mode('normal');
    await f.broker('info', undefined, { dispose: true }, 409);
    await f.broker('info', undefined, { pause: 'close' }, 409);
    const before = await f.remote();
    await f.broker('info', undefined, {}, 409);
    assert.deepEqual((await f.remote()).counts, before.counts);
    assert.equal(before.counts.revoke, 0);
    assert.equal(before.counts.create, 1);
  } finally {
    await f.close();
  }
});
