import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { effectFixture } from './support/work-effect-fixture.ts';
import type { MintRecord, MintCleanup } from '../../crates/work-effect-worker/protocol.ts';

async function fixture(
  role: 'task' | 'snapshot' = 'task',
  purpose: 'upload' | 'readback' = 'upload',
  observed = true,
  interrupts: Record<string, string> = {},
) {
  const f = await effectFixture();
  try {
    assert.equal((await f.execute(role === 'task' ? f.task.id : f.snapshot.id)).state, 'closed');
    const a = await f.call({
        action: 'reserve-credential',
        credential: { preparation_id: f.p.id, role, purpose },
      }),
      id = a.id;
    await f.backup();
    if (observed) {
      await f.restart({ LOCAL_MINT_LEDGER_LOST: 'observe', ...interrupts });
      await f.mode('mint-revoke-failed');
    } else await f.mode('mint-lost');
    assert.equal(
      (await f.effect<{ state: string }>({ action: 'mint', input: { attempt_id: id } })).state,
      'outcome_unknown',
    );
    const ledger = () => f.effect<MintRecord>({ action: 'mint-lookup', attempt_id: id });
    assert.equal(Boolean((await ledger()).observation), observed);
    await f.restart();
    await f.mode('normal');
    return {
      ...f,
      id,
      get DB() {
        return f.DB;
      },
      ledger,
      recover: (status = 200, input: unknown = { attempt_id: id }) =>
        f.effect<Record<string, unknown>>({ action: 'mint-reconcile', input }, status),
      mint: () => f.effect<Record<string, unknown>>({ action: 'mint', input: { attempt_id: id } }),
      row: () =>
        f.DB.prepare(
          'SELECT state,observation,envelope,receipt,revision FROM work_credential_attempt WHERE attempt_id=?',
        )
          .bind(id)
          .first<Record<string, unknown>>(),
      broker: (
        method: string,
        argument?: unknown,
        extra: Record<string, unknown> = {},
        status = 200,
      ) =>
        f.effect<Record<string, unknown>>(
          { action: 'mint-broker-call', input: { attempt_id: id }, method, argument, ...extra },
          status,
        ),
      safety: (method: string, args: unknown[] = [], status = 200) =>
        f.effect<Record<string, unknown>>({ action: 'mint-safety-call', method, args }, status),
    };
  } catch (error) {
    await f.close();
    throw error;
  }
}
for (const role of ['task', 'snapshot'] as const)
  for (const purpose of ['upload', 'readback'] as const) {
    test(`${role}/${purpose}: known-ID recovery revokes once, retains charge and survives restart without mint/Git/release`, async () => {
      const f = await fixture(role, purpose);
      try {
        const before = await f.remote(),
          o = (await f.ledger()).observation!;
        assert.equal(before.repos[0]!.tokens[0]!.state, 'active');
        const result = await f.recover();
        assert.equal(result.cleanup, 'revoke_acknowledged');
        assert.equal(result.op_synchronized, true);
        assert.equal(result.state, 'outcome_unknown');
        const l = await f.ledger(),
          r = (await f.row())!,
          after = await f.remote();
        assert.equal(l.cleanup!.token_id, o.token_id);
        assert.equal(l.cleanup_requested, true);
        assert.equal(l.cleanup!.scope, purpose === 'upload' ? 'write' : 'read');
        assert.equal(l.state, 'outcome_unknown');
        assert.equal(r.state, 'revocation_pending');
        assert.equal(r.receipt, null);
        assert.equal(after.counts.revoke, before.counts.revoke! + 1);
        assert.equal(after.repos[0]!.tokens[0]!.state, 'revoked');
        assert.equal(after.counts.mint, 1);
        assert.equal(after.counts.create, 1);
        assert.equal(after.counts.git, before.counts.git);
        assert.equal(
          await f.DB.prepare(
            "SELECT sum(reserved_bytes) AS n FROM work_credential_attempt WHERE attempt_id=? AND state!='closed'",
          )
            .bind(f.id)
            .first('n'),
          8192,
        );
        assert.equal(
          await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
            .bind(f.p.id)
            .first('state'),
          'dispatched',
        );
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
        assert.doesNotMatch(
          JSON.stringify([result, l, r, after]),
          /SYNTHETIC_MINT_SECRET|plaintext|ciphertext/,
        );
        await f.restart();
        assert.equal((await f.recover()).op_synchronized, true);
        assert.equal((await f.mint()).state, 'outcome_unknown');
        assert.deepEqual((await f.remote()).counts, after.counts);
      } finally {
        await f.close();
      }
    });
  }
test('a lost mint reply without a token ID remains unobserved even with exactly one active matching token', async () => {
  const f = await fixture('task', 'upload', false);
  try {
    const before = await f.remote();
    assert.equal((await f.recover()).cleanup, 'token_unobserved');
    assert.equal((await f.ledger()).observation, null);
    assert.equal((await f.ledger()).cleanup, undefined);
    assert.equal((await f.row())!.state, 'dispatched');
    assert.equal((await f.remote()).counts.revoke, before.counts.revoke);
    assert.equal((await f.remote()).repos[0]!.tokens[0]!.state, 'active');
    await f.broker('revokeToken', 'mint-1', {}, 409);
    await f.restart();
    assert.equal((await f.recover()).cleanup, 'token_unobserved');
    assert.equal((await f.mint()).state, 'outcome_unknown');
    assert.equal((await f.remote()).counts.mint, 1);
  } finally {
    await f.close();
  }
});
test('cleanup intent fences custody for an admitted in-flight mint and retains late evidence', async () => {
  const f = await effectFixture();
  try {
    await f.execute();
    const a = await f.call({
      action: 'reserve-credential',
      credential: { preparation_id: f.p.id, role: 'task', purpose: 'upload' },
    });
    await f.restart({ LOCAL_MINT_BEGIN_CLEANUP: 'true' });
    const result = await f.effect<{ state: string }>({
      action: 'mint',
      input: { attempt_id: a.id },
    });
    assert.equal(result.state, 'outcome_unknown');
    const l = await f.effect<MintRecord>({ action: 'mint-lookup', attempt_id: a.id });
    assert.equal(l.cleanup_requested, true);
    assert.equal(l.revoke_acknowledged, true);
    assert.equal(l.state, 'outcome_unknown');
    assert.equal((await f.remote()).repos[0]!.tokens[0]!.state, 'revoked');
    const before = (await f.remote()).counts;
    await f.restart();
    const recovered = await f.effect<{ op_synchronized: boolean }>({
      action: 'mint-reconcile',
      input: { attempt_id: a.id },
    });
    assert.equal(recovered.op_synchronized, true);
    assert.equal((await f.remote()).counts.revoke, before.revoke);
    assert.equal((await f.remote()).counts.mint, 1);
  } finally {
    await f.close();
  }
});
for (const loss of ['mint-revoke-lost', 'mint-revoke-lost-remove']) {
  test(`lost ${loss} keeps uncertainty; only a later positive observation supplies cleanup evidence`, async () => {
    const f = await fixture();
    try {
      await f.mode(loss);
      assert.equal((await f.recover()).cleanup, 'unconfirmed');
      let l = await f.ledger();
      assert.equal(l.revoke_acknowledged, false);
      assert.equal(l.cleanup, undefined);
      const counts = (await f.remote()).counts;
      await f.restart();
      // Preserve the provider's inventory-removal behavior across recovery.
      await f.mode(loss === 'mint-revoke-lost' ? 'normal' : 'mint-remove-revoked');
      const recovered = await f.recover();
      l = await f.ledger();
      assert.equal(
        recovered.cleanup,
        loss === 'mint-revoke-lost' ? 'revoked_inventory' : 'unconfirmed',
      );
      assert.equal(Boolean(l.cleanup), loss === 'mint-revoke-lost');
      assert.equal((await f.remote()).counts.revoke, counts.revoke);
      assert.equal((await f.remote()).counts.mint, 1);
    } finally {
      await f.close();
    }
  });
}
test('positive ID-specific acknowledgement survives token removal and restart', async () => {
  const f = await fixture();
  try {
    await f.mode('mint-remove-revoked');
    assert.equal((await f.recover()).cleanup, 'revoke_acknowledged');
    assert.equal((await f.ledger()).cleanup!.method, 'revoke_acknowledged');
    const counts = (await f.remote()).counts;
    await f.restart();
    assert.equal((await f.recover()).op_synchronized, true);
    assert.deepEqual((await f.remote()).counts, counts);
  } finally {
    await f.close();
  }
});
for (const mode of [
  'replaced-repo',
  'wrong-description',
  'incomplete-inventory',
  'list-lost',
  'mint-substitute-scope',
  'mint-substitute-expiry',
  'mint-expired',
  'mint-missing-token',
  'empty-inventory',
  'multiple-tokens',
]) {
  test(`recovery quarantines ${mode} without revoking a substituted or unobserved token`, async () => {
    const f = await fixture();
    try {
      const before = (await f.remote()).counts;
      await f.mode(mode);
      assert.equal((await f.recover()).cleanup, 'unconfirmed');
      assert.equal((await f.ledger()).cleanup, undefined);
      assert.equal((await f.remote()).counts.revoke, before.revoke);
      assert.equal((await f.remote()).counts.mint, 1);
    } finally {
      await f.close();
    }
  });
}
for (const mode of ['freeze', 'floor', 'pending', 'missing-key', 'op-disabled', 'restore']) {
  test(`${mode}: independent cleanup preserves Native fencing and needs no wrapping key`, async () => {
    const f = await fixture('task', 'upload', true, { LOCAL_MINT_CLEANUP_LOST: 'true' });
    try {
      assert.equal((await f.row())!.state, 'dispatched');
      if (mode === 'freeze') await f.checkpoint({ action: 'freeze' });
      if (mode === 'floor') await f.checkpoint({ action: 'raise-floor', floor: 2 });
      if (mode === 'pending') {
        const c = await f.DB.prepare(
          'SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1',
        ).first();
        assert.equal(
          (
            await f.checkpoint({
              action: 'begin',
              expected: c,
              operation: 'recovery-pending',
              release: 1,
            })
          ).status,
          200,
        );
      }
      if (mode === 'missing-key')
        await f.restart({ WORK_CREDENTIAL_KEY_FLOOR: '2', WORK_CREDENTIAL_KEY_V1: '' });
      if (mode === 'op-disabled') await f.restart({ WORK_EFFECT_STORE_ENABLED: 'false' });
      if (mode === 'restore') await f.restore();
      const before = (await f.remote()).counts,
        native = await f.row();
      const result = await f.recover();
      assert.equal(result.cleanup, 'revoke_acknowledged');
      assert.equal(result.op_synchronized, mode === 'missing-key');
      assert.equal((await f.ledger()).cleanup!.token_id, 'mint-1');
      assert.equal((await f.remote()).counts.revoke, before.revoke! + 1);
      assert.equal((await f.remote()).counts.mint, 1);
      if (mode !== 'missing-key') assert.deepEqual(await f.row(), native);
      if (mode === 'restore') assert.equal((await f.row())!.state, 'reserved');
    } finally {
      await f.close();
    }
  });
}
test('read-only broker and safety-only reconciler reject widening, raw methods and unadmitted attempts', async () => {
  const f = await fixture();
  try {
    assert.deepEqual((await f.bindingNames('mint-maintenance')).sort(), [
      'ARTIFACTS',
      'MINT_LOOKUP',
      'WORK_ARTIFACTS_ACCOUNT',
      'WORK_ARTIFACTS_NAMESPACE',
      'WORK_AUTHORITY_ID',
      'WORK_MINT_MAINTENANCE_ENABLED',
    ]);
    assert.deepEqual((await f.bindingNames('mint-reconcile')).sort(), [
      'MINT_ARTIFACTS_MAINTENANCE',
      'MINT_MAINTENANCE',
      'OP_EFFECT_STORE',
      'WORK_ARTIFACTS_ACCOUNT',
      'WORK_ARTIFACTS_NAMESPACE',
      'WORK_AUTHORITY_ID',
      'WORK_MINT_RECONCILE_ENABLED',
    ]);
    for (const action of ['mint-broker-public', 'mint-reconcile-public'])
      await f.effect({ action }, 404);
    const before = (await f.remote()).counts;
    for (const extra of [
      { repo_id: 'unrelated' },
      { scope: 'write' },
      { token_id: 'mint-1' },
      { url: 'https://wrong.invalid' },
    ])
      await f.recover(409, { attempt_id: f.id, ...extra });
    await f.recover(409, { attempt_id: randomBytes(32).toString('base64url') });
    for (const method of [
      'claim',
      'observe',
      'custody',
      'abandon',
      'close',
      'bootstrap',
      'freeze',
      'reset',
    ])
      await f.safety(method, [], 409);
    for (const method of ['begin', 'record', 'claim', 'observe', 'custody', 'revoked', 'reset'])
      await f.effect({ action: 'mint-lookup-call', method, args: [] }, 409);
    for (const method of ['create', 'get', 'createToken', 'fork', 'delete', 'mint', 'env'])
      await f.effect(
        { action: 'mint-broker-factory-call', method, input: { attempt_id: f.id } },
        409,
      );
    assert.deepEqual((await f.remote()).counts, before);
    for (const method of [
      'createToken',
      'fork',
      'readFile',
      'readTree',
      'delete',
      'get',
      'repo',
      'lookup',
      'plan',
      'env',
    ])
      await f.broker(method, undefined, {}, 409);
    assert.equal((await f.remote()).counts.mint, 1);
    assert.equal((await f.remote()).counts.revoke, before.revoke);
    const disabled: Record<string, string>[] = [
      { WORK_MINT_RECONCILE_ENABLED: 'false' },
      { WORK_MINT_MAINTENANCE_ENABLED: 'false' },
      { WORK_MINT_MAINTENANCE_NAMESPACE: 'foreign' },
    ];
    for (const overrides of disabled) {
      await f.restart(overrides);
      const r = await f.recover(overrides.WORK_MINT_RECONCILE_ENABLED ? 409 : 200);
      if (!overrides.WORK_MINT_RECONCILE_ENABLED) assert.equal(r.cleanup, 'unconfirmed');
      assert.equal((await f.remote()).counts.revoke, before.revoke);
    }
  } finally {
    await f.close();
  }
});
test('failed revoke retains an active liability; later known-ID cleanup does not mint again', async () => {
  const f = await fixture();
  try {
    await f.mode('mint-revoke-failed');
    assert.equal((await f.recover()).cleanup, 'unconfirmed');
    assert.equal((await f.ledger()).revoke_acknowledged, false);
    assert.equal((await f.remote()).repos[0]!.tokens[0]!.state, 'active');
    await f.restart();
    await f.mode('normal');
    assert.equal((await f.recover()).cleanup, 'revoke_acknowledged');
    assert.equal((await f.remote()).counts.mint, 1);
  } finally {
    await f.close();
  }
});
test('acknowledgement is durable before a lost follow-up inventory and supports later token removal', async () => {
  const f = await fixture();
  try {
    await f.mode('mint-list-after-revoke-lost');
    assert.equal((await f.recover()).cleanup, 'unconfirmed');
    assert.equal((await f.ledger()).revoke_acknowledged, true);
    assert.equal((await f.ledger()).cleanup, undefined);
    const before = (await f.remote()).counts;
    await f.restart();
    await f.mode('mint-remove-revoked');
    assert.equal((await f.recover()).cleanup, 'revoke_acknowledged');
    assert.equal((await f.remote()).counts.revoke, before.revoke);
    assert.equal((await f.remote()).counts.mint, 1);
  } finally {
    await f.close();
  }
});
test('safety evidence requires exact stored metadata and acknowledgement; the first proof is immutable', async () => {
  const f = await fixture();
  try {
    const r = await f.ledger(),
      proof: MintCleanup = {
        ...r.observation!,
        format_version: 1,
        method: 'revoke_acknowledged',
        receipt: 'b'.repeat(64),
      };
    // A receipt hash is not itself a qualified provider acknowledgement.
    await f.safety('record', [f.id, r.plan.digest, proof], 409);
    for (const change of [
      { repo_id: 'foreign' },
      { token_id: 'mint-2' },
      { scope: 'read' },
      { expires_at: proof.expires_at + 1 },
      { format_version: 2 },
      { method: 'expired' },
      { receipt: 'invalid' },
      { plaintext: 'unrequested' },
    ])
      await f.safety(
        'record',
        [f.id, r.plan.digest, { ...proof, method: 'revoked_inventory', ...change }],
        409,
      );
    await f.safety('begin', [f.id, 'a'.repeat(64)], 409);
    await f.recover();
    const accepted = (await f.ledger()).cleanup!,
      { observed_at, ...retained } = accepted;
    assert.ok(observed_at > 0);
    await f.safety('record', [f.id, r.plan.digest, retained]);
    await f.safety('record', [f.id, r.plan.digest, { ...retained, receipt: 'd'.repeat(64) }], 409);
    await f.safety(
      'record',
      [f.id, r.plan.digest, { ...retained, method: 'revoked_inventory' }],
      409,
    );
    assert.deepEqual((await f.ledger()).cleanup, accepted);
  } finally {
    await f.close();
  }
});
test('an exact Native revocation-pending status upgrades a retained custody record without provider replay', async () => {
  const f = await effectFixture();
  try {
    await f.execute();
    const a = await f.call({
      action: 'reserve-credential',
      credential: { preparation_id: f.p.id, role: 'task', purpose: 'upload' },
    });
    const mint = () => f.effect<{ state: string }>({ action: 'mint', input: { attempt_id: a.id } });
    assert.equal((await mint()).state, 'custodied');
    await f.call({ action: 'credential-revoke', id: a.id });
    assert.equal((await f.row(a.id))!.state, 'revocation_pending');
    const before = (await f.remote()).counts;
    assert.equal((await mint()).state, 'outcome_unknown');
    assert.deepEqual((await f.remote()).counts, before);
    assert.equal(
      (await f.effect<MintRecord>({ action: 'mint-lookup', attempt_id: a.id })).cleanup_requested,
      true,
    );
    assert.equal(
      (
        await f.effect<{ cleanup: string }>({
          action: 'mint-reconcile',
          input: { attempt_id: a.id },
        })
      ).cleanup,
      'revoke_acknowledged',
    );
    assert.equal((await f.remote()).counts.revoke, before.revoke! + 1);
    assert.equal((await f.remote()).counts.mint, 1);
  } finally {
    await f.close();
  }
});
test('a held maintenance capability rechecks identity, disposal and completed cleanup', async () => {
  const f = await fixture();
  try {
    const r = await f.ledger();
    await f.safety('begin', [f.id, r.plan.digest]);
    await f.broker('info', undefined, { pause: 'replace' }, 409);
    await f.mode('normal');
    await f.broker('info', undefined, { dispose: true }, 409);
    const proof: MintCleanup = {
      ...r.observation!,
      format_version: 1,
      method: 'revoked_inventory',
      receipt: 'c'.repeat(64),
    };
    // The privileged fixture simulates independent completion while a stub is held.
    await f.broker('info', undefined, { complete: proof }, 409);
    const before = (await f.remote()).counts;
    await f.broker('info', undefined, {}, 409);
    assert.deepEqual((await f.remote()).counts, before);
  } finally {
    await f.close();
  }
});
test('the broker only revokes the stored ID after safety intent; plaintext and other IDs are refused', async () => {
  const f = await fixture('task', 'upload', true, {
    LOCAL_MINT_LEDGER_LOST: 'observe-and-abandon',
  });
  try {
    const r = await f.ledger();
    assert.equal(r.cleanup_requested, undefined);
    await f.broker('revokeToken', 'mint-1', {}, 409);
    await f.safety('begin', [f.id, r.plan.digest]);
    for (const token of ['SYNTHETIC_MINT_SECRET_1', 'token-synthetic-1', 'unrelated', 'mint-2'])
      await f.broker('revokeToken', token, {}, 409);
    const before = (await f.remote()).counts;
    assert.equal(await f.broker('revokeToken', 'mint-1'), true);
    assert.equal((await f.remote()).counts.revoke, before.revoke! + 1);
    assert.equal((await f.recover()).cleanup, 'revoked_inventory');
  } finally {
    await f.close();
  }
});
test('custodied success is not eligible for recovery, but lost custody acknowledgement and failed revoke abandon it', async () => {
  const f = await effectFixture();
  try {
    await f.execute();
    const a = await f.call({
      action: 'reserve-credential',
      credential: { preparation_id: f.p.id, role: 'task', purpose: 'upload' },
    });
    await f.restart({ LOCAL_MINT_LEDGER_LOST: 'custody' });
    await f.mode('mint-revoke-failed');
    assert.equal(
      (await f.effect<{ state: string }>({ action: 'mint', input: { attempt_id: a.id } })).state,
      'outcome_unknown',
    );
    const l = await f.effect<MintRecord>({ action: 'mint-lookup', attempt_id: a.id });
    assert.equal(l.state, 'outcome_unknown');
    assert.equal(l.cleanup_requested, true);
    assert.equal(l.revoke_acknowledged, false);
    await f.restart();
    await f.mode('normal');
    assert.equal(
      (
        await f.effect<{ cleanup: string }>({
          action: 'mint-reconcile',
          input: { attempt_id: a.id },
        })
      ).cleanup,
      'revoke_acknowledged',
    );
    assert.equal((await f.remote()).counts.mint, 1);
    const snap = await f.execute(f.snapshot.id);
    assert.equal(snap.state, 'closed');
    const b = await f.call({
      action: 'reserve-credential',
      credential: { preparation_id: f.p.id, role: 'snapshot', purpose: 'readback' },
    });
    assert.equal(
      (await f.effect<{ state: string }>({ action: 'mint', input: { attempt_id: b.id } })).state,
      'custodied',
    );
    const before = (await f.remote()).counts;
    await f.effect({ action: 'mint-reconcile', input: { attempt_id: b.id } }, 409);
    await f.effect(
      {
        action: 'mint-safety-call',
        method: 'revoked',
        args: [
          b.id,
          (await f.effect<MintRecord>({ action: 'mint-lookup', attempt_id: b.id })).plan.digest,
        ],
      },
      409,
    );
    assert.deepEqual((await f.remote()).counts, before);
  } finally {
    await f.close();
  }
});
