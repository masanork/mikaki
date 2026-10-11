import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { effectFixture } from './support/work-effect-fixture.ts';
import type { MintRecord } from '../../crates/work-effect-worker/protocol.ts';

async function fixture(
  role: 'task' | 'snapshot' = 'task',
  purpose: 'upload' | 'readback' = 'upload',
  custody = true,
) {
  const f = await effectFixture();
  try {
    await f.execute(role === 'task' ? f.task.id : f.snapshot.id);
    const a = await f.call({
        action: 'reserve-credential',
        credential: { preparation_id: f.p.id, role, purpose },
      }),
      id = a.id;
    await f.backup();
    if (!custody) {
      await f.restart({ LOCAL_MINT_LEDGER_LOST: 'observe' });
      await f.mode('mint-revoke-failed');
    }
    const mint = () =>
      f.effect<Record<string, unknown>>({ action: 'mint', input: { attempt_id: id } });
    assert.equal((await mint()).state, custody ? 'custodied' : 'outcome_unknown');
    await f.restart();
    await f.mode('normal');
    if (custody) {
      await f.call({ action: 'credential-revoke', id });
      assert.equal((await mint()).state, 'outcome_unknown');
    }
    const ledger = () => f.effect<MintRecord>({ action: 'mint-lookup', attempt_id: id });
    const recover = () =>
      f.effect<Record<string, unknown>>({ action: 'mint-reconcile', input: { attempt_id: id } });
    const close = (status = 200, input: unknown = { attempt_id: id }) =>
      f.effect<Record<string, unknown>>({ action: 'mint-close', input }, status);
    return {
      ...f,
      id,
      ledger,
      mint,
      recover,
      finish: close,
      get DB() {
        return f.DB;
      },
      row: () =>
        f.DB.prepare(
          'SELECT state,revision,observation,envelope,key_version,confirmation,receipt FROM work_credential_attempt WHERE attempt_id=?',
        )
          .bind(id)
          .first<Record<string, unknown>>(),
    };
  } catch (error) {
    await f.close();
    throw error;
  }
}
for (const role of ['task', 'snapshot'] as const)
  for (const purpose of ['upload', 'readback'] as const) {
    test(`${role}/${purpose}: a Native-decrypted bearer refusal closes only that credential and survives restart without replay`, async () => {
      const f = await fixture(role, purpose);
      try {
        assert.equal((await f.recover()).cleanup, 'revoke_acknowledged');
        assert.ok((await f.row())!.envelope);
        const before = (await f.remote()).counts;
        const result = await f.finish(),
          l = await f.ledger(),
          r = (await f.row())!;
        assert.equal(result.state, 'closed');
        assert.equal(result.op_synchronized, true);
        assert.equal(l.state, 'closed');
        assert.equal(l.refusal!.status, 403);
        assert.equal(l.refusal!.scope, purpose === 'upload' ? 'write' : 'read');
        assert.equal(r.state, 'closed');
        assert.equal(r.envelope, null);
        assert.equal(r.confirmation, 'refused');
        assert.equal(r.receipt, l.refusal!.receipt);
        assert.equal((await f.remote()).counts.git, (before.git ?? 0) + 1);
        assert.equal((await f.remote()).counts.mint, 1);
        assert.equal(
          await f.DB.prepare(
            "SELECT sum(reserved_bytes) AS n FROM work_credential_attempt WHERE attempt_id=? AND state!='closed'",
          )
            .bind(f.id)
            .first('n'),
          null,
        );
        assert.equal(
          await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
            .bind(f.p.id)
            .first('state'),
          'dispatched',
        );
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
        assert.doesNotMatch(
          JSON.stringify([result, l, r, await f.remote()]),
          /SYNTHETIC_MINT_SECRET|plaintext|ciphertext|Authorization/,
        );
        const after = (await f.remote()).counts;
        await f.restart();
        assert.equal((await f.finish()).op_synchronized, true);
        assert.equal((await f.mint()).state, 'closed');
        assert.deepEqual((await f.remote()).counts, after);
      } finally {
        await f.close();
      }
    });
  }
test('control-plane cleanup without encrypted custody cannot certify a bearer refusal or release charge', async () => {
  const f = await fixture('task', 'upload', false);
  try {
    await f.recover();
    assert.equal((await f.row())!.envelope, null);
    const before = (await f.remote()).counts;
    assert.equal((await f.finish()).cleanup, 'refusal_unconfirmed');
    assert.equal((await f.ledger()).refusal, undefined);
    assert.equal((await f.row())!.state, 'revocation_pending');
    assert.deepEqual((await f.remote()).counts, before);
    assert.equal(
      await f.DB.prepare(
        "SELECT reserved_bytes FROM work_credential_attempt WHERE attempt_id=? AND state!='closed'",
      )
        .bind(f.id)
        .first('reserved_bytes'),
      8192,
    );
  } finally {
    await f.close();
  }
});
for (const mode of [
  'git-active',
  'git-unavailable',
  'git-redirect',
  'replaced-repo',
  'wrong-description',
  'incomplete-inventory',
  'mint-substitute-scope',
  'mint-substitute-expiry',
  'mint-expired',
]) {
  test(`${mode}: refusal failure retains custody, charge and the same admission`, async () => {
    const f = await fixture();
    try {
      await f.recover();
      await f.mode(mode);
      const native = await f.row(),
        before = (await f.remote()).counts;
      assert.equal((await f.finish()).cleanup, 'refusal_unconfirmed');
      assert.equal((await f.ledger()).refusal, undefined);
      assert.deepEqual(await f.row(), native);
      assert.equal((await f.remote()).counts.mint, 1);
      assert.equal((await f.remote()).counts.revoke, before.revoke);
      await f.restart();
      await f.mode('normal');
      assert.equal((await f.finish()).state, 'closed');
    } finally {
      await f.close();
    }
  });
}
test('missing/substituted wrapping authority and unframed ciphertext mutation fail closed', async () => {
  const f = await fixture();
  try {
    await f.recover();
    const native = (await f.row())!,
      before = (await f.remote()).counts;
    await f.restart({ WORK_CREDENTIAL_KEY_FLOOR: '2', WORK_CREDENTIAL_KEY_V1: '' });
    assert.equal((await f.finish()).cleanup, 'refusal_unconfirmed');
    assert.deepEqual((await f.remote()).counts, before);
    await f.restart();
    await assert.rejects(
      f.DB.prepare('UPDATE work_credential_attempt SET envelope=? WHERE attempt_id=?')
        .bind(String(native.envelope).replace(/.$/, '!'), f.id)
        .run(),
      /work_preparation_guard_failed/,
    );
    assert.equal((await f.row())!.envelope, native.envelope);
    await f.restart({ WORK_CREDENTIAL_KEY_V1: randomBytes(32).toString('base64url') });
    assert.equal((await f.finish()).cleanup, 'refusal_unconfirmed');
    assert.deepEqual((await f.remote()).counts, before);
    assert.equal((await f.ledger()).state, 'outcome_unknown');
  } finally {
    await f.close();
  }
});
for (const fault of [
  'LOCAL_MINT_REFUSAL_LOST',
  'LOCAL_MINT_CLOSE_LOST',
  'LOCAL_MINT_CLOSE_FREEZE',
]) {
  test(`${fault}: independent refusal survives lost acknowledgements or Native fencing`, async () => {
    const f = await fixture();
    try {
      await f.recover();
      const before = (await f.remote()).counts;
      await f.restart({ [fault]: 'true' });
      const result = await f.finish();
      assert.equal(result.state, 'closed');
      assert.equal(result.op_synchronized, fault === 'LOCAL_MINT_REFUSAL_LOST');
      const l = await f.ledger();
      assert.ok(l.refusal);
      assert.equal(l.state, 'closed');
      assert.equal((await f.remote()).counts.git, (before.git ?? 0) + 1);
      assert.equal(
        (await f.row())!.state,
        fault === 'LOCAL_MINT_CLOSE_FREEZE' ? 'revocation_pending' : 'closed',
      );
      const after = (await f.remote()).counts;
      await f.restart({ WORK_CREDENTIAL_KEY_FLOOR: '2', WORK_CREDENTIAL_KEY_V1: '' });
      assert.equal((await f.finish()).op_synchronized, fault !== 'LOCAL_MINT_CLOSE_FREEZE');
      assert.deepEqual((await f.remote()).counts, after);
    } finally {
      await f.close();
    }
  });
}
test('whole D1 restore cannot reopen a strongly closed mint or reconstruct its secret', async () => {
  const f = await fixture();
  try {
    await f.recover();
    await f.finish();
    const before = (await f.remote()).counts;
    await f.restore();
    assert.equal((await f.row())!.state, 'reserved');
    assert.equal((await f.finish()).op_synchronized, false);
    assert.equal((await f.mint()).state, 'closed');
    assert.deepEqual((await f.remote()).counts, before);
    const r = await f.ledger();
    for (const method of ['abandon', 'revoked', 'custody'])
      await f.effect({ action: 'mint-ledger-call', method, args: [f.id, r.plan.digest] }, 409);
    assert.equal((await f.ledger()).state, 'closed');
  } finally {
    await f.close();
  }
});
test('closure capabilities deny supplied destinations, plaintext, cold/public and widened RPC', async () => {
  const f = await fixture();
  try {
    await f.finish(409); // No control-plane cleanup proof yet.
    await f.recover();
    const before = (await f.remote()).counts;
    for (const action of ['mint-close-public', 'mint-refusal-public'])
      await f.effect({ action }, 404);
    await f.finish(409, { attempt_id: randomBytes(32).toString('base64url') });
    for (const extra of [
      { repo_id: 'foreign' },
      { receipt: 'a'.repeat(64) },
      { plaintext: 'unrequested' },
      { url: 'https://wrong.invalid' },
    ])
      await f.finish(409, { attempt_id: f.id, ...extra });
    for (const method of [
      'claim',
      'observe',
      'custody',
      'begin',
      'abandon',
      'revoked',
      'reset',
      'freeze',
    ])
      await f.effect({ action: 'mint-refusal-call', method, args: [] }, 409);
    const r = await f.ledger();
    for (const input of [
      {
        action: 'mint-refusal',
        attempt_id: f.id,
        digest: r.plan.digest,
        ...r.observation,
        key_version: 1,
        plaintext: 'unrequested',
      },
      {
        action: 'mint-refusal',
        attempt_id: f.id,
        digest: r.plan.digest,
        ...r.observation,
        key_version: 2,
      },
      {
        action: 'mint-close',
        attempt_id: f.id,
        digest: r.plan.digest,
        ...r.observation,
        key_version: 1,
        receipt: 'a'.repeat(64),
      },
    ])
      await f.effect({ action: 'plan', input }, 409);
    assert.deepEqual((await f.remote()).counts, before);
    await f.restart({ WORK_MINT_CLOSURE_ENABLED: 'false' });
    await f.finish(409);
    await f.restart({ WORK_MINT_REFUSAL_TRANSPORT_ENABLED: 'false' });
    assert.equal((await f.finish()).cleanup, 'refusal_unconfirmed');
    assert.deepEqual((await f.remote()).counts, before);
    await f.restart();
    await f.finish();
    const proof = (await f.ledger()).refusal!,
      { observed_at, ...retained } = proof;
    assert.ok(observed_at);
    await f.effect({
      action: 'mint-refusal-call',
      method: 'refused',
      args: [f.id, r.plan.digest, retained],
    });
    for (const change of [
      { receipt: 'c'.repeat(64) },
      { token_id: 'mint-2' },
      { status: 200 },
      { key_version: 2 },
    ])
      await f.effect(
        {
          action: 'mint-refusal-call',
          method: 'refused',
          args: [f.id, r.plan.digest, { ...retained, ...change }],
        },
        409,
      );
    assert.deepEqual((await f.ledger()).refusal, proof);
    assert.deepEqual(
      (await f.bindingNames('mint-closure')).filter((n) => !n.startsWith('WORK_')).sort(),
      ['MINT_REFUSAL_CHECKPOINT', 'OP_MINT_STORE'],
    );
    assert.deepEqual(
      (await f.bindingNames('mint-refusal-transport')).filter((n) => !n.startsWith('WORK_')).sort(),
      ['ARTIFACTS', 'MINT_LOOKUP'],
    );
  } finally {
    await f.close();
  }
});
test('refusal transport rejects non-fixed requests before provider I/O', async () => {
  const f = await fixture();
  try {
    await f.recover();
    const r = await f.ledger();
    const url = `https://${'a'.repeat(32)}.artifacts.cloudflare.net/git/mikaki-dev/${r.plan.name}.git/info/refs?service=git-upload-pack`;
    const headers = { Authorization: 'Bearer SYNTHETIC_UNQUALIFIED', 'X-Mikaki-Attempt-ID': f.id };
    const before = (await f.remote()).counts;
    for (const change of [
      { headers: {} },
      { method: 'POST' },
      { url: 'https://wrong.invalid/' },
      { url: url.replace('git-upload-pack', 'git-receive-pack') },
      { url: url + '&extra=1' },
      { headers: { ...headers, 'X-Mikaki-Attempt-ID': randomBytes(32).toString('base64url') } },
    ])
      await f.effect({ action: 'mint-refusal-transport', url, headers, ...change }, 409);
    assert.deepEqual((await f.remote()).counts, before);
  } finally {
    await f.close();
  }
});
test('Native closure audit abort retains independent proof and retries without another network probe', async () => {
  const f = await fixture();
  try {
    await f.recover();
    const native = await f.row();
    await f.DB.exec(
      "CREATE TRIGGER fail_mint_close BEFORE INSERT ON work_audit WHEN NEW.action='credential.closed' BEGIN SELECT RAISE(ABORT,'synthetic closure audit failure'); END;",
    );
    const first = await f.finish();
    assert.equal(first.state, 'closed');
    assert.equal(first.op_synchronized, false);
    assert.deepEqual(await f.row(), native);
    assert.ok((await f.ledger()).refusal);
    const before = (await f.remote()).counts;
    await f.DB.exec('DROP TRIGGER fail_mint_close');
    assert.equal((await f.finish()).op_synchronized, true);
    assert.deepEqual((await f.remote()).counts, before);
    assert.equal((await f.row())!.envelope, null);
  } finally {
    await f.close();
  }
});
test('preparation cancellation retains refusal cleanup without reopening producer authority', async () => {
  const f = await fixture();
  try {
    await f.recover();
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    assert.equal((await f.finish()).op_synchronized, true);
    assert.equal(
      await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
        .bind(f.p.id)
        .first('state'),
      'cleanup_pending',
    );
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
    assert.equal((await f.remote()).counts.mint, 1);
  } finally {
    await f.close();
  }
});
