import assert from 'node:assert/strict';
import { createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { effectFixture } from './support/work-effect-fixture.ts';
import type { MintPlan, MintRecord } from '../../crates/work-effect-worker/protocol.ts';

type Role = 'task' | 'snapshot';
type Purpose = 'upload' | 'readback';
async function fixture(role: Role = 'task', purpose: Purpose = 'upload') {
  const key = randomBytes(32);
  const f = await effectFixture({ WORK_CREDENTIAL_KEY_V1: key.toString('base64url') });
  try {
    const initial = role === 'task' ? f.task : f.snapshot;
    assert.equal((await f.execute(initial.id)).state, 'closed');
    const a = await f.call({
      action: 'reserve-credential',
      credential: { preparation_id: f.p.id, role, purpose },
    });
    const id = a.id;
    return {
      ...f,
      get DB() {
        return f.DB;
      },
      key,
      id,
      mint: (status = 200, input: unknown = { attempt_id: id }) =>
        f.effect<Record<string, unknown>>({ action: 'mint', input }, status),
      mintPlan: (status = 200) =>
        f.effect<MintPlan>(
          { action: 'plan', input: { action: 'mint-plan', attempt_id: id } },
          status,
        ),
      mintLedger: () => f.effect<MintRecord | null>({ action: 'mint-lookup', attempt_id: id }),
      mintRow: () =>
        f.DB.prepare(
          'SELECT body,state,observation,envelope,key_version,nonce,revision FROM work_credential_attempt WHERE attempt_id=?',
        )
          .bind(id)
          .first<Record<string, unknown>>(),
    };
  } catch (error) {
    await f.close();
    throw error;
  }
}
for (const mode of [
  'mint-lost',
  'get-lost',
  'list-lost',
  'replaced-repo',
  'mint-wrong-scope',
  'mint-overlong',
  'mint-missing-token',
  'mint-wrong-token',
  'mint-incomplete',
]) {
  test(`unknown ${mode} retains the mint slot across restart without another provider call`, async () => {
    const f = await fixture();
    try {
      await f.mode(mode);
      assert.equal((await f.mint()).state, 'outcome_unknown');
      const l = (await f.mintLedger())!;
      assert.equal(l.state, 'outcome_unknown');
      const before = await f.remote();
      assert.equal(
        before.counts.mint,
        mode === 'get-lost' || mode === 'list-lost' || mode === 'replaced-repo' ? 0 : 1,
      );
      if (mode.startsWith('mint-') && mode !== 'mint-lost')
        assert.equal(before.repos[0]!.tokens[0]!.state, 'revoked');
      if (mode === 'mint-lost') assert.equal(before.repos[0]!.tokens[0]!.state, 'active');
      assert.equal((await f.mintRow())!.envelope, null);
      await f.restart();
      await f.mode('normal');
      assert.equal((await f.mint()).state, 'outcome_unknown');
      assert.deepEqual((await f.remote()).counts, before.counts);
      assert.doesNotMatch(
        JSON.stringify([l, await f.mintRow()]),
        /SYNTHETIC_MINT_SECRET|plaintext/,
      );
    } finally {
      await f.close();
    }
  });
}
for (const pause of ['pending', 'freeze', 'revoke']) {
  test(`${pause} between Native plan and mint admission denies provider I/O`, async () => {
    const f = await fixture();
    try {
      await f.restart({ LOCAL_EFFECT_PAUSE: pause });
      await f.mint(409);
      assert.equal((await f.remote()).counts.mint, 0);
      assert.equal(await f.mintLedger(), null);
    } finally {
      await f.close();
    }
  });
}
for (const loss of ['claim', 'custody', 'native']) {
  test(`lost ${loss} acknowledgement never causes another mint, including whole D1 restore`, async () => {
    const f = await fixture();
    try {
      await f.backup();
      await f.restart(
        loss === 'native'
          ? { LOCAL_EFFECT_CAPTURE_LOST: 'true' }
          : { LOCAL_MINT_LEDGER_LOST: loss },
      );
      await f.mint(loss === 'claim' ? 409 : 200);
      const before = await f.remote();
      assert.equal(before.counts.mint, loss === 'claim' ? 0 : 1);
      const l = (await f.mintLedger())!;
      assert.equal(l.state, 'outcome_unknown');
      if (loss !== 'claim') {
        assert.equal(l.revoke_acknowledged, true);
        assert.equal((await f.mintRow())!.state, 'revocation_pending');
        assert.equal(before.repos[0]!.tokens[0]!.state, 'revoked');
      }
      await f.restore();
      assert.equal((await f.mintRow())!.state, 'reserved');
      assert.equal((await f.mint()).state, 'outcome_unknown');
      assert.deepEqual((await f.remote()).counts, before.counts);
    } finally {
      await f.close();
    }
  });
}
test('freeze during provider mint retains independent cleanup evidence while Native remains fenced', async () => {
  const f = await fixture();
  try {
    await f.mode('freeze-during-mint');
    assert.equal((await f.mint()).state, 'outcome_unknown');
    const r = (await f.mintRow())!,
      l = (await f.mintLedger())!;
    assert.equal(r.state, 'dispatched');
    assert.equal(r.envelope, null);
    assert.equal(r.observation, null);
    assert.equal(l.revoke_acknowledged, true);
    assert.equal((await f.remote()).repos[0]!.tokens[0]!.state, 'revoked');
    const counts = (await f.remote()).counts;
    await f.restart();
    assert.equal((await f.mint()).state, 'outcome_unknown');
    assert.deepEqual((await f.remote()).counts, counts);
  } finally {
    await f.close();
  }
});
for (const pause of ['revoke', 'source', 'rotate']) {
  test(`${pause} after admission routes the returned mint to cleanup without productive custody`, async () => {
    const f = await fixture();
    try {
      await f.restart({
        LOCAL_MINT_CAPTURE_PAUSE: pause,
        WORK_CREDENTIAL_KEY_V2: randomBytes(32).toString('base64url'),
      });
      assert.equal((await f.mint()).state, 'outcome_unknown');
      const l = (await f.mintLedger())!,
        r = (await f.mintRow())!;
      assert.equal(l.state, 'outcome_unknown');
      assert.equal(l.revoke_acknowledged, true);
      assert.equal(r.state, 'revocation_pending');
      assert.equal(Boolean(r.envelope), pause !== 'rotate');
      if (pause === 'source')
        assert.equal(
          await f.DB.prepare('SELECT count(*) AS n FROM work_source_access WHERE active=1').first(
            'n',
          ),
          0,
        );
      assert.equal((await f.remote()).counts.mint, 1);
      assert.equal((await f.remote()).repos[0]!.tokens[0]!.state, 'revoked');
      const before = (await f.remote()).counts;
      await f.restart();
      assert.equal((await f.mint()).state, 'outcome_unknown');
      assert.deepEqual((await f.remote()).counts, before);
    } finally {
      await f.close();
    }
  });
}
test('a restored reserved journal cannot mint again or allocate another ID in the same independent slot', async () => {
  const f = await fixture();
  try {
    const p = await f.mintPlan();
    await f.backup();
    assert.equal((await f.mint()).state, 'custodied');
    const counts = (await f.remote()).counts;
    await f.restore();
    assert.equal((await f.mintRow())!.state, 'dispatched');
    const recovered = await f.mint();
    assert.equal(recovered.state, 'custodied');
    assert.equal(recovered.op_synchronized, false);
    assert.deepEqual((await f.remote()).counts, counts);
    const different = {
      ...p,
      attempt_id: randomBytes(32).toString('base64url'),
      digest: 'c'.repeat(64),
    };
    await f.effect({ action: 'mint-claim', plan: different }, 409);
    assert.equal(await f.effect({ action: 'mint-lookup', attempt_id: different.attempt_id }), null);
  } finally {
    await f.close();
  }
});
test('mint admission requires the independent initial closure, not a primary fabricated receipt', async () => {
  const f = await effectFixture();
  try {
    await f.call({ action: 'dispatch-credential', id: f.task.id });
    await f.call({
      action: 'capture-credential',
      id: f.task.id,
      credential: {
        repo_id: 'synthetic-1',
        token_id: 'synthetic-token',
        scope: 'write',
        expires_at: Math.floor(Date.now() / 1000) + 120,
      },
    });
    await f.call({
      action: 'credential-close',
      id: f.task.id,
      credential: { confirmation: 'refused' },
      receipt: 'd'.repeat(64),
    });
    const a = await f.call({
      action: 'reserve-credential',
      credential: { preparation_id: f.p.id, role: 'task', purpose: 'upload' },
    });
    await f.effect({ action: 'mint', input: { attempt_id: a.id } }, 409);
    assert.equal((await f.remote()).counts.mint, 0);
    assert.equal(await f.effect({ action: 'mint-lookup', attempt_id: a.id }), null);
  } finally {
    await f.close();
  }
});
test('private mint transport rejects widening, cold flags, stale keys and capability mutations', async () => {
  const f = await fixture();
  try {
    await f.effect({ action: 'mint-public' }, 404);
    for (const extra of [
      { url: 'https://wrong.invalid' },
      { scope: 'write' },
      { ttl: 300 },
      { repo_id: 'wrong' },
      { plaintext: 'arbitrary' },
    ])
      await f.mint(409, { attempt_id: f.id, ...extra });
    for (const method of [
      'begin',
      'bootstrap',
      'freeze',
      'reset',
      'close',
      'claimEffect',
      'observeEffect',
      'env',
    ])
      await f.effect({ action: 'mint-ledger-call', method, input: {} }, 409);
    await f.restart({ WORK_MINT_GATE_ENABLED: 'false' });
    await f.mint(409);
    await f.restart({ WORK_CREDENTIAL_KEY_FLOOR: '2' });
    await f.mint(409);
    assert.equal((await f.remote()).counts.mint, 0);
    assert.equal(await f.mintLedger(), null);
  } finally {
    await f.close();
  }
});
test('mint checkpoint binds scope, repo, deadline and key; retries never replace intent or free capacity', async () => {
  const f = await fixture();
  try {
    const p = await f.mintPlan();
    for (const extra of [
      { scope: 'read' },
      { repo_id: 'unrelated' },
      { initial_attempt_id: f.snapshot.id },
      { deadline: Math.floor(Date.now() / 1000) + 60 },
      { key_version: 0 },
      { url: 'https://wrong.invalid' },
    ]) {
      await f.effect({ action: 'mint-claim', plan: { ...p, ...extra } }, 409);
    }
    assert.equal(await f.mintLedger(), null);
    const claim = await f.effect<{ started: boolean }>({ action: 'mint-claim', plan: p });
    assert.equal(claim.started, true);
    const reordered = Object.fromEntries(Object.entries(p).reverse());
    assert.equal(
      (await f.effect<{ started: boolean }>({ action: 'mint-claim', plan: reordered })).started,
      false,
    );
    for (const extra of [
      { key_version: 2 },
      { key_fingerprint: 'e'.repeat(64) },
      { digest: 'f'.repeat(64) },
    ])
      await f.effect({ action: 'mint-claim', plan: { ...p, ...extra } }, 409);
    assert.equal((await f.mint()).state, 'outcome_unknown');
    assert.equal((await f.remote()).counts.mint, 0);
    await f.checkpoint({ action: 'raise-floor', floor: 2 });
    await f.effect({ action: 'mint-claim', plan: p }, 409);
    assert.equal((await f.mint()).state, 'outcome_unknown');
  } finally {
    await f.close();
  }
});
test('a fresh mint shares the bounded retained capacity with initial effects', async () => {
  const f = await fixture();
  try {
    const p = await f.mintPlan();
    const base = (await f.ledger())!.plan;
    for (let i = 0; i < 255; i++)
      await f.effect({
        action: 'ledger-claim',
        plan: {
          ...base,
          attempt_id: randomBytes(32).toString('base64url'),
          digest: i.toString(16).padStart(64, '0'),
          name: `wk-${i.toString(16).padStart(32, '0')}-code`,
          checkpoint: p.checkpoint,
        },
      });
    await f.mint(409);
    assert.equal(await f.mintLedger(), null);
    assert.equal((await f.remote()).counts.mint, 0);
  } finally {
    await f.close();
  }
});
function numberField(n: number) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}
function digestFields(domain: string, fields: (string | Buffer)[]) {
  const h = createHash('sha256');
  for (const value of [domain, ...fields]) {
    const b = typeof value === 'string' ? Buffer.from(value) : value;
    h.update(numberField(b.length)).update(b);
  }
  return h.digest();
}
for (const role of ['task', 'snapshot'] as const)
  for (const purpose of ['upload', 'readback'] as const) {
    test(`${role}/${purpose}: exact one-shot mint enters independently decryptable Native custody, without copy verification or release`, async () => {
      const f = await fixture(role, purpose);
      try {
        const p = await f.mintPlan();
        assert.equal(p.scope, purpose === 'upload' ? 'write' : 'read');
        assert.equal(p.repo_id, 'synthetic-1');
        assert.equal(p.key_version, 1);
        const results = await Promise.all([f.mint(), f.mint()]);
        assert.ok(results.some((r) => r.state === 'custodied'));
        assert.ok(results.some((r) => r.op_synchronized === true));
        assert.ok(results.every((r) => ['custodied', 'outcome_unknown'].includes(String(r.state))));
        assert.equal((await f.remote()).counts.mint, 1);
        const r = (await f.mintRow())!,
          l = (await f.mintLedger())!;
        assert.equal(r.state, 'captured');
        assert.equal(l.state, 'custodied');
        assert.equal(l.observation!.scope, p.scope);
        assert.ok(l.observation!.expires_at <= p.deadline);
        const e = JSON.parse(String(r.envelope)).data;
        const aad = digestFields('mikaki.work-credential-envelope.v1', [
          Buffer.from(p.digest, 'hex'),
          String(r.observation),
          numberField(1),
          numberField(1),
        ]);
        const cipher = Buffer.from(e.ciphertext, 'base64url');
        const decipher = createDecipheriv('aes-256-gcm', f.key, Buffer.from(e.nonce, 'base64url'));
        decipher.setAAD(aad);
        decipher.setAuthTag(cipher.subarray(-16));
        const plain = Buffer.concat([decipher.update(cipher.subarray(0, -16)), decipher.final()]);
        assert.equal(plain.toString(), 'SYNTHETIC_MINT_SECRET_1');
        plain.fill(0);
        assert.doesNotMatch(JSON.stringify([results, r, l]), /SYNTHETIC_MINT_SECRET|plaintext/);
        assert.equal(
          await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
            .bind(f.p.id)
            .first('state'),
          'dispatched',
        );
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
        const counts = (await f.remote()).counts;
        await f.restart();
        assert.equal((await f.mint()).state, 'custodied');
        assert.deepEqual((await f.remote()).counts, counts);
      } finally {
        await f.close();
      }
    });
  }
