import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fixture } from './server-support.ts';
import { rejoinPair } from './rejoin-server-support.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
type Pair = Awaited<ReturnType<typeof rejoinPair>>;
function intent(p: Pair, next = p.successor(), who?: Server['a']) {
  return { previous: p.previous, next, scope: p.scope(who), operation_id: randomUUID() };
}
async function cancel(f: Server, c: ReturnType<typeof intent>, who = f.a, expected = 200) {
  return f.response<{ outcome: 'cancelled' | 'admitted'; operation_id: string }>(
    await f.request(`/messaging/channels/${c.next.channel.id}/rejoin/cancel`, 'POST', c, who),
    expected,
  );
}
test('unpublished same-key proposals receive permanent zero-consent tombstones and exact stable cancellation receipts', async () => {
  const f = await fixture();
  try {
    const p = await rejoinPair(f),
      c = intent(p);
    await cancel(f, c, f.a, 409);
    await p.close();
    const receipt = await cancel(f, c);
    assert.equal(receipt.outcome, 'cancelled');
    assert.deepEqual(await cancel(f, c), receipt);
    assert.equal((await p.status(c.next)).state, 'cancelled');
    await cancel(f, { ...c, operation_id: randomUUID() }, f.a, 409);
    await p.close(p.previous, f.b);
    for (const who of [f.a, f.b]) await p.rejoin(c.next, who, 409);
    assert.deepEqual(
      await f.env.DB.prepare(
        'SELECT blocked,a_consent,b_consent FROM messaging_channel WHERE channel_id=?',
      )
        .bind(c.next.channel.id)
        .first(),
      { blocked: 1, a_consent: 0, b_consent: 0 },
    );
    const fresh = p.successor();
    assert.equal((await p.rejoin(fresh)).ready, false);
    assert.equal((await p.rejoin(fresh, f.b)).ready, true);
  } finally {
    await f.close();
  }
});
test('competing pending proposals can be vetoed before selecting the peer proposal under the same original parent; bilateral consent is never cancelled', async () => {
  const f = await fixture();
  try {
    const p = await rejoinPair(f),
      x = p.successor(),
      y = p.successor();
    await p.close();
    await p.close(p.previous, f.b);
    assert.equal((await p.rejoin(x)).ready, false);
    assert.equal((await p.rejoin(y, f.b)).ready, false);
    assert.equal((await cancel(f, intent(p, x))).outcome, 'cancelled');
    assert.equal((await p.rejoin(y)).ready, true);
    const c = intent(p, y, f.b);
    assert.equal((await cancel(f, c, f.b)).outcome, 'admitted');
    assert.equal((await p.status(y)).state, 'admitted');
    assert.equal(
      (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
        .bind(y.channel.id)
        .first<{ blocked: number }>())!.blocked,
      0,
    );
    await p.close(y);
    assert.equal((await cancel(f, c, f.b)).outcome, 'admitted');
    assert.equal((await p.status(y)).state, 'closed');
  } finally {
    await f.close();
  }
});
test('cancellation racing the final approval has a single atomic result and no cancelled bilateral child', async () => {
  const f = await fixture();
  try {
    const p = await rejoinPair(f),
      c = intent(p);
    await p.close();
    await p.close(p.previous, f.b);
    await p.rejoin(c.next);
    const [veto, approval] = await Promise.all([
      f.request(`/messaging/channels/${c.next.channel.id}/rejoin/cancel`, 'POST', c),
      f.request(
        `/messaging/channels/${c.next.channel.id}/rejoin`,
        'POST',
        { previous: p.previous, next: c.next },
        f.b,
      ),
    ]);
    const result = await f.response<{ outcome: string }>(veto);
    const row = (await f.env.DB.prepare(
      'SELECT blocked,a_consent,b_consent FROM messaging_channel WHERE channel_id=?',
    )
      .bind(c.next.channel.id)
      .first<{ blocked: number; a_consent: number; b_consent: number }>())!;
    if (result.outcome === 'cancelled') {
      assert.equal(approval.status, 409);
      assert.equal(row.blocked, 1);
      assert.notEqual(row.a_consent + row.b_consent, 2);
    } else {
      assert.equal(result.outcome, 'admitted');
      assert.equal(approval.status, 200);
      assert.equal(row.blocked, 0);
      assert.equal(row.a_consent + row.b_consent, 2);
    }
    assert.equal((await cancel(f, c)).outcome, result.outcome);
  } finally {
    await f.close();
  }
});
test('failed cancellation transactions leave no tombstone or receipt and committed lost D1 replies reconcile on primary', async () => {
  const f = await fixture();
  try {
    const p = await rejoinPair(f),
      c = intent(p);
    await p.close();
    await f.env.DB.exec(
      "CREATE TRIGGER deny_cancel BEFORE INSERT ON messaging_rejoin_cancellation BEGIN SELECT RAISE(ABORT,'injected_cancel_failure'); END",
    );
    await cancel(f, c, f.a, 409);
    assert.equal(
      await f.env.DB.prepare('SELECT channel_id FROM messaging_channel WHERE channel_id=?')
        .bind(c.next.channel.id)
        .first(),
      null,
    );
    await f.env.DB.exec('DROP TRIGGER deny_cancel');
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('INSERT INTO messaging_rejoin_cancellation', 'lost_recovery_reply', f.a.owner)
      .run();
    assert.equal((await cancel(f, c)).outcome, 'cancelled');
  } finally {
    await f.close();
  }
});
test('veto requires exact original closure, current caller and SSO, scope, role, origin and bounded body; a revoked peer cannot prevent veto', async () => {
  const f = await fixture();
  try {
    const p = await rejoinPair(f),
      c = intent(p),
      path = `/messaging/channels/${c.next.channel.id}/rejoin/cancel`;
    await p.close();
    await cancel(f, c, await f.seed(), 409);
    await cancel(f, { ...c, scope: p.scope(f.b) }, f.a, 409);
    await cancel(f, { ...c, previous: { ...c.previous, inviter_scope: p.scope(f.b) } }, f.a, 409);
    await cancel(
      f,
      {
        ...c,
        previous: {
          ...c.previous,
          channel: { ...c.previous.channel, group: randomBytes(16).toString('base64url') },
        },
      },
      f.a,
      409,
    );
    await f.response(await f.request(path, 'POST', c, f.a, { Origin: 'https://evil.test' }), 403);
    await f.response(await f.request(path, 'POST', { ...c, extra: true }), 400);
    await f.response(await f.request(path, 'POST', { ...c, extra: 'x'.repeat(2700) }), 413);
    const collision = p.successor();
    await f.response(
      await f.request(`/messaging/channels/${collision.channel.id}/invitation`, 'POST', collision),
    );
    await cancel(f, { ...c, next: collision }, f.a, 409);
    await p.rejoin(c.next);
    await cancel(f, { ...c, next: { ...c.next, inviter_scope: p.scope(f.b) } }, f.a, 409);
    await f.env.DB.prepare("UPDATE messaging_generation SET status='revoked' WHERE scope_hash=?")
      .bind(p.scope(f.b))
      .run();
    assert.equal((await cancel(f, c)).outcome, 'cancelled');
    assert.equal((await p.status(c.next)).state, 'cancelled');
    await cancel(f, intent(p, c.next, f.b), f.b, 409);
  } finally {
    await f.close();
  }
});
test('all five live SSO predicates guard cancellation inside the atomic SQL batch', async () => {
  for (const mode of ['account', 'epoch', 'credential', 'session', 'expiry']) {
    const f = await fixture();
    try {
      const p = await rejoinPair(f),
        c = intent(p);
      await p.close();
      await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
        .bind('INSERT INTO messaging_rejoin_cancellation', mode, f.a.owner)
        .run();
      await cancel(f, c, f.a, 409);
      assert.equal(
        await f.env.DB.prepare('SELECT channel_id FROM messaging_channel WHERE channel_id=?')
          .bind(c.next.channel.id)
          .first(),
        null,
      );
      assert.equal(
        (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_rejoin_cancellation').first<{
          n: number;
        }>())!.n,
        0,
      );
    } finally {
      await f.close();
    }
  }
});
test('retained cancellation quota is bounded per owner without evicting old vetoes or leaving an overflow child', async () => {
  const f = await fixture();
  try {
    const p = await rejoinPair(f);
    await p.close();
    const first = intent(p);
    assert.equal((await cancel(f, first)).outcome, 'cancelled');
    for (let i = 1; i < 32; i++) await cancel(f, intent(p));
    const overflow = intent(p);
    await cancel(f, overflow, f.a, 409);
    assert.equal(
      await f.env.DB.prepare('SELECT channel_id FROM messaging_channel WHERE channel_id=?')
        .bind(overflow.next.channel.id)
        .first(),
      null,
    );
    assert.equal((await cancel(f, first)).outcome, 'cancelled');
    await p.rejoin(first.next, f.a, 409);
  } finally {
    await f.close();
  }
});
