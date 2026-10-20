import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fixture, keys } from './server-support.ts';
import type { InvitationOffer, CloseReason } from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
async function pair(f: Server) {
  for (const who of [f.a, f.b])
    await f.response(await f.request('/messaging/account', 'POST', {}, who));
  const a = await f.start(),
    b = await f.start(keys(), randomUUID(), 0, f.b);
  await f.complete(a);
  await f.complete(b);
  const endpoints = [
    { scope: f.scope(a.c), fingerprint: a.c.scope.fingerprint },
    { scope: f.scope(b.c), fingerprint: b.c.scope.fingerprint },
  ].sort((a, b) => (a.scope < b.scope ? -1 : 1));
  const offer: InvitationOffer = {
    channel: {
      id: randomUUID(),
      group: randomBytes(16).toString('base64url'),
      a: endpoints[0],
      b: endpoints[1],
    },
    inviter_scope: f.scope(a.c),
  };
  for (const who of [f.a, f.b])
    await f.response(
      await f.request(`/messaging/channels/${offer.channel.id}/invitation`, 'POST', offer, who),
    );
  const intent = (who = f.a, reason: CloseReason = 'epoch_conflict') => ({
    offer,
    scope: who === f.a ? f.scope(a.c) : f.scope(b.c),
    operation_id: randomUUID(),
    reason,
  });
  const close = async (value = intent(), who = f.a, status = 200) =>
    f.response(
      await f.request(`/messaging/channels/${offer.channel.id}/close`, 'POST', value, who),
      status,
    );
  const successor = (): InvitationOffer => ({
    ...offer,
    channel: { ...offer.channel, id: randomUUID(), group: randomBytes(16).toString('base64url') },
  });
  const rejoin = async (next: InvitationOffer, who = f.a, status = 200) =>
    f.response<{ ready: boolean; predecessor_id: string }>(
      await f.request(
        `/messaging/channels/${next.channel.id}/rejoin`,
        'POST',
        { previous: offer, next },
        who,
      ),
      status,
    );
  return { a, b, offer, intent, close, successor, rejoin };
}
test('channel close is owner-bound, exact and permanent; peer revocation does not prevent termination', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      v = p.intent();
    await p.close({ ...v, scope: f.scope(p.b.c) }, f.a, 403);
    await p.close(
      {
        ...v,
        offer: {
          ...p.offer,
          channel: { ...p.offer.channel, group: randomBytes(16).toString('base64url') },
        },
      },
      f.a,
      409,
    );
    await f.response(
      await f.request(
        `/messaging/devices/${p.b.c.device.device_id}/revoke`,
        'POST',
        { expected_revision: 1 },
        f.b,
      ),
    );
    const accepted = await p.close(v);
    assert.deepEqual(await p.close(v), accepted);
    await p.close({ ...v, reason: 'leave' }, f.a, 409);
    await f.response(
      await f.request(`/messaging/channels/${p.offer.channel.id}/invitation`, 'POST', p.offer),
      409,
    );
    await f.response(
      await f.request(`/messaging/channels/${p.offer.channel.id}/bindings/${f.scope(p.a.c)}`),
      403,
    );
    assert.deepEqual(await p.close(v), accepted);
    await p.rejoin(p.successor(), f.a, 409);
  } finally {
    await f.close();
  }
});
test('rejoin requires each owners own close receipt, a fresh group and exact endpoints; consent cannot bypass predecessor checks', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      next = p.successor();
    await p.rejoin(next, f.a, 409);
    await p.close(p.intent());
    assert.equal((await p.rejoin(next)).ready, false);
    await p.rejoin(next, f.b, 409);
    await f.response(
      await f.request(`/messaging/channels/${next.channel.id}/invitation`, 'POST', next, f.b),
      409,
    );
    await p.close(p.intent(f.b), f.b);
    await p.rejoin(
      { ...next, channel: { ...next.channel, group: p.offer.channel.group } },
      f.b,
      400,
    );
    assert.equal((await p.rejoin(next, f.b)).ready, true);
    assert.equal((await p.rejoin(next)).predecessor_id, p.offer.channel.id);
    const row = await f.env.DB.prepare(
      'SELECT blocked,bootstrap_complete,predecessor_id FROM messaging_channel WHERE channel_id=?',
    )
      .bind(next.channel.id)
      .first();
    assert.deepEqual(row, {
      blocked: 0,
      bootstrap_complete: 0,
      predecessor_id: p.offer.channel.id,
    });
    assert.equal(
      (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
        .bind(p.offer.channel.id)
        .first<{ blocked: number }>())!.blocked,
      1,
    );
    const other = p.successor();
    await p.rejoin(other, f.a, 409);
  } finally {
    await f.close();
  }
});
test('atomic close rollback does not freeze without its receipt, and successful lost D1 replies reconcile', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      v = p.intent();
    await f.env.DB.prepare(
      "CREATE TRIGGER fixture_close_failure BEFORE UPDATE OF blocked ON messaging_channel BEGIN SELECT RAISE(ABORT,'fixture_close_abort'); END",
    ).run();
    await p.close(v, f.a, 503);
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_channel_close').first<{
        n: number;
      }>())!.n,
      0,
    );
    assert.equal(
      (await f.env.DB.prepare('SELECT blocked FROM messaging_channel').first<{
        blocked: number;
      }>())!.blocked,
      0,
    );
    await f.env.DB.prepare('DROP TRIGGER fixture_close_failure').run();
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('INSERT INTO messaging_channel_close', 'lost_recovery_reply', f.a.owner)
      .run();
    const receipt = await p.close(v);
    assert.deepEqual(await p.close(v), receipt);
  } finally {
    await f.close();
  }
});
test('SSO predicates are checked at termination writes; origin and identity substitutions do not create receipts', async () => {
  for (const mode of ['account', 'epoch', 'credential', 'session', 'expiry']) {
    const f = await fixture();
    try {
      const p = await pair(f);
      await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
        .bind('INSERT INTO messaging_channel_close', mode, f.a.owner)
        .run();
      await p.close(p.intent(), f.a, 503);
      assert.equal(
        (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_channel_close').first<{
          n: number;
        }>())!.n,
        0,
      );
      assert.equal(
        (await f.env.DB.prepare('SELECT blocked FROM messaging_channel').first<{
          blocked: number;
        }>())!.blocked,
        0,
      );
    } finally {
      await f.close();
    }
  }
  const f = await fixture();
  try {
    const p = await pair(f);
    await f.response(
      await f.request(`/messaging/channels/${p.offer.channel.id}/close`, 'POST', p.intent(), f.a, {
        Origin: 'https://evil.test',
      }),
      403,
    );
  } finally {
    await f.close();
  }
});
test('concurrent successor consent admits only one active child and retains both old closure tombstones', async () => {
  const f = await fixture();
  try {
    const p = await pair(f);
    await p.close(p.intent());
    await p.close(p.intent(f.b), f.b);
    const x = p.successor(),
      y = p.successor();
    assert.equal((await p.rejoin(x)).ready, false);
    assert.equal((await p.rejoin(y, f.b)).ready, false);
    const responses = await Promise.all([
      f.request(
        `/messaging/channels/${x.channel.id}/rejoin`,
        'POST',
        { previous: p.offer, next: x },
        f.b,
      ),
      f.request(
        `/messaging/channels/${y.channel.id}/rejoin`,
        'POST',
        { previous: p.offer, next: y },
        f.a,
      ),
    ]);
    assert.deepEqual(responses.map((r) => r.status).sort(), [200, 409]);
    assert.equal(
      (await f.env.DB.prepare(
        'SELECT count(*) AS n FROM messaging_channel WHERE predecessor_id=? AND a_consent=1 AND b_consent=1',
      )
        .bind(p.offer.channel.id)
        .first<{ n: number }>())!.n,
      1,
    );
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_channel_close').first<{
        n: number;
      }>())!.n,
      2,
    );
  } finally {
    await f.close();
  }
});
