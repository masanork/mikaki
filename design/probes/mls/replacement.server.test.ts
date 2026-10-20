import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fixture, keys } from './server-support.ts';
import { pair } from './replacement-server-support.ts';
test('replacement retains owner continuity, permanently blocks the parent and needs both exact current scopes', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      body = p.approval();
    assert.equal((await p.approve(body)).ready, false);
    assert.deepEqual(await p.approve(body), await p.approve(body));
    await f.response(
      await f.request(`/messaging/channels/${p.next.channel.id}/invitation`, 'POST', p.next, f.b),
      409,
    );
    assert.equal((await p.approve(p.approval(f.b), f.b)).ready, true);
    assert.equal((await p.approve(body)).ready, true);
    assert.equal(
      (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
        .bind(p.previous.channel.id)
        .first<{ blocked: number }>())!.blocked,
      1,
    );
    await p.approve({ ...body, operation_id: randomUUID() }, f.a, 409);
    await p.approve({ ...body, scope: f.scope(p.b.c) }, f.b, 400);
  } finally {
    await f.close();
  }
});
test('a failed replacement batch rolls back parent closure and all consent; lost committed replies reconcile', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      body = p.approval();
    await f.env.DB.exec(
      "CREATE TRIGGER deny_replacement BEFORE INSERT ON messaging_replacement_approval BEGIN SELECT RAISE(ABORT,'injected_replacement_failure'); END",
    );
    await p.approve(body, f.a, 409);
    assert.equal(
      (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
        .bind(p.previous.channel.id)
        .first<{ blocked: number }>())!.blocked,
      0,
    );
    assert.equal(
      await f.env.DB.prepare('SELECT channel_id FROM messaging_channel WHERE channel_id=?')
        .bind(p.next.channel.id)
        .first(),
      null,
    );
    await f.env.DB.exec('DROP TRIGGER deny_replacement');
    await f.env.DB.prepare(
      "INSERT INTO fixture_messaging_fault VALUES(1,'messaging_replacement_approval','lost_recovery_reply',NULL,1)",
    ).run();
    assert.equal((await p.approve(body)).ready, false);
  } finally {
    await f.close();
  }
});
test('another account/device, two changed members, mismatched predecessor and fresh-group reuse cannot authorize replacement', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      body = p.approval();
    await p.approve(
      {
        ...body,
        previous: {
          ...p.previous,
          channel: { ...p.previous.channel, group: randomBytes(16).toString('base64url') },
        },
      },
      f.a,
      409,
    );
    await p.approve(
      {
        ...body,
        next: { ...p.next, channel: { ...p.next.channel, group: p.previous.channel.group } },
      },
      f.a,
      400,
    );
    const other = await f.start(keys(), randomUUID(), 0, f.b);
    await f.complete(other);
    const changed = [
      { scope: f.scope(p.a.c), fingerprint: p.a.c.scope.fingerprint },
      { scope: f.scope(other.c), fingerprint: other.c.scope.fingerprint },
    ].sort((a, b) => (a.scope < b.scope ? -1 : 1));
    await p.approve(
      {
        ...body,
        next: {
          channel: { ...p.next.channel, a: changed[0], b: changed[1] },
          inviter_scope: f.scope(p.a.c),
        },
      },
      f.a,
      409,
    );
    const newA = await f.start(keys(), p.a.c.device.device_id, 1, f.a);
    await f.complete(newA);
    const both = [
      { scope: f.scope(newA.c), fingerprint: newA.c.scope.fingerprint },
      { scope: f.scope(p.rotated.c), fingerprint: p.rotated.c.scope.fingerprint },
    ].sort((a, b) => (a.scope < b.scope ? -1 : 1));
    await p.approve(
      {
        ...body,
        scope: f.scope(newA.c),
        next: {
          channel: { ...p.next.channel, a: both[0], b: both[1] },
          inviter_scope: f.scope(newA.c),
        },
      },
      f.a,
      409,
    );
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_replacement_approval').first<{
        n: number;
      }>())!.n,
      0,
    );
  } finally {
    await f.close();
  }
});

test('replacement checks all live SSO predicates inside the batch and rolls back parent freeze when authority changes', async () => {
  for (const mode of ['account', 'epoch', 'credential', 'session', 'expiry']) {
    const f = await fixture();
    try {
      const p = await pair(f);
      await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
        .bind('INSERT INTO messaging_replacement_approval', mode, f.a.owner)
        .run();
      await p.approve(p.approval(), f.a, 409);
      assert.equal(
        (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
          .bind(p.previous.channel.id)
          .first<{ blocked: number }>())!.blocked,
        0,
      );
      assert.equal(
        (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_replacement_approval').first<{
          n: number;
        }>())!.n,
        0,
      );
    } finally {
      await f.close();
    }
  }
});
test('origin, unrelated owner and revocation reject replacement without a new consent', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      body = p.approval(),
      other = await f.seed();
    await f.response(
      await f.request(`/messaging/channels/${p.next.channel.id}/replace`, 'POST', body, f.a, {
        Origin: 'https://evil.test',
      }),
      403,
    );
    await p.approve(body, other, 409);
    await f.env.DB.prepare("UPDATE messaging_generation SET status='revoked' WHERE scope_hash=?")
      .bind(f.scope(p.rotated.c))
      .run();
    await p.approve(body, f.a, 409);
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_replacement_approval').first<{
        n: number;
      }>())!.n,
      0,
    );
  } finally {
    await f.close();
  }
});
test('concurrent final approval of competing changed-key successors admits only one bilateral child', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      x = p.approval(),
      y = {
        ...p.approval(f.b),
        next: {
          ...p.next,
          channel: {
            ...p.next.channel,
            id: randomUUID(),
            group: randomBytes(16).toString('base64url'),
          },
        },
      };
    assert.equal((await p.approve(x)).ready, false);
    assert.equal((await p.approve(y, f.b)).ready, false);
    const replies = await Promise.all([
      f.request(
        `/messaging/channels/${x.next.channel.id}/replace`,
        'POST',
        { ...p.approval(f.b), next: x.next },
        f.b,
      ),
      f.request(
        `/messaging/channels/${y.next.channel.id}/replace`,
        'POST',
        { ...p.approval(), next: y.next },
        f.a,
      ),
    ]);
    assert.deepEqual(replies.map((r) => r.status).sort(), [200, 409]);
    assert.equal(
      (await f.env.DB.prepare(
        'SELECT count(*) AS n FROM messaging_channel WHERE predecessor_id=? AND blocked=0 AND a_consent=1 AND b_consent=1',
      )
        .bind(p.previous.channel.id)
        .first<{ n: number }>())!.n,
      1,
    );
  } finally {
    await f.close();
  }
});
