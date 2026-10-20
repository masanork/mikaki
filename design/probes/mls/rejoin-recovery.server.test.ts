import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fixture, digest } from './server-support.ts';
import { rejoinPair } from './rejoin-server-support.ts';
test('rejoin status requires each own parent close, distinguishes unpublished consent and observes permanently closed children, including an unapproved peer endpoint', async () => {
  const f = await fixture();
  try {
    const p = await rejoinPair(f),
      next = p.successor();
    await p.status(next, f.a, 403);
    await p.close();
    assert.equal((await p.status(next)).state, 'unpublished');
    await p.status(next, f.b, 403);
    await p.close(p.previous, f.b);
    assert.equal((await p.rejoin(next)).ready, false);
    assert.equal((await p.status(next)).state, 'waiting');
    assert.equal((await p.status(next, f.b)).state, 'unpublished');
    await p.close(next, f.b);
    assert.equal((await p.status(next)).state, 'closed');
    assert.equal((await p.status(next, f.b)).state, 'closed');
    await p.rejoin(next, f.a, 409);
    await p.close(next);
    const fresh = p.successor(next);
    assert.equal((await p.rejoin(fresh, f.a, 200, next)).ready, false);
    assert.equal((await p.rejoin(fresh, f.b, 200, next)).ready, true);
    const result = await p.status(fresh, f.a, 200, next);
    assert.equal(result.state, 'admitted');
    assert.equal(result.complete, false);
    assert.deepEqual(Object.keys(result).sort(), [
      'channel',
      'complete',
      'expired',
      'inviter_scope',
      'predecessor_id',
      'scope',
      'state',
    ]);
  } finally {
    await f.close();
  }
});
test('rejoin metadata binds the exact predecessor, role, owner, own scope, origin and body bounds; a colliding child cannot look unpublished', async () => {
  const f = await fixture();
  try {
    const p = await rejoinPair(f),
      next = p.successor();
    await p.close();
    await p.close(p.previous, f.b);
    await p.rejoin(next);
    await p.status({ ...next, inviter_scope: p.scope(f.b) }, f.a, 409);
    await p.status(next, f.a, 403, {
      ...p.previous,
      channel: { ...p.previous.channel, group: randomBytes(16).toString('base64url') },
    });
    const other = await f.seed(),
      path = `/messaging/channels/${next.channel.id}/rejoin/status`,
      body = { previous: p.previous, next, scope: p.scope() };
    await f.response(await f.request(path, 'POST', body, other), 403);
    await f.response(await f.request(path, 'POST', { ...body, scope: p.scope(f.b) }), 403);
    await f.response(
      await f.request(path, 'POST', body, f.a, { Origin: 'https://evil.test' }),
      403,
    );
    await f.response(await f.request(path, 'POST', { ...body, extra: true }), 400);
    await f.response(await f.request(path, 'POST', { ...body, extra: 'x'.repeat(3000) }), 413);
    const collision = p.successor();
    await f.response(
      await f.request(`/messaging/channels/${collision.channel.id}/invitation`, 'POST', collision),
    );
    await p.status(collision, f.a, 409);
    await f.response(await f.request(`${path}/unexpected`, 'POST', body), 404);
  } finally {
    await f.close();
  }
});
test('expired consumed admission packets are reported before activation; completed groups ignore packet age and a revoked peer cannot hide closure', async () => {
  const f = await fixture();
  try {
    const p = await rejoinPair(f),
      next = p.successor();
    await p.close();
    await p.close(p.previous, f.b);
    await p.rejoin(next);
    await p.rejoin(next, f.b);
    const wire = randomBytes(32),
      packet = {
        channel_id: next.channel.id,
        message_id: randomUUID(),
        sender_scope: p.scope(f.b),
        recipient_scope: p.scope(),
        kind: 'key_package',
        digest: digest(wire),
        expires_at: Math.floor(Date.now() / 1000) + 3600,
        wire: wire.toString('base64url'),
      };
    await f.response(
      await f.request(
        `/messaging/channels/${next.channel.id}/invitation/packets`,
        'POST',
        packet,
        f.b,
      ),
    );
    assert.equal((await p.status(next)).expired, false);
    await f.env.DB.prepare(
      'UPDATE messaging_invitation_packet SET expires_at=unixepoch()-1,finished=1,wire=NULL WHERE channel_id=?',
    )
      .bind(next.channel.id)
      .run();
    assert.equal((await p.status(next)).expired, true);
    await f.env.DB.prepare('UPDATE messaging_channel SET bootstrap_complete=1 WHERE channel_id=?')
      .bind(next.channel.id)
      .run();
    const completed = await p.status(next);
    assert.equal(completed.complete, true);
    assert.equal(completed.expired, false);
    await p.close(next, f.b);
    await f.env.DB.prepare("UPDATE messaging_generation SET status='revoked' WHERE scope_hash=?")
      .bind(p.scope(f.b))
      .run();
    assert.equal((await p.status(next)).state, 'closed');
    await p.status(next, f.b, 403);
  } finally {
    await f.close();
  }
});
test('all five live SSO predicates are rechecked after the child status lookup', async () => {
  for (const mode of ['account', 'epoch', 'credential', 'session', 'expiry']) {
    const f = await fixture();
    try {
      const p = await rejoinPair(f),
        next = p.successor();
      await p.close();
      await p.close(p.previous, f.b);
      await p.rejoin(next);
      await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
        .bind('SELECT own.*,EXISTS', mode, f.a.owner)
        .run();
      await p.status(next, f.a, 403);
    } finally {
      await f.close();
    }
  }
});
