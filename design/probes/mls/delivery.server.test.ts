import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fixture, keys, digest } from './server-support.ts';
import {
  envelopeHash,
  type DeliveryChannel,
  type DeliveryEnvelope,
  type DeliveryReceipt,
} from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
async function pair(f: Server) {
  await f.response(await f.request('/messaging/account', 'POST', {}, f.a));
  await f.response(await f.request('/messaging/account', 'POST', {}, f.b));
  const a = await f.start(),
    b = await f.start(keys(), randomUUID(), 0, f.b);
  await f.complete(a);
  await f.complete(b);
  const endpoints = [
    { scope: f.scope(a.c), fingerprint: a.c.scope.fingerprint },
    { scope: f.scope(b.c), fingerprint: b.c.scope.fingerprint },
  ].sort((a, b) => (a.scope < b.scope ? -1 : 1));
  const channel: DeliveryChannel = {
    id: randomUUID(),
    group: randomBytes(16).toString('base64url'),
    a: endpoints[0],
    b: endpoints[1],
  };
  const base = `/messaging/channels/${channel.id}`;
  const grant = async (who = f.a) =>
    f.response<{ ready: boolean }>(await f.request(base, 'POST', channel, who));
  const envelope = (patch: Partial<DeliveryEnvelope> = {}): DeliveryEnvelope => {
    const wire = randomBytes(256);
    return {
      channel_id: channel.id,
      message_id: randomUUID(),
      sender_scope: f.scope(a.c),
      recipient_scope: f.scope(b.c),
      kind: 'application',
      wire: wire.toString('base64url'),
      digest: digest(wire),
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      ...patch,
    };
  };
  const send = async (e: DeliveryEnvelope, who = f.a, status = 200) =>
    f.response<{ status: string; receipt: DeliveryReceipt }>(
      await f.request(`${base}/messages`, 'POST', e, who),
      status,
    );
  const inbox = async (who = f.b, scope = f.scope(b.c), status = 200) =>
    f.response<{ message: (DeliveryReceipt & { wire: string }) | null }>(
      await f.request(`${base}/inbox/${scope}`, 'GET', undefined, who),
      status,
    );
  const consume = async (e: DeliveryEnvelope, who = f.b, status = 200) =>
    f.response(
      await f.request(
        `${base}/messages/${e.message_id}/consume`,
        'POST',
        {
          recipient_scope: e.recipient_scope,
          digest: e.digest,
          envelope_hash: await envelopeHash(e),
        },
        who,
      ),
      status,
    );
  return { a, b, channel, base, grant, envelope, send, inbox, consume };
}
test('mailbox requires bilateral exact device grants, same-origin SSO and current generations', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      e = p.envelope();
    assert.equal((await p.grant()).ready, false);
    await p.send(e, f.a, 409);
    await p.inbox(f.b, f.scope(p.b.c), 403);
    assert.equal((await p.grant(f.b)).ready, true);
    for (const headers of [{ Cookie: '' }, { Origin: 'https://evil.test' }] as Record<
      string,
      string
    >[])
      assert.ok(
        [401, 403].includes(
          (await f.request(`${p.base}/messages`, 'POST', e, f.a, headers)).status,
        ),
      );
    await p.send(e, f.b, 409);
    await p.inbox(f.a, f.scope(p.b.c), 403);
    await p.send({ ...e, sender_scope: f.scope(p.b.c), recipient_scope: f.scope(p.a.c) }, f.a, 409);
    await p.send({ ...e, digest: randomBytes(32).toString('base64url') }, f.a, 400);
    await p.send(e);
    await f.response(
      await f.request(
        `/messaging/devices/${p.b.c.device.device_id}/revoke`,
        'POST',
        { expected_revision: 1 },
        f.b,
      ),
    );
    await p.send(e, f.a, 409);
    await p.inbox(f.b, f.scope(p.b.c), 403);
    await p.consume(e, f.b, 409);
    assert.equal(
      (await f.env.DB.prepare('SELECT consumed FROM messaging_mail').first<{ consumed: number }>())!
        .consumed,
      0,
    );
  } finally {
    await f.close();
  }
});
test('durable acceptance is exact and idempotent; consumption is recipient-only, ordered and keeps retry tombstones', async () => {
  const f = await fixture();
  try {
    const p = await pair(f);
    await p.grant();
    await p.grant(f.b);
    const e = p.envelope(),
      first = await p.send(e);
    assert.equal(first.status, 'stored');
    assert.equal(first.receipt.envelope_hash, await envelopeHash(e));
    assert.equal(Object.hasOwn(first.receipt, 'wire'), false);
    assert.deepEqual(await p.send(e), first);
    await p.send({ ...e, kind: 'commit' }, f.a, 409);
    const second = p.envelope();
    await p.send(second);
    assert.equal((await p.inbox()).message!.message_id, e.message_id);
    await p.consume(second, f.b, 409);
    await p.consume(e, f.a, 409);
    await p.consume({ ...e, digest: randomBytes(32).toString('base64url') }, f.b, 409);
    await p.consume(e);
    await p.consume(e);
    assert.deepEqual(await p.send(e), first);
    assert.equal((await p.inbox()).message!.message_id, second.message_id);
    const row = await f.env.DB.prepare(
      'SELECT wire,consumed FROM messaging_mail WHERE message_id=?',
    )
      .bind(e.message_id)
      .first();
    assert.deepEqual(row, { wire: null, consumed: 1 });
    await p.consume(second);
    assert.equal((await p.inbox()).message, null);
    await f.response(await f.request(`${p.base}/block`, 'POST', {}, f.b));
    await p.send(p.envelope(), f.a, 409);
    await p.inbox(f.b, f.scope(p.b.c), 403);
    await f.response(await f.request(p.base, 'POST', p.channel, f.a), 409);
  } finally {
    await f.close();
  }
});
test('admission bounds retention, rejects expired mail and never skips an expired predecessor', async () => {
  const f = await fixture();
  try {
    const p = await pair(f);
    await p.grant();
    await p.grant(f.b);
    await p.send(p.envelope({ expires_at: 1 }), f.a, 409);
    await p.send(p.envelope({ expires_at: Math.floor(Date.now() / 1000) + 90000 }), f.a, 409);
    const old = p.envelope();
    await p.send(old);
    await f.env.DB.prepare('UPDATE messaging_mail SET expires_at=1 WHERE message_id=?')
      .bind(old.message_id)
      .run();
    await p.send(p.envelope());
    await p.inbox(f.b, f.scope(p.b.c), 410);
    for (let i = 2; i < 64; i++) await p.send(p.envelope());
    await p.send(p.envelope(), f.a, 409);
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_mail').first<{ n: number }>())!
        .n,
      64,
    );
  } finally {
    await f.close();
  }
});
test('SQL admission rechecks SSO authority; a lost successful D1 response reconciles durable acceptance', async () => {
  const f = await fixture();
  try {
    const p = await pair(f);
    await p.grant();
    await p.grant(f.b);
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('INSERT INTO messaging_mail', 'lost_delivery_reply', f.a.owner)
      .run();
    const e = p.envelope();
    assert.equal((await p.send(e)).status, 'stored');
    assert.deepEqual(await p.send(e), await p.send(e));
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('INSERT INTO messaging_mail', 'credential', f.a.owner)
      .run();
    await p.send(p.envelope(), f.a, 409);
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_mail').first<{ n: number }>())!
        .n,
      1,
    );
  } finally {
    await f.close();
  }
});
test('competing duplicate sends allocate one sequence; different intent cannot replace accepted ciphertext', async () => {
  const f = await fixture();
  try {
    const p = await pair(f);
    await p.grant();
    await p.grant(f.b);
    const e = p.envelope();
    const replies = await Promise.all(Array.from({ length: 4 }, () => p.send(e)));
    assert.ok(replies.every((r) => r.receipt.sequence === replies[0].receipt.sequence));
    const conflict = p.envelope({ message_id: e.message_id });
    await p.send(conflict, f.a, 409);
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_mail').first<{ n: number }>())!
        .n,
      1,
    );
  } finally {
    await f.close();
  }
});

test('all live SSO predicates are checked at mailbox insertion and loss during inbox reads cannot look synchronized', async () => {
  for (const mode of ['account', 'epoch', 'credential', 'session', 'expiry']) {
    const f = await fixture();
    try {
      const p = await pair(f);
      await p.grant();
      await p.grant(f.b);
      await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
        .bind('INSERT INTO messaging_mail', mode, f.a.owner)
        .run();
      await p.send(p.envelope(), f.a, 409);
      assert.equal(
        (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_mail').first<{ n: number }>())!
          .n,
        0,
        mode,
      );
    } finally {
      await f.close();
    }
  }
  const f = await fixture();
  try {
    const p = await pair(f);
    await p.grant();
    await p.grant(f.b);
    await p.send(p.envelope());
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('SELECT m.*', 'credential', f.b.owner)
      .run();
    await p.inbox(f.b, f.scope(p.b.c), 403);
  } finally {
    await f.close();
  }
});
test('channel leases refresh only the pinned pair and discard tokens if authority changes while signing', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      path = `${p.base}/bindings/${f.scope(p.a.c)}`;
    assert.equal((await f.request(path)).status, 403);
    await p.grant();
    await p.grant(f.b);
    const bindings = await f.response<{ own: string; peer: string }>(await f.request(path));
    assert.deepEqual(f.binding(bindings.own).device, p.a.c.device);
    assert.deepEqual(f.binding(bindings.peer).device, p.b.c.device);
    assert.equal((await f.request(path, 'GET', undefined, f.b)).status, 403);
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,4)')
      .bind('SELECT g.*,unixepoch()', 'credential', f.a.owner)
      .run();
    assert.equal((await f.request(path)).status, 403);
  } finally {
    await f.close();
  }
});

test('channel consent quota retains old generations and never reports an uncommitted approval as success', async () => {
  const f = await fixture();
  try {
    const p = await pair(f);
    await p.grant();
    await p.grant(f.b);
    const another = () => ({
      ...p.channel,
      id: randomUUID(),
      group: randomBytes(16).toString('base64url'),
    });
    for (let i = 1; i < 32; i++) {
      const c = another();
      await f.response(await f.request(`/messaging/channels/${c.id}`, 'POST', c));
    }
    const denied = another();
    await f.response(await f.request(`/messaging/channels/${denied.id}`, 'POST', denied), 409);
    assert.equal((await p.grant()).ready, true);
    // A peer's pending invitation exists, but cannot bypass this owner's cap.
    await f.response(await f.request(`/messaging/channels/${denied.id}`, 'POST', denied, f.b));
    await f.response(await f.request(`/messaging/channels/${denied.id}`, 'POST', denied), 409);
    const replacement = await f.start(keys(), p.a.c.device.device_id, 1);
    await f.complete(replacement);
    const points = [
      { scope: f.scope(replacement.c), fingerprint: replacement.c.scope.fingerprint },
      { scope: f.scope(p.b.c), fingerprint: p.b.c.scope.fingerprint },
    ].sort((a, b) => (a.scope < b.scope ? -1 : 1));
    const next = { ...another(), a: points[0], b: points[1] };
    await f.response(await f.request(`/messaging/channels/${next.id}`, 'POST', next), 409);
  } finally {
    await f.close();
  }
});
