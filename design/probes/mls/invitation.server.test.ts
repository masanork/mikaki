import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fixture, keys, digest } from './server-support.ts';
import {
  envelopeHash,
  type InvitationOffer,
  type DeliveryEnvelope,
  type DeliveryReceipt,
} from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
async function pair(f: Server) {
  for (const who of [f.a, f.b])
    await f.response(await f.request('/messaging/account', 'POST', {}, who));
  const a = await f.start(),
    b = await f.start(keys(), randomUUID(), 0, f.b);
  await f.complete(a);
  await f.complete(b);
  const points = [
    { scope: f.scope(a.c), fingerprint: a.c.scope.fingerprint },
    { scope: f.scope(b.c), fingerprint: b.c.scope.fingerprint },
  ].sort((a, b) => (a.scope < b.scope ? -1 : 1));
  const offer: InvitationOffer = {
    channel: {
      id: randomUUID(),
      group: randomBytes(16).toString('base64url'),
      a: points[0],
      b: points[1],
    },
    inviter_scope: f.scope(a.c),
  };
  const base = `/messaging/channels/${offer.channel.id}/invitation`;
  const approve = async (who = f.a, value = offer, status = 200) =>
    f.response<{ ready: boolean; complete: boolean }>(
      await f.request(base, 'POST', value, who),
      status,
    );
  const envelope = (
    kind: DeliveryEnvelope['kind'],
    patch: Partial<DeliveryEnvelope> = {},
  ): DeliveryEnvelope => {
    const wire = randomBytes(256),
      sender = kind === 'key_package' ? f.scope(b.c) : f.scope(a.c),
      recipient = kind === 'key_package' ? f.scope(a.c) : f.scope(b.c);
    return {
      message_id: randomUUID(),
      channel_id: offer.channel.id,
      sender_scope: sender,
      recipient_scope: recipient,
      kind,
      wire: wire.toString('base64url'),
      digest: digest(wire),
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      ...patch,
    };
  };
  const send = async (
    e: DeliveryEnvelope,
    status = 200,
    who = e.kind === 'key_package' ? f.b : f.a,
  ) =>
    f.response<{ receipt: DeliveryReceipt }>(
      await f.request(`${base}/packets`, 'POST', e, who),
      status,
    );
  const snapshot = async (
    who = f.a,
    scope = who === f.a ? f.scope(a.c) : f.scope(b.c),
    status = 200,
  ) =>
    f.response<{
      ready: boolean;
      complete: boolean;
      packet: (DeliveryReceipt & { wire: string }) | null;
    }>(await f.request(`${base}/${scope}`, 'GET', undefined, who), status);
  const consume = async (
    e: DeliveryEnvelope,
    status = 200,
    who = e.kind === 'key_package' ? f.a : f.b,
  ) =>
    f.response<{ status: string; complete: boolean }>(
      await f.request(
        `${base}/packets/${e.message_id}/consume`,
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
  const untilWelcome = async () => {
    await approve();
    await approve(f.b);
    const kp = envelope('key_package'),
      commit = envelope('invite_commit'),
      welcome = envelope('welcome');
    await send(kp);
    await consume(kp);
    await send(commit);
    await send(welcome);
    return { kp, commit, welcome };
  };
  return { a, b, offer, base, approve, envelope, send, snapshot, consume, untilWelcome };
}
test('initial invitation fixes both devices, group and inviter; both owners must approve before packets or normal mail', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      kp = p.envelope('key_package');
    assert.equal((await p.approve()).ready, false);
    assert.equal((await p.snapshot()).ready, false);
    await p.send(kp, 409);
    await p.approve(f.b, { ...p.offer, inviter_scope: f.scope(p.b.c) }, 409);
    await p.approve(
      f.b,
      { ...p.offer, channel: { ...p.offer.channel, group: randomBytes(16).toString('base64url') } },
      409,
    );
    assert.equal((await p.approve(f.b)).ready, true);
    await p.snapshot(f.b, f.scope(p.a.c), 403);
    await p.send(kp, 409, f.a);
    await p.send(
      { ...kp, sender_scope: kp.recipient_scope, recipient_scope: kp.sender_scope },
      409,
      f.a,
    );
    const normal = p.envelope('application');
    await f.response(
      await f.request(`/messaging/channels/${p.offer.channel.id}/messages`, 'POST', normal),
      409,
    );
    await f.response(
      await f.request(p.base, 'POST', p.offer, f.a, { Origin: 'https://evil.test' }),
      403,
    );
  } finally {
    await f.close();
  }
});
test('three fixed packets enforce durable predecessor receipts; only Welcome consumption activates normal traffic', async () => {
  const f = await fixture();
  try {
    const p = await pair(f);
    await p.approve();
    await p.approve(f.b);
    const kp = p.envelope('key_package'),
      commit = p.envelope('invite_commit'),
      welcome = p.envelope('welcome');
    await p.send(commit, 409);
    await p.send(welcome, 409);
    const kpReceipt = await p.send(kp);
    assert.equal((await p.snapshot()).packet!.message_id, kp.message_id);
    assert.equal((await p.snapshot(f.b)).packet, null);
    await p.send(commit, 409);
    assert.equal((await p.consume(kp)).complete, false);
    const cReceipt = await p.send(commit);
    await p.send(welcome);
    assert.equal((await p.snapshot(f.b)).packet!.message_id, welcome.message_id);
    await p.consume(commit, 503, f.b);
    await p.consume(welcome, 503, f.a);
    assert.equal((await p.snapshot()).complete, false);
    assert.equal((await p.consume(welcome)).complete, true);
    assert.equal((await p.consume(welcome)).complete, true);
    assert.equal((await p.snapshot()).complete, true);
    assert.deepEqual(await p.send(kp), kpReceipt);
    assert.deepEqual(await p.send(commit), cReceipt);
    const rows = await f.env.DB.prepare(
      'SELECT wire,finished FROM messaging_invitation_packet',
    ).all();
    assert.ok(rows.results.every((r) => r.finished === 1 && r.wire === null));
    await f.response(
      await f.request(
        `/messaging/channels/${p.offer.channel.id}/messages`,
        'POST',
        p.envelope('application'),
      ),
    );
    const reused = p.envelope('application', {
      message_id: kp.message_id,
      sender_scope: kp.sender_scope,
      recipient_scope: kp.recipient_scope,
    });
    await f.response(
      await f.request(`/messaging/channels/${p.offer.channel.id}/messages`, 'POST', reused, f.b),
      409,
    );
  } finally {
    await f.close();
  }
});
test('duplicate packets keep one immutable receipt; expiry and second KeyPackages never reset the invitation', async () => {
  const f = await fixture();
  try {
    const p = await pair(f);
    await p.approve();
    await p.approve(f.b);
    const kp = p.envelope('key_package');
    const replies = await Promise.all(Array.from({ length: 4 }, () => p.send(kp)));
    assert.ok(replies.every((r) => r.receipt.sequence === replies[0].receipt.sequence));
    await p.send(p.envelope('key_package'), 409);
    await p.send({ ...kp, expires_at: kp.expires_at + 1 }, 409);
    await f.env.DB.prepare('UPDATE messaging_invitation_packet SET expires_at=1').run();
    await p.snapshot(f.a, f.scope(p.a.c), 410);
    await p.consume(kp, 503);
    await p.send(p.envelope('invite_commit'), 409);
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_invitation_packet').first<{
        n: number;
      }>())!.n,
      1,
    );
  } finally {
    await f.close();
  }
});
test('Welcome consumption and activation roll back together; successful lost database replies reconcile exact receipts', async () => {
  const f = await fixture();
  try {
    const p = await pair(f);
    await p.approve();
    await p.approve(f.b);
    const kp = p.envelope('key_package');
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('INSERT INTO messaging_invitation_packet', 'lost_invitation_reply', f.b.owner)
      .run();
    await p.send(kp);
    await p.consume(kp);
    await p.send(p.envelope('invite_commit'));
    const w = p.envelope('welcome');
    await p.send(w);
    await f.env.DB.prepare(
      "CREATE TRIGGER fixture_block_activation BEFORE UPDATE OF bootstrap_complete ON messaging_channel BEGIN SELECT RAISE(ABORT,'fixture_activation_abort'); END",
    ).run();
    await p.consume(w, 503);
    const row = await f.env.DB.prepare(
      "SELECT p.finished,p.wire,c.bootstrap_complete FROM messaging_invitation_packet p JOIN messaging_channel c ON c.channel_id=p.channel_id WHERE p.kind='welcome'",
    ).first<{ finished: number; wire: string; bootstrap_complete: number }>();
    assert.equal(row!.finished, 0);
    assert.ok(row!.wire);
    assert.equal(row!.bootstrap_complete, 0);
    await f.env.DB.prepare('DROP TRIGGER fixture_block_activation').run();
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('UPDATE messaging_invitation_packet AS p', 'lost_invitation_reply', f.b.owner)
      .run();
    assert.equal((await p.consume(w)).complete, true);
  } finally {
    await f.close();
  }
});
test('packet SQL fences active SSO at insertion; revoked peers and authority loss during snapshot cannot authorize admission', async () => {
  for (const mode of ['account', 'epoch', 'credential', 'session', 'expiry']) {
    const f = await fixture();
    try {
      const p = await pair(f);
      await p.approve();
      await p.approve(f.b);
      await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
        .bind('INSERT INTO messaging_invitation_packet', mode, f.b.owner)
        .run();
      await p.send(p.envelope('key_package'), 409);
      assert.equal(
        (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_invitation_packet').first<{
          n: number;
        }>())!.n,
        0,
      );
    } finally {
      await f.close();
    }
  }
  const f = await fixture();
  try {
    const p = await pair(f);
    await p.approve();
    await p.approve(f.b);
    await p.send(p.envelope('key_package'));
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('SELECT p.*', 'credential', f.a.owner)
      .run();
    await p.snapshot(f.a, f.scope(p.a.c), 403);
    await f.env.DB.prepare('UPDATE credential SET active=1 WHERE credential_id=?')
      .bind(f.a.credential)
      .run();
    await f.response(
      await f.request(
        `/messaging/devices/${p.b.c.device.device_id}/revoke`,
        'POST',
        { expected_revision: 1 },
        f.b,
      ),
    );
    await p.snapshot(f.a, f.scope(p.a.c), 403);
  } finally {
    await f.close();
  }
});
