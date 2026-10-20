import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fixture, digest } from './server-support.ts';
import { pair } from './replacement-server-support.ts';
import type { InvitationOffer } from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
async function status(f: Server, offer: InvitationOffer, scope: string, who = f.a, expected = 200) {
  return f.response<{ ready: boolean; complete: boolean; blocked: boolean; expired: boolean }>(
    await f.request(
      `/messaging/channels/${offer.channel.id}/invitation/status`,
      'POST',
      { offer, scope },
      who,
    ),
    expected,
  );
}
test('admission metadata reports own consent, bilateral readiness and permanent closure without releasing wire', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      a = p.approval(),
      b = p.approval(f.b);
    await p.approve(a);
    const waiting = await status(f, p.next, a.scope);
    assert.deepEqual(Object.keys(waiting).sort(), [
      'blocked',
      'channel',
      'complete',
      'expired',
      'inviter_scope',
      'ready',
    ]);
    assert.equal(waiting.ready, false);
    await status(f, p.next, b.scope, f.b, 403);
    await p.approve(b, f.b);
    assert.equal((await status(f, p.next, b.scope, f.b)).ready, true);
    await f.response(
      await f.request(
        `/messaging/channels/${p.next.channel.id}/close`,
        'POST',
        { offer: p.next, scope: b.scope, operation_id: randomUUID(), reason: 'cancel_invitation' },
        f.b,
      ),
    );
    const closed = await status(f, p.next, a.scope);
    assert.equal(closed.blocked, true);
    assert.equal(closed.complete, false);
    await f.response(
      await f.request(`/messaging/channels/${p.next.channel.id}/invitation/${a.scope}`, 'GET'),
      403,
    );
    await f.env.DB.prepare("UPDATE messaging_generation SET status='revoked' WHERE scope_hash=?")
      .bind(b.scope)
      .run();
    assert.equal((await status(f, p.next, a.scope)).blocked, true);
    await status(f, p.next, b.scope, f.b, 403);
  } finally {
    await f.close();
  }
});
test('expired consumed KeyPackages and Welcome are visible before completion, but expiry cannot invalidate a completed admission', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      a = p.approval(),
      b = p.approval(f.b);
    await p.approve(a);
    await p.approve(b, f.b);
    const wire = randomBytes(32),
      packet = {
        channel_id: p.next.channel.id,
        message_id: randomUUID(),
        sender_scope: b.scope,
        recipient_scope: a.scope,
        kind: 'key_package',
        digest: digest(wire),
        expires_at: Math.floor(Date.now() / 1000) + 3600,
        wire: wire.toString('base64url'),
      };
    await f.response(
      await f.request(
        `/messaging/channels/${p.next.channel.id}/invitation/packets`,
        'POST',
        packet,
        f.b,
      ),
    );
    assert.equal((await status(f, p.next, a.scope)).expired, false);
    await f.env.DB.prepare(
      'UPDATE messaging_invitation_packet SET expires_at=unixepoch()-1,finished=1,wire=NULL WHERE channel_id=?',
    )
      .bind(p.next.channel.id)
      .run();
    assert.equal((await status(f, p.next, a.scope)).expired, true);
    assert.equal((await status(f, p.next, b.scope, f.b)).expired, true);
    await f.env.DB.prepare(
      "UPDATE messaging_invitation_packet SET kind='welcome',finished=0,wire=? WHERE channel_id=?",
    )
      .bind(packet.wire, p.next.channel.id)
      .run();
    assert.equal((await status(f, p.next, b.scope, f.b)).expired, true);
    await f.env.DB.prepare('UPDATE messaging_channel SET bootstrap_complete=1 WHERE channel_id=?')
      .bind(p.next.channel.id)
      .run();
    const complete = await status(f, p.next, a.scope);
    assert.equal(complete.expired, false);
    assert.equal(complete.complete, true);
  } finally {
    await f.close();
  }
});
test('admission status binds owner, scope, exact offer, origin, bounded body and current SSO on the primary', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      a = p.approval(),
      other = await f.seed();
    await p.approve(a);
    await status(f, p.next, a.scope, other, 403);
    await status(f, p.next, p.approval(f.b).scope, f.a, 403);
    await status(
      f,
      { ...p.next, channel: { ...p.next.channel, group: randomBytes(16).toString('base64url') } },
      a.scope,
      f.a,
      403,
    );
    const path = `/messaging/channels/${p.next.channel.id}/invitation/status`;
    await f.response(
      await f.request(path, 'POST', { offer: p.next, scope: a.scope }, f.a, {
        Origin: 'https://evil.test',
      }),
      403,
    );
    await f.response(
      await f.request(path, 'POST', { offer: p.next, scope: a.scope, extra: true }),
      400,
    );
    await f.response(
      await f.request(path, 'POST', { offer: p.next, scope: a.scope, extra: 'x'.repeat(2000) }),
      413,
    );
    await f.env.DB.prepare('UPDATE sso_session SET revoked=1 WHERE sso_id=?')
      .bind(f.a.session)
      .run();
    await status(f, p.next, a.scope, f.a, 401);
  } finally {
    await f.close();
  }
});
