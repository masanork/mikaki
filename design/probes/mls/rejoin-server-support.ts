import { randomBytes, randomUUID } from 'node:crypto';
import { fixture, keys } from './server-support.ts';
import type { InvitationOffer } from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
export async function rejoinPair(f: Server) {
  for (const who of [f.a, f.b])
    await f.response(await f.request('/messaging/account', 'POST', {}, who));
  const a = await f.start(),
    b = await f.start(keys(), randomUUID(), 0, f.b);
  await f.complete(a);
  await f.complete(b);
  const endpoints = [a, b]
    .map((d) => ({ scope: f.scope(d.c), fingerprint: d.c.scope.fingerprint }))
    .sort((a, b) => (a.scope < b.scope ? -1 : 1));
  const previous: InvitationOffer = {
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
      await f.request(
        `/messaging/channels/${previous.channel.id}/invitation`,
        'POST',
        previous,
        who,
      ),
    );
  const successor = (old = previous): InvitationOffer => ({
    ...old,
    channel: { ...old.channel, id: randomUUID(), group: randomBytes(16).toString('base64url') },
  });
  const scope = (who = f.a) => (who === f.a ? f.scope(a.c) : f.scope(b.c));
  const close = async (offer = previous, who = f.a) =>
    f.response(
      await f.request(
        `/messaging/channels/${offer.channel.id}/close`,
        'POST',
        { offer, scope: scope(who), operation_id: randomUUID(), reason: 'cancel_invitation' },
        who,
      ),
    );
  const rejoin = async (next: InvitationOffer, who = f.a, expected = 200, old = previous) =>
    f.response<{ ready: boolean }>(
      await f.request(
        `/messaging/channels/${next.channel.id}/rejoin`,
        'POST',
        { previous: old, next },
        who,
      ),
      expected,
    );
  const status = async (next: InvitationOffer, who = f.a, expected = 200, old = previous) =>
    f.response<{ state: string; complete: boolean; expired: boolean }>(
      await f.request(
        `/messaging/channels/${next.channel.id}/rejoin/status`,
        'POST',
        { previous: old, next, scope: scope(who) },
        who,
      ),
      expected,
    );
  return { a, b, previous, successor, scope, close, rejoin, status };
}
