import { randomBytes, randomUUID } from 'node:crypto';
import { fixture, keys } from './server-support.ts';
import type { InvitationOffer } from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
export async function pair(f: Server) {
  for (const who of [f.a, f.b])
    await f.response(await f.request('/messaging/account', 'POST', {}, who));
  const a = await f.start(),
    b = await f.start(keys(), randomUUID(), 0, f.b);
  await f.complete(a);
  await f.complete(b);
  const endpoint = (d: typeof a) => ({ scope: f.scope(d.c), fingerprint: d.c.scope.fingerprint });
  const offer = (endpoints: ReturnType<typeof endpoint>[]): InvitationOffer => {
    endpoints.sort((a, b) => (a.scope < b.scope ? -1 : 1));
    return {
      channel: {
        id: randomUUID(),
        group: randomBytes(16).toString('base64url'),
        a: endpoints[0],
        b: endpoints[1],
      },
      inviter_scope: f.scope(a.c),
    };
  };
  const previous = offer([endpoint(a), endpoint(b)]);
  for (const who of [f.a, f.b])
    await f.response(
      await f.request(
        `/messaging/channels/${previous.channel.id}/invitation`,
        'POST',
        previous,
        who,
      ),
    );
  await f.env.DB.prepare('UPDATE messaging_channel SET bootstrap_complete=1 WHERE channel_id=?')
    .bind(previous.channel.id)
    .run();
  const rotated = await f.start(keys(), b.c.device.device_id, 1, f.b);
  await f.complete(rotated);
  const next = offer([endpoint(a), endpoint(rotated)]);
  const approval = (who = f.a) => ({
    previous,
    next,
    scope: who === f.a ? f.scope(a.c) : f.scope(rotated.c),
    operation_id: randomUUID(),
  });
  const approve = async (body = approval(), who = f.a, status = 200) =>
    f.response<{ ready: boolean; operation_id: string }>(
      await f.request(`/messaging/channels/${body.next.channel.id}/replace`, 'POST', body, who),
      status,
    );
  return { a, b, rotated, previous, next, approval, approve };
}
