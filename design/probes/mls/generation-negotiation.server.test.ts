import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { fixture, keys, proof } from './server-support.ts';
import { pair } from './replacement-server-support.ts';
import type { InvitationOffer } from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
async function setup(f: Server) {
  const p = await pair(f),
    latest = await f.start(keys(), p.b.c.device.device_id, 2, f.b),
    latestProof = proof(latest.c, latest.k);
  await f.complete(latest, latestProof);
  const endpoints = [p.next.channel.a, p.next.channel.b]
    .map((e) =>
      e.scope === f.scope(p.rotated.c)
        ? { scope: f.scope(latest.c), fingerprint: latest.c.scope.fingerprint }
        : e,
    )
    .sort((a, b) => (a.scope < b.scope ? -1 : 1));
  const next: InvitationOffer = {
    ...p.next,
    channel: {
      ...p.next.channel,
      id: randomUUID(),
      group: randomBytes(16).toString('base64url'),
      a: endpoints[0],
      b: endpoints[1],
    },
  };
  return {
    ...p,
    latest,
    latestProof,
    intent: { previous: p.previous, next, scope: f.scope(latest.c), operation_id: randomUUID() },
  };
}
async function read(
  f: Server,
  intent: Awaited<ReturnType<typeof setup>>['intent'],
  who = f.b,
  status = 200,
) {
  return f.response<{ binding: string; operation_id: string; scope: string }>(
    await f.request(
      `/messaging/channels/${intent.next.channel.id}/replace/predecessor`,
      'POST',
      intent,
      who,
    ),
    status,
  );
}
test('a third generation obtains the original historical leaf as a revoked signed binding without any consent, closure or private state', async () => {
  const f = await fixture();
  try {
    const p = await setup(f),
      result = await read(f, p.intent),
      old = f.binding(result.binding);
    assert.deepEqual(old.device, p.b.c.device);
    assert.equal(old.public_key, p.b.k.publicKey.export({ format: 'jwk' }).x);
    assert.equal(old.status, 'revoked');
    assert.equal(result.operation_id, p.intent.operation_id);
    assert.equal(result.scope, p.intent.scope);
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_replacement_approval').first<{
        n: number;
      }>())!.n,
      0,
    );
    assert.equal(
      (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
        .bind(p.previous.channel.id)
        .first<{ blocked: number }>())!.blocked,
      0,
    );
    assert.equal(
      await f.env.DB.prepare('SELECT channel_id FROM messaging_channel WHERE channel_id=?')
        .bind(p.intent.next.channel.id)
        .first(),
      null,
    );
    // Completion retries must reuse the exact proof, including its original iat/exp.
    assert.equal(f.binding((await f.complete(p.latest, p.latestProof)).binding).status, 'active');
  } finally {
    await f.close();
  }
});
test('historical membership requires the changed current owner and exact completed parent, endpoints, role, scope, origin and bounded body', async () => {
  const f = await fixture();
  try {
    const p = await setup(f),
      path = `/messaging/channels/${p.intent.next.channel.id}/replace/predecessor`;
    await read(f, p.intent, f.a, 403);
    await read(f, p.intent, await f.seed(), 403);
    await read(f, { ...p.intent, scope: f.scope(p.a.c) }, f.a, 403);
    await read(
      f,
      { ...p.intent, previous: { ...p.previous, inviter_scope: f.scope(p.b.c) } },
      f.b,
      403,
    );
    await read(
      f,
      {
        ...p.intent,
        previous: {
          ...p.previous,
          channel: { ...p.previous.channel, group: randomBytes(16).toString('base64url') },
        },
      },
      f.b,
      403,
    );
    await f.response(
      await f.request(path, 'POST', p.intent, f.b, { Origin: 'https://evil.test' }),
      403,
    );
    await f.response(await f.request(path, 'POST', { ...p.intent, extra: true }, f.b), 400);
    await f.response(
      await f.request(path, 'POST', { ...p.intent, extra: 'x'.repeat(3000) }, f.b),
      413,
    );
    await read(f, p.approval(f.b), f.b, 403);
    await f.env.DB.prepare('UPDATE messaging_channel SET bootstrap_complete=0 WHERE channel_id=?')
      .bind(p.previous.channel.id)
      .run();
    await read(f, p.intent, f.b, 403);
  } finally {
    await f.close();
  }
});
test('both current endpoints must remain active; a superseded or revoked caller or peer cannot obtain historical membership', async () => {
  for (const own of [true, false]) {
    const f = await fixture();
    try {
      const p = await setup(f);
      await f.env.DB.prepare("UPDATE messaging_generation SET status='revoked' WHERE scope_hash=?")
        .bind(own ? p.intent.scope : f.scope(p.a.c))
        .run();
      await read(f, p.intent, f.b, 403);
    } finally {
      await f.close();
    }
  }
});
test('all live SSO predicates are rechecked after asynchronous historical-binding signing', async () => {
  for (const mode of ['account', 'epoch', 'credential', 'session', 'expiry']) {
    const f = await fixture();
    try {
      const p = await setup(f);
      await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,2)')
        .bind(
          'SELECT g.*,unixepoch() AS now FROM messaging_generation g JOIN messaging_live_device',
          mode,
          f.b.owner,
        )
        .run();
      await read(f, p.intent, f.b, 403);
    } finally {
      await f.close();
    }
  }
});
