import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fixture, keys, digest } from './server-support.ts';
import { pair } from './replacement-server-support.ts';
import type { InvitationOffer } from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
type Intent = ReturnType<Awaited<ReturnType<typeof pair>>['approval']>;
async function setup(f: Server) {
  const p = await pair(f),
    a = p.approval(),
    b = p.approval(f.b);
  await p.approve(a);
  await p.approve(b, f.b);
  const latest = await f.start(keys(), p.b.c.device.device_id, 2, f.b);
  await f.complete(latest);
  return {
    ...p,
    aApproval: a,
    bApproval: b,
    latest,
    intent: {
      previous: p.previous,
      next: p.next,
      scope: f.scope(latest.c),
      operation_id: randomUUID(),
    },
  };
}
async function stop(f: Server, intent: Intent, who = f.b, status = 200) {
  return f.response<{
    predecessor_id: string;
    channel: InvitationOffer['channel'];
    inviter_scope: string;
    scope: string;
    operation_id: string;
    state: string;
  }>(
    await f.request(
      `/messaging/channels/${intent.next.channel.id}/replace/stop`,
      'POST',
      intent,
      who,
    ),
    status,
  );
}
async function row(f: Server, id: string) {
  return f.env.DB.prepare('SELECT * FROM messaging_channel WHERE channel_id=?').bind(id).first<{
    blocked: number;
    a_consent: number;
    b_consent: number;
    bootstrap_complete: number;
  }>();
}
async function receipts(f: Server) {
  return (
    await f.env.DB.prepare('SELECT * FROM messaging_replacement_stop ORDER BY operation_id').all()
  ).results;
}
function proposal(p: Awaited<ReturnType<typeof setup>>, f: Server): Intent {
  const endpoints = [
    { scope: f.scope(p.a.c), fingerprint: p.a.c.scope.fingerprint },
    { scope: f.scope(p.latest.c), fingerprint: p.latest.c.scope.fingerprint },
  ].sort((a, b) => (a.scope < b.scope ? -1 : 1));
  return {
    previous: p.previous,
    next: {
      channel: {
        id: randomUUID(),
        group: randomBytes(16).toString('base64url'),
        a: endpoints[0],
        b: endpoints[1],
      },
      inviter_scope: f.scope(p.a.c),
    },
    scope: f.scope(p.a.c),
    operation_id: randomUUID(),
  };
}
test('the latest same-slot device can explicitly stop an admitted incomplete successor; this grants no consent, live lease, packet or history', async () => {
  const f = await fixture();
  try {
    const p = await setup(f),
      original = await row(f, p.previous.channel.id),
      failed = await row(f, p.next.channel.id);
    assert.equal(failed!.bootstrap_complete, 0);
    // The original close route correctly refuses a scope outside this child.
    await f.response(
      await f.request(
        `/messaging/channels/${p.next.channel.id}/close`,
        'POST',
        {
          offer: p.next,
          scope: p.intent.scope,
          operation_id: randomUUID(),
          reason: 'cancel_invitation',
        },
        f.b,
      ),
      400,
    );
    await f.response(
      await f.request(
        `/messaging/channels/${p.next.channel.id}/close`,
        'POST',
        {
          offer: p.next,
          scope: f.scope(p.rotated.c),
          operation_id: randomUUID(),
          reason: 'cancel_invitation',
        },
        f.b,
      ),
      403,
    );
    const result = await stop(f, p.intent);
    assert.deepEqual(result, {
      predecessor_id: p.previous.channel.id,
      channel: p.next.channel,
      inviter_scope: p.next.inviter_scope,
      scope: p.intent.scope,
      operation_id: p.intent.operation_id,
      state: 'closed',
    });
    assert.deepEqual(await stop(f, p.intent), result);
    assert.deepEqual(await row(f, p.previous.channel.id), original);
    assert.deepEqual(await row(f, p.next.channel.id), { ...failed, blocked: 1 });
    assert.equal((await receipts(f)).length, 1);
    for (const table of [
      'messaging_channel_close',
      'messaging_replacement_cancellation',
      'messaging_invitation_packet',
      'messaging_mail',
    ])
      assert.equal(
        (await f.env.DB.prepare(`SELECT count(*) AS n FROM ${table}`).first<{ n: number }>())!.n,
        0,
      );
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_replacement_approval').first<{
        n: number;
      }>())!.n,
      2,
    );
    for (const [who, scope] of [
      [f.a, f.scope(p.a.c)],
      [f.b, f.scope(p.rotated.c)],
      [f.b, p.intent.scope],
    ] as const) {
      await f.response(
        await f.request(
          `/messaging/channels/${p.next.channel.id}/bindings/${scope}`,
          'GET',
          undefined,
          who,
        ),
        403,
      );
      await f.response(
        await f.request(
          `/messaging/channels/${p.next.channel.id}/invitation/${scope}`,
          'GET',
          undefined,
          who,
        ),
        403,
      );
      await f.response(
        await f.request(
          `/messaging/channels/${p.next.channel.id}/inbox/${scope}`,
          'GET',
          undefined,
          who,
        ),
        403,
      );
    }
    await p.approve(p.aApproval, f.a, 409);
    await p.approve(p.bApproval, f.b, 409);
    await stop(f, { ...p.intent, operation_id: randomUUID() }, f.b, 409);
  } finally {
    await f.close();
  }
});
test('fresh latest-key agreement stays blocked until explicit stop and still requires both exact new approvals; a retained stop cannot close the new conversation', async () => {
  const f = await fixture();
  try {
    const p = await setup(f),
      fresh = proposal(p, f);
    await p.approve(fresh, f.a, 409);
    assert.equal(await row(f, fresh.next.channel.id), null);
    await stop(f, p.intent);
    assert.equal((await p.approve(fresh)).ready, false);
    await f.response(
      await f.request(`/messaging/channels/${fresh.next.channel.id}/bindings/${f.scope(p.a.c)}`),
      403,
    );
    const own = { ...fresh, scope: p.intent.scope, operation_id: randomUUID() };
    // Historical proof is still a revoked binding for B1, never B2 transport authority.
    const proof = await f.response<{ binding: string }>(
      await f.request(
        `/messaging/channels/${fresh.next.channel.id}/replace/predecessor`,
        'POST',
        own,
        f.b,
      ),
    );
    assert.deepEqual(f.binding(proof.binding).device, p.b.c.device);
    assert.equal(f.binding(proof.binding).status, 'revoked');
    assert.equal((await p.approve(own, f.b)).ready, true);
    await f.response(
      await f.request(
        `/messaging/channels/${fresh.next.channel.id}/bindings/${p.intent.scope}`,
        'GET',
        undefined,
        f.b,
      ),
    );
    const current = await row(f, fresh.next.channel.id);
    await stop(f, p.intent);
    assert.deepEqual(await row(f, fresh.next.channel.id), current);
    await stop(f, { ...p.intent, next: fresh.next }, f.b, 409);
    assert.deepEqual(await row(f, fresh.next.channel.id), current);
    assert.equal((await row(f, p.next.channel.id))!.blocked, 1);
    assert.equal((await row(f, p.previous.channel.id))!.blocked, 1);
  } finally {
    await f.close();
  }
});
test('each further current generation and each owner has an independent immutable stop receipt, including when the peer is revoked', async () => {
  const f = await fixture();
  try {
    const p = await setup(f);
    await stop(f, { ...p.intent, scope: f.scope(p.rotated.c) }, f.b, 409);
    await stop(f, p.intent);
    const newer = await f.start(keys(), p.b.c.device.device_id, 3, f.b);
    await f.complete(newer);
    await stop(f, p.intent, f.b, 409);
    const nextIntent = { ...p.intent, scope: f.scope(newer.c), operation_id: randomUUID() };
    await stop(f, nextIntent);
    const aIntent = { ...p.intent, scope: f.scope(p.a.c), operation_id: randomUUID() };
    await f.env.DB.prepare("UPDATE messaging_generation SET status='revoked' WHERE scope_hash=?")
      .bind(nextIntent.scope)
      .run();
    await stop(f, aIntent, f.a);
    assert.equal((await receipts(f)).length, 3);
    await stop(f, nextIntent, f.b, 409);
    await stop(f, { ...aIntent, operation_id: randomUUID() }, f.a, 409);
    assert.equal((await receipts(f)).length, 3);
  } finally {
    await f.close();
  }
});
test('stop requires the same historical device slot and exact admitted child and completed original, never another owner/device or an absent or pending proposal', async () => {
  const f = await fixture();
  try {
    const p = await setup(f),
      other = await f.start(keys(), randomUUID(), 0, f.b);
    await f.complete(other);
    await stop(f, p.intent, await f.seed(), 409);
    await stop(f, p.intent, f.a, 409);
    await stop(f, { ...p.intent, scope: f.scope(other.c) }, f.b, 409);
    await stop(f, { ...p.intent, scope: f.scope(p.b.c) }, f.b, 409);
    await stop(
      f,
      { ...p.intent, previous: { ...p.previous, inviter_scope: f.scope(p.b.c) } },
      f.b,
      409,
    );
    await stop(
      f,
      {
        ...p.intent,
        previous: {
          ...p.previous,
          channel: { ...p.previous.channel, group: randomBytes(16).toString('base64url') },
        },
      },
      f.b,
      409,
    );
    await stop(
      f,
      {
        ...p.intent,
        next: {
          ...p.next,
          channel: { ...p.next.channel, group: randomBytes(16).toString('base64url') },
        },
      },
      f.b,
      409,
    );
    await stop(
      f,
      { ...p.intent, next: { ...p.next, inviter_scope: f.scope(p.rotated.c) } },
      f.b,
      409,
    );
    const absent = {
      ...p.intent,
      next: { ...p.next, channel: { ...p.next.channel, id: randomUUID() } },
    };
    await stop(f, absent, f.b, 409);
    assert.equal(await row(f, absent.next.channel.id), null);
    await f.env.DB.prepare('UPDATE messaging_channel SET bootstrap_complete=0 WHERE channel_id=?')
      .bind(p.previous.channel.id)
      .run();
    await stop(f, p.intent, f.b, 409);
    await f.env.DB.prepare('UPDATE messaging_channel SET bootstrap_complete=1 WHERE channel_id=?')
      .bind(p.previous.channel.id)
      .run();
    await f.env.DB.prepare('UPDATE messaging_channel SET b_consent=0 WHERE channel_id=?')
      .bind(p.next.channel.id)
      .run();
    await stop(f, p.intent, f.b, 409);
    assert.equal((await row(f, p.next.channel.id))!.blocked, 0);
    assert.equal((await receipts(f)).length, 0);
  } finally {
    await f.close();
  }
});
test('body, route, origin and exact stable stop intent are enforced without writes', async () => {
  const f = await fixture();
  try {
    const p = await setup(f),
      path = `/messaging/channels/${p.next.channel.id}/replace/stop`;
    await f.response(
      await f.request(path, 'POST', p.intent, f.b, { Origin: 'https://evil.test' }),
      403,
    );
    await f.response(await f.request(path, 'POST', { ...p.intent, extra: true }, f.b), 400);
    await f.response(
      await f.request(path, 'POST', { ...p.intent, extra: 'x'.repeat(3000) }, f.b),
      413,
    );
    await f.response(
      await f.request(path, 'POST', { ...p.intent, operation_id: 'invalid' }, f.b),
      400,
    );
    await stop(f, { ...p.intent, scope: 'invalid' }, f.b, 400);
    await stop(f, { ...p.intent, next: p.previous }, f.b, 400);
    await f.response(
      await f.request(`/messaging/channels/${randomUUID()}/replace/stop`, 'POST', p.intent, f.b),
      400,
    );
    assert.equal((await receipts(f)).length, 0);
    assert.equal((await row(f, p.next.channel.id))!.blocked, 0);
  } finally {
    await f.close();
  }
});
test('atomic stop rollback leaves the admitted channel intact; a lost committed batch response reconciles its exact receipt', async () => {
  const f = await fixture();
  try {
    const p = await setup(f);
    await f.env.DB.exec(
      "CREATE TRIGGER deny_stop BEFORE UPDATE ON messaging_channel WHEN NEW.channel_id='" +
        p.next.channel.id +
        "' BEGIN SELECT RAISE(ABORT,'injected_stop_failure'); END",
    );
    await stop(f, p.intent, f.b, 409);
    assert.equal((await receipts(f)).length, 0);
    assert.equal((await row(f, p.next.channel.id))!.blocked, 0);
    await f.env.DB.exec('DROP TRIGGER deny_stop');
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('INSERT INTO messaging_replacement_stop', 'lost_recovery_reply', f.b.owner)
      .run();
    const receipt = await stop(f, p.intent);
    assert.deepEqual(await stop(f, p.intent), receipt);
    assert.equal((await receipts(f)).length, 1);
    assert.equal((await row(f, p.next.channel.id))!.blocked, 1);
  } finally {
    await f.close();
  }
});
test('all live SSO predicates are required inside the stop batch and during final primary receipt reconciliation', async () => {
  for (const mode of ['account', 'epoch', 'credential', 'session', 'expiry']) {
    for (const committed of [false, true]) {
      const f = await fixture();
      try {
        const p = await setup(f);
        await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
          .bind(
            committed ? 'SELECT 1 AS stopped' : 'INSERT INTO messaging_replacement_stop',
            mode,
            f.b.owner,
          )
          .run();
        await stop(f, p.intent, f.b, committed ? 503 : 409);
        assert.equal((await receipts(f)).length, committed ? 1 : 0);
        assert.equal((await row(f, p.next.channel.id))!.blocked, committed ? 1 : 0);
      } finally {
        await f.close();
      }
    }
  }
});
test('retained stop receipts are bounded per owner across generations; reaching the limit preserves exact retries and rolls back a fresh stop', async () => {
  const f = await fixture();
  try {
    const p = await setup(f);
    await stop(f, p.intent);
    // Repeated real registrations retain separate stop receipts for one child,
    // without first exhausting the distinct 32-channel consent limit.
    for (let i = 0; i < 31; i++) {
      p.latest = await f.start(keys(), p.b.c.device.device_id, i + 3, f.b);
      await f.complete(p.latest);
      p.intent = { ...p.intent, scope: f.scope(p.latest.c), operation_id: randomUUID() };
      await stop(f, p.intent);
    }
    await stop(f, p.intent);
    const fresh = proposal(p, f);
    await p.approve(fresh);
    await p.approve({ ...fresh, scope: p.intent.scope, operation_id: randomUUID() }, f.b);
    await stop(f, { ...p.intent, next: fresh.next, operation_id: randomUUID() }, f.b, 409);
    assert.equal((await row(f, fresh.next.channel.id))!.blocked, 0);
    assert.equal((await receipts(f)).length, 32);
    // One owner's limit and stop do not replace the other owner's explicit record.
    await stop(
      f,
      { ...p.intent, next: fresh.next, scope: f.scope(p.a.c), operation_id: randomUUID() },
      f.a,
    );
    assert.equal((await receipts(f)).length, 33);
  } finally {
    await f.close();
  }
});
test('stopping with a still-current endpoint prevents an existing invitation packet from being read, consumed or republished, without erasing it', async () => {
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
    const base = `/messaging/channels/${p.next.channel.id}/invitation`;
    const stored = await f.response<{ receipt: { envelope_hash: string } }>(
      await f.request(`${base}/packets`, 'POST', packet, f.b),
    );
    const before = (await f.env.DB.prepare('SELECT * FROM messaging_invitation_packet').all())
      .results;
    const snapshot = await f.response<{ packet: { wire: string } }>(
      await f.request(`${base}/${a.scope}`),
    );
    assert.equal(snapshot.packet.wire, packet.wire);
    await stop(f, { ...a, operation_id: randomUUID() }, f.a);
    for (const [who, scope] of [
      [f.a, a.scope],
      [f.b, b.scope],
    ] as const) {
      await f.response(await f.request(`${base}/${scope}`, 'GET', undefined, who), 403);
      await f.response(
        await f.request(
          `/messaging/channels/${p.next.channel.id}/bindings/${scope}`,
          'GET',
          undefined,
          who,
        ),
        403,
      );
    }
    await f.response(
      await f.request(`${base}/packets/${packet.message_id}/consume`, 'POST', {
        recipient_scope: a.scope,
        digest: packet.digest,
        envelope_hash: stored.receipt.envelope_hash,
      }),
      503,
    );
    await f.response(await f.request(`${base}/packets`, 'POST', packet, f.b), 409);
    assert.deepEqual(
      (await f.env.DB.prepare('SELECT * FROM messaging_invitation_packet').all()).results,
      before,
    );
    assert.equal((await row(f, p.next.channel.id))!.blocked, 1);
  } finally {
    await f.close();
  }
});
test('authority lost after receipt insertion inside the transaction rolls back both receipt and freeze instead of confirming a partial stop', async () => {
  const changes = [
    'UPDATE account_security SET active=0 WHERE account_id=NEW.owner_id',
    'UPDATE account_security SET epoch=epoch+1 WHERE account_id=NEW.owner_id',
    'UPDATE credential SET active=0 WHERE account_id=NEW.owner_id',
    'UPDATE sso_session SET revoked=1 WHERE account_id=NEW.owner_id',
    'UPDATE sso_session SET expires_at=unixepoch()-1 WHERE account_id=NEW.owner_id',
  ];
  for (const change of changes) {
    const f = await fixture();
    try {
      const p = await setup(f);
      await f.env.DB.exec(
        `CREATE TRIGGER revoke_during_stop AFTER INSERT ON messaging_replacement_stop BEGIN ${change}; END`,
      );
      await stop(f, p.intent, f.b, 409);
      assert.equal((await receipts(f)).length, 0);
      assert.equal((await row(f, p.next.channel.id))!.blocked, 0);
      // The authority mutation was in that same rolled-back D1 transaction.
      assert.equal(
        (await f.env.DB.prepare(
          'SELECT count(*) AS n FROM messaging_live_owner WHERE secret_hash=?',
        )
          .bind(digest(f.b.secret))
          .first<{ n: number }>())!.n,
        1,
      );
      await f.env.DB.exec('DROP TRIGGER revoke_during_stop');
      await stop(f, p.intent);
    } finally {
      await f.close();
    }
  }
});
test('racing final consent never lets a stop convert a pending proposal into a cancelled or implicitly approved one', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      a = p.approval(),
      b = p.approval(f.b),
      intent = { ...a, operation_id: randomUUID() };
    await p.approve(a);
    await stop(f, intent, f.a, 409);
    const pending = await row(f, p.next.channel.id);
    assert.equal(pending!.blocked, 0);
    assert.equal(pending!.a_consent + pending!.b_consent, 1);
    const [termination, admission] = await Promise.all([
      f.request(`/messaging/channels/${p.next.channel.id}/replace/stop`, 'POST', intent),
      f.request(`/messaging/channels/${p.next.channel.id}/replace`, 'POST', b, f.b),
    ]);
    assert.ok([200, 409].includes(termination.status));
    assert.ok([200, 409].includes(admission.status));
    const final = await row(f, p.next.channel.id);
    assert.equal(final!.a_consent + final!.b_consent, 2);
    assert.equal(final!.blocked, termination.status === 200 ? 1 : 0);
    assert.equal((await receipts(f)).length, termination.status === 200 ? 1 : 0);
    if (termination.status === 409) assert.equal(admission.status, 200);
    // The same explicit stop intent can retry once final consent is confirmed.
    await stop(f, intent, f.a);
    assert.equal((await row(f, p.next.channel.id))!.blocked, 1);
    assert.equal((await receipts(f)).length, 1);
  } finally {
    await f.close();
  }
});
test('stop preflight is a read-only exact current-slot admission check and cannot become a stop receipt or survive SSO loss', async () => {
  const f = await fixture();
  try {
    const p = await setup(f),
      path = `/messaging/channels/${p.next.channel.id}/replace/stop/status`;
    const read = async (intent = p.intent, who = f.b, status = 200) =>
      f.response<{ state: string }>(await f.request(path, 'POST', intent, who), status);
    assert.equal((await read()).state, 'admitted');
    assert.equal((await receipts(f)).length, 0);
    assert.equal((await row(f, p.next.channel.id))!.blocked, 0);
    await read(p.intent, f.a, 409);
    await read({ ...p.intent, scope: f.scope(p.rotated.c) }, f.b, 409);
    await read({ ...p.intent, next: { ...p.next, inviter_scope: f.scope(p.rotated.c) } }, f.b, 409);
    await f.response(
      await f.request(path, 'POST', p.intent, f.b, { Origin: 'https://evil.test' }),
      403,
    );
    await f.response(await f.request(path, 'POST', { ...p.intent, extra: true }, f.b), 400);
    await stop(f, p.intent);
    assert.equal((await read()).state, 'closed');
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind("SELECT CASE WHEN c.blocked=1 THEN 'closed'", 'session', f.b.owner)
      .run();
    await read(p.intent, f.b, 409);
    assert.equal((await receipts(f)).length, 1);
  } finally {
    await f.close();
  }
});
