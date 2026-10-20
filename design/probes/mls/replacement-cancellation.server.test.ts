import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fixture } from './server-support.ts';
import { pair } from './replacement-server-support.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
type Approval = ReturnType<Awaited<ReturnType<typeof pair>>['approval']>;
function cancelIntent(a: Approval) {
  const { operation_id: approval_id, ...rest } = a;
  return { ...rest, approval_id, operation_id: randomUUID() };
}
async function cancel(f: Server, c: ReturnType<typeof cancelIntent>, who = f.a, status = 200) {
  return f.response<{ outcome: 'cancelled' | 'admitted'; operation_id: string }>(
    await f.request(`/messaging/channels/${c.next.channel.id}/replace/cancel`, 'POST', c, who),
    status,
  );
}
async function state(f: Server, a: Approval, who = f.a, status = 200) {
  return f.response<{ state: string }>(
    await f.request(`/messaging/channels/${a.next.channel.id}/replace/status`, 'POST', a, who),
    status,
  );
}
function alternate(a: Approval): Approval {
  return {
    ...a,
    next: {
      ...a.next,
      channel: {
        ...a.next.channel,
        id: randomUUID(),
        group: randomBytes(16).toString('base64url'),
      },
    },
  };
}
test('unpublished cancellation permanently blocks the exact proposal and parent, retries its exact receipt, and allows explicit fresh approval', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      a = p.approval(),
      c = cancelIntent(a);
    assert.equal((await state(f, a)).state, 'unpublished');
    const receipt = await cancel(f, c);
    assert.equal(receipt.outcome, 'cancelled');
    assert.deepEqual(await cancel(f, c), receipt);
    assert.equal((await state(f, a)).state, 'cancelled');
    await cancel(f, { ...c, operation_id: randomUUID() }, f.a, 409);
    await p.approve(a, f.a, 409);
    assert.equal(
      (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
        .bind(p.previous.channel.id)
        .first<{ blocked: number }>())!.blocked,
      1,
    );
    const next = alternate(p.approval());
    assert.equal((await p.approve(next)).ready, false);
    assert.equal((await p.approve({ ...p.approval(f.b), next: next.next }, f.b)).ready, true);
  } finally {
    await f.close();
  }
});
test('competing owner proposals are resolved by explicit veto before choosing the peer proposal; stale approval IDs cannot cancel it', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      a = p.approval(),
      b = alternate(p.approval(f.b));
    assert.equal((await p.approve(a)).ready, false);
    assert.equal((await p.approve(b, f.b)).ready, false);
    await cancel(f, cancelIntent({ ...a, operation_id: randomUUID() }), f.a, 409);
    assert.equal((await cancel(f, cancelIntent(a))).outcome, 'cancelled');
    assert.equal((await p.approve({ ...p.approval(), next: b.next })).ready, true);
    assert.equal((await state(f, b, f.b)).state, 'admitted');
    const late = cancelIntent(b);
    assert.equal((await cancel(f, late, f.b)).outcome, 'admitted');
    assert.equal(
      (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
        .bind(b.next.channel.id)
        .first<{ blocked: number }>())!.blocked,
      0,
    );
  } finally {
    await f.close();
  }
});
test('peer veto is observable and remains possible when that peer registry scope is revoked, while the caller scope stays current', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      a = p.approval(),
      b = p.approval(f.b);
    await p.approve(a);
    await f.env.DB.prepare("UPDATE messaging_generation SET status='revoked' WHERE scope_hash=?")
      .bind(f.scope(p.rotated.c))
      .run();
    assert.equal((await cancel(f, cancelIntent(a))).outcome, 'cancelled');
    assert.equal((await state(f, a)).state, 'cancelled');
    await cancel(f, cancelIntent(b), f.b, 409);
  } finally {
    await f.close();
  }
});
test('cancellation versus final approval has one atomic outcome and never reports cancellation for a bilateral admitted child', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      a = p.approval(),
      b = p.approval(f.b),
      c = cancelIntent(a);
    await p.approve(a);
    const [stop, admit] = await Promise.all([
      f.request(`/messaging/channels/${p.next.channel.id}/replace/cancel`, 'POST', c, f.a),
      f.request(`/messaging/channels/${p.next.channel.id}/replace`, 'POST', b, f.b),
    ]);
    const result = await f.response<{ outcome: string }>(stop),
      row = (await f.env.DB.prepare(
        'SELECT blocked,a_consent,b_consent FROM messaging_channel WHERE channel_id=?',
      )
        .bind(p.next.channel.id)
        .first<{ blocked: number; a_consent: number; b_consent: number }>())!;
    if (result.outcome === 'cancelled') {
      assert.equal(admit.status, 409);
      assert.equal(row.blocked, 1);
      assert.notEqual(row.a_consent + row.b_consent, 2);
    } else {
      assert.equal(result.outcome, 'admitted');
      assert.equal(admit.status, 200);
      assert.equal(row.blocked, 0);
      assert.equal(row.a_consent + row.b_consent, 2);
    }
    assert.equal((await cancel(f, c)).outcome, result.outcome);
  } finally {
    await f.close();
  }
});
test('cancellation batch rolls back closure and tombstone on failure, and reconciles a lost committed reply', async () => {
  const f = await fixture();
  try {
    const p = await pair(f),
      c = cancelIntent(p.approval());
    await f.env.DB.exec(
      "CREATE TRIGGER deny_cancel BEFORE INSERT ON messaging_replacement_cancellation BEGIN SELECT RAISE(ABORT,'injected_cancel_failure'); END",
    );
    await cancel(f, c, f.a, 409);
    assert.equal(
      await f.env.DB.prepare('SELECT channel_id FROM messaging_channel WHERE channel_id=?')
        .bind(p.next.channel.id)
        .first(),
      null,
    );
    assert.equal(
      (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
        .bind(p.previous.channel.id)
        .first<{ blocked: number }>())!.blocked,
      0,
    );
    await f.env.DB.exec('DROP TRIGGER deny_cancel');
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('INSERT INTO messaging_replacement_cancellation', 'lost_recovery_reply', f.a.owner)
      .run();
    assert.equal((await cancel(f, c)).outcome, 'cancelled');
  } finally {
    await f.close();
  }
});
test('all live SSO predicates, exact descriptors, scope, origin and bounded body guard cancellation writes and status reads', async () => {
  for (const mode of ['account', 'epoch', 'credential', 'session', 'expiry']) {
    const f = await fixture();
    try {
      const p = await pair(f),
        c = cancelIntent(p.approval());
      await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
        .bind('INSERT INTO messaging_replacement_cancellation', mode, f.a.owner)
        .run();
      await cancel(f, c, f.a, 409);
      assert.equal(
        (await f.env.DB.prepare(
          'SELECT count(*) AS n FROM messaging_replacement_cancellation',
        ).first<{ n: number }>())!.n,
        0,
      );
      assert.equal(
        (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
          .bind(p.previous.channel.id)
          .first<{ blocked: number }>())!.blocked,
        0,
      );
    } finally {
      await f.close();
    }
  }
  const f = await fixture();
  try {
    const p = await pair(f),
      a = p.approval(),
      c = cancelIntent(a),
      other = await f.seed();
    await cancel(f, c, other, 409);
    await state(f, a, other, 409);
    await cancel(
      f,
      {
        ...c,
        previous: {
          ...c.previous,
          channel: { ...c.previous.channel, group: randomBytes(16).toString('base64url') },
        },
      },
      f.a,
      409,
    );
    await f.response(
      await f.request(`/messaging/channels/${p.next.channel.id}/replace/cancel`, 'POST', c, f.a, {
        Origin: 'https://evil.test',
      }),
      403,
    );
    await f.response(
      await f.request(
        `/messaging/channels/${p.next.channel.id}/replace/cancel`,
        'POST',
        { ...c, extra: 'x'.repeat(3000) },
        f.a,
      ),
      413,
    );
  } finally {
    await f.close();
  }
});
