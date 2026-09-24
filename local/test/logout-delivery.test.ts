import assert from 'node:assert/strict';
import { before, beforeEach, after, test } from 'node:test';
import { decodeJwt } from 'jose';
import { startLocal } from '../runtime.ts';
import { CLIENT, now, p, query, row, guard } from '../shared.ts';
import {
  logoutEvent,
  fanout,
  claim,
  settle,
  expire,
  outcome,
  sendLogout,
  deliveryHealth,
} from '../logout-delivery.ts';

type LocalRuntime = Awaited<ReturnType<typeof startLocal>>;
let local: LocalRuntime;
let db: LocalRuntime['opDB'];
before(async () => {
  local = await startLocal({ scheduler: false });
  db = local.opDB;
  await db.batch([
    query(db, "INSERT INTO account_security VALUES('account',1,1)"),
    query(db, "INSERT INTO credential VALUES('cred','account',1)"),
    query(db, "INSERT INTO app_connection VALUES('account',?,1,1)", [CLIENT]),
    query(
      db,
      "INSERT INTO sso_session(sso_id,account_id,credential_id,epoch,expires_at,revoked) VALUES('sso','account','cred',1,?,0)",
      [now() + 3600],
    ),
  ]);
});
after(async () => {
  await local?.close();
});
beforeEach(async () => {
  await db.batch([
    query(db, 'DELETE FROM logout_delivery'),
    query(db, 'DELETE FROM sso_logout_event'),
    query(db, 'DELETE FROM client_session'),
    query(db, 'UPDATE sso_session SET revoked=0'),
  ]);
});
async function seed(count = 1) {
  for (let i = 0; i < count; i++)
    await query(db, "INSERT INTO client_session VALUES(?,?,'sso','account','sub',1,1)", [
      CLIENT,
      `sid-${i}`,
    ]).run();
  await db.batch([
    logoutEvent(db, 'sso'),
    query(db, "UPDATE sso_session SET revoked=1 WHERE sso_id='sso'"),
  ]);
}
const state = (id: string | number) => row(db, 'SELECT * FROM logout_delivery WHERE id=?', [id]);

test('revocation and durable event roll back together; bounded fanout resumes without duplicates', async () => {
  await assert.rejects(
    db.batch([
      logoutEvent(db, 'sso'),
      query(db, 'UPDATE sso_session SET revoked=1'),
      ...guard(db, '0'),
    ]),
  );
  assert.equal((await row(db, 'SELECT COUNT(*) AS n FROM sso_logout_event')).n, 0);
  assert.equal((await row(db, 'SELECT revoked FROM sso_session')).revoked, 0);
  await seed(p('logout_delivery.fanout_batch_size') + 1);
  await fanout(db);
  assert.equal((await row(db, 'SELECT COUNT(*) AS n FROM logout_delivery')).n, 100);
  assert.equal((await row(db, 'SELECT expanded FROM sso_logout_event')).expanded, 0);
  await Promise.all([fanout(db), fanout(db)]);
  assert.equal((await row(db, 'SELECT COUNT(*) AS n FROM logout_delivery')).n, 101);
  assert.equal((await row(db, 'SELECT expanded FROM sso_logout_event')).expanded, 1);
  assert.equal(
    (
      await row(
        db,
        'SELECT COUNT(*) AS n FROM logout_delivery d JOIN sso_logout_event e ON e.id=d.event_id WHERE d.deadline!=e.deadline',
      )
    ).n,
    0,
  );
});

test('concurrent claim is exclusive and enforces the client-wide limit; stale completion is fenced', async () => {
  await seed(6);
  await fanout(db);
  const at = now();
  const tasks = (await Promise.all(Array.from({ length: 8 }, () => claim(db, at)))).filter(Boolean);
  assert.equal(tasks.length, p('logout_delivery.max_inflight_per_client'));
  assert.equal(new Set(tasks.map((t) => t.id)).size, tasks.length);
  const later = at + p('logout_delivery.lease_ttl');
  const replacement = await claim(db, later);
  const previous = tasks.find((t) => t.id === replacement.id);
  assert.ok(previous);
  assert.notEqual(previous.lease, replacement.lease);
  await settle(db, previous, { state: 'delivered', reason: 'success', next: later }, 200, later);
  assert.equal((await state(previous.id)).lease, replacement.lease);
  await settle(db, replacement, { state: 'delivered', reason: 'success', next: later }, 200, later);
  assert.equal((await state(previous.id)).state, 'delivered');
});

test('retry decisions honor HTTP classes, capped jitter, Retry-After, deadline and attempt limit', () => {
  const task = { attempts: 1, deadline: 100000 };
  for (const code of [200, 204, 299])
    assert.equal(outcome(task, code, null, 100).state, 'delivered');
  for (const code of [301, 307, 400, 401, 403, 404])
    assert.equal(outcome(task, code, null, 100).state, 'failed');
  for (const code of [0, 408, 429, 500, 503, 599])
    assert.equal(outcome(task, code, null, 100).next, 105);
  assert.equal(outcome({ ...task, attempts: 48 }, 503, null, 100).reason, 'attempt_limit');
  assert.equal(outcome(task, 503, '120', 100).next, 220);
  assert.equal(outcome(task, 429, new Date(220000).toUTCString(), 100).next, 220);
  assert.equal(outcome(task, 503, '-1', 100).next, 105);
  assert.equal(outcome(task, 503, '9'.repeat(400), 100).state, 'expired');
  assert.equal(outcome({ ...task, deadline: 105 }, 503, null, 100).state, 'expired');
  assert.equal(outcome({ ...task, attempts: 40 }, 503, null, 100, () => 1).next, 3700);
  assert.equal(outcome({ ...task, attempts: 40 }, 503, null, 100, () => 0).next, 105);
});

test('retry remains unavailable until due; expired leases exhaust attempts and deadlines', async () => {
  await seed();
  await fanout(db);
  const at = now();
  const task = await claim(db, at);
  await settle(db, task, outcome(task, 503, '120', at), 503, at);
  assert.equal(await claim(db, at + 119), null);
  const retry = await claim(db, at + 120);
  assert.equal(retry.attempts, 2);
  await query(db, 'UPDATE logout_delivery SET attempts=?', [
    p('logout_delivery.max_attempts'),
  ]).run();
  await expire(db, at + 121);
  assert.equal((await state(task.id)).state, 'leased');
  await expire(db, at + 120 + p('logout_delivery.lease_ttl'));
  assert.equal((await state(task.id)).reason, 'attempt_limit');
  await query(db, "UPDATE logout_delivery SET state='pending',attempts=0,deadline=?", [at]).run();
  await expire(db, at);
  assert.equal((await state(task.id)).state, 'expired');
  assert.equal((await deliveryHealth(db, at)).alert, true);
});

test('each delivery signs a fresh token, refuses redirects and bounds untrusted response consumption', async () => {
  const tokens: ReturnType<typeof decodeJwt>[] = [];
  let cancelled = false;
  const transport = async (url: string | URL | Request, init?: RequestInit) => {
    assert.equal(url, 'http://127.0.0.1:18878/backchannel');
    assert.ok(init);
    assert.equal(init.redirect, 'manual');
    assert.ok(init.signal);
    assert.ok(init.body instanceof URLSearchParams);
    const token = init.body.get('logout_token');
    assert.ok(token);
    tokens.push(decodeJwt(token));
    return new Response(
      new ReadableStream({
        pull(c) {
          c.enqueue(new Uint8Array(p('logout_delivery.max_response_bytes')));
        },
        cancel() {
          cancelled = true;
        },
      }),
      { status: 503, headers: { 'Retry-After': '120' } },
    );
  };
  const task = { client_id: CLIENT, sid: 'same-sid' };
  for (let i = 0; i < 2; i++)
    assert.deepEqual(await sendLogout({ OP_PRIVATE_JWK: local.opKeys.private }, task, transport), {
      status: 503,
      retryAfter: '120',
    });
  assert.ok(cancelled);
  assert.notEqual(tokens[0].jti, tokens[1].jti);
  assert.equal(tokens[0].sid, tokens[1].sid);
  assert.equal(tokens[0].aud, CLIENT);
  assert.ok(typeof tokens[0].exp === 'number' && typeof tokens[0].iat === 'number');
  assert.ok(tokens[0].exp > tokens[0].iat);
});

test('scheduled handler recovers durable fanout without the immediate notification wake-up', async () => {
  await seed();
  assert.equal((await deliveryHealth(db)).unexpanded, 1);
  await local.op.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
  const result = await row(db, 'SELECT * FROM logout_delivery');
  assert.equal(result.state, 'delivered');
  assert.equal(result.attempts, 1);
  assert.equal((await row(local.rpDB, 'SELECT COUNT(*) AS n FROM tombstone')).n, 1);
  await local.op.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
  assert.equal((await state(result.id)).attempts, 1);
});

test('late fanout does not extend delivery deadlines; monitoring includes unexpanded events', async () => {
  await seed();
  const at = now();
  await query(db, 'UPDATE sso_logout_event SET created_at=?,deadline=?', [
    at - p('logout_delivery.retry_deadline'),
    at,
  ]).run();
  const health = await deliveryHealth(db, at);
  assert.equal(health.alert, true);
  assert.equal(health.unexpanded, 1);
  await fanout(db);
  assert.equal(await claim(db, at), null);
  await expire(db, at);
  const delivery = await row(db, 'SELECT * FROM logout_delivery');
  assert.equal(delivery.state, 'expired');
  assert.equal(delivery.attempts, 0);
});

test('permanent destination failure stays terminal across scheduled runs and raises an aggregate alert', async () => {
  await seed();
  await fanout(db);
  await query(db, "UPDATE logout_delivery SET client_id='unregistered'").run();
  await local.op.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
  const delivery = await row(db, 'SELECT * FROM logout_delivery');
  assert.equal(delivery.state, 'failed');
  assert.equal(delivery.reason, 'http_permanent');
  assert.equal((await deliveryHealth(db)).failed, 1);
  await local.op.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
  assert.equal((await state(delivery.id)).attempts, 1);
});
