import assert from 'node:assert/strict';
import { before, beforeEach, after, test } from 'node:test';
import { startLocal } from '../runtime.ts';
import { retryLogout, adminCommand } from '../logout-admin.ts';
import { logoutEvent, fanout } from '../logout-delivery.ts';
import { collect, retained } from '../gc.ts';
import { CLIENT, now, p, query, row } from '../shared.ts';
type LocalRuntime = Awaited<ReturnType<typeof startLocal>>;
let local: LocalRuntime;
let db: LocalRuntime['opDB'];
before(async () => {
  local = await startLocal({ scheduler: false });
  db = local.opDB;
  await db.batch([
    query(db, "INSERT INTO account_security VALUES('a',1,1)"),
    query(db, "INSERT INTO credential VALUES('cr','a',1)"),
    query(db, "INSERT INTO app_connection VALUES('a',?,1,1)", [CLIENT]),
  ]);
});
after(async () => {
  await local?.close();
});
beforeEach(async () => {
  await db.batch(
    [
      'logout_retry_audit',
      'logout_delivery',
      'sso_logout_event',
      'client_session',
      'sso_session',
    ].map((t) => query(db, `DELETE FROM ${t}`)),
  );
});
async function seed() {
  const at = now();
  await db.batch([
    query(db, "INSERT INTO sso_session VALUES('s','a','cr',1,?,1,?)", [at - 100, at - 1]),
    query(db, "INSERT INTO client_session VALUES(?,'failed','s','a','sub',1,1)", [CLIENT]),
    query(db, "INSERT INTO client_session VALUES(?,'success','s','a','sub',1,1)", [CLIENT]),
    logoutEvent(db, 's'),
  ]);
  await fanout(db);
  await db.batch([
    query(db, 'UPDATE sso_logout_event SET deadline=?,gc_after=?', [at - 1, at - 1]),
    query(
      db,
      "UPDATE logout_delivery SET state=CASE WHEN sid='failed' THEN 'failed' ELSE 'delivered' END, attempts=3,finished_at=?,deadline=?,gc_after=?",
      [at - 10, at - 1, at - 1],
    ),
  ]);
  const event = (await row(db, 'SELECT id FROM sso_logout_event')).id;
  const deadline = at + 3600;
  return {
    event,
    revision: 0,
    deadline,
    retainUntil: retained(deadline + p('retention.delivery_result_ttl')),
    actor: 'local-operator',
    reason: 'network_recovered',
  };
}
const count = async (t: string) => (await row(db, `SELECT COUNT(*) AS n FROM ${t}`)).n;

test('retry changes only failed targets and atomically records actor, deadlines and prior attempts', async () => {
  const request = await seed();
  const result = await retryLogout(db, request);
  assert.equal(result.revision, 1);
  const failed = await row(db, "SELECT * FROM logout_delivery WHERE sid='failed'");
  assert.equal(failed.state, 'pending');
  assert.equal(failed.attempts, 0);
  assert.equal(failed.deadline, request.deadline);
  assert.equal(failed.gc_after, request.retainUntil);
  const success = await row(db, "SELECT * FROM logout_delivery WHERE sid='success'");
  assert.equal(success.state, 'delivered');
  assert.equal(success.attempts, 3);
  const audit = await row(db, 'SELECT * FROM logout_retry_audit');
  assert.equal(audit.actor, request.actor);
  assert.equal(audit.new_deadline, request.deadline);
  assert.equal(audit.retain_until, request.retainUntil);
  assert.equal(JSON.parse(audit.targets)[0].attempts, 3);
  assert.equal(JSON.parse(audit.targets).length, 1);
  assert.equal((await collect(db, 'op')).count, 0);
  // Exercise the real signed delivery path after the operator transaction.
  await local.op.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
  assert.equal(
    (await row(db, "SELECT state FROM logout_delivery WHERE sid='failed'")).state,
    'delivered',
  );
});

test('concurrent duplicate retries commit once', async () => {
  const request = await seed();
  const outcomes = await Promise.allSettled([retryLogout(db, request), retryLogout(db, request)]);
  assert.equal(outcomes.filter((x) => x.status === 'fulfilled').length, 1);
  assert.equal(await count('logout_retry_audit'), 1);
  assert.equal((await row(db, 'SELECT revision FROM sso_logout_event')).revision, 1);
});

test('incomplete, busy and partially collected events are refused without partial audit writes', async () => {
  const request = await seed();
  await query(db, 'UPDATE sso_logout_event SET expanded=0').run();
  await assert.rejects(retryLogout(db, request));
  await query(db, 'UPDATE sso_logout_event SET expanded=1').run();
  await query(db, "UPDATE logout_delivery SET state='pending' WHERE sid='failed'").run();
  await assert.rejects(retryLogout(db, request));
  await query(db, "UPDATE logout_delivery SET state='failed' WHERE sid='failed'").run();
  await query(db, "DELETE FROM logout_delivery WHERE sid='success'").run();
  await assert.rejects(retryLogout(db, request));
  assert.equal(await count('logout_retry_audit'), 0);
  assert.equal((await row(db, 'SELECT revision FROM sso_logout_event')).revision, 0);
});

test('GC racing retry either preserves the entire retry or causes a clean rejection', async () => {
  const request = await seed();
  const results = await Promise.allSettled([collect(db, 'op'), retryLogout(db, request)]);
  assert.equal(results[0].status, 'fulfilled');
  if (results[1].status === 'fulfilled') {
    assert.equal(await count('logout_delivery'), 2);
    assert.equal(await count('sso_logout_event'), 1);
    assert.equal(await count('logout_retry_audit'), 1);
  } else {
    assert.equal(await count('logout_retry_audit'), 0);
    assert.equal(await count('sso_logout_event'), 0);
  }
});

test('operator parser rejects malformed dates and retention shorter than the required bound', async () => {
  const request = await seed();
  const iso = (t: number) => new Date(t * 1000).toISOString().replace('.000Z', 'Z');
  assert.equal((await adminCommand(db, 'logout-list', 'operator'))[0].retryable, 1);
  await assert.rejects(
    adminCommand(
      db,
      `logout-retry ${request.event} 0 2026-02-30T00:00:00Z ${iso(request.retainUntil)} operator_retry`,
      'operator',
    ),
  );
  await assert.rejects(retryLogout(db, { ...request, retainUntil: request.deadline }));
  await assert.rejects(retryLogout(db, { ...request, revision: 1 }));
  const result = await adminCommand(
    db,
    `logout-retry ${request.event} 0 ${iso(request.deadline)} ${iso(request.retainUntil)} operator_retry`,
    'operator',
  );
  assert.equal(result.revision, 1);
});

test('audit survives event GC until its own retention ends', async () => {
  const request = await seed();
  await retryLogout(db, request);
  await local.op.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
  const audit = await row(db, 'SELECT * FROM logout_retry_audit');
  await collect(db, 'op', request.retainUntil);
  assert.equal(await count('sso_logout_event'), 0);
  assert.equal(await count('logout_retry_audit'), 1);
  await collect(db, 'op', audit.gc_after);
  assert.equal(await count('logout_retry_audit'), 0);
});

test('failure after audit insertion rolls back the audit, revision and deadline together', async () => {
  const request = await seed();
  const original = await row(db, 'SELECT * FROM sso_logout_event');
  await query(
    db,
    `CREATE TRIGGER reject_retry_update BEFORE UPDATE ON logout_delivery
    BEGIN SELECT RAISE(ABORT, 'injected_retry_failure'); END`,
  ).run();
  try {
    await assert.rejects(retryLogout(db, request));
    assert.equal(await count('logout_retry_audit'), 0);
    assert.deepEqual(await row(db, 'SELECT * FROM sso_logout_event'), original);
    assert.equal(
      (await row(db, "SELECT state FROM logout_delivery WHERE sid='failed'")).state,
      'failed',
    );
  } finally {
    await query(db, 'DROP TRIGGER reject_retry_update').run();
  }
});
