import assert from 'node:assert/strict';
import { before, beforeEach, after, test } from 'node:test';
import { startLocal } from '../runtime.mjs';
import { revokeAccountSessions, expandAccountRevocations } from '../account-admin.mjs';
import { adminCommand } from '../logout-admin.mjs';
import { collect } from '../gc.mjs';
import { now, p, query, row } from '../shared.mjs';
let local, db;
before(async () => {
  local = await startLocal({ scheduler: false });
  db = local.opDB;
  await db.batch([
    query(db, "INSERT INTO account_security VALUES('a',0,1)"),
    query(db, "INSERT INTO credential VALUES('cr','a',1)"),
  ]);
});
after(async () => {
  await local?.close();
});
beforeEach(async () => {
  await db.batch([
    ...['logout_delivery', 'sso_logout_event', 'sso_session', 'revocation_event'].map((t) =>
      query(db, `DELETE FROM ${t}`),
    ),
    query(db, "UPDATE account_security SET epoch=0,active=1 WHERE account_id='a'"),
  ]);
});
const request = { account: 'a', epoch: 0, actor: 'operator', reason: 'session_reset' };
const count = async (t) => (await row(db, `SELECT COUNT(*) AS n FROM ${t}`)).n;
const sso = (id, epoch = 0) =>
  query(db, "INSERT INTO sso_session VALUES(?,'a','cr',?,?,0,?)", [
    id,
    epoch,
    now() - 100,
    now() - 1,
  ]);

test('concurrent account revocation consumes the expected epoch once and records its actor', async () => {
  const result = await Promise.allSettled([
    revokeAccountSessions(db, request),
    revokeAccountSessions(db, request),
  ]);
  assert.equal(result.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal((await row(db, 'SELECT epoch FROM account_security')).epoch, 1);
  assert.equal(await count('revocation_event'), 1);
  assert.equal((await row(db, 'SELECT actor FROM revocation_event')).actor, 'operator');
  await assert.rejects(revokeAccountSessions(db, request));
});

test('bounded fanout resumes, prevents premature GC and excludes new-epoch sessions', async () => {
  for (let start = 0; start < 101; start += 50)
    await db.batch(
      Array.from({ length: Math.min(50, 101 - start) }, (_, i) => sso(`s-${start + i}`)),
    );
  await revokeAccountSessions(db, request);
  await sso('new', 1).run();
  // The new fixture is already expired; keep it long enough for this test.
  await query(db, "UPDATE sso_session SET gc_after=? WHERE sso_id='new'", [now() + 1000]).run();
  assert.equal((await collect(db, 'op')).count, 0);
  await expandAccountRevocations(db);
  assert.equal(await count('sso_logout_event'), p('logout_delivery.fanout_batch_size'));
  assert.equal((await row(db, 'SELECT expanded FROM revocation_event')).expanded, 0);
  await Promise.all([expandAccountRevocations(db), expandAccountRevocations(db)]);
  assert.equal(await count('sso_logout_event'), 101);
  assert.equal((await row(db, 'SELECT expanded FROM revocation_event')).expanded, 1);
  assert.equal(await row(db, "SELECT id FROM sso_logout_event WHERE sso_id='new'"), null);
  assert.equal(
    (
      await row(
        db,
        'SELECT COUNT(*) AS n FROM sso_logout_event e JOIN revocation_event r ON e.created_at=r.created_at WHERE e.deadline!=r.deadline',
      )
    ).n,
    0,
  );
});

test('event storage failure rolls back epoch change and disabled accounts are rejected', async () => {
  await query(
    db,
    "CREATE TRIGGER reject_account_event BEFORE INSERT ON revocation_event BEGIN SELECT RAISE(ABORT,'injected'); END",
  ).run();
  try {
    await assert.rejects(revokeAccountSessions(db, request));
  } finally {
    await query(db, 'DROP TRIGGER reject_account_event').run();
  }
  assert.equal((await row(db, 'SELECT epoch FROM account_security')).epoch, 0);
  await query(db, 'UPDATE account_security SET active=0').run();
  await assert.rejects(revokeAccountSessions(db, request));
  assert.equal(await count('revocation_event'), 0);
});

test('operator command validates input and retains audit until expansion and retention complete', async () => {
  assert.equal((await adminCommand(db, 'account-list', 'operator'))[0].epoch, 0);
  await assert.rejects(adminCommand(db, 'account-revoke a -1 session_reset', 'operator'));
  await assert.rejects(revokeAccountSessions(db, { ...request, epoch: Number.MAX_SAFE_INTEGER }));
  await adminCommand(db, 'account-revoke a 0 security_incident', 'operator');
  const event = await row(db, 'SELECT * FROM revocation_event');
  assert.equal((await collect(db, 'op', event.gc_after)).count, 0);
  await expandAccountRevocations(db);
  assert.equal((await collect(db, 'op', event.gc_after - 1)).count, 0);
  assert.equal((await collect(db, 'op', event.gc_after)).deleted.revocation_event, 1);
});

test('overlapping account revocations share an SSO event with the earliest original deadline', async () => {
  await sso('old').run();
  await revokeAccountSessions(db, request);
  await query(db, 'UPDATE revocation_event SET deadline=deadline-60 WHERE through_epoch=0').run();
  await revokeAccountSessions(db, { ...request, epoch: 1 });
  await expandAccountRevocations(db);
  assert.equal(await count('sso_logout_event'), 1);
  const event = await row(db, 'SELECT * FROM sso_logout_event');
  assert.equal(
    event.deadline,
    (await row(db, 'SELECT MIN(deadline) AS deadline FROM revocation_event')).deadline,
  );
  assert.equal((await row(db, 'SELECT COUNT(*) AS n FROM revocation_event WHERE expanded=1')).n, 2);
});
