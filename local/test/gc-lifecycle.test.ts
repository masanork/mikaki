import assert from 'node:assert/strict';
import { before, beforeEach, after, test } from 'node:test';
import { startLocal } from '../runtime.ts';
import { collect, retained } from '../gc.ts';
import { logoutEvent, fanout, claim, settle } from '../logout-delivery.ts';
import { CLIENT, now, p, query, row } from '../shared.ts';

type LocalRuntime = Awaited<ReturnType<typeof startLocal>>;
let local: LocalRuntime;
let db: LocalRuntime['opDB'];
const tables = [
  'logout_delivery',
  'sso_logout_event',
  'token_issue',
  'code_context',
  'authorization_code',
  'client_session',
  'sso_context',
  'sso_session',
];
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
  await db.batch(tables.map((t) => query(db, `DELETE FROM ${t}`)));
});
const count = async (table: string) => (await row(db, `SELECT COUNT(*) AS n FROM ${table}`)).n;
async function seed(expiry: number, gcAfter: number) {
  await db.batch([
    query(db, "INSERT INTO sso_session VALUES('s','a','cr',1,?,0,?)", [expiry, gcAfter]),
    query(db, "INSERT INTO sso_context VALUES('s','secret',1)"),
    query(db, "INSERT INTO client_session VALUES(?,'sid','s','a','sub',1,0)", [CLIENT]),
    query(
      db,
      "INSERT INTO authorization_code VALUES('code',?,'sid',1,'redirect','challenge',1,'issue',1)",
      [CLIENT],
    ),
    query(db, "INSERT INTO code_context VALUES('code','nonce')"),
    query(db, "INSERT INTO token_issue VALUES('code','issue','access',1,'local-op-1',1,0)"),
  ]);
}

test('expired code/access evidence survives while the parent session is valid and through saved retention', async () => {
  const at = now();
  await seed(at + 100, at + 200);
  assert.equal(await count('token_issue'), 1);
  assert.equal((await row(db, 'SELECT COUNT(*) AS n FROM valid_client_session')).n, 1);
  assert.equal((await collect(db, 'op', at)).count, 0);
  assert.equal((await row(db, 'SELECT COUNT(*) AS n FROM valid_client_session')).n, 1);
  assert.equal((await collect(db, 'op', at + 199)).count, 0);
  assert.equal((await collect(db, 'op', at + 200)).count, 6);
  for (const table of tables) assert.equal(await count(table), 0, table);
  assert.equal(await count('account_security'), 1);
  assert.equal(await count('credential'), 1);
  assert.equal(await count('app_connection'), 1);
});

test('unexpanded events and pending/leased deliveries block history collection', async () => {
  const at = now();
  await seed(at - 100, at - 1);
  await logoutEvent(db, 's').run();
  await query(db, 'UPDATE sso_logout_event SET deadline=?,gc_after=?', [at - 1, at - 1]).run();
  assert.equal((await collect(db, 'op', at)).count, 0);
  await fanout(db);
  assert.equal((await collect(db, 'op', at)).count, 0);
  await query(db, 'UPDATE logout_delivery SET deadline=?', [at + 100]).run();
  const task = await claim(db);
  assert.ok(task);
  assert.equal((await collect(db, 'op', at)).count, 0);
  await settle(db, task, { state: 'delivered', reason: 'success', next: at }, 200, at);
  const delivery = await row(db, 'SELECT * FROM logout_delivery');
  assert.ok(delivery.gc_after >= retained(at + p('retention.delivery_result_ttl')));
  assert.equal((await collect(db, 'op', delivery.gc_after - 1)).count, 0);
  assert.equal((await collect(db, 'op', delivery.gc_after)).count, 8);
});

test('terminal deliveries remain until both event retention and extended delivery deadlines permit deletion', async () => {
  const at = now();
  await seed(at - 100, at - 1);
  await logoutEvent(db, 's').run();
  await fanout(db);
  const task = await claim(db);
  await settle(db, task, { state: 'failed', reason: 'http_permanent', next: at }, 400, at);
  await db.batch([
    query(db, 'UPDATE sso_logout_event SET deadline=?,gc_after=?', [at - 1, at + 100]),
    query(db, 'UPDATE logout_delivery SET deadline=?,gc_after=?', [at - 1, at - 1]),
  ]);
  assert.equal((await collect(db, 'op', at)).count, 0);
  // Extension is persisted before GC; no stale candidate list can bypass it.
  await query(db, 'UPDATE logout_delivery SET deadline=?,gc_after=?', [at + 300, at + 400]).run();
  assert.equal((await collect(db, 'op', at + 100)).count, 0);
  assert.equal((await collect(db, 'op', at + 399)).count, 0);
  assert.equal((await collect(db, 'op', at + 400)).count, 8);
});

test('budget exhaustion between child and parent cleanup is safe and restartable', async () => {
  const at = now();
  await seed(at - 100, at - 1);
  // Leave exactly one deletion for the issuance subtree in this invocation.
  const n = p('retention.gc_batch_size') - 1;
  for (let i = 0; i < n; i += 50)
    await db.batch(
      Array.from({ length: Math.min(50, n - i) }, (_, j) =>
        query(db, 'INSERT INTO rate_window VALUES(?,1,?)', [`b-${i + j}`, at - 1]),
      ),
    );
  assert.equal((await collect(db, 'op', at)).count, n + 1);
  assert.equal(await count('token_issue'), 0);
  assert.equal(await count('authorization_code'), 1);
  assert.equal(await count('sso_session'), 1);
  assert.equal((await collect(db, 'op', at)).count, 5);
  assert.deepEqual((await query(db, 'PRAGMA foreign_key_check').all()).results, []);
});
