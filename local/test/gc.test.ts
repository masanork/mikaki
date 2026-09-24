import assert from 'node:assert/strict';
import { before, beforeEach, after, test } from 'node:test';
import { startLocal } from '../runtime.ts';
import { collect, retained } from '../gc.ts';
import { CLIENT, RP, p, now, query, row, signed } from '../shared.ts';

type LocalRuntime = Awaited<ReturnType<typeof startLocal>>;
let local: LocalRuntime;
let op: LocalRuntime['opDB'];
let rp: LocalRuntime['rpDB'];
before(async () => {
  local = await startLocal({ scheduler: false });
  op = local.opDB;
  rp = local.rpDB;
});
after(async () => {
  await local?.close();
});
beforeEach(async () => {
  await op.batch(
    ['ceremony', 'op_login', 'assertion_use', 'rate_window'].map((table) =>
      query(op, `DELETE FROM ${table}`),
    ),
  );
  await rp.batch(
    ['login', 'logout_transaction', 'app_session', 'logout_use', 'tombstone'].map((table) =>
      query(rp, `DELETE FROM ${table}`),
    ),
  );
});
const count = async (db: LocalRuntime['opDB'], table: string) =>
  (await row(db, `SELECT COUNT(*) AS n FROM ${table}`)).n;
const login = (id: string, expiry: number, retention: number) =>
  query(
    op,
    "INSERT INTO op_login(id,browser_hash,csrf,request,expires_at,gc_after) VALUES(?,?,?,'{}',?,?)",
    [id, 'browser', 'csrf', expiry, retention],
  );

test('GC preserves saved retention and live children, then deletes children before parents', async () => {
  const at = now();
  await op.batch([
    login('parent', at - 10, at - 1),
    login('future', at - 10, at + 1000),
    login('active', at + 10, at - 1),
    query(
      op,
      "INSERT INTO ceremony(id,login_id,purpose,challenge,browser_hash,expires_at,gc_after) VALUES('c','parent','authentication','challenge','browser',?,?)",
      [at - 5, at + 100],
    ),
  ]);
  assert.equal((await collect(op, 'op', at)).count, 0);
  assert.equal(await count(op, 'op_login'), 3);
  const result = await collect(op, 'op', at + 100);
  assert.equal(result.deleted.ceremony, 1);
  assert.equal(result.deleted.op_login, 2);
  assert.equal((await row(op, 'SELECT id FROM op_login')).id, 'future');
});

test('a collection run respects the shared row budget and later runs resume', async () => {
  const limit = p('retention.gc_batch_size'),
    at = now();
  // Batches of 50 stay within D1 statement limits on either runtime.
  for (let start = 0; start < limit + 3; start += 50) {
    await op.batch(
      Array.from({ length: Math.min(50, limit + 3 - start) }, (_, i) =>
        query(op, 'INSERT INTO rate_window VALUES(?,1,?)', [`bucket-${start + i}`, at - 1]),
      ),
    );
  }
  assert.equal((await collect(op, 'op', at)).count, limit);
  assert.equal(await count(op, 'rate_window'), 3);
  assert.equal((await collect(op, 'op', at)).count, 3);
});

test('GC and a retention extension cannot leave a shortened or deleted tombstone', async () => {
  const at = now();
  await query(rp, 'INSERT INTO tombstone VALUES(?,?)', ['sid', at - 1]).run();
  await Promise.all([
    collect(rp, 'rp', at),
    query(
      rp,
      'INSERT INTO tombstone VALUES(?,?) ON CONFLICT(sid) DO UPDATE SET expires_at=MAX(expires_at,excluded.expires_at)',
      ['sid', at + 1000],
    ).run(),
  ]);
  assert.equal(
    (await row(rp, "SELECT expires_at FROM tombstone WHERE sid='sid'")).expires_at,
    at + 1000,
  );
});

test('GC keeps active RP sessions and their tombstones; expired sessions are removed first', async () => {
  const at = now();
  await rp.batch([
    query(rp, "INSERT INTO app_session VALUES('hash','sid','sub',1,?,?,?,'token',?)", [
      at + 10,
      at + 100,
      at + 10,
      at - 1,
    ]),
    query(rp, "INSERT INTO tombstone VALUES('sid',?)", [at - 1]),
  ]);
  assert.equal((await collect(rp, 'rp', at)).count, 0);
  assert.equal((await collect(rp, 'rp', at + 100)).count, 2);
});

test('backchannel retention covers sessions issued with a longer old policy and never shrinks', async () => {
  const at = now(),
    parent = at + 90 * 86400;
  await query(rp, "INSERT INTO app_session VALUES('hash','long','sub',1,?,?,?,'token',?)", [
    at + 100,
    parent,
    at + 100,
    retained(parent),
  ]).run();
  async function notify(jti: string) {
    const jwt = await signed(
      { OP_PRIVATE_JWK: local.opKeys.private },
      'op',
      {
        sid: 'long',
        jti,
        events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
      },
      CLIENT,
      p('oidc_logout.token_ttl'),
      'logout+jwt',
    );
    const response = await local.rp.fetch(`${RP}/backchannel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ logout_token: jwt }),
    });
    assert.equal(response.status, 200);
  }
  await notify('first');
  const saved = (await row(rp, "SELECT expires_at FROM tombstone WHERE sid='long'")).expires_at;
  assert.ok(saved >= retained(parent));
  assert.equal(await count(rp, 'app_session'), 0);
  await notify('second');
  assert.equal(
    (await row(rp, "SELECT expires_at FROM tombstone WHERE sid='long'")).expires_at,
    saved,
  );
  await collect(rp, 'rp', at + 31 * 86400);
  assert.equal(await count(rp, 'tombstone'), 1);
});

test('replay records without an explicit GC bound are kept, and scheduled handlers collect eligible records', async () => {
  const at = now();
  await op.batch([
    query(op, "INSERT INTO assertion_use VALUES(?,'retained','endpoint','a',?,NULL)", [
      CLIENT,
      at - 1,
    ]),
    query(op, "INSERT INTO assertion_use VALUES(?,'expired','endpoint','b',?,?)", [
      CLIENT,
      at - 1,
      at - 1,
    ]),
    query(op, "INSERT INTO rate_window VALUES('old',1,?)", [at - 1]),
  ]);
  await query(rp, "INSERT INTO login VALUES('state','browser','nonce','verifier',?,?,0)", [
    at - 1,
    at - 1,
  ]).run();
  await local.op.scheduled({ cron: '0 * * * *', scheduledTime: new Date() });
  await local.rp.scheduled({ cron: '0 * * * *', scheduledTime: new Date() });
  assert.equal(await count(op, 'assertion_use'), 1);
  assert.equal((await row(op, 'SELECT jti FROM assertion_use')).jti, 'retained');
  assert.equal(await count(op, 'rate_window'), 0);
  assert.equal(await count(rp, 'login'), 0);
});
