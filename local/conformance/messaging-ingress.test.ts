/** Real product-package ingress: independent counters, atomic limits and expiry. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import type { D1Database } from '@cloudflare/workers-types';
import { messagingFixture as fixture } from './support/messaging-product-fixture.ts';

type Fixture = Awaited<ReturnType<typeof fixture>>;
const origin = 'https://mikaki.test';
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const deployment = digest('messaging-deployment');
const sourceKey = (source: string) => digest(`messaging-source:${source}`);

async function request(
  f: Fixture,
  path = '/messaging/account',
  source?: string,
  target = f.worker,
  headers: Record<string, string> = {},
) {
  const response = await target.fetch(`${origin}${path}`, {
    headers: { ...headers, ...(source ? { 'CF-Connecting-IP': source } : {}) },
    redirect: 'manual',
  });
  return { status: response.status, headers: response.headers, body: await response.text() };
}

async function policy(f: Fixture, source: number, total: number) {
  await f.DB.prepare(
    'UPDATE messaging_resource_policy SET source_per_minute=?,deployment_per_minute=? WHERE id=1',
  )
    .bind(source, total)
    .run();
}

async function reset(f: Fixture) {
  await f.DB.batch([
    f.DB.prepare('DELETE FROM messaging_request_window'),
    f.DB.prepare('DELETE FROM auth_request_window'),
  ]);
}

// Fixed windows legitimately change at a minute boundary. If a short scenario
// spans that boundary, repeat once in the new window instead of requiring a
// throttled response to survive expiry. Every other failure remains a failure.
async function stableWindow(f: Fixture, run: () => Promise<void>) {
  for (let attempt = 0; attempt < 2; attempt++) {
    await reset(f);
    const minute = Math.floor(Date.now() / 60000);
    try {
      await run();
    } catch (error) {
      if (attempt !== 0 || Math.floor(Date.now() / 60000) === minute) throw error;
      continue;
    }
    if (Math.floor(Date.now() / 60000) === minute) return;
  }
  throw new Error('Ingress scenario crossed two minute boundaries');
}

async function windows(db: D1Database, table: 'auth_request_window' | 'messaging_request_window') {
  return (await db.prepare(`SELECT * FROM ${table} ORDER BY key_hash,window_start`).all()).results;
}

async function seedWindows(f: Fixture, count: number, start: number, prefix: string) {
  for (let offset = 0; offset < count; offset += 200) {
    await f.DB.batch(
      Array.from({ length: Math.min(200, count - offset) }, (_, i) =>
        f.DB.prepare('INSERT INTO messaging_request_window VALUES(?,?,1)').bind(
          digest(`${prefix}:${offset + i}`),
          start,
        ),
      ),
    );
  }
}

test(
  'Chat source and deployment budgets are shared across isolates and reserve both counters atomically',
  { timeout: 60000 },
  async () => {
    const f = await fixture(true, { replica: true });
    try {
      await stableWindow(f, async () => {
        await policy(f, 3, 100);
        const replies = await Promise.all(
          Array.from({ length: 6 }, (_, i) =>
            request(f, undefined, '192.0.2.1', i % 2 ? f.worker : f.replica),
          ),
        );
        assert.equal(replies.filter((r) => r.status === 401).length, 3);
        assert.equal(replies.filter((r) => r.status === 429).length, 3);
        for (const reply of replies.filter((r) => r.status === 429)) {
          assert.equal(reply.headers.get('Retry-After'), '60');
          assert.equal(reply.headers.get('Cache-Control'), 'no-store');
          assert.deepEqual(JSON.parse(reply.body), { error: 'temporarily_unavailable' });
        }
        assert.equal(
          await f.DB.prepare('SELECT attempts FROM messaging_request_window WHERE key_hash=?')
            .bind(deployment)
            .first('attempts'),
          3,
          'source rejection does not debit the global budget',
        );
        assert.equal((await request(f, undefined, '192.0.2.2')).status, 401);
        assert.deepEqual(await windows(f.DB, 'auth_request_window'), []);
        assert.ok(
          (await windows(f.DB, 'messaging_request_window')).every(
            (row) => typeof row.key_hash === 'string' && /^[A-Za-z0-9_-]{43}$/.test(row.key_hash),
          ),
        );
      });
      await stableWindow(f, async () => {
        await policy(f, 10, 4);
        const replies = await Promise.all(
          Array.from({ length: 6 }, (_, i) =>
            request(f, undefined, `192.0.2.${i + 1}`, i % 2 ? f.worker : f.replica),
          ),
        );
        assert.equal(replies.filter((r) => r.status === 401).length, 4);
        assert.equal(replies.filter((r) => r.status === 429).length, 2);
        const rows = await windows(f.DB, 'messaging_request_window');
        assert.equal(rows.length, 5, 'rejected sources do not allocate another counter');
        assert.equal(rows.find((row) => row.key_hash === deployment)?.attempts, 4);
        assert.deepEqual(await windows(f.DB, 'auth_request_window'), []);
      });
    } finally {
      await f.harness.close();
    }
  },
);

test(
  'Chat exhaustion cannot spend login budgets and login exhaustion cannot spend Chat budgets',
  { timeout: 60000 },
  async () => {
    const f = await fixture(true);
    try {
      const actor = await f.seed();
      await stableWindow(f, async () => {
        await policy(f, 1, 1);
        await f.DB.prepare(
          'UPDATE auth_resource_policy SET source_per_minute=1,deployment_per_minute=1',
        ).run();
        assert.equal((await request(f, undefined, '192.0.2.1')).status, 401);
        assert.equal((await request(f, undefined, '192.0.2.1')).status, 429);
        const mutation = await f.worker.fetch(`${origin}/messaging/account`, {
          method: 'POST',
          redirect: 'manual',
          headers: {
            Origin: origin,
            'CF-Connecting-IP': '192.0.2.1',
            cookie: `__Host-op-sso=${actor.secret}`,
          },
        });
        assert.equal(mutation.status, 429);
        await mutation.text();
        assert.equal(
          await f.DB.prepare('SELECT count(*) AS n FROM messaging_account WHERE owner_id=?')
            .bind(actor.account)
            .first('n'),
          0,
        );
        assert.deepEqual(await windows(f.DB, 'auth_request_window'), []);
        const chat = await windows(f.DB, 'messaging_request_window');
        const signin = await request(f, '/signin?lang=ja', '192.0.2.1');
        assert.equal(signin.status, 302);
        assert.equal(new URL(signin.headers.get('Location')!).pathname, '/login');
        assert.match(signin.headers.get('Set-Cookie')!, /^__Host-op-browser=/);
        assert.equal((await request(f, '/signin?lang=ja', '192.0.2.1')).status, 429);
        assert.deepEqual(await windows(f.DB, 'messaging_request_window'), chat);
        const auth = await windows(f.DB, 'auth_request_window');
        await f.DB.prepare('DELETE FROM messaging_request_window').run();
        assert.equal((await request(f, undefined, '192.0.2.1')).status, 401);
        assert.equal((await request(f, undefined, '192.0.2.1')).status, 429);
        assert.deepEqual(await windows(f.DB, 'auth_request_window'), auth);
      });
    } finally {
      await f.harness.close();
    }
  },
);

test(
  'missing addresses share a Chat budget and cookies or forwarded headers cannot manufacture another source',
  { timeout: 60000 },
  async () => {
    const f = await fixture(true);
    try {
      await stableWindow(f, async () => {
        await policy(f, 1, 10);
        assert.equal((await request(f)).status, 401);
        assert.equal(
          (
            await request(f, undefined, undefined, f.replica, {
              cookie: '__Host-op-sso=attacker',
              'X-Forwarded-For': '192.0.2.44',
              'True-Client-IP': '192.0.2.45',
            })
          ).status,
          429,
        );
        assert.equal((await request(f, undefined, '192.0.2.1')).status, 401);
        assert.equal((await windows(f.DB, 'messaging_request_window')).length, 3);
        assert.deepEqual(await windows(f.DB, 'auth_request_window'), []);
      });
    } finally {
      await f.harness.close();
    }
  },
);

test(
  'Chat capacity rejects partial reservations, retains live counters and admits existing buckets at the cap',
  { timeout: 60000 },
  async () => {
    const f = await fixture(true);
    try {
      await stableWindow(f, async () => {
        await policy(f, 3, 3);
        const window = Math.floor(Date.now() / 60000) * 60;
        await seedWindows(f, 9999, window + 120, 'live');
        assert.equal((await request(f, undefined, '192.0.2.1')).status, 429);
        assert.equal((await windows(f.DB, 'messaging_request_window')).length, 9999);
        assert.equal((await request(f, '/signin?lang=ja', '192.0.2.1')).status, 302);
        await f.DB.batch([
          f.DB.prepare('DELETE FROM messaging_request_window WHERE key_hash=?').bind(
            digest('live:0'),
          ),
          f.DB.prepare('INSERT INTO messaging_request_window VALUES(?,?,1)').bind(
            deployment,
            window,
          ),
          f.DB.prepare('INSERT INTO messaging_request_window VALUES(?,?,1)').bind(
            sourceKey('192.0.2.1'),
            window,
          ),
        ]);
        assert.equal((await request(f, undefined, '192.0.2.1')).status, 401);
        assert.equal((await windows(f.DB, 'messaging_request_window')).length, 10000);
        assert.equal((await request(f, undefined, '192.0.2.2')).status, 429);
        assert.equal(
          await f.DB.prepare('SELECT attempts FROM messaging_request_window WHERE key_hash=?')
            .bind(deployment)
            .first('attempts'),
          2,
        );
      });
    } finally {
      await f.harness.close();
    }
  },
);

test(
  'Chat storage failures roll back expiry and reservations while login remains available; missing policy fails closed',
  { timeout: 60000 },
  async () => {
    const f = await fixture(true);
    try {
      await stableWindow(f, async () => {
        const window = Math.floor(Date.now() / 60000) * 60;
        const source = sourceKey('192.0.2.1');
        await f.DB.batch([
          f.DB.prepare('INSERT INTO messaging_request_window VALUES(?,?,1)').bind(
            deployment,
            window,
          ),
          f.DB.prepare('INSERT INTO messaging_request_window VALUES(?,?,1)').bind(source, window),
          f.DB.prepare('INSERT INTO messaging_request_window VALUES(?,?,1)').bind(
            digest('expired'),
            window - 180,
          ),
          f.DB.prepare(
            `CREATE TRIGGER fail_chat_reservation BEFORE UPDATE ON messaging_request_window WHEN NEW.key_hash='${source}' BEGIN SELECT RAISE(ABORT,'injected reservation failure'); END`,
          ),
        ]);
        const before = await windows(f.DB, 'messaging_request_window');
        try {
          const failed = await request(f, undefined, '192.0.2.1');
          assert.equal(failed.status, 503);
          assert.deepEqual(JSON.parse(failed.body), { error: 'messaging_unavailable' });
          assert.deepEqual(await windows(f.DB, 'messaging_request_window'), before);
          assert.equal((await request(f, '/signin?lang=ja', '192.0.2.1')).status, 302);
        } finally {
          await f.DB.prepare('DROP TRIGGER fail_chat_reservation').run();
        }
        assert.equal((await request(f, undefined, '192.0.2.1')).status, 401);
      });
      const actor = await f.seed();
      await f.DB.prepare('DELETE FROM messaging_resource_policy').run();
      assert.equal((await request(f)).status, 503);
      const config = await request(f, '/vault/messaging-config', undefined, f.worker, {
        cookie: `__Host-op-sso=${actor.secret}`,
      });
      assert.equal(config.status, 503);
      assert.equal((await request(f, '/signin?lang=ja', '192.0.2.2')).status, 302);
    } finally {
      await f.harness.close();
    }
  },
);

test(
  'Chat expiry is bounded on ingress and scheduled collection, with independent failure and preserved live rows',
  { timeout: 60000 },
  async () => {
    const f = await fixture(true);
    try {
      const window = Math.floor(Date.now() / 60000) * 60;
      await seedWindows(f, 1200, window - 180, 'expired');
      await f.DB.prepare('INSERT INTO messaging_request_window VALUES(?,?,1)')
        .bind(digest('live'), window + 120)
        .run();
      const count = () =>
        f.DB.prepare('SELECT count(*) AS n FROM messaging_request_window WHERE window_start<?')
          .bind(window)
          .first('n');
      assert.equal((await request(f)).status, 401);
      assert.equal(await count(), 200, 'one request reclaims at most 1000 old counters');
      await f.DB.batch([
        f.DB.prepare('INSERT INTO auth_request_window VALUES(?,?,1)').bind(
          digest('old auth'),
          window - 180,
        ),
        f.DB.prepare(
          "CREATE TRIGGER fail_chat_gc BEFORE DELETE ON messaging_request_window BEGIN SELECT RAISE(ABORT,'injected Chat cleanup failure'); END",
        ),
      ]);
      await f.worker.scheduled({ cron: '* * * * *' });
      assert.equal(await count(), 200);
      assert.deepEqual(
        await windows(f.DB, 'auth_request_window'),
        [],
        'Chat GC failure does not stop auth GC',
      );
      await f.DB.prepare('DROP TRIGGER fail_chat_gc').run();
      await seedWindows(f, 1000, window - 180, 'another expired batch');
      await f.worker.scheduled({ cron: '* * * * *' });
      assert.equal(await count(), 200);
      await f.worker.scheduled({ cron: '* * * * *' });
      assert.equal(await count(), 0);
      assert.equal(
        await f.DB.prepare('SELECT attempts FROM messaging_request_window WHERE key_hash=?')
          .bind(digest('live'))
          .first('attempts'),
        1,
      );
      assert.equal((await request(f, '/signin?lang=ja')).status, 302);
    } finally {
      await f.harness.close();
    }
  },
);

for (const defaultBuild of [false, true]) {
  test(`disabled Chat collection has no messaging schema dependency (default build=${defaultBuild})`, async () => {
    const f = await fixture(false, { defaultBuild });
    try {
      await f.worker.scheduled({ cron: '* * * * *' });
      assert.equal((await request(f)).status, 404);
      assert.equal((await request(f, '/signin?lang=ja')).status, 302);
      assert.equal(
        await f.DB.prepare(
          "SELECT count(*) AS n FROM sqlite_master WHERE name LIKE 'messaging_%'",
        ).first('n'),
        0,
      );
    } finally {
      await f.harness.close();
    }
  });
}
