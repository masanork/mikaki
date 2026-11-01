import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('shared D1 admission limits guessing across Workers and rolls back lookup failures', async () => {
  const script = await readFile(new URL('./rate-worker.mjs', import.meta.url), 'utf8');
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: ['first', 'second'].map((name) => ({
        name,
        modules: true,
        script,
        compatibilityDate: '2026-10-19',
        d1Databases: { DB: 'device-rate-probe' },
        bindings: { TEST_KEY: '07'.repeat(32) },
      })),
    }),
  );
  try {
    const db = await mf.getD1Database('DB', 'first');
    await db.batch([
      db.prepare('CREATE TABLE rate_probe(bucket INTEGER PRIMARY KEY, attempts INTEGER NOT NULL)'),
      db.prepare(
        'CREATE TABLE lookup_probe(user_index TEXT PRIMARY KEY, state TEXT NOT NULL, expires_at INTEGER NOT NULL)',
      ),
      db
        .prepare('INSERT INTO lookup_probe VALUES(?,?,?)')
        .bind('rP8eDgUUftdMC6Fkx3PEnW2mr7lUkCpZiqFsyscvKdo', 'pending', 180),
      db
        .prepare('INSERT INTO lookup_probe VALUES(?,?,?)')
        .bind('SFKbHO7fgp9s8MQJdorws9p-PRS2hbmHbDxTDS41Xko', 'pending', 400),
    ]);
    const workers = await Promise.all(['first', 'second'].map((name) => mf.getWorker(name)));
    const query = async (n, code, now) => {
      const response = await workers[n % 2].fetch('https://fixture.invalid/', {
        method: 'POST',
        body: JSON.stringify({ code, now }),
      });
      return { status: response.status, body: await response.json() };
    };
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, n) => query(n, '2345-6789', 120)),
    );
    assert.equal(results.filter((r) => r.status === 200 && r.body.matched).length, 5);
    assert.equal(results.filter((r) => r.status === 429).length, 15);
    assert.equal(
      (await db.prepare('SELECT attempts FROM rate_probe WHERE bucket=?').bind(2).first()).attempts,
      5,
    );

    // Expiry uses a strict boundary; malformed codes consume the same budget.
    assert.deepEqual(await query(0, '23456789', 180), { status: 200, body: { matched: false } });
    for (let i = 0; i < 4; i++) assert.equal((await query(i, 'invalid!', 180)).status, 200);
    assert.equal((await query(0, '23456789', 180)).status, 429);
    assert.deepEqual(await query(0, 'abcd-efgh', 240), { status: 200, body: { matched: true } });

    await db.prepare('DROP TABLE lookup_probe').run();
    assert.equal((await query(0, '23456789', 300)).status, 503);
    assert.equal(
      await db.prepare('SELECT attempts FROM rate_probe WHERE bucket=?').bind(5).first(),
      null,
    );
  } finally {
    await mf.dispose();
  }
});
