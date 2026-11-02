import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('two isolated Workers share atomic D1 grant redemption and token-record rollback', async () => {
  const script = await readFile(new URL('./d1-worker.mjs', import.meta.url), 'utf8');
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: ['first', 'second'].map((name) => ({
        name,
        modules: true,
        script,
        compatibilityDate: '2026-10-19',
        d1Databases: { DB: 'device-grant-probe' },
      })),
    }),
  );
  try {
    const db = await mf.getD1Database('DB', 'first');
    await db.batch([
      db.prepare(`CREATE TABLE grant_probe(code_digest TEXT PRIMARY KEY, client_id TEXT NOT NULL,
        key_thumbprint TEXT NOT NULL, expires_at INTEGER NOT NULL, state TEXT NOT NULL,
        owner TEXT NOT NULL)`),
      db.prepare('CREATE TABLE token_probe(token_digest TEXT PRIMARY KEY, owner TEXT NOT NULL)'),
      db.prepare(
        'CREATE TABLE replay_probe(key_thumbprint TEXT NOT NULL, jti_hash TEXT NOT NULL, PRIMARY KEY(key_thumbprint,jti_hash))',
      ),
    ]);
    const workers = await Promise.all(['first', 'second'].map((name) => mf.getWorker(name)));
    const insert = (code, expires = 200, state = 'approved') =>
      db
        .prepare('INSERT INTO grant_probe VALUES(?,?,?,?,?,?)')
        .bind(code, 'nihos', 'key', expires, state, 'alice')
        .run();
    let proofSequence = 0;
    const redeem = async (worker, input) => {
      const response = await worker.fetch('https://fixture.invalid/', {
        method: 'POST',
        body: JSON.stringify({ proofId: `proof-${proofSequence++}`, ...input }),
      });
      return { status: response.status, body: await response.json() };
    };
    const base = { client: 'nihos', key: 'key', now: 100 };
    for (let i = 0; i < 10; i++) {
      const code = `grant-${i}`;
      await insert(code);
      const results = await Promise.all(
        workers.map((worker, n) => redeem(worker, { ...base, code, token: `token-${i}-${n}` })),
      );
      assert.deepEqual(
        results.map((r) => r.status),
        [200, 200],
      );
      assert.deepEqual(results.map((r) => r.body.changed).sort(), [0, 1]);
      assert.deepEqual(
        results.flatMap((r) => r.body.tokens).map((x) => x.owner),
        ['alice'],
      );
      assert.equal(
        (
          await db
            .prepare('SELECT COUNT(*) AS n FROM token_probe WHERE token_digest IN (?,?)')
            .bind(`token-${i}-0`, `token-${i}-1`)
            .first()
        ).n,
        1,
      );
    }
    await insert('wrong');
    for (const bad of [{ client: 'other' }, { key: 'other' }, { now: 200 }]) {
      const result = await redeem(workers[0], {
        ...base,
        ...bad,
        code: 'wrong',
        token: 'not-created',
      });
      assert.equal(result.body.changed, 0);
      assert.deepEqual(result.body.tokens, []);
    }
    assert.equal(
      (await db.prepare('SELECT state FROM grant_probe WHERE code_digest=?').bind('wrong').first())
        .state,
      'approved',
    );
    for (const state of ['pending', 'denied']) {
      await insert(state, 200, state);
      const result = await redeem(workers[0], { ...base, code: state, token: `token-${state}` });
      assert.equal(result.body.changed, 0);
      assert.deepEqual(result.body.tokens, []);
    }
    await insert('lost-response');
    // Simulate a committed result that the client cannot observe.
    assert.equal(
      (await redeem(workers[0], { ...base, code: 'lost-response', token: 'lost-token' })).body
        .changed,
      1,
    );
    const lostRetry = await redeem(workers[1], {
      ...base,
      code: 'lost-response',
      token: 'new-token',
    });
    assert.equal(lostRetry.body.changed, 0);
    assert.deepEqual(lostRetry.body.tokens, []);
    assert.equal(
      (
        await db
          .prepare('SELECT COUNT(*) AS n FROM token_probe WHERE token_digest=?')
          .bind('new-token')
          .first()
      ).n,
      0,
    );
    await insert('rollback');
    await db.prepare('INSERT INTO token_probe VALUES(?,?)').bind('duplicate', 'prior').run();
    assert.equal(
      (await redeem(workers[0], { ...base, code: 'rollback', token: 'duplicate' })).status,
      409,
    );
    assert.equal(
      (
        await db
          .prepare('SELECT state FROM grant_probe WHERE code_digest=?')
          .bind('rollback')
          .first()
      ).state,
      'approved',
    );
    const retry = await redeem(workers[1], { ...base, code: 'rollback', token: 'retry' });
    assert.deepEqual(retry.body.tokens, [{ owner: 'alice' }]);

    await insert('proof-original');
    await insert('proof-replay');
    assert.equal(
      (
        await redeem(workers[0], {
          ...base,
          code: 'proof-original',
          token: 'proof-token',
          proofId: 'same-proof',
        })
      ).body.changed,
      1,
    );
    assert.equal(
      (
        await redeem(workers[1], {
          ...base,
          code: 'proof-replay',
          token: 'bad-token',
          proofId: 'same-proof',
        })
      ).status,
      409,
    );
    assert.equal(
      (
        await db
          .prepare('SELECT state FROM grant_probe WHERE code_digest=?')
          .bind('proof-replay')
          .first()
      ).state,
      'approved',
    );
    assert.equal(
      (
        await redeem(workers[1], {
          ...base,
          code: 'proof-replay',
          token: 'good-token',
          proofId: 'fresh-proof',
        })
      ).body.changed,
      1,
    );

    await insert('rollback-proof');
    assert.equal(
      (
        await redeem(workers[0], {
          ...base,
          code: 'rollback-proof',
          token: 'duplicate',
          proofId: 'rolled-back-proof',
        })
      ).status,
      409,
    );
    assert.equal(
      (
        await redeem(workers[1], {
          ...base,
          code: 'rollback-proof',
          token: 'fresh-token',
          proofId: 'rolled-back-proof',
        })
      ).body.changed,
      1,
    );
  } finally {
    await mf.dispose();
  }
});
