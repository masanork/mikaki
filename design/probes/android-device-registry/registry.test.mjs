import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('device enrollment and revocation fail closed under races and lost responses', async () => {
  const script = await readFile(new URL('./worker.mjs', import.meta.url), 'utf8');
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: ['one', 'two'].map((name) => ({
        name,
        modules: true,
        script,
        compatibilityDate: '2026-10-19',
        d1Databases: { DB: 'android-device-registry-probe' },
      })),
    }),
  );
  try {
    const db = await mf.getD1Database('DB', 'one');
    await db.batch([
      db.prepare(
        'CREATE TABLE session(id TEXT PRIMARY KEY, owner TEXT NOT NULL, active INTEGER NOT NULL, expires_at INTEGER NOT NULL)',
      ),
      db.prepare(`CREATE TABLE enrollment(id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
        owner TEXT NOT NULL, device_id TEXT NOT NULL, key_thumbprint TEXT NOT NULL,
        state TEXT NOT NULL, expires_at INTEGER NOT NULL, nonce_hash TEXT NOT NULL)`),
      db.prepare(`CREATE TABLE device(id TEXT PRIMARY KEY, owner TEXT NOT NULL,
        key_thumbprint TEXT NOT NULL UNIQUE, state TEXT NOT NULL, revision INTEGER NOT NULL)`),
      db.prepare(
        'CREATE TABLE replay(key_thumbprint TEXT NOT NULL, jti_hash TEXT NOT NULL, PRIMARY KEY(key_thumbprint,jti_hash))',
      ),
      db.prepare(
        "INSERT INTO session VALUES('a','alice',1,200),('a2','alice',1,200),('b','bob',1,200),('dead','alice',0,200)",
      ),
    ]);
    const workers = await Promise.all(['one', 'two'].map((name) => mf.getWorker(name)));
    let proofSequence = 0;
    const send = async (worker, value) => {
      const response = await worker.fetch('https://fixture.invalid/', {
        method: 'POST',
        body: JSON.stringify({ proofId: `proof-${proofSequence++}`, ...value }),
      });
      return { status: response.status, body: await response.json() };
    };
    const enroll = (id, device, key = `key-${id}`) =>
      db
        .prepare("INSERT INTO enrollment VALUES(?,'a','alice',?,?,'pending',150,'challenge')")
        .bind(id, device, key)
        .run();
    const base = {
      action: 'complete',
      id: 'enroll',
      session: 'a',
      owner: 'alice',
      key: 'key-enroll',
      now: 100,
      nonceHash: 'challenge',
    };
    await enroll('enroll', 'phone');
    for (const change of [
      { session: 'a2' },
      { session: 'dead' },
      { owner: 'bob', session: 'b' },
      { key: 'other' },
      { nonceHash: 'other' },
      { now: 150 },
    ]) {
      assert.deepEqual((await send(workers[0], { ...base, ...change })).body.completed, []);
    }
    await db.prepare("UPDATE session SET active=0 WHERE id='a'").run();
    assert.deepEqual((await send(workers[0], base)).body.completed, []);
    await db.prepare("UPDATE session SET active=1 WHERE id='a'").run();
    const raced = await Promise.all(workers.map((worker) => send(worker, base)));
    assert.deepEqual(raced.map((result) => result.body.completed.length).sort(), [0, 1]);
    // A retry after an unobserved commit cannot allocate a second device.
    assert.deepEqual((await send(workers[0], base)).body.completed, []);
    assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM device').first()).n, 1);

    // A uniqueness failure rolls the enrollment consumption back in the batch.
    await enroll('duplicate', 'other-phone', 'key-enroll');
    assert.equal((await send(workers[0], { ...base, id: 'duplicate' })).status, 409);
    assert.equal(
      (await db.prepare("SELECT state FROM enrollment WHERE id='duplicate'").first()).state,
      'pending',
    );
    assert.equal(
      (await db.prepare('SELECT COUNT(*) AS n FROM replay').first()).n,
      1,
      'duplicate key rolls back the proof reservation',
    );
    const usedProof = await db.prepare('SELECT jti_hash FROM replay').first();
    assert.equal(
      (await send(workers[1], { ...base, id: 'duplicate', proofId: usedProof.jti_hash })).status,
      409,
    );
    assert.equal(
      (await db.prepare("SELECT state FROM enrollment WHERE id='duplicate'").first()).state,
      'pending',
      'a replay also rolls back challenge consumption',
    );

    const revoke = {
      action: 'revoke',
      id: 'phone',
      owner: 'alice',
      session: 'a',
      revision: 1,
      now: 100,
    };
    for (const change of [
      { owner: 'bob', session: 'b' },
      { session: 'dead' },
      { revision: 2 },
      { now: 200 },
    ]) {
      assert.deepEqual((await send(workers[0], { ...revoke, ...change })).body.revoked, []);
    }
    const revoked = await Promise.all(workers.map((worker) => send(worker, revoke)));
    assert.deepEqual(revoked.map((result) => result.body.revoked.length).sort(), [0, 1]);
    assert.deepEqual((await send(workers[0], revoke)).body.revoked, []);
    assert.deepEqual(
      await db.prepare("SELECT state,revision FROM device WHERE id='phone'").first(),
      { state: 'revoked', revision: 2 },
    );
  } finally {
    await mf.dispose();
  }
});
