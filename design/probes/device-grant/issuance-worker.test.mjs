import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('device and user indexes, replay reservation and audit commit atomically across Workers', async () => {
  const script = await readFile(new URL('./issuance-worker.mjs', import.meta.url), 'utf8');
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: ['first', 'second'].map((name) => ({
        name,
        modules: true,
        script,
        compatibilityDate: '2026-10-19',
        d1Databases: { DB: 'issuance-probe' },
      })),
    }),
  );
  try {
    const db = await mf.getD1Database('DB', 'first');
    await db.batch([
      db.prepare(
        'CREATE TABLE replay_probe(key_thumbprint TEXT NOT NULL, jti_hash TEXT NOT NULL, PRIMARY KEY(key_thumbprint,jti_hash))',
      ),
      db.prepare(`CREATE TABLE issuance_probe(device_digest TEXT PRIMARY KEY,user_index TEXT NOT NULL UNIQUE,
        client_id TEXT NOT NULL,scope TEXT NOT NULL,key_thumbprint TEXT NOT NULL,
        expires_at INTEGER NOT NULL,state TEXT NOT NULL CHECK(state='pending'))`),
      db.prepare('CREATE TABLE audit_probe(id TEXT PRIMARY KEY)'),
      db.prepare("INSERT INTO audit_probe VALUES('duplicate')"),
    ]);
    const workers = await Promise.all(['first', 'second'].map((name) => mf.getWorker(name)));
    const issue = async (worker, fields) =>
      worker.fetch('https://fixture.invalid/', {
        method: 'POST',
        body: JSON.stringify({
          client: 'nihos',
          scope: 'bookshelf.read',
          key: 'key',
          expires: 600,
          ...fields,
        }),
      });
    // Distinct initiation requests whose human-readable codes collide.
    const results = await Promise.all([
      issue(workers[0], {
        deviceDigest: 'device-a',
        userIndex: 'same-user-index',
        proofId: 'proof-a',
      }),
      issue(workers[1], {
        deviceDigest: 'device-b',
        userIndex: 'same-user-index',
        proofId: 'proof-b',
      }),
    ]);
    assert.deepEqual(results.map((r) => r.status).sort(), [201, 409]);
    assert.equal((await db.prepare('SELECT count(*) AS n FROM issuance_probe').first()).n, 1);
    assert.equal((await db.prepare('SELECT count(*) AS n FROM replay_probe').first()).n, 1);
    assert.equal((await db.prepare('SELECT count(*) AS n FROM audit_probe').first()).n, 2);
    const rejected =
      results[0].status === 409
        ? { deviceDigest: 'device-a', proofId: 'proof-a' }
        : { deviceDigest: 'device-b', proofId: 'proof-b' };
    assert.equal(
      (await issue(workers[0], { ...rejected, userIndex: 'fresh-user-index' })).status,
      201,
    );
    const issued = await db
      .prepare(
        'SELECT client_id,scope,key_thumbprint,expires_at,state FROM issuance_probe WHERE device_digest=?',
      )
      .bind(rejected.deviceDigest)
      .first();
    assert.deepEqual(issued, {
      client_id: 'nihos',
      scope: 'bookshelf.read',
      key_thumbprint: 'key',
      expires_at: 600,
      state: 'pending',
    });

    // A later audit failure cannot leave either a pending grant or a spent proof.
    const failed = {
      deviceDigest: 'device-failed',
      userIndex: 'user-failed',
      proofId: 'proof-failed',
    };
    assert.equal((await issue(workers[0], { ...failed, fault: true })).status, 409);
    assert.equal(
      await db
        .prepare('SELECT * FROM issuance_probe WHERE device_digest=?')
        .bind(failed.deviceDigest)
        .first(),
      null,
    );
    assert.equal(
      await db.prepare('SELECT * FROM replay_probe WHERE jti_hash=?').bind(failed.proofId).first(),
      null,
    );
    assert.equal((await issue(workers[1], failed)).status, 201);

    // A replay or device-code collision cannot leave a partial second record.
    assert.equal(
      (
        await issue(workers[0], {
          deviceDigest: 'device-other',
          userIndex: 'user-other',
          proofId: failed.proofId,
        })
      ).status,
      409,
    );
    assert.equal(
      (
        await issue(workers[0], {
          deviceDigest: failed.deviceDigest,
          userIndex: 'user-other',
          proofId: 'proof-other',
        })
      ).status,
      409,
    );
    assert.equal(
      await db.prepare('SELECT * FROM replay_probe WHERE jti_hash=?').bind('proof-other').first(),
      null,
    );
    assert.equal(
      await db
        .prepare('SELECT * FROM issuance_probe WHERE user_index=?')
        .bind('user-other')
        .first(),
      null,
    );
  } finally {
    await mf.dispose();
  }
});
