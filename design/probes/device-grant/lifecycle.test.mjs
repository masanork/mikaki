import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('synthetic grant lifecycle uses one D1 state across initiation, lookup and redemption', async () => {
  const names = ['issuance-worker.mjs', 'rate-worker.mjs', 'd1-worker.mjs'];
  const scripts = await Promise.all(
    names.map((name) => readFile(new URL(`./${name}`, import.meta.url), 'utf8')),
  );
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: scripts.map((script, i) => ({
        name: `worker-${i}`,
        modules: true,
        script,
        compatibilityDate: '2026-10-19',
        d1Databases: { DB: 'lifecycle-probe' },
        bindings: { TEST_KEY: '07'.repeat(32) },
      })),
    }),
  );
  try {
    const db = await mf.getD1Database('DB', 'worker-0');
    await db.batch([
      db.prepare(`CREATE TABLE grant_probe(code_digest TEXT PRIMARY KEY,user_index TEXT NOT NULL UNIQUE,
        client_id TEXT NOT NULL,scope TEXT NOT NULL,key_thumbprint TEXT NOT NULL,
        expires_at INTEGER NOT NULL,state TEXT NOT NULL,owner TEXT)`),
      db.prepare('CREATE VIEW lookup_probe AS SELECT user_index,state,expires_at FROM grant_probe'),
      db.prepare('CREATE TABLE rate_probe(bucket INTEGER PRIMARY KEY, attempts INTEGER NOT NULL)'),
      db.prepare(
        'CREATE TABLE replay_probe(key_thumbprint TEXT NOT NULL, jti_hash TEXT NOT NULL, PRIMARY KEY(key_thumbprint,jti_hash))',
      ),
      db.prepare('CREATE TABLE audit_probe(id TEXT PRIMARY KEY)'),
      db.prepare('CREATE TABLE token_probe(token_digest TEXT PRIMARY KEY, owner TEXT NOT NULL)'),
    ]);
    const [issuer, lookup, token] = await Promise.all(
      scripts.map((_, i) => mf.getWorker(`worker-${i}`)),
    );
    const post = async (worker, body) =>
      worker.fetch('https://fixture.invalid/', { method: 'POST', body: JSON.stringify(body) });
    const initiation = {
      deviceDigest: 'digest',
      userIndex: 'rP8eDgUUftdMC6Fkx3PEnW2mr7lUkCpZiqFsyscvKdo',
      client: 'nihos',
      scope: 'bookshelf.read',
      key: 'key',
      proofId: 'start-proof',
      expires: 600,
    };
    assert.equal((await post(issuer, initiation)).status, 201);
    assert.deepEqual(await (await post(lookup, { code: '2345-6789', now: 100 })).json(), {
      matched: true,
    });

    const request = {
      code: 'digest',
      client: 'nihos',
      key: 'key',
      now: 100,
      token: 'token',
      proofId: 'token-before',
    };
    assert.equal((await (await post(token, request)).json()).changed, 0);

    // This is a synthetic local stand-in, not a passkey or owner authorization.
    // The conditional decision also demonstrates approve/deny races.
    const decide = (userIndex, state, owner) =>
      db
        .prepare(
          `UPDATE grant_probe SET state=?,owner=?
      WHERE user_index=? AND state='pending' AND expires_at>?`,
        )
        .bind(state, owner, userIndex, 100)
        .run();
    assert.equal((await decide(initiation.userIndex, 'approved', 'fixture-owner')).meta.changes, 1);
    assert.equal((await decide(initiation.userIndex, 'denied', null)).meta.changes, 0);
    const raceIndex = 'race-index';
    assert.equal(
      (
        await post(issuer, {
          ...initiation,
          deviceDigest: 'race',
          userIndex: raceIndex,
          proofId: 'race-start',
        })
      ).status,
      201,
    );
    const decisions = await Promise.all([
      decide(raceIndex, 'approved', 'fixture-owner'),
      decide(raceIndex, 'denied', null),
    ]);
    assert.deepEqual(decisions.map((result) => result.meta.changes).sort(), [0, 1]);
    const state = await db
      .prepare('SELECT state,owner FROM grant_probe WHERE code_digest=?')
      .bind('digest')
      .first();
    assert.equal(state.owner, 'fixture-owner');
    assert.equal(state.state, 'approved');
    const wrong = await (
      await post(token, { ...request, key: 'wrong-key', proofId: 'wrong-key-proof' })
    ).json();
    assert.equal(wrong.changed, 0);
    const redeemed = await (await post(token, { ...request, proofId: 'token-proof' })).json();
    assert.deepEqual(redeemed.tokens, [{ owner: 'fixture-owner' }]);
    const repeated = await (
      await post(token, { ...request, proofId: 'next-proof', token: 'other-token' })
    ).json();
    assert.equal(repeated.changed, 0);
    assert.deepEqual(repeated.tokens, []);
    assert.equal((await db.prepare('SELECT count(*) AS n FROM token_probe').first()).n, 1);
    assert.equal(
      (
        await post(issuer, {
          ...initiation,
          deviceDigest: 'denied',
          userIndex: 'deny-index',
          proofId: 'deny-start',
        })
      ).status,
      201,
    );
    assert.equal((await decide('deny-index', 'denied', null)).meta.changes, 1);
    assert.equal((await decide('deny-index', 'approved', 'fixture-owner')).meta.changes, 0);
    const denied = await (
      await post(token, {
        ...request,
        code: 'denied',
        proofId: 'denied-proof',
        token: 'denied-token',
      })
    ).json();
    assert.equal(denied.changed, 0);
    assert.deepEqual(denied.tokens, []);
    assert.equal(
      (
        await post(issuer, {
          ...initiation,
          deviceDigest: 'expired',
          userIndex: 'expired-index',
          proofId: 'expired-start',
          expires: 100,
        })
      ).status,
      201,
    );
    assert.equal((await decide('expired-index', 'approved', 'fixture-owner')).meta.changes, 0);
    const expired = await (
      await post(token, {
        ...request,
        code: 'expired',
        proofId: 'expired-proof',
        token: 'expired-token',
      })
    ).json();
    assert.equal(expired.changed, 0);
    assert.deepEqual(expired.tokens, []);
    assert.equal((await db.prepare('SELECT count(*) AS n FROM token_probe').first()).n, 1);
    assert.deepEqual(await (await post(lookup, { code: '23456789', now: 100 })).json(), {
      matched: false,
    });
  } finally {
    await mf.dispose();
  }
});
