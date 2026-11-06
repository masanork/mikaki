import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const nonce = Buffer.alloc(32, 9).toString('base64url');
const nonceHash = createHash('sha256').update(nonce).digest('base64url');
const endpoint = 'https://auth.example/native/installations/complete';
const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const { x, y } = key.publicKey.export({ format: 'jwk' });
const thumbprint = createHash('sha256')
  .update(JSON.stringify({ crv: 'P-256', kty: 'EC', x, y }))
  .digest('base64url');
function proof(claimNonce = nonce) {
  const input = `${encode({ typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: 'EC', crv: 'P-256', x, y } })}.${encode({ htm: 'POST', htu: endpoint, iat: 1000, jti: 'actual-proof', nonce: claimNonce })}`;
  return `${input}.${sign('sha256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}
function verify(compact, expectedNonce = nonce) {
  const result = spawnSync(
    'cargo',
    ['run', '--quiet', '--locked', '-p', 'mikaki-oidc', '--example', 'installation_proof_probe'],
    {
      input: JSON.stringify({ compact, nonce: expectedNonce, thumbprint }),
      encoding: 'utf8',
      timeout: 60_000,
    },
  );
  assert.equal(result.error, undefined);
  return result.status === 0 ? JSON.parse(result.stdout) : null;
}

test('real signed and bound proof is reserved with local D1 enrollment', async () => {
  const accepted = verify(proof());
  assert.deepEqual(accepted, {
    key: thumbprint,
    proofId: createHash('sha256').update('actual-proof').digest('base64url'),
    nonceHash,
  });
  assert.equal(verify(proof(Buffer.alloc(32, 8).toString('base64url'))), null);
  const forged = proof().split('.');
  forged[2] = Buffer.alloc(64).toString('base64url');
  assert.equal(verify(forged.join('.')), null);
  const script = await readFile(new URL('./worker.mjs', import.meta.url), 'utf8');
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: ['one', 'two'].map((name) => ({
        name,
        modules: true,
        script,
        compatibilityDate: '2026-10-19',
        d1Databases: { DB: 'installation-proof-probe' },
      })),
    }),
  );
  try {
    const db = await mf.getD1Database('DB', 'one');
    await db.batch([
      db.prepare(
        'CREATE TABLE session(id TEXT PRIMARY KEY,owner TEXT NOT NULL,active INTEGER NOT NULL,expires_at INTEGER NOT NULL)',
      ),
      db.prepare(
        'CREATE TABLE enrollment(id TEXT PRIMARY KEY,session_id TEXT NOT NULL,owner TEXT NOT NULL,device_id TEXT NOT NULL,key_thumbprint TEXT NOT NULL,state TEXT NOT NULL,expires_at INTEGER NOT NULL,nonce_hash TEXT NOT NULL)',
      ),
      db.prepare(
        'CREATE TABLE device(id TEXT PRIMARY KEY,owner TEXT NOT NULL,key_thumbprint TEXT NOT NULL UNIQUE,state TEXT NOT NULL,revision INTEGER NOT NULL)',
      ),
      db.prepare(
        'CREATE TABLE replay(key_thumbprint TEXT NOT NULL,jti_hash TEXT NOT NULL,PRIMARY KEY(key_thumbprint,jti_hash))',
      ),
      db.prepare("INSERT INTO session VALUES('s','owner',1,1100)"),
      db
        .prepare("INSERT INTO enrollment VALUES('first','s','owner','phone',?,'pending',1060,?)")
        .bind(thumbprint, nonceHash),
      db
        .prepare(
          "INSERT INTO enrollment VALUES('second','s','owner','other-phone',?,'pending',1060,?)",
        )
        .bind(thumbprint, nonceHash),
    ]);
    const workers = await Promise.all(['one', 'two'].map((name) => mf.getWorker(name)));
    const complete = (worker, id) =>
      worker.fetch('https://fixture.invalid/', {
        method: 'POST',
        body: JSON.stringify({
          action: 'complete',
          id,
          session: 's',
          owner: 'owner',
          now: 1000,
          ...accepted,
        }),
      });
    await db.prepare("UPDATE enrollment SET nonce_hash='replaced' WHERE id='first'").run();
    assert.deepEqual((await (await complete(workers[0], 'first')).json()).completed, []);
    await db.prepare("UPDATE enrollment SET nonce_hash=? WHERE id='first'").bind(nonceHash).run();
    await db.prepare("UPDATE session SET active=0 WHERE id='s'").run();
    assert.deepEqual((await (await complete(workers[0], 'first')).json()).completed, []);
    await db.prepare("UPDATE session SET active=1 WHERE id='s'").run();
    assert.deepEqual((await (await complete(workers[0], 'first')).json()).completed, [
      { id: 'phone' },
    ]);
    assert.equal((await complete(workers[1], 'second')).status, 409);
    assert.equal(
      (await db.prepare("SELECT state FROM enrollment WHERE id='second'").first()).state,
      'pending',
    );
  } finally {
    await mf.dispose();
  }
});
