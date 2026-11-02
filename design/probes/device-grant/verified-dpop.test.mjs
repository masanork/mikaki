import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const pair = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
function compact(
  key,
  { jti = 'one', htu = 'https://issuer.example/token', htm = 'POST', iat = 1000 } = {},
) {
  const { x, y } = key.publicKey.export({ format: 'jwk' });
  const header = encode({ typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: 'EC', crv: 'P-256', x, y } });
  const input = `${header}.${encode({ jti, htu, htm, iat })}`;
  const signature = sign('sha256', Buffer.from(input), {
    key: key.privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${input}.${signature.toString('base64url')}`;
}
function verified(jwt) {
  const result = spawnSync(
    'cargo',
    ['run', '--quiet', '--locked', '-p', 'mikaki-oidc', '--example', 'device_dpop_probe'],
    {
      input: jwt,
      encoding: 'utf8',
      timeout: 60_000,
    },
  );
  assert.equal(result.error, undefined);
  return result.status === 0 ? JSON.parse(result.stdout) : null;
}

test('host-verified DPoP proof drives local D1 key binding and replay reservation', async () => {
  const key = pair();
  const attacker = pair();
  const jwt = compact(key);
  const accepted = verified(jwt);
  assert.ok(accepted);
  assert.equal(accepted.jti_hash, createHash('sha256').update('one').digest('base64url'));
  assert.equal(accepted.retain_until, 1070);
  assert.equal(verified(compact(key, { htu: 'https://issuer.example/other' })), null);
  assert.equal(verified(compact(key, { htm: 'GET' })), null);
  assert.equal(verified(compact(key, { iat: 929 })), null);
  const [header, claims] = jwt.split('.');
  const forged = compact(attacker).split('.')[2];
  assert.equal(verified(`${header}.${claims}.${forged}`), null);
  const wrong = verified(compact(attacker, { jti: 'other-key' }));
  assert.ok(wrong);
  assert.notEqual(wrong.thumbprint, accepted.thumbprint);

  const script = await readFile(new URL('./d1-worker.mjs', import.meta.url), 'utf8');
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: ['first', 'second'].map((name) => ({
        name,
        modules: true,
        script,
        compatibilityDate: '2026-10-19',
        d1Databases: { DB: 'verified-dpop-probe' },
      })),
    }),
  );
  try {
    const db = await mf.getD1Database('DB', 'first');
    await db.batch([
      db.prepare(
        'CREATE TABLE grant_probe(code_digest TEXT PRIMARY KEY,client_id TEXT NOT NULL,key_thumbprint TEXT NOT NULL,expires_at INTEGER NOT NULL,state TEXT NOT NULL,owner TEXT NOT NULL)',
      ),
      db.prepare('CREATE TABLE token_probe(token_digest TEXT PRIMARY KEY,owner TEXT NOT NULL)'),
      db.prepare(
        'CREATE TABLE replay_probe(key_thumbprint TEXT NOT NULL,jti_hash TEXT NOT NULL,PRIMARY KEY(key_thumbprint,jti_hash))',
      ),
      db
        .prepare('INSERT INTO grant_probe VALUES(?,?,?,?,?,?)')
        .bind('grant-a', 'nihos', accepted.thumbprint, 1100, 'approved', 'alice'),
      db
        .prepare('INSERT INTO grant_probe VALUES(?,?,?,?,?,?)')
        .bind('grant-b', 'nihos', accepted.thumbprint, 1100, 'approved', 'alice'),
    ]);
    const workers = await Promise.all(['first', 'second'].map((name) => mf.getWorker(name)));
    const redeem = async (worker, code, proof, token) => {
      const response = await worker.fetch('https://fixture.invalid/', {
        method: 'POST',
        body: JSON.stringify({
          code,
          client: 'nihos',
          key: proof.thumbprint,
          proofId: proof.jti_hash,
          now: 1000,
          token,
        }),
      });
      return { status: response.status, body: await response.json() };
    };
    assert.equal((await redeem(workers[0], 'grant-a', wrong, 'bad')).body.changed, 0);
    assert.deepEqual((await redeem(workers[0], 'grant-a', accepted, 'good')).body.tokens, [
      { owner: 'alice' },
    ]);
    assert.equal((await redeem(workers[1], 'grant-b', accepted, 'replay')).status, 409);
    assert.equal(
      (
        await db
          .prepare('SELECT state FROM grant_probe WHERE code_digest=?')
          .bind('grant-b')
          .first()
      ).state,
      'approved',
    );
    assert.equal((await db.prepare('SELECT count(*) AS n FROM token_probe').first()).n, 1);
  } finally {
    await mf.dispose();
  }
});
