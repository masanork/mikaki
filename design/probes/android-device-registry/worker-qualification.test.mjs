import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { resolve } from 'node:path';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

const origin = 'https://auth.example';
const cookie = 'qualification-sso-secret';
const hash = createHash('sha256').update(cookie).digest('base64url');
const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const { x, y } = key.publicKey.export({ format: 'jwk' });
const enc = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
function proof(
  path,
  nonce,
  jti = randomUUID(),
  signingKey = key,
  jwk = { kty: 'EC', crv: 'P-256', x, y },
) {
  const claims = { htm: 'POST', htu: origin + path, iat: Math.floor(Date.now() / 1000), jti };
  if (nonce) claims.nonce = nonce;
  const payload = `${enc({ typ: 'dpop+jwt', alg: 'ES256', jwk })}.${enc(claims)}`;
  return `${payload}.${sign('sha256', Buffer.from(payload), { key: signingKey.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

test('qualification Worker binds live SSO and signed key to one D1 installation', async () => {
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modulesRoot: resolve('local/generated/installation'),
      modules: [
        { type: 'ESModule', path: resolve('local/generated/installation/worker.bundle.mjs') },
        {
          type: 'CompiledWasm',
          path: resolve('local/generated/installation/qualification_bg.wasm'),
        },
      ],
      compatibilityDate: '2026-10-19',
      d1Databases: { DB: 'installation' },
      bindings: { MIKAKI_ISSUER: origin },
    }),
  );
  try {
    const db = await mf.getD1Database('DB');
    const schema = [
      'CREATE TABLE fixture_installation_fault(id INTEGER PRIMARY KEY,mode TEXT)',
      'CREATE TABLE account_security(account_id TEXT PRIMARY KEY,epoch INTEGER,active INTEGER)',
      'CREATE TABLE credential(credential_id TEXT PRIMARY KEY,account_id TEXT,active INTEGER)',
      'CREATE TABLE sso_session(sso_id TEXT PRIMARY KEY,account_id TEXT,credential_id TEXT,epoch INTEGER,expires_at INTEGER,revoked INTEGER)',
      'CREATE TABLE sso_context(sso_id TEXT,secret_hash TEXT)',
      'CREATE TABLE dbsc_session(sso_id TEXT,cookie_expires_at INTEGER)',
      'CREATE TABLE client(client_id TEXT PRIMARY KEY,active INTEGER,client_type TEXT,auth_method TEXT,sector_identifier TEXT)',
      'CREATE TABLE client_redirect_uri(client_id TEXT,redirect_uri TEXT,active INTEGER)',
      "INSERT INTO account_security VALUES('account',1,1)",
      "INSERT INTO credential VALUES('credential','account',1)",
      "INSERT INTO sso_session VALUES('session','account','credential',1,unixepoch()+3600,0)",
      `INSERT INTO sso_context VALUES('session','${hash}')`,
      "INSERT INTO client VALUES('dfd936fd-f33d-4f82-ae39-f25e08ec7948',1,'native','none','app.mikaki.org')",
      "INSERT INTO client_redirect_uri VALUES('dfd936fd-f33d-4f82-ae39-f25e08ec7948','https://app.mikaki.org/oidc/native/callback',1)",
    ];
    const extra = await readFile('crates/worker/installation-qualification/0001.sql', 'utf8');
    await db.batch(
      [
        ...schema,
        ...extra
          .split(';')
          .map((s) => s.trim())
          .filter(Boolean),
      ].map((s) => db.prepare(s)),
    );
    async function send(path, body, dpop, withCookie = true) {
      return mf.dispatchFetch(origin + path, {
        method: 'POST',
        headers: {
          origin,
          'content-type': 'application/json',
          'x-mikaki-app': '1',
          dpop,
          ...(withCookie ? { cookie: `__Host-op-sso=${cookie}` } : {}),
        },
        body: JSON.stringify(body),
      });
    }
    const start = '/native/installations/start',
      complete = '/native/installations/complete';
    assert.equal((await send(start, {}, proof(start), false)).status, 401);
    const startProof = proof(start);
    const response = await send(start, {}, startProof);
    assert.equal(response.status, 200, await response.clone().text());
    const pending = await response.json();
    assert.equal((await send(start, {}, startProof)).status, 409);
    assert.equal((await send(complete, { id: pending.id }, proof(complete, 'wrong'))).status, 400);
    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const otherPublic = other.publicKey.export({ format: 'jwk' });
    const otherJwk = { kty: 'EC', crv: 'P-256', x: otherPublic.x, y: otherPublic.y };
    assert.equal(
      (
        await send(
          complete,
          { id: pending.id },
          proof(complete, pending.nonce, randomUUID(), other, otherJwk),
        )
      ).status,
      400,
    );
    const results = await Promise.all([
      send(complete, { id: pending.id }, proof(complete, pending.nonce)),
      send(complete, { id: pending.id }, proof(complete, pending.nonce)),
    ]);
    assert.deepEqual(results.map((r) => r.status).sort(), [200, 409]);
    assert.equal((await results.find((r) => r.status === 200).json()).status, 'active');
    assert.equal(
      (await send(complete, { id: pending.id }, proof(complete, pending.nonce))).status,
      409,
    );
    const next = await send(start, {}, proof(start));
    const pending2 = await next.json();
    // Invalidate authority after the owner and pending reads but before D1's
    // completion batch. None of these attempts may consume the challenge.
    const resets = {
      session: "UPDATE sso_session SET revoked=0 WHERE sso_id='session'",
      account: "UPDATE account_security SET active=1 WHERE account_id='account'",
      epoch: "UPDATE account_security SET epoch=1 WHERE account_id='account'",
      credential: "UPDATE credential SET active=1 WHERE credential_id='credential'",
      client: 'UPDATE client SET active=1',
      redirect: 'UPDATE client_redirect_uri SET active=1',
    };
    for (const [mode, reset] of Object.entries(resets)) {
      await db.prepare('INSERT INTO fixture_installation_fault VALUES(1,?)').bind(mode).run();
      const attempted = proof(complete, pending2.nonce);
      assert.equal((await send(complete, { id: pending2.id }, attempted)).status, 409, mode);
      assert.equal(
        (
          await db
            .prepare('SELECT consumed FROM installation_pending WHERE id=?')
            .bind(pending2.id)
            .first()
        ).consumed,
        0,
        mode,
      );
      await db.prepare(reset).run();
    }
    // The same key was already registered above. The final insert fails its
    // unique constraint after the preceding update and replay insert; the D1
    // batch must roll both writes back.
    const replayId = randomUUID();
    const replayHash = createHash('sha256').update(replayId).digest('base64url');
    const duplicate = await send(
      complete,
      { id: pending2.id },
      proof(complete, pending2.nonce, replayId),
    );
    assert.equal(duplicate.status, 500);
    assert.equal(
      (
        await db
          .prepare('SELECT consumed FROM installation_pending WHERE id=?')
          .bind(pending2.id)
          .first()
      ).consumed,
      0,
    );
    assert.equal(
      await db
        .prepare('SELECT jti_hash FROM installation_proof_use WHERE jti_hash=?')
        .bind(replayHash)
        .first(),
      null,
    );
    await db.prepare("UPDATE sso_session SET revoked=1 WHERE sso_id='session'").run();
    assert.equal(
      (await send(complete, { id: pending2.id }, proof(complete, pending2.nonce))).status,
      401,
    );
    assert.equal((await db.prepare('SELECT count(*) AS n FROM installation_device').first()).n, 1);
    assert.equal(
      (
        await db
          .prepare('SELECT consumed FROM installation_pending WHERE id=?')
          .bind(pending2.id)
          .first()
      ).consumed,
      0,
    );
  } finally {
    await mf.dispose();
  }
});
