import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

test('session check authenticates its RP, binds sid, and observes D1 revocation and lease changes', async () => {
  const issuer = 'https://mikaki.test';
  const endpoint = `${issuer}/session/check`;
  const clientId = 'session-check-rp';
  const codeHash = randomBytes(32).toString('base64url');
  const accessHash = randomBytes(32).toString('base64url');
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  assert.ok(jwk.x && jwk.y);
  const sec1 = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url'),
  ]);
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        vars: { MIKAKI_ISSUER: issuer },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const runtime = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, runtime, { actor: 'test', reason: 'session check test' });
    const now = Math.floor(Date.now() / 1000);
    const redirectUri = 'https://rp.example/callback';
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('account',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('credential','account',1)"),
      DB.prepare(
        "INSERT INTO client(client_id,revision,active,auth_method,sector_identifier) VALUES(?,1,1,'private_key_jwt','rp.example')",
      ).bind(clientId),
      DB.prepare('INSERT INTO client_key VALUES(?, ?, 1, 1, ?, ?)').bind(
        clientId,
        'client-key',
        'ES256',
        sec1,
      ),
      DB.prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)').bind(
        clientId,
        redirectUri,
      ),
      DB.prepare("INSERT INTO signing_key VALUES('op-key',1,1,'ES256',?)").bind(
        JSON.stringify({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }),
      ),
      DB.prepare("INSERT INTO app_connection VALUES('account',?,1,1)").bind(clientId),
      DB.prepare('INSERT INTO sso_session VALUES(?,?,?,?,?,0)').bind(
        'sso',
        'account',
        'credential',
        1,
        now + 3600,
      ),
      DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind('sso', 'secret-hash', now),
      DB.prepare('INSERT INTO client_session VALUES(?,?,?,?,?,?,0)').bind(
        clientId,
        'owned-sid',
        'sso',
        'account',
        'pairwise-sub',
        1,
      ),
      DB.prepare('INSERT INTO authorization_code VALUES(?,?,?,?,?,?,?,?,?)').bind(
        codeHash,
        clientId,
        'owned-sid',
        1,
        redirectUri,
        '',
        now + 60,
        'exchange',
        now,
      ),
      DB.prepare('INSERT INTO token_issue VALUES(?,?,?,?,?,?,0)').bind(
        codeHash,
        'exchange',
        accessHash,
        now + 60,
        'op-key',
        now,
      ),
    ]);
    const assertion = async (audience = endpoint) =>
      new SignJWT({ jti: randomUUID() })
        .setProtectedHeader({ alg: 'ES256', kid: 'client-key' })
        .setIssuer(clientId)
        .setSubject(clientId)
        .setAudience(audience)
        .setIssuedAt()
        .setExpirationTime('45s')
        .sign(privateKey);
    const check = async (sid, audience = endpoint) =>
      worker.fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_id: clientId,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: await assertion(audience),
          sid,
        }),
      });
    const valid = await check('owned-sid');
    assert.equal(valid.status, 200);
    assert.equal(valid.headers.get('cache-control'), 'no-store');
    const body = (await valid.json()) as Record<string, unknown>;
    assert.equal(body.active, true);
    assert.equal(body.sub, 'pairwise-sub');
    assert.equal(body.auth_time, now);
    assert.equal(body.lease_ttl, 300);
    assert.equal(body.app_idle_timeout, 604800);
    assert.equal(body.policy_revision, runtime.policy_revision);
    assert.equal(body.session_policy_revision, 1);
    assert.deepEqual(await (await check('other-sid')).json(), { active: false });
    assert.equal((await check('owned-sid', `${issuer}/token`)).status, 401);
    await DB.prepare(
      'UPDATE session_validation_policy SET lease_ttl_seconds=30,revision=revision+1 WHERE id=1',
    ).run();
    const shorter = (await (await check('owned-sid')).json()) as Record<string, unknown>;
    assert.equal(shorter.lease_ttl, 30);
    assert.equal(shorter.session_policy_revision, 2);
    await DB.prepare("UPDATE sso_session SET revoked=1 WHERE sso_id='sso'").run();
    assert.deepEqual(await (await check('owned-sid')).json(), { active: false });
  } finally {
    await harness.close();
  }
});
