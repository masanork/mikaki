import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, jwtVerify } from 'jose';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const issuer = 'https://issuer.example';
const hash = (s: string) => createHash('sha256').update(s).digest('base64url');
const random = () => randomBytes(32).toString('base64url');

test('normal-profile secret authentication is confined to configured Access client', async () => {
  const key = await generateKeyPair('ES256', { extractable: true });
  const privateJwk = { ...(await exportJWK(key.privateKey)), kid: 'op', alg: 'ES256' };
  const publicJwk = { ...(await exportJWK(key.publicKey)), kid: 'op', alg: 'ES256' };
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  config.assets.directory = new URL('../../assets', import.meta.url).pathname;
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.vars = {
    MIKAKI_ISSUER: issuer,
    MIKAKI_ACCESS_SECRET_CLIENT_ID: 'access',
    OP_PRIVATE_JWK: JSON.stringify(privateJwk),
  };
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [{ config }],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'test', reason: 'Access secret isolation' },
    );
    const clientSecret = random();
    await DB.batch([
      DB.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256',?)").bind(
        JSON.stringify(publicJwk),
      ),
      ...['access', 'other'].map((id) =>
        DB.prepare(
          "INSERT INTO client(client_id,revision,active,client_type,auth_method,allow_missing_pkce,sector_identifier) VALUES(?,1,1,'web','client_secret_basic',0,'example.com')",
        ).bind(id),
      ),
      DB.prepare("INSERT INTO account_security VALUES('account',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('credential','account',1)"),
      DB.prepare(
        "INSERT INTO app_connection(account_id,client_id,grant_version,active,reviewed_redirect_uri,reviewed_scope,reviewed_client_revision,reviewed_grant_version) VALUES('account','access',1,1,'https://example.com/callback','openid profile email',1,1)",
      ),
      DB.prepare(
        "INSERT INTO client_redirect_uri(client_id,redirect_uri,active) VALUES('access','https://example.com/callback',1)",
      ),
      DB.prepare("INSERT INTO sso_session VALUES('sso','account','credential',1,?,0)").bind(
        Math.floor(Date.now() / 1000) + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(
        hash('cookie-secret'),
        Math.floor(Date.now() / 1000),
      ),
      DB.prepare(
        "INSERT INTO access_email_binding VALUES('access','account','Owner@example.test',1,1,123)",
      ),
      ...['access', 'other'].map((id) =>
        DB.prepare(
          'INSERT INTO client_secret(client_id,revision,active,secret_hash) VALUES(?,1,1,?)',
        ).bind(id, hash(clientSecret)),
      ),
    ]);
    const count = async () =>
      (await DB.prepare('SELECT COUNT(*) AS n FROM client_auth_use').first()).n;
    const request = async (id: string, provided: string, verifier?: string) =>
      worker.fetch(`${issuer}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${Buffer.from(`${id}:${provided}`).toString('base64')}`,
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: random(),
          redirect_uri: 'https://example.com/callback',
          ...(verifier ? { code_verifier: verifier } : {}),
        }).toString(),
      });
    const before = await count();
    await request('other', clientSecret, random());
    await request('access', random(), random());
    await request('access', clientSecret);
    assert.equal(await count(), before);
    await request('access', clientSecret, random());
    assert.equal(await count(), before + 1, 'valid client reaches code exchange');
    const verifier = random();
    const authorize = new URL(`${issuer}/authorize`);
    for (const [key, value] of Object.entries({
      response_type: 'code',
      client_id: 'access',
      redirect_uri: 'https://example.com/callback',
      scope: 'email profile openid',
      state: 's'.repeat(1600),
      nonce: random(),
      code_challenge: hash(verifier),
      code_challenge_method: 'S256',
    }))
      authorize.searchParams.set(key, value);
    const oversized = new URL(authorize);
    oversized.searchParams.set('state', 's'.repeat(4097));
    const oversizedResponse = await worker.fetch(oversized.toString(), {
      headers: { Cookie: '__Host-op-sso=cookie-secret' },
      redirect: 'manual',
    });
    assert.equal(
      new URL(oversizedResponse.headers.get('location')!).searchParams.get('error'),
      'invalid_request',
    );
    const auth = await worker.fetch(authorize.toString(), {
      headers: { Cookie: '__Host-op-sso=cookie-secret' },
      redirect: 'manual',
    });
    const location = new URL(auth.headers.get('location')!);
    assert.ok(location.searchParams.get('code'), location.toString());
    const response = await worker.fetch(`${issuer}/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`access:${clientSecret}`).toString('base64')}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: location.searchParams.get('code')!,
        redirect_uri: 'https://example.com/callback',
        code_verifier: verifier,
      }).toString(),
    });
    assert.equal(response.status, 200, await response.clone().text());
    const issued = (await response.json()) as { id_token: string; access_token: string };
    const verified = await jwtVerify(issued.id_token, key.publicKey, {
      issuer,
      audience: 'access',
      algorithms: ['ES256'],
    });
    assert.equal(verified.payload.email, 'Owner@example.test');
    assert.equal(verified.payload.email_verified, true);
    const userinfo = async () =>
      worker.fetch(`${issuer}/userinfo`, {
        headers: { authorization: `Bearer ${issued.access_token}` },
      });
    const firstInfo = await userinfo();
    assert.equal(firstInfo.status, 200);
    assert.equal(((await firstInfo.json()) as { email?: string }).email, 'Owner@example.test');
    const revokedVerifier = random();
    authorize.searchParams.set('code_challenge', hash(revokedVerifier));
    const secondAuth = await worker.fetch(authorize.toString(), {
      headers: { Cookie: '__Host-op-sso=cookie-secret' },
      redirect: 'manual',
    });
    const secondCode = new URL(secondAuth.headers.get('location')!).searchParams.get('code');
    assert.ok(secondCode);
    await DB.prepare(
      "UPDATE access_email_binding SET active=0,revision=revision+1 WHERE client_id='access' AND account_id='account'",
    ).run();
    const afterRevocation = await userinfo();
    assert.equal(afterRevocation.status, 200);
    assert.equal(((await afterRevocation.json()) as { email?: string }).email, undefined);
    const revoked = await worker.fetch(`${issuer}/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`access:${clientSecret}`).toString('base64')}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: secondCode,
        redirect_uri: 'https://example.com/callback',
        code_verifier: revokedVerifier,
      }).toString(),
    });
    assert.equal(revoked.status, 400, 'a revoked email binding cannot be issued');
    const afterIssued = await count();
    await DB.prepare(
      "UPDATE client SET allow_missing_pkce=1,revision=revision+1 WHERE client_id='access'",
    ).run();
    await request('access', clientSecret, random());
    assert.equal(await count(), afterIssued, 'misconfigured client is rejected');
    await DB.prepare(
      "UPDATE client SET allow_missing_pkce=0,revision=revision+1 WHERE client_id='access'",
    ).run();
    await DB.prepare(
      "UPDATE client_secret SET active=0,revision=revision+1 WHERE client_id='access'",
    ).run();
    await request('access', clientSecret, random());
    assert.equal(await count(), afterIssued, 'retired secret is rejected');
  } finally {
    await harness.close();
  }
});
