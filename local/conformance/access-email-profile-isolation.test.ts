import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, jwtVerify } from 'jose';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const issuer = 'https://issuer.example';
const random = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');

test('Access bindings and verified-email consent stay isolated when both profiles are enabled', async () => {
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
    MIKAKI_CLIENT_SECRET_BASIC: 'on',
    MIKAKI_VERIFIED_EMAIL: 'on',
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
      { actor: 'test', reason: 'profile isolation' },
    );
    const secret = random(),
      callback = 'https://example.com/callback';
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256',?)").bind(
        JSON.stringify(publicJwk),
      ),
      DB.prepare("INSERT INTO account_security VALUES('account',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('credential','account',1)"),
      DB.prepare("INSERT INTO sso_session VALUES('sso','account','credential',1,?,0)").bind(
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(hash('cookie-secret'), now),
      ...['access', 'normal'].flatMap((id) => [
        DB.prepare(
          "INSERT INTO client(client_id,revision,active,client_type,auth_method,allow_missing_pkce,sector_identifier) VALUES(?,1,1,'web','client_secret_basic',0,'example.com')",
        ).bind(id),
        DB.prepare(
          'INSERT INTO client_secret(client_id,revision,active,secret_hash) VALUES(?,1,1,?)',
        ).bind(id, hash(secret)),
        DB.prepare(
          'INSERT INTO client_redirect_uri(client_id,redirect_uri,active) VALUES(?,?,1)',
        ).bind(id, callback),
        DB.prepare(
          "INSERT INTO app_connection(account_id,client_id,grant_version,active,reviewed_redirect_uri,reviewed_scope,reviewed_client_revision,reviewed_grant_version) VALUES('account',?,1,1,?,?,1,1)",
        ).bind(id, callback, id === 'access' ? 'openid profile email' : 'openid email'),
      ]),
      DB.prepare(
        "INSERT INTO account_verified_email VALUES('account','verified@example.test',1,1,123,1)",
      ),
      DB.prepare("INSERT INTO client_email_policy VALUES('normal',1,1)"),
      DB.prepare(
        "INSERT INTO account_email_release(account_id,client_id,email_revision,account_epoch,client_revision,grant_version,active) VALUES('account','normal',1,1,1,1,1)",
      ),
      DB.prepare(
        "INSERT INTO access_email_binding VALUES('access','account','access@example.test',1,1,123)",
      ),
      DB.prepare(
        "INSERT INTO access_email_binding VALUES('normal','account','wrong@example.test',1,1,123)",
      ),
    ]);
    const authorize = async (client: string, scope: string, verifier: string) => {
      const url = new URL(`${issuer}/authorize`);
      for (const [name, value] of Object.entries({
        response_type: 'code',
        client_id: client,
        redirect_uri: callback,
        scope,
        state: random(),
        code_challenge: hash(verifier),
        code_challenge_method: 'S256',
      }))
        url.searchParams.set(name, value);
      const response = await worker.fetch(url.toString(), {
        headers: { Cookie: '__Host-op-sso=cookie-secret' },
        redirect: 'manual',
      });
      return new URL(response.headers.get('location')!);
    };
    const issue = async (client: string, scope: string, method: 'basic' | 'post' = 'basic') => {
      const verifier = random(),
        location = await authorize(client, scope, verifier);
      const code = location.searchParams.get('code');
      assert.ok(code, location.toString());
      const response = await worker.fetch(`${issuer}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          ...(method === 'basic'
            ? { authorization: `Basic ${Buffer.from(`${client}:${secret}`).toString('base64')}` }
            : {}),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: callback,
          code_verifier: verifier,
          ...(method === 'post' ? { client_id: client, client_secret: secret } : {}),
        }).toString(),
      });
      assert.equal(response.status, 200, await response.clone().text());
      const issued = (await response.json()) as { id_token: string; access_token: string };
      const verified = await jwtVerify(issued.id_token, key.publicKey, {
        issuer,
        audience: client,
        algorithms: ['ES256'],
      });
      return { token: issued.access_token, email: verified.payload.email };
    };
    const info = async (token: string) => {
      const response = await worker.fetch(`${issuer}/userinfo`, {
        headers: { authorization: `Bearer ${token}` },
      });
      assert.equal(response.status, 200, await response.clone().text());
      return (await response.json()) as { email?: string };
    };
    const rejectedPost = await worker.fetch(`${issuer}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: 'normal',
        client_secret: secret,
        code: random(),
        redirect_uri: callback,
        code_verifier: random(),
      }).toString(),
    });
    assert.equal(
      rejectedPost.status,
      401,
      'Access enablement must not enable secret_post for normal clients',
    );
    assert.equal(
      (await authorize('access', 'openid email', random())).searchParams.get('error'),
      'invalid_scope',
    );
    const access = await issue('access', 'email profile openid');
    const normal = await issue('normal', 'openid email');
    assert.equal(access.email, 'access@example.test');
    assert.equal(normal.email, 'verified@example.test');
    // A stray generic consent marker must never turn an Access token into a
    // generic verified-email release, including after its Access binding changes.
    await DB.batch([
      DB.prepare("INSERT INTO client_email_policy VALUES('access',1,1)"),
      DB.prepare(
        "INSERT INTO account_email_release(account_id,client_id,email_revision,account_epoch,client_revision,grant_version,active) VALUES('account','access',1,1,1,1,1)",
      ),
      DB.prepare(
        'INSERT INTO authorization_email_scope(code_hash) SELECT code_hash FROM token_issue WHERE access_hash=?',
      ).bind(hash(access.token)),
    ]);
    assert.equal((await info(access.token)).email, 'access@example.test');
    assert.equal((await info(normal.token)).email, 'verified@example.test');
    await DB.prepare(
      "UPDATE account_email_release SET active=0,revision=revision+1 WHERE account_id='account' AND client_id='normal'",
    ).run();
    assert.equal((await info(normal.token)).email, undefined);
    assert.equal((await info(access.token)).email, 'access@example.test');
    const commitSql = await readFile(
      new URL('../../crates/worker/sql/commit-authorization-code.sql', import.meta.url),
      'utf8',
    );
    const accessCommit = async () => {
      const verifier = random(),
        location = await authorize('access', 'email profile openid', verifier);
      const code = location.searchParams.get('code');
      assert.ok(code, location.toString());
      const codeHash = createHash('sha256')
        .update(Buffer.from(code, 'base64url'))
        .digest('base64url');
      const snapshot = await DB.prepare(
        'SELECT ac.sid,v.sub,v.expires_at AS parent_expiry,sx.auth_time,b.email,b.revision FROM authorization_code ac JOIN eligible_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid JOIN client_session cs ON cs.client_id=ac.client_id AND cs.sid=ac.sid JOIN sso_context sx ON sx.sso_id=cs.sso_id JOIN access_email_binding b ON b.client_id=cs.client_id AND b.account_id=cs.account_id AND b.active=1 WHERE ac.code_hash=?',
      )
        .bind(codeHash)
        .first();
      assert.ok(snapshot);
      const reservation = random(),
        operation = random(),
        current = Math.floor(Date.now() / 1000),
        retained = current + 300;
      await DB.prepare(
        "INSERT INTO client_auth_use(accepted_by,client_id,method,endpoint,credential_id,client_revision,credential_revision,retain_until) VALUES(?,'access','client_secret_basic',?,'',1,1,?)",
      )
        .bind(reservation, `${issuer}/token`, retained)
        .run();
      return [
        codeHash,
        'access',
        callback,
        hash(verifier),
        1,
        '',
        1,
        'client_secret_basic',
        `${issuer}/token`,
        reservation,
        retained,
        'op',
        1,
        snapshot.sid,
        snapshot.sub,
        null,
        snapshot.auth_time,
        snapshot.parent_expiry,
        operation,
        current + 120,
        current + 120,
        random(),
        JSON.stringify(publicJwk),
        'ES256',
        null,
        null,
        null,
        0,
        'openid email profile',
        null,
        0,
        null,
        null,
        snapshot.email,
        snapshot.revision,
        'account',
      ];
    };
    const control = await accessCommit();
    assert.equal(
      (
        await DB.prepare(commitSql)
          .bind(...control)
          .run()
      ).meta.changes,
      1,
    );
    const mixed = await accessCommit();
    await DB.prepare('INSERT INTO authorization_email_scope(code_hash) VALUES(?)')
      .bind(mixed[0])
      .run();
    assert.equal(
      (
        await DB.prepare(commitSql)
          .bind(...mixed)
          .run()
      ).meta.changes,
      0,
      'mixed profile markers must fence code consumption',
    );
    const stale = await accessCommit();
    await DB.prepare(
      "UPDATE access_email_binding SET email='changed@example.test',revision=revision+1 WHERE client_id='access' AND account_id='account'",
    ).run();
    assert.equal(
      (
        await DB.prepare(commitSql)
          .bind(...stale)
          .run()
      ).meta.changes,
      0,
      'binding changes must fence code consumption',
    );
    assert.equal(
      (await info(access.token)).email,
      undefined,
      'existing token cannot disclose a changed binding',
    );
    await DB.prepare(
      "UPDATE access_email_binding SET active=0,revision=revision+1 WHERE client_id='access' AND account_id='account'",
    ).run();
    assert.equal((await info(access.token)).email, undefined);
    await DB.batch([
      DB.prepare(
        "UPDATE client SET auth_method='client_secret_post',revision=revision+1 WHERE client_id='access'",
      ),
      DB.prepare(
        "UPDATE app_connection SET reviewed_client_revision=2 WHERE client_id='access' AND account_id='account'",
      ),
      DB.prepare(
        "UPDATE access_email_binding SET active=1,revision=revision+1 WHERE client_id='access' AND account_id='account'",
      ),
    ]);
    const post = await issue('access', 'openid email profile', 'post');
    assert.equal(post.email, 'changed@example.test');
    assert.equal((await info(post.token)).email, 'changed@example.test');
  } finally {
    await harness.close();
  }
});
