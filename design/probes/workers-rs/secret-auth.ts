import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createTestHarness } from 'wrangler';
import { exportJWK, generateKeyPair, jwtVerify } from 'jose';
import { activateWorkerPolicy } from '../../../scripts/worker-policy-store.ts';
import { registerSecretClient, rotateSecretClient } from '../../../scripts/client-admin-store.ts';

const root = fileURLToPath(new URL('../../..', import.meta.url));
const conformanceConfig = fileURLToPath(
  new URL('../../../crates/worker/wrangler.conformance.jsonc', import.meta.url),
);
const normalConfig = fileURLToPath(
  new URL('../../../crates/worker/wrangler.jsonc', import.meta.url),
);
const policy = JSON.parse(
  await readFile(new URL('../../../local/generated/worker-policy.json', import.meta.url), 'utf8'),
);
const issuer = 'https://issuer.example';
const redirectUri = 'https://rp.example/callback';
const accountId = 'secret-test-account';
const cookie = randomBytes(32).toString('base64url');
const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
const clients = [
  {
    id: 'basic-one',
    method: 'client_secret_basic',
    secret: randomBytes(32).toString('base64url'),
    allowMissingPkce: true,
  },
  { id: 'basic:two', method: 'client_secret_basic', secret: randomBytes(32).toString('base64url') },
  { id: 'post-one', method: 'client_secret_post', secret: randomBytes(32).toString('base64url') },
];

const pair = await generateKeyPair('ES256', { extractable: true });
const privateJwk = { ...(await exportJWK(pair.privateKey)), kid: 'secret-test-op', alg: 'ES256' };
const publicJwk = { ...(await exportJWK(pair.publicKey)), kid: 'secret-test-op', alg: 'ES256' };
const harness = createTestHarness({
  root,
  workers: [
    {
      configPath: conformanceConfig,
      vars: { MIKAKI_ISSUER: issuer },
      secrets: { OP_PRIVATE_JWK: JSON.stringify(privateJwk) },
    },
    {
      configPath: normalConfig,
      vars: {
        MIKAKI_ISSUER: issuer,
        MIKAKI_CLIENT_SECRET_BASIC: 'on',
        MIKAKI_VERIFIED_EMAIL: 'on',
      },
      secrets: { OP_PRIVATE_JWK: JSON.stringify(privateJwk) },
    },
  ],
});
type ProbeWorker = Pick<ReturnType<typeof harness.getWorker>, 'fetch'>;

async function authorize(
  worker: ProbeWorker,
  clientId: string,
  options: { noPkce?: boolean; expectError?: boolean; scope?: string } = {},
) {
  const target = new URL('/authorize', issuer);
  target.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: options.scope ?? 'openid',
    state: 'secret-auth-state',
    ...(!options.noPkce ? { code_challenge: challenge, code_challenge_method: 'S256' } : {}),
  }).toString();
  const response = await worker.fetch(target, {
    headers: { cookie: `__Host-op-sso=${cookie}` },
    redirect: 'manual',
  });
  assert.equal(response.status, 302, await response.text());
  const location = response.headers.get('location');
  assert.ok(location);
  const callback = new URL(location);
  const result = options.expectError
    ? callback.searchParams.get('error')
    : callback.searchParams.get('code');
  assert.ok(result, `unexpected authorization redirect: ${location}`);
  return result;
}

async function exchange(
  worker: ProbeWorker,
  client: (typeof clients)[number],
  code: string,
  options: { noVerifier?: boolean; secret?: string; mixed?: boolean } = {},
) {
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    ...(!options.noVerifier ? { code_verifier: verifier } : {}),
  });
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
  if (client.method === 'client_secret_basic') {
    headers.authorization = `Basic ${Buffer.from(
      `${encodeURIComponent(client.id)}:${encodeURIComponent(options.secret ?? client.secret)}`,
    ).toString('base64')}`;
  } else {
    form.set('client_id', client.id);
    form.set('client_secret', options.secret ?? client.secret);
  }
  if (options.mixed) {
    form.set('client_secret', client.secret);
  }
  const response = await worker.fetch(`${issuer}/token`, {
    method: 'POST',
    headers,
    body: form.toString(),
  });
  return {
    status: response.status,
    challenge: response.headers.get('www-authenticate'),
    body: (await response.json()) as { id_token?: string; access_token?: string; error?: string },
  };
}

try {
  await harness.listen();
  const conformant = harness.getWorker('mikaki-op-conformance');
  const normal = harness.getWorker('mikaki-op-worker');
  await conformant.applyD1Migrations('DB');
  await normal.applyD1Migrations('DB');
  const env = await conformant.getEnv();
  await activateWorkerPolicy(env.DB, policy, { actor: 'secret-probe', reason: 'conformance test' });
  const discovery = (await (
    await conformant.fetch(`${issuer}/.well-known/openid-configuration`)
  ).json()) as { token_endpoint_auth_methods_supported: string[] };
  assert.deepEqual(discovery.token_endpoint_auth_methods_supported, [
    'private_key_jwt',
    'client_secret_basic',
    'client_secret_post',
  ]);
  const normalDiscovery = (await (
    await normal.fetch(`${issuer}/.well-known/openid-configuration`)
  ).json()) as { token_endpoint_auth_methods_supported: string[] };
  assert.deepEqual(normalDiscovery.token_endpoint_auth_methods_supported, [
    'private_key_jwt',
    'client_secret_basic',
    'none',
  ]);
  const now = Math.floor(Date.now() / 1000);
  await env.DB.batch([
    env.DB.prepare('INSERT INTO account_security(account_id,epoch,active) VALUES(?,1,1)').bind(
      accountId,
    ),
    env.DB.prepare('INSERT INTO credential(credential_id,account_id,active) VALUES(?,?,1)').bind(
      'secret-test-credential',
      accountId,
    ),
    env.DB.prepare(
      "INSERT INTO signing_key(kid,generation,active,algorithm,public_jwk) VALUES(?,1,1,'ES256',?)",
    ).bind('secret-test-op', JSON.stringify(publicJwk)),
    env.DB.prepare(
      'INSERT INTO sso_session(sso_id,account_id,credential_id,epoch,expires_at,revoked) VALUES(?,?,?,1,?,0)',
    ).bind('secret-test-sso', accountId, 'secret-test-credential', now + 900),
    env.DB.prepare('INSERT INTO sso_context(sso_id,secret_hash,auth_time) VALUES(?,?,?)').bind(
      'secret-test-sso',
      createHash('sha256').update(cookie).digest('base64url'),
      now - 30,
    ),
  ]);
  for (const client of clients) {
    await env.DB.batch([
      env.DB.prepare(
        'INSERT INTO client(client_id,revision,active,auth_method,allow_missing_pkce,sector_identifier) VALUES(?,1,1,?,?,?)',
      ).bind(client.id, client.method, client.allowMissingPkce ? 1 : 0, 'https://rp.example'),
      env.DB.prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)').bind(
        client.id,
        redirectUri,
      ),
      env.DB.prepare(
        'INSERT INTO client_secret(client_id,revision,active,secret_hash) VALUES(?,1,1,?)',
      ).bind(client.id, createHash('sha256').update(client.secret).digest('base64url')),
      env.DB.prepare(
        'INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES(?,?,1,1)',
      ).bind(accountId, client.id),
    ]);
  }

  // Exercise the same registration operation operators use, not just seeded rows.
  const managed = {
    id: randomUUID(),
    method: 'client_secret_basic',
    secret: randomBytes(32).toString('base64url'),
  };
  await registerSecretClient(
    env.DB,
    {
      client_id: managed.id,
      sector_identifier: 'rp.example',
      redirect_uris: [redirectUri],
      secret: managed.secret,
    },
    'probe',
    'managed registration',
  );
  await env.DB.prepare(
    "INSERT INTO app_connection(account_id,client_id,grant_version,active,reviewed_redirect_uri,reviewed_scope,reviewed_client_revision,reviewed_grant_version) VALUES(?,?,1,1,?,'openid',1,1)",
  )
    .bind(accountId, managed.id, redirectUri)
    .run();
  const managedCode = await authorize(normal, managed.id);
  assert.equal((await exchange(normal, managed, managedCode)).status, 200);
  await env.DB.batch([
    env.DB.prepare('INSERT INTO account_verified_email VALUES(?,?,1,1,?,1)').bind(
      accountId,
      'owner@example.org',
      now,
    ),
    env.DB.prepare(
      'INSERT INTO client_email_policy(client_id,client_revision,enabled) VALUES(?,1,1)',
    ).bind(managed.id),
    env.DB.prepare(
      "UPDATE app_connection SET reviewed_scope='openid profile email' WHERE account_id=? AND client_id=?",
    ).bind(accountId, managed.id),
  ]);
  const scope = 'email openid profile';
  const noConsent = await exchange(normal, managed, await authorize(normal, managed.id, { scope }));
  assert.equal(noConsent.status, 200, JSON.stringify(noConsent.body));
  assert.equal(
    (await jwtVerify(noConsent.body.id_token!, pair.publicKey, { issuer, audience: managed.id }))
      .payload.email,
    undefined,
  );
  await env.DB.prepare(
    'INSERT INTO account_email_release(account_id,client_id,email_revision,account_epoch,client_revision,grant_version,active) VALUES(?,?,1,1,1,1,1)',
  )
    .bind(accountId, managed.id)
    .run();
  const consent = await exchange(normal, managed, await authorize(normal, managed.id, { scope }));
  assert.equal(consent.status, 200, JSON.stringify(consent.body));
  const claims = (
    await jwtVerify(consent.body.id_token!, pair.publicKey, { issuer, audience: managed.id })
  ).payload;
  assert.equal(claims.email, 'owner@example.org');
  assert.equal(claims.email_verified, true);
  // Run the very same SQL used by the Worker after taking a claim snapshot.
  // Revoke and regrant before commit to force the otherwise hard-to-hit race.
  const commitSql = await readFile(
    new URL('../../../crates/worker/sql/commit-authorization-code.sql', import.meta.url),
    'utf8',
  );
  async function commitFixture() {
    const rawCode = await authorize(normal, managed.id, { scope });
    const codeHash = createHash('sha256')
      .update(Buffer.from(rawCode, 'base64url'))
      .digest('base64url');
    const snapshot = await env.DB.prepare(
      'SELECT ac.sid,v.sub,v.expires_at AS parent_expiry,sx.auth_time,er.email,er.email_revision,er.release_revision FROM authorization_code ac JOIN eligible_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid JOIN client_session cs ON cs.client_id=ac.client_id AND cs.sid=ac.sid JOIN sso_context sx ON sx.sso_id=cs.sso_id JOIN eligible_verified_email_release er ON er.account_id=cs.account_id AND er.client_id=cs.client_id WHERE ac.code_hash=?',
    )
      .bind(codeHash)
      .first();
    assert.ok(snapshot);
    const reservation = randomBytes(32).toString('base64url'),
      operation = randomBytes(32).toString('base64url');
    const current = Math.floor(Date.now() / 1000),
      retained = current + 300;
    await env.DB.prepare(
      "INSERT INTO client_auth_use(accepted_by,client_id,method,endpoint,credential_id,client_revision,credential_revision,retain_until) VALUES(?,?,'client_secret_basic',?,'',1,1,?)",
    )
      .bind(reservation, managed.id, `${issuer}/token`, retained)
      .run();
    const args = [
      codeHash,
      managed.id,
      redirectUri,
      challenge,
      1,
      '',
      1,
      'client_secret_basic',
      `${issuer}/token`,
      reservation,
      retained,
      'secret-test-op',
      1,
      snapshot.sid,
      snapshot.sub,
      null,
      snapshot.auth_time,
      snapshot.parent_expiry,
      operation,
      current + 120,
      current + 120,
      'unused-access-hash',
      JSON.stringify(publicJwk),
      'ES256',
      null,
      null,
      null,
      0,
      'openid profile',
      snapshot.email,
      1,
      snapshot.email_revision,
      snapshot.release_revision,
      null,
      null,
      accountId,
    ];
    return { codeHash, args };
  }
  const control = await commitFixture();
  assert.equal(
    (
      await env.DB.prepare(commitSql)
        .bind(...control.args)
        .run()
    ).meta.changes,
    1,
  );
  const stale = await commitFixture();
  await env.DB.prepare(
    'UPDATE account_email_release SET active=0,revision=revision+1 WHERE account_id=? AND client_id=?',
  )
    .bind(accountId, managed.id)
    .run();
  await env.DB.prepare(
    'UPDATE account_email_release SET active=1,revision=revision+1 WHERE account_id=? AND client_id=?',
  )
    .bind(accountId, managed.id)
    .run();
  assert.equal(
    (
      await env.DB.prepare(commitSql)
        .bind(...stale.args)
        .run()
    ).meta.changes,
    0,
  );
  assert.equal(
    (
      await env.DB.prepare('SELECT consumed_by FROM authorization_code WHERE code_hash=?')
        .bind(stale.codeHash)
        .first()
    ).consumed_by,
    null,
  );
  // Observe the live authorization state inside the same D1 transaction that
  // persists each token. Race a withdrawal against an actual code exchange;
  // an emitted email is valid only if the grant still existed at commit.
  await env.DB.exec(
    "CREATE TABLE email_race_observation(code_hash TEXT PRIMARY KEY,eligible INTEGER NOT NULL); CREATE TRIGGER email_race_observe AFTER INSERT ON token_issue BEGIN INSERT INTO email_race_observation SELECT NEW.code_hash,EXISTS(SELECT 1 FROM eligible_verified_email_release WHERE account_id='secret-test-account' AND client_id='" +
      managed.id +
      "'); END;",
  );
  const raceOutcomes = { withEmail: 0, withoutEmail: 0, rejected: 0 };
  for (let attempt = 0; attempt < 8; attempt++) {
    await env.DB.prepare(
      'UPDATE account_email_release SET active=1,revision=revision+1 WHERE account_id=? AND client_id=?',
    )
      .bind(accountId, managed.id)
      .run();
    const raceCode = await authorize(normal, managed.id, { scope });
    const [exchanged] = await Promise.all([
      exchange(normal, managed, raceCode),
      env.DB.prepare(
        'UPDATE account_email_release SET active=0,revision=revision+1 WHERE account_id=? AND client_id=?',
      )
        .bind(accountId, managed.id)
        .run(),
    ]);
    if (exchanged.status === 200) {
      const raceClaims = (
        await jwtVerify(exchanged.body.id_token!, pair.publicKey, { issuer, audience: managed.id })
      ).payload;
      const record = await env.DB.prepare(
        'SELECT eligible FROM email_race_observation WHERE code_hash=?',
      )
        .bind(createHash('sha256').update(Buffer.from(raceCode, 'base64url')).digest('base64url'))
        .first();
      assert.ok(record);
      if (raceClaims.email !== undefined) {
        raceOutcomes.withEmail++;
        assert.equal(record.eligible, 1);
      } else raceOutcomes.withoutEmail++;
    } else {
      raceOutcomes.rejected++;
      assert.equal(exchanged.body.id_token, undefined);
    }
  }
  console.log('email issuance/withdrawal race outcomes', raceOutcomes);
  await env.DB.exec('DROP TRIGGER email_race_observe; DROP TABLE email_race_observation');
  await env.DB.prepare(
    'UPDATE account_email_release SET active=1,revision=revision+1 WHERE account_id=? AND client_id=?',
  )
    .bind(accountId, managed.id)
    .run();
  await env.DB.prepare(
    "UPDATE app_connection SET reviewed_scope='openid email' WHERE account_id=? AND client_id=?",
  )
    .bind(accountId, managed.id)
    .run();
  const emailOnly = await exchange(
    normal,
    managed,
    await authorize(normal, managed.id, { scope: 'email openid' }),
  );
  assert.equal(emailOnly.status, 200, JSON.stringify(emailOnly.body));
  const fetchUserinfo = () =>
    normal.fetch(`${issuer}/userinfo`, {
      headers: { authorization: `Bearer ${emailOnly.body.access_token}` },
    });
  const info = await fetchUserinfo();
  assert.equal(info.status, 200, await info.clone().text());
  const infoBody = (await info.json()) as { email?: string; email_verified?: boolean };
  assert.equal(infoBody.email, 'owner@example.org');
  assert.equal(infoBody.email_verified, true);
  await env.DB.prepare(
    "UPDATE app_connection SET reviewed_scope='openid' WHERE account_id=? AND client_id=?",
  )
    .bind(accountId, managed.id)
    .run();
  const noEmailScope = await exchange(normal, managed, await authorize(normal, managed.id));
  assert.equal(noEmailScope.status, 200, JSON.stringify(noEmailScope.body));
  assert.equal(
    (await jwtVerify(noEmailScope.body.id_token!, pair.publicKey, { issuer, audience: managed.id }))
      .payload.email,
    undefined,
  );
  await env.DB.prepare(
    "UPDATE app_connection SET reviewed_scope='openid profile email' WHERE account_id=? AND client_id=?",
  )
    .bind(accountId, managed.id)
    .run();
  await env.DB.prepare(
    'UPDATE account_email_release SET active=0,revision=revision+1 WHERE account_id=? AND client_id=?',
  )
    .bind(accountId, managed.id)
    .run();
  const afterRevoke = await fetchUserinfo();
  assert.equal(afterRevoke.status, 200);
  assert.equal(((await afterRevoke.json()) as { email?: string }).email, undefined);
  const withdrawn = await exchange(normal, managed, await authorize(normal, managed.id, { scope }));
  assert.equal(withdrawn.status, 200, JSON.stringify(withdrawn.body));
  assert.equal(
    (await jwtVerify(withdrawn.body.id_token!, pair.publicKey, { issuer, audience: managed.id }))
      .payload.email,
    undefined,
  );
  await env.DB.prepare(
    "UPDATE app_connection SET reviewed_redirect_uri=?, reviewed_scope='openid', reviewed_client_revision=1, reviewed_grant_version=grant_version",
  )
    .bind(redirectUri)
    .run();
  const normalCode = await authorize(normal, clients[1].id);
  assert.equal((await exchange(normal, clients[1], normalCode, { noVerifier: true })).status, 400);
  assert.equal((await exchange(normal, clients[1], normalCode)).status, 200);
  const pendingRotationCode = await authorize(normal, clients[1].id);
  const replacement = randomBytes(32).toString('base64url');
  await rotateSecretClient(
    env.DB,
    clients[1].id,
    { secret: replacement, expected_revision: 1 },
    'probe',
    'rotation',
  );
  assert.equal((await exchange(normal, clients[1], pendingRotationCode)).status, 401);
  assert.equal(
    (await exchange(normal, { ...clients[1], secret: replacement }, pendingRotationCode)).status,
    400,
  );
  await env.DB.prepare('UPDATE app_connection SET reviewed_client_revision=2 WHERE client_id=?')
    .bind(clients[1].id)
    .run();
  const replacementCode = await authorize(normal, clients[1].id);
  assert.equal(
    (await exchange(normal, { ...clients[1], secret: replacement }, replacementCode)).status,
    200,
  );
  clients[1].secret = replacement;
  assert.equal(
    await authorize(normal, clients[0].id, { noPkce: true, expectError: true }),
    'invalid_request',
  );
  const normalReject = await exchange(normal, clients[0], randomBytes(32).toString('base64url'), {
    secret: randomBytes(32).toString('base64url'),
  });
  assert.equal(normalReject.status, 401);
  const normalPostReject = await exchange(
    normal,
    clients[2],
    randomBytes(32).toString('base64url'),
  );
  assert.equal(normalPostReject.status, 400);
  for (const client of clients) {
    const code = await authorize(conformant, client.id);
    const swappedMethod = await exchange(
      conformant,
      {
        ...client,
        method:
          client.method === 'client_secret_basic' ? 'client_secret_post' : 'client_secret_basic',
      },
      code,
    );
    assert.equal(swappedMethod.status, 401);
    const wrong = await exchange(conformant, client, code, {
      secret: randomBytes(32).toString('base64url'),
    });
    assert.equal(wrong.status, 401);
    if (client.method === 'client_secret_basic') {
      assert.equal(wrong.challenge, 'Basic realm="mikaki-token"');
    }
    if (client.method === 'client_secret_basic') {
      const mixed = await exchange(conformant, client, code, { mixed: true });
      assert.equal(mixed.status, 400);
    }
    const valid = await exchange(conformant, client, code);
    assert.equal(valid.status, 200, JSON.stringify(valid.body));
    assert.ok(valid.body.id_token);
    const verified = await jwtVerify(valid.body.id_token, pair.publicKey, {
      issuer,
      audience: client.id,
    });
    assert.ok(verified.payload.sub);
    const replay = await exchange(conformant, client, code);
    assert.equal(replay.status, 400);
    assert.equal(replay.body.error, 'invalid_grant');
  }
  assert.equal(
    await authorize(conformant, clients[1].id, { noPkce: true, expectError: true }),
    'invalid_request',
  );
  const noPkceCode = await authorize(conformant, clients[0].id, { noPkce: true });
  const injectedVerifier = await exchange(conformant, clients[0], noPkceCode);
  assert.equal(injectedVerifier.status, 400);
  assert.equal(injectedVerifier.body.error, 'invalid_grant');
  const noPkceExchange = await exchange(conformant, clients[0], noPkceCode, { noVerifier: true });
  assert.equal(noPkceExchange.status, 200, JSON.stringify(noPkceExchange.body));
  const challengedCode = await authorize(conformant, clients[0].id);
  const missingVerifier = await exchange(conformant, clients[0], challengedCode, {
    noVerifier: true,
  });
  assert.equal(missingVerifier.status, 400);
  assert.equal(missingVerifier.body.error, 'invalid_grant');
  assert.equal((await exchange(conformant, clients[0], challengedCode)).status, 200);
  const basicCode = await authorize(conformant, clients[0].id);
  const wrongClient = await exchange(conformant, clients[1], basicCode);
  assert.equal(wrongClient.status, 400);
  assert.equal(wrongClient.body.error, 'invalid_grant');
  await assert.rejects(
    env.DB.prepare('UPDATE client_secret SET secret_hash=? WHERE client_id=?')
      .bind(createHash('sha256').update('replacement').digest('base64url'), clients[0].id)
      .run(),
  );
  await env.DB.prepare('UPDATE client_secret_attempt SET attempts=? WHERE client_id=?')
    .bind(policy.token_attempts_per_client, clients[0].id)
    .run();
  const limited = await exchange(
    conformant,
    clients[0],
    await authorize(conformant, clients[0].id),
  );
  assert.equal(limited.status, 401);
  console.log(
    'mikaki-worker: opt-in normal Basic with PKCE and conformance secret authentication passed',
  );
} finally {
  await harness.close();
}

const disabledHarness = createTestHarness({
  root,
  workers: [{ configPath: normalConfig, vars: { MIKAKI_ISSUER: issuer } }],
});
try {
  await disabledHarness.listen();
  const worker = disabledHarness.getWorker('mikaki-op-worker');
  const discovery = (await (
    await worker.fetch(`${issuer}/.well-known/openid-configuration`)
  ).json()) as {
    token_endpoint_auth_methods_supported: string[];
  };
  assert.deepEqual(discovery.token_endpoint_auth_methods_supported, ['private_key_jwt', 'none']);
} finally {
  await disabledHarness.close();
}
