import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createTestHarness } from 'wrangler';
import { exportJWK, generateKeyPair, jwtVerify } from 'jose';
import { activateWorkerPolicy } from '../../../scripts/worker-policy-store.ts';

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
      vars: { MIKAKI_ISSUER: issuer },
      secrets: { OP_PRIVATE_JWK: JSON.stringify(privateJwk) },
    },
  ],
});
type ProbeWorker = Pick<ReturnType<typeof harness.getWorker>, 'fetch'>;

async function authorize(
  worker: ProbeWorker,
  clientId: string,
  options: { noPkce?: boolean; expectError?: boolean } = {},
) {
  const target = new URL('/authorize', issuer);
  target.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid',
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
  assert.ok(result);
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
    body: (await response.json()) as { id_token?: string; error?: string },
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
  assert.deepEqual(normalDiscovery.token_endpoint_auth_methods_supported, ['private_key_jwt']);
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

  const normalReject = await exchange(normal, clients[0], randomBytes(32).toString('base64url'));
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
    'mikaki-worker: isolated client_secret_basic/post, normal rejection, mixed-method rejection, code binding and replay passed',
  );
} finally {
  await harness.close();
}
