import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { readFile, writeFile } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { createTestHarness } from 'wrangler';
import { exportJWK, generateKeyPair } from 'jose';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const issuer = 'https://host.docker.internal:8792';
const alias = 'mikaki-local-20260923';
const redirectUri = `https://suite-frontend:8443/test/a/${alias}/callback`;
const pair = await generateKeyPair('ES256', { extractable: true });
const privateJwk = {
  ...(await exportJWK(pair.privateKey)),
  kid: 'mikaki-oidf-local',
  alg: 'ES256',
  use: 'sig',
};
const publicJwk = {
  ...(await exportJWK(pair.publicKey)),
  kid: 'mikaki-oidf-local',
  alg: 'ES256',
  use: 'sig',
};
const harness = createTestHarness({
  root: new URL('../..', import.meta.url).pathname,
  workers: [
    {
      configPath: new URL('../../crates/worker/wrangler.conformance.jsonc', import.meta.url)
        .pathname,
      vars: { MIKAKI_ISSUER: issuer },
      secrets: { OP_PRIVATE_JWK: JSON.stringify(privateJwk) },
    },
  ],
});
let server;
try {
  await harness.listen();
  const worker = harness.getWorker('mikaki-op-conformance');
  await worker.applyD1Migrations('DB');
  const env = await worker.getEnv();
  const policy = JSON.parse(
    await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
  );
  await activateWorkerPolicy(env.DB, policy, {
    actor: 'oidf-local',
    reason: 'local conformance run',
  });
  await env.DB.prepare(
    "INSERT INTO signing_key(kid,generation,active,algorithm,public_jwk) VALUES(?,1,1,'ES256',?)",
  )
    .bind('mikaki-oidf-local', JSON.stringify(publicJwk))
    .run();
  const passkeyPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const passkeyPublic = passkeyPair.publicKey.export({ format: 'jwk' });
  const passkeyId = randomBytes(32).toString('base64url');
  const userHandle = randomBytes(32).toString('base64url');
  const coseKey = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    Buffer.from(passkeyPublic.x, 'base64url'),
    Buffer.from([0x22, 0x58, 0x20]),
    Buffer.from(passkeyPublic.y, 'base64url'),
  ]).toString('base64url');
  await env.DB.batch([
    env.DB.prepare('INSERT INTO account_security(account_id,epoch,active) VALUES(?,1,1)').bind(
      'oidf-passkey-account',
    ),
    env.DB.prepare('INSERT INTO credential(credential_id,account_id,active) VALUES(?,?,1)').bind(
      passkeyId,
      'oidf-passkey-account',
    ),
    env.DB.prepare(
      'INSERT INTO passkey_credential(credential_id,public_key,user_handle,counter,backup_eligible,backup_state,revision) VALUES(?,?,?,0,0,0,1)',
    ).bind(passkeyId, coseKey, userHandle),
  ]);
  await writeFile(
    new URL('../generated/oidf-passkey.json', import.meta.url),
    JSON.stringify({
      credentialId: Buffer.from(passkeyId, 'base64url').toString('base64'),
      userHandle: Buffer.from(userHandle, 'base64url').toString('base64'),
      privateKey: passkeyPair.privateKey
        .export({ format: 'der', type: 'pkcs8' })
        .toString('base64'),
      rpId: 'host.docker.internal',
    }),
    { mode: 0o600 },
  );
  const clients = [
    ['basic-one', 'client_secret_basic'],
    ['basic-two', 'client_secret_basic'],
    ['post-one', 'client_secret_post'],
  ];
  const config = {
    alias,
    description: 'mikaki local OIDC conformance probe',
    server: { discoveryUrl: `${issuer}/.well-known/openid-configuration` },
  };
  for (const [index, [id, method]] of clients.entries()) {
    const secret = randomBytes(32).toString('base64url');
    const clientId = `mikaki-${id}`;
    const hash = createHash('sha256').update(secret).digest('base64url');
    await env.DB.batch([
      env.DB.prepare(
        'INSERT INTO client(client_id,revision,active,auth_method,allow_missing_pkce,sector_identifier) VALUES(?,1,1,?,1,?)',
      ).bind(clientId, method, 'https://suite-frontend:8443'),
      env.DB.prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)').bind(
        clientId,
        redirectUri,
      ),
      env.DB.prepare(
        'INSERT INTO client_secret(client_id,revision,active,secret_hash) VALUES(?,1,1,?)',
      ).bind(clientId, hash),
    ]);
    const key = ['client', 'client2', 'client_secret_post'][index];
    config[key] = { client_id: clientId, client_secret: secret, client_name: clientId };
  }
  const authorizeUrl = new URL('/authorize', issuer);
  authorizeUrl.search = new URLSearchParams({
    client_id: 'mikaki-basic-one',
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid',
    state: 'passkey-preflight',
  }).toString();
  const pending = await worker.fetch(authorizeUrl, { redirect: 'manual' });
  assert.equal(pending.status, 302);
  const browserCookie = pending.headers.get('set-cookie').split(';')[0];
  const loginUrl = new URL(pending.headers.get('location'));
  assert.equal(loginUrl.pathname, '/login');
  const loginPage = await worker.fetch(loginUrl, {
    headers: { cookie: browserCookie, 'Accept-Language': 'en-US,en;q=0.9' },
  });
  assert.equal(loginPage.status, 200);
  const loginHtml = await loginPage.text();
  assert.match(loginHtml, /<html lang="en">/);
  assert.match(loginHtml, /id="app" data-tx="[A-Za-z0-9_-]{43}"/);
  assert.match(loginHtml, /data-client="mikaki-basic-one"/);
  assert.match(loginHtml, /src="\/login\/login\.js"/);
  const loginScript = await worker.fetch(new URL('/login/login.js', issuer));
  assert.equal(loginScript.status, 200);
  assert.match(await loginScript.text(), /Allow and sign in with passkey/);
  const tx = loginUrl.searchParams.get('tx');
  const row = await env.DB.prepare('SELECT challenge FROM login_transaction WHERE tx_id=?')
    .bind(tx)
    .first();
  const clientData = Buffer.from(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: row.challenge,
      origin: issuer,
      crossOrigin: false,
    }),
  );
  const authenticatorData = Buffer.concat([
    createHash('sha256').update('host.docker.internal').digest(),
    Buffer.from([0x05, 0, 0, 0, 1]),
  ]);
  const signed = Buffer.concat([
    authenticatorData,
    createHash('sha256').update(clientData).digest(),
  ]);
  const assertion = {
    id: passkeyId,
    client_data: clientData.toString('base64url'),
    authenticator_data: authenticatorData.toString('base64url'),
    signature: sign('sha256', signed, passkeyPair.privateKey).toString('base64url'),
    user_handle: userHandle,
  };
  const completed = await worker.fetch(`${issuer}/login/finish`, {
    method: 'POST',
    headers: { cookie: browserCookie, origin: issuer, 'content-type': 'application/json' },
    body: JSON.stringify({ tx, consent: true, response: assertion }),
  });
  assert.equal(completed.status, 200, await completed.text());
  assert.match(
    completed.headers.get('set-cookie'),
    new RegExp(`Max-Age=${policy.sso_absolute_ttl_seconds}(?:;|$)`),
  );
  const replay = await worker.fetch(`${issuer}/login/finish`, {
    method: 'POST',
    headers: { cookie: browserCookie, origin: issuer, 'content-type': 'application/json' },
    body: JSON.stringify({ tx, consent: true, response: assertion }),
  });
  assert.equal(replay.status, 400);
  const ssoCookie = completed.headers.get('set-cookie').split(';')[0];
  const resumed = await worker.fetch(authorizeUrl, {
    headers: { cookie: ssoCookie },
    redirect: 'manual',
  });
  assert.equal(resumed.status, 302);
  assert.ok(new URL(resumed.headers.get('location')).searchParams.get('code'));
  console.log('passkey authorization preflight passed');
  if (process.env.MIKAKI_PREFLIGHT_ONLY === '1') {
    await harness.close();
    process.exit(0);
  }
  await writeFile(
    new URL('../generated/oidf-local-config.json', import.meta.url),
    JSON.stringify(config, null, 2),
    { mode: 0o600 },
  );
  server = createServer(
    {
      key: await readFile(new URL('../generated/oidf-local.key', import.meta.url)),
      cert: await readFile(new URL('../generated/oidf-local.crt', import.meta.url)),
    },
    async (incoming, outgoing) => {
      try {
        if (incoming.headers.host !== 'host.docker.internal:8792') {
          outgoing.writeHead(403).end();
          return;
        }
        const response = await worker.fetch(new URL(incoming.url, issuer), {
          method: incoming.method,
          headers: Object.fromEntries(
            Object.entries(incoming.headers).map(([name, value]) => [
              name,
              Array.isArray(value) ? value.join(', ') : (value ?? ''),
            ]),
          ),
          redirect: 'manual',
          ...(!['GET', 'HEAD'].includes(incoming.method)
            ? { body: Readable.toWeb(incoming), duplex: 'half' }
            : {}),
        });
        outgoing.writeHead(response.status, Object.fromEntries(response.headers));
        if (response.body) Readable.fromWeb(response.body).pipe(outgoing);
        else outgoing.end();
      } catch (error) {
        console.error('worker relay error', error);
        outgoing.writeHead(500).end();
      }
    },
  );
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(8792, '0.0.0.0', resolve);
  });
  console.log(`mikaki local conformance worker listening at ${issuer}`);
  const shutdown = async () => {
    await new Promise((resolve) => server.close(resolve));
    await harness.close();
  };
  process.on('SIGINT', () => {
    void shutdown().then(() => process.exit(0));
  });
  process.on('SIGTERM', () => {
    void shutdown().then(() => process.exit(0));
  });
} catch (error) {
  console.error(error);
  if (server) server.close();
  await harness.close();
  process.exitCode = 1;
}
