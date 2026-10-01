import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { readFile, writeFile } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { createTestHarness } from 'wrangler';
import { exportJWK, generateKeyPair } from 'jose';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

function requiredHeader(
  response: { headers: { get(name: string): string | null } },
  name: string,
): string {
  const value = response.headers.get(name);
  assert.ok(value, `${name} header is required`);
  return value;
}

const issuer = 'https://host.docker.internal:8792';
const fapi = process.env.MIKAKI_OIDF_PROFILE === 'fapi2';
const alias = `mikaki-local-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`;
const redirectUri = `https://suite-frontend:8443/test/a/${alias}/callback`;
const postLogoutRedirectUri = `https://suite-frontend:8443/test/a/${alias}/post_logout_redirect`;
const backchannelOrigin =
  process.env.MIKAKI_BACKCHANNEL_TEST_ORIGIN ?? 'https://suite-frontend:8443';
const backchannelLogoutUri = `${backchannelOrigin}/test/a/${alias}/backchannel_logout`;
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
      vars: { MIKAKI_ISSUER: issuer, ...(fapi ? { MIKAKI_DEPLOYMENT_PROFILE: 'fapi2' } : {}) },
      secrets: { OP_PRIVATE_JWK: JSON.stringify(privateJwk) },
    },
  ],
});
let server: ReturnType<typeof createServer> | undefined;
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
  assert.ok(passkeyPublic.x && passkeyPublic.y);
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
  const config: Record<string, unknown> = {
    alias,
    description: fapi ? 'mikaki local FAPI2 Final AS probe' : 'mikaki local OIDC conformance probe',
    server: { discoveryUrl: `${issuer}/.well-known/openid-configuration` },
    ...(fapi
      ? {
          resource: {
            resourceUrl: `${issuer}/userinfo`,
            resourceMethod: 'GET',
            resourceMediaType: 'application/json',
          },
        }
      : {}),
  };
  if (fapi) {
    for (const [index, clientKey] of ['client', 'client2'].entries()) {
      const registered = await generateKeyPair('ES256', { extractable: true });
      const kid = `fapi-client-${index + 1}`;
      const privateKey = {
        ...(await exportJWK(registered.privateKey)),
        kid,
        alg: 'ES256',
        use: 'sig',
      };
      const publicKey = await exportJWK(registered.publicKey);
      assert.ok(publicKey.x && publicKey.y);
      const clientId = `mikaki-fapi-${index + 1}`;
      await env.DB.batch([
        env.DB.prepare(
          "INSERT INTO client(client_id,revision,active,auth_method,sector_identifier) VALUES(?,1,1,'private_key_jwt',?)",
        ).bind(clientId, 'https://suite-frontend:8443'),
        env.DB.prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)').bind(
          clientId,
          index === 0 ? redirectUri : `${redirectUri}?dummy1=lorem&dummy2=ipsum`,
        ),
        env.DB.prepare(
          "INSERT INTO client_key(client_id,kid,revision,active,algorithm,public_key_sec1) VALUES(?,?,1,1,'ES256',?)",
        ).bind(
          clientId,
          kid,
          Buffer.concat([
            Buffer.from([4]),
            Buffer.from(publicKey.x, 'base64url'),
            Buffer.from(publicKey.y, 'base64url'),
          ]),
        ),
      ]);
      config[clientKey] = {
        client_id: clientId,
        scope: 'openid profile',
        dpop_signing_alg: 'ES256',
        jwks: { keys: [privateKey] },
      };
    }
  } else
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
          'INSERT INTO client_post_logout_redirect_uri(client_id,redirect_uri,active) VALUES(?,?,1)',
        ).bind(clientId, postLogoutRedirectUri),
        env.DB.prepare(
          'INSERT INTO client_backchannel_logout_uri(client_id,logout_uri,active) VALUES(?,?,1)',
        ).bind(clientId, backchannelLogoutUri),
        env.DB.prepare(
          'INSERT INTO client_secret(client_id,revision,active,secret_hash) VALUES(?,1,1,?)',
        ).bind(clientId, hash),
      ]);
      const key = ['client', 'client2', 'client_secret_post'][index];
      config[key] = {
        client_id: clientId,
        client_secret: secret,
        client_name: clientId,
        post_logout_redirect_uris: [postLogoutRedirectUri],
        backchannel_logout_uri: backchannelLogoutUri,
        backchannel_logout_session_required: true,
      };
    }
  if (!fapi) {
    const home = await worker.fetch(new URL('/', issuer));
    assert.equal(home.status, 200);
    assert.equal(home.headers.get('cache-control'), 'no-store');
    const homeHtml = await home.text();
    assert.match(homeHtml, /<html lang="ja">/);
    assert.match(homeHtml, /href="\/enroll\?lang=ja"/);
    assert.match(homeHtml, /サインインはアプリから/);
    const englishHome = await worker.fetch(new URL('/?lang=en', issuer));
    assert.equal(englishHome.status, 200);
    const englishHomeHtml = await englishHome.text();
    assert.match(englishHomeHtml, /Sign in from your app/);
    assert.match(englishHomeHtml, /href="\/enroll\?lang=en"/);
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
    const browserCookie = requiredHeader(pending, 'set-cookie').split(';')[0];
    const loginUrl = new URL(requiredHeader(pending, 'location'));
    assert.equal(loginUrl.pathname, '/login');
    const loginPage = await worker.fetch(loginUrl, {
      headers: { cookie: browserCookie, 'Accept-Language': 'en-US,en;q=0.9' },
    });
    assert.equal(loginPage.status, 200);
    const loginHtml = await loginPage.text();
    assert.match(loginHtml, /<html lang="en">/);
    assert.match(loginHtml, /id="app" data-tx="[A-Za-z0-9_-]{43}"/);
    assert.match(loginHtml, /data-client="mikaki-basic-one"/);
    assert.ok(loginHtml.includes(`data-rp-uri="${redirectUri}"`));
    assert.match(loginHtml, /src="\/login\/login\.js"/);
    const loginScript = await worker.fetch(new URL('/login/login.js', issuer));
    assert.equal(loginScript.status, 200);
    assert.match(await loginScript.text(), /Sign in with passkey/);
    const tx = loginUrl.searchParams.get('tx');
    const cueUrl = new URL(`/login/cue?tx=${tx}`, issuer);
    const cue = await worker.fetch(cueUrl, { headers: { cookie: browserCookie } });
    assert.equal(cue.status, 200);
    assert.equal(cue.headers.get('cache-control'), 'no-store');
    assert.equal(cue.headers.get('cross-origin-resource-policy'), 'same-origin');
    const cueBody: unknown = await cue.json();
    assert.ok(
      typeof cueBody === 'object' &&
        cueBody !== null &&
        'seed' in cueBody &&
        typeof cueBody.seed === 'string' &&
        'refresh_in_ms' in cueBody &&
        typeof cueBody.refresh_in_ms === 'number',
    );
    assert.match(cueBody.seed, /^[A-Za-z0-9_-]{43}$/);
    assert.ok(cueBody.refresh_in_ms >= 1_000 && cueBody.refresh_in_ms <= 21_000);
    assert.equal((await worker.fetch(cueUrl)).status, 400);
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
      requiredHeader(completed, 'set-cookie'),
      new RegExp(`Max-Age=${policy.sso_absolute_ttl_seconds}(?:;|$)`),
    );
    const replay = await worker.fetch(`${issuer}/login/finish`, {
      method: 'POST',
      headers: { cookie: browserCookie, origin: issuer, 'content-type': 'application/json' },
      body: JSON.stringify({ tx, consent: true, response: assertion }),
    });
    assert.equal(replay.status, 400);
    const ssoCookie = requiredHeader(completed, 'set-cookie').split(';')[0];
    const resumed = await worker.fetch(authorizeUrl, {
      headers: { cookie: ssoCookie },
      redirect: 'manual',
    });
    assert.equal(resumed.status, 302);
    assert.ok(new URL(requiredHeader(resumed, 'location')).searchParams.get('code'));
    console.log('passkey authorization preflight passed');
  } else {
    const discovery = await worker.fetch(`${issuer}/.well-known/openid-configuration`);
    assert.equal(discovery.status, 200);
    assert.equal(
      ((await discovery.json()) as { require_pushed_authorization_requests: boolean })
        .require_pushed_authorization_requests,
      true,
    );
    console.log('FAPI2 PAR discovery preflight passed');
  }
  if (process.env.MIKAKI_PREFLIGHT_ONLY === '1') {
    await harness.close();
    process.exit(0);
  }
  await writeFile(
    new URL('../generated/oidf-local-config.json', import.meta.url),
    JSON.stringify(config, null, 2),
    { mode: 0o600 },
  );
  const relayServer = createServer(
    {
      key: await readFile(new URL('../generated/oidf-local.key', import.meta.url)),
      cert: await readFile(new URL('../generated/oidf-local.crt', import.meta.url)),
      ...(fapi
        ? {
            minVersion: 'TLSv1.2' as const,
            ciphers:
              'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384',
          }
        : {}),
    },
    async (incoming, outgoing) => {
      try {
        if (incoming.headers.host !== 'host.docker.internal:8792') {
          outgoing.writeHead(403).end();
          return;
        }
        const response = await worker.fetch(new URL(incoming.url ?? '/', issuer), {
          method: incoming.method,
          headers: Object.fromEntries(
            Object.entries(incoming.headers).map(([name, value]) => [
              name,
              Array.isArray(value) ? value.join(', ') : (value ?? ''),
            ]),
          ),
          redirect: 'manual',
          ...(!['GET', 'HEAD'].includes(incoming.method ?? 'GET')
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
  server = relayServer;
  await new Promise<void>((resolve, reject) => {
    relayServer.once('error', reject);
    relayServer.listen(8792, '0.0.0.0', resolve);
  });
  console.log(`mikaki local conformance worker listening at ${issuer}`);
  const shutdown = async () => {
    await new Promise<void>((resolve, reject) =>
      relayServer.close((error) => (error ? reject(error) : resolve())),
    );
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
