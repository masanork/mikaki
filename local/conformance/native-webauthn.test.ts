import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const issuer = 'https://mikaki.test';
const fingerprint = Array(32).fill('AB').join(':');
const androidOrigin = `android:apk-key-hash:${Buffer.alloc(32, 0xab).toString('base64url')}`;
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();
const opaque = () => randomBytes(32).toString('base64url');

test('WebView app origins require the pinned signing key and preserve signed challenge, RP, UV and replay checks', async () => {
  const configPath = new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname;
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  config.assets.directory = new URL('../../assets', import.meta.url).pathname;
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.queues.consumers = [];
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        config: {
          ...config,
          vars: {
            MIKAKI_ISSUER: issuer,
            MIKAKI_ANDROID_SHA256_CERT_FINGERPRINT: fingerprint,
            MIKAKI_APPLE_TEAM_ID: 'ABCDEFGHIJ',
          },
        },
      },
      { config: { ...config, name: 'unpinned', vars: { MIKAKI_ISSUER: issuer } } },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    const unpinned = harness.getWorker('unpinned');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'native-passkey-test', reason: 'APK origin qualification' },
    );
    for (const [host, relations] of [
      [
        issuer,
        [
          'delegate_permission/common.handle_all_urls',
          'delegate_permission/common.get_login_creds',
        ],
      ],
      ['https://app.mikaki.org', ['delegate_permission/common.handle_all_urls']],
    ]) {
      const response = await worker.fetch(`${host}/.well-known/assetlinks.json`);
      assert.equal(response.status, 200);
      assert.match(response.headers.get('content-type')!, /application\/json/);
      assert.deepEqual(await response.json(), [
        {
          relation: relations,
          target: {
            namespace: 'android_app',
            package_name: 'app.tossa.mikaki',
            sha256_cert_fingerprints: [fingerprint],
          },
        },
      ]);
      assert.equal(response.headers.get('set-cookie'), null);
    }
    assert.deepEqual(
      await (await worker.fetch(`${issuer}/.well-known/apple-app-site-association`)).json(),
      {
        webcredentials: {
          apps: ['ABCDEFGHIJ.app.tossa.mikaki', 'ABCDEFGHIJ.app.tossa.mikaki.dev'],
        },
      },
    );
    assert.equal((await unpinned.fetch(`${issuer}/.well-known/assetlinks.json`)).status, 404);
    assert.equal(
      (await unpinned.fetch(`${issuer}/.well-known/apple-app-site-association`)).status,
      404,
    );
    assert.equal((await worker.fetch('https://evil.test/.well-known/assetlinks.json')).status, 404);
    assert.equal((await worker.fetch('https://app.mikaki.org/authorize')).status, 404);

    const secret = opaque(),
      sourceId = opaque(),
      userHandle = opaque();
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(sourceId),
      DB.prepare("INSERT INTO passkey_credential VALUES(?,'synthetic-public-key',?,0,0,0,1)").bind(
        sourceId,
        userHandle,
      ),
      DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(
        sourceId,
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
        hash(secret).toString('base64url'),
        now,
      ),
    ]);
    const headers = {
      Cookie: `__Host-op-sso=${secret}`,
      Origin: issuer,
      'Content-Type': 'application/json',
    };
    const registrationStart = await worker.fetch(`${issuer}/vault/passkeys/start`, {
      method: 'POST',
      headers,
    });
    assert.equal(registrationStart.status, 200);
    const options = (await registrationStart.json()) as {
      transaction_id: string;
      challenge: string;
    };
    const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = key.publicKey.export({ format: 'jwk' });
    const cose = Buffer.concat([
      Buffer.from('a5010203262001215820', 'hex'),
      Buffer.from(jwk.x!, 'base64url'),
      Buffer.from('225820', 'hex'),
      Buffer.from(jwk.y!, 'base64url'),
    ]);
    const credentialId = randomBytes(32);
    const auth = Buffer.concat([
      hash('mikaki.test'),
      Buffer.from('4500000000', 'hex'),
      Buffer.alloc(16),
      Buffer.from([0, credentialId.length]),
      credentialId,
      cose,
    ]);
    const registration = {
      id: credentialId.toString('base64url'),
      client_data: Buffer.from(
        JSON.stringify({
          type: 'webauthn.create',
          challenge: options.challenge,
          origin: androidOrigin,
        }),
      ).toString('base64url'),
      attestation: Buffer.concat([
        Buffer.from('a363666d74646e6f6e656761747453746d74a068617574684461746158', 'hex'),
        Buffer.from([auth.length]),
        auth,
      ]).toString('base64url'),
    };
    const registrationBody = JSON.stringify({
      transaction_id: options.transaction_id,
      response: registration,
    });
    assert.equal(
      (
        await unpinned.fetch(`${issuer}/vault/passkeys/finish`, {
          method: 'POST',
          headers,
          body: registrationBody,
        })
      ).status,
      401,
    );
    assert.equal(
      (
        await worker.fetch(`${issuer}/vault/passkeys/finish`, {
          method: 'POST',
          headers,
          body: registrationBody,
        })
      ).status,
      200,
    );

    let counter = 0;
    const login = async (
      patch: {
        origin?: string;
        challenge?: string;
        rpId?: string;
        flags?: number;
        badSignature?: boolean;
      } = {},
      target = worker,
    ) => {
      const started = await target.fetch(`${issuer}/signin`, { redirect: 'manual' });
      assert.equal(started.status, 302);
      const tx = new URL(started.headers.get('location')!).searchParams.get('tx')!;
      const cookie = started.headers.get('set-cookie')!.split(';')[0];
      const row = (await DB.prepare('SELECT challenge FROM web_login_transaction WHERE tx_id=?')
        .bind(tx)
        .first()) as { challenge: string };
      const client = Buffer.from(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: patch.challenge ?? row.challenge,
          origin: patch.origin ?? androidOrigin,
        }),
      );
      const authenticatorData = Buffer.alloc(37);
      hash(patch.rpId ?? 'mikaki.test').copy(authenticatorData);
      authenticatorData[32] = patch.flags ?? 5;
      authenticatorData.writeUInt32BE(++counter, 33);
      const signed = sign(
        'sha256',
        Buffer.concat([authenticatorData, hash(client)]),
        key.privateKey,
      );
      if (patch.badSignature) signed[signed.length - 1] ^= 1;
      const body = JSON.stringify({
        tx,
        consent: true,
        response: {
          id: registration.id,
          client_data: client.toString('base64url'),
          authenticator_data: authenticatorData.toString('base64url'),
          signature: signed.toString('base64url'),
          user_handle: userHandle,
        },
      });
      const finish = () =>
        target.fetch(`${issuer}/login/finish`, {
          method: 'POST',
          headers: { Origin: issuer, Cookie: cookie, 'Content-Type': 'application/json' },
          body,
        });
      return { response: await finish(), finish };
    };
    for (const patch of [
      { origin: 'https://evil.test' },
      { origin: `android:apk-key-hash:${Buffer.alloc(32, 0xcd).toString('base64url')}` },
      { challenge: opaque() },
      { rpId: 'evil.test' },
      { flags: 1 },
      { badSignature: true },
    ]) {
      assert.equal((await login(patch)).response.status, 401, JSON.stringify(patch));
    }
    assert.equal((await login({}, unpinned)).response.status, 401);
    const accepted = await login();
    assert.equal(accepted.response.status, 200, await accepted.response.clone().text());
    assert.equal((await accepted.finish()).status, 400, 'successful ceremonies remain single-use');
    assert.equal(
      (await login({ origin: issuer })).response.status,
      200,
      'browser-origin passkeys still work',
    );
  } finally {
    await harness.close();
  }
});
