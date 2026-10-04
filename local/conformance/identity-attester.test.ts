import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { exportJWK, generateKeyPair, SignJWT, jwtVerify } from 'jose';
import { androidAttestationFixture, fixtureKey } from './support/android-attestation-fixture.ts';
const root = 'https://issuer.example';
const audience = `${root}/identity/attester`;
const client = 'native-fixture';
const secret = () => randomBytes(32).toString('base64url');
const hash = (s: string) => createHash('sha256').update(s).digest('base64url');
test('native attester broker binds one-use challenges, PoP, trusted service verdicts and nonce-bound holder JWTs in workerd', async () => {
  const cert = async (name: string) =>
    (
      await readFile(
        new URL(`../../crates/identity/tests/fixtures/trust/${name}.der`, import.meta.url),
      )
    ).toString('base64');
  const chain = await Promise.all(['attester', 'intermediate'].map(cert));
  const anchor = await cert('root');
  const signing = {
    jwk: JSON.stringify({ ...fixtureKey(5), kid: 'attester' }),
    chain,
    trust_anchors: [anchor],
  };
  const policy = hash('fixture-verifier-policy');
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations/',
    import.meta.url,
  ).pathname;
  config.vars = {
    MIKAKI_ISSUER: root,
    IDENTITY_ENABLED: 'true',
    IDENTITY_WALLET_ENABLED: 'true',
    IDENTITY_HAIP_ENABLED: 'true',
    IDENTITY_ATTESTER_ENABLED: 'true',
    IDENTITY_ISSUER_JWK: JSON.stringify({ ...fixtureKey(4), kid: 'credential' }),
    IDENTITY_ATTESTER_SIGNING: JSON.stringify(signing),
    IDENTITY_ATTESTER_CLIENTS: JSON.stringify([
      { client_id: client, verifier_policy_hash: policy },
    ]),
  };
  config.ratelimits = [
    { name: 'IDENTITY_RATE_LIMIT', namespace_id: '1030', simple: { limit: 1000, period: 60 } },
  ];
  config.services = [{ binding: 'IDENTITY_ANDROID_VERIFIER', service: 'android-verifier-good' }];
  const modes = [
    'good',
    'reject',
    'key',
    'challenge',
    'client',
    'purpose',
    'policy',
    'expired',
    'oversized',
    'redirect',
    'timeout',
  ];
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      { config },
      ...modes
        .filter((m) => m !== 'good')
        .map((mode) => ({
          config: {
            ...config,
            name: `attester-${mode}`,
            services: [
              { binding: 'IDENTITY_ANDROID_VERIFIER', service: `android-verifier-${mode}` },
            ],
          },
        })),
      {
        config: {
          ...config,
          name: 'attester-disabled',
          vars: { ...config.vars, IDENTITY_ATTESTER_ENABLED: 'false' },
        },
      },
      { config: { ...config, name: 'attester-missing-verifier', services: [] } },
      {
        config: {
          ...config,
          name: 'attester-role-collision',
          vars: {
            ...config.vars,
            IDENTITY_ATTESTER_SIGNING: JSON.stringify({
              ...signing,
              jwk: config.vars.IDENTITY_ISSUER_JWK,
            }),
          },
        },
      },
      {
        config: {
          ...config,
          name: 'attester-policy-changed',
          vars: {
            ...config.vars,
            IDENTITY_ATTESTER_CLIENTS: JSON.stringify([
              { client_id: client, verifier_policy_hash: hash('other-policy') },
            ]),
          },
        },
      },
      ...modes.map((mode) => ({
        config: {
          name: `android-verifier-${mode}`,
          main: new URL('./support/android-verifier-fixture.mjs', import.meta.url).pathname,
          compatibility_date: '2026-10-02',
          compatibility_flags: ['nodejs_compat'],
          vars: { FIXTURE_ROOT: anchor, FIXTURE_POLICY_HASH: policy, FIXTURE_MODE: mode },
        },
      })),
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const instance = await generateKeyPair('ES256', { extractable: true });
    const holder = await generateKeyPair('ES256', { extractable: true });
    const publicKey = await exportJWK(instance.publicKey);
    const holderPublic = await exportJWK(holder.publicKey);
    const request = (
      target: Pick<typeof worker, 'fetch'>,
      path: string,
      body: unknown,
      headers = {},
    ) =>
      target.fetch(`${audience}/${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
      });
    const challenge = async (purpose = 'client', headers = {}, c_nonce?: string) => {
      const response = await request(
        worker,
        'challenge',
        { client_id: client, purpose, ...(c_nonce ? { c_nonce } : {}) },
        headers,
      );
      assert.equal(response.status, 200, await response.clone().text());
      return ((await response.json()) as any).challenge as string;
    };
    const proof = async (challenge: string, purpose: string, pair = instance, patch = {}) => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: client,
        aud: audience,
        nonce: challenge,
        purpose,
        iat: now,
        exp: now + 60,
        ...patch,
      })
        .setProtectedHeader({
          typ: 'mikaki-wallet-attester-proof+jwt',
          alg: 'ES256',
          jwk: await exportJWK(pair.publicKey),
        })
        .sign(pair.privateKey);
    };
    const enrollment = async (
      challenge: string,
      purpose = 'client',
      pair = instance,
      c_nonce?: string,
    ) => ({
      client_id: client,
      purpose,
      challenge,
      public_key: await exportJWK(pair.publicKey),
      certificate_chain: androidAttestationFixture(challenge, await exportJWK(pair.privateKey)),
      proof: await proof(challenge, purpose, pair),
      ...(c_nonce ? { c_nonce } : {}),
    });
    for (const name of [
      'attester-disabled',
      'attester-missing-verifier',
      'attester-role-collision',
    ]) {
      const response = await request(harness.getWorker(name), 'challenge', {
        client_id: client,
        purpose: 'client',
      });
      assert.equal(response.status, name === 'attester-disabled' ? 404 : 503);
    }
    assert.equal(
      (await request(worker, 'challenge', { client_id: 'unknown', purpose: 'client' })).status,
      503,
    );
    assert.equal(
      (
        await request(worker, 'challenge', {
          client_id: client,
          purpose: 'holder',
          c_nonce: secret(),
        })
      ).status,
      400,
    );
    const c = await challenge();
    const body = await enrollment(c);
    for (const patch of [
      { client_id: 'other' },
      { purpose: 'holder' },
      { challenge: secret() },
      { public_key: holderPublic },
      { proof: await proof(c, 'client', holder) },
      { proof: await proof(c, 'client', instance, { aud: `${root}/identity/issuer` }) },
      { proof: await proof(c, 'client', instance, { purpose: 'holder' }) },
      {
        certificate_chain: androidAttestationFixture(
          secret(),
          await exportJWK(instance.privateKey),
        ),
      },
    ])
      assert.ok((await request(worker, 'attestation', { ...body, ...patch })).status >= 400);
    for (const mode of modes.filter((m) => m !== 'good')) {
      const rejected = await request(harness.getWorker(`attester-${mode}`), 'attestation', body);
      assert.equal(rejected.status, 503, `${mode}: ${await rejected.text()}`);
    }
    const tampered = structuredClone(body);
    const der = Buffer.from(tampered.certificate_chain[0], 'base64');
    der[der.length - 1] ^= 1;
    tampered.certificate_chain[0] = der.toString('base64');
    assert.equal(
      (await request(worker, 'attestation', tampered)).status,
      503,
      'fixture service rejects bad certificate signature',
    );
    assert.equal(
      (await request(harness.getWorker('attester-policy-changed'), 'attestation', body)).status,
      400,
    );
    assert.equal(
      (
        (await DB.prepare('SELECT used FROM identity_attester_challenge WHERE challenge_hash=?')
          .bind(hash(c))
          .first()) as any
      ).used,
      0,
      'invalid proof/verdict leaves challenge unconsumed',
    );
    const accepted = await request(worker, 'attestation', body);
    assert.equal(accepted.status, 200, await accepted.clone().text());
    const token = ((await accepted.json()) as any).attestation as string;
    const attesterKey = createPublicKey(createPrivateKey({ key: fixtureKey(5), format: 'jwk' }));
    const verified = await jwtVerify(token, attesterKey, { issuer: audience, subject: client });
    assert.deepEqual((verified.payload.cnf as any).jwk, publicKey);
    assert.deepEqual(verified.protectedHeader.x5c, chain);
    assert.equal(verified.protectedHeader.typ, 'oauth-client-attestation+jwt');
    assert.equal((await request(worker, 'attestation', body)).status, 400, 'one-use challenge');
    const headers = async (aud = audience) => ({
      'OAuth-Client-Attestation': token,
      'OAuth-Client-Attestation-PoP': await new SignJWT({
        iss: client,
        aud,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
        jti: secret(),
      })
        .setProtectedHeader({ typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' })
        .sign(instance.privateKey),
    });
    const nonceResponse = await worker.fetch(`${root}/identity/issuer/nonce`, { method: 'POST' });
    assert.equal(nonceResponse.status, 200);
    const nonce = ((await nonceResponse.json()) as any).c_nonce;
    const auth = await headers();
    assert.equal(
      (
        await request(
          worker,
          'challenge',
          { client_id: client, purpose: 'holder', c_nonce: nonce },
          await headers(`${root}/identity/issuer`),
        )
      ).status,
      400,
    );
    const hc = await challenge('holder', auth, nonce);
    assert.equal(
      (
        await request(
          worker,
          'challenge',
          { client_id: client, purpose: 'holder', c_nonce: nonce },
          auth,
        )
      ).status,
      400,
      'client PoP replay rejected',
    );
    const hb = await enrollment(hc, 'holder', holder, nonce);
    assert.equal(
      (await request(worker, 'attestation', hb)).status,
      400,
      'holder redemption needs authenticated instance',
    );
    assert.equal(
      (await request(worker, 'attestation', { ...hb, c_nonce: secret() }, await headers())).status,
      400,
    );
    const reusedKey = await enrollment(hc, 'holder', instance, nonce);
    assert.equal(
      (await request(worker, 'attestation', reusedKey, await headers())).status,
      400,
      'holder cannot reuse client-instance key',
    );
    const issued = await request(worker, 'attestation', hb, await headers());
    assert.equal(issued.status, 200, await issued.clone().text());
    const holderToken = ((await issued.json()) as any).attestation;
    const keyClaims = await jwtVerify(holderToken, attesterKey);
    assert.equal(keyClaims.protectedHeader.typ, 'key-attestation+jwt');
    assert.equal(keyClaims.payload.nonce, nonce);
    assert.deepEqual(keyClaims.payload.attested_keys, [holderPublic]);
    assert.equal(keyClaims.payload.key_storage, undefined);
    assert.equal(keyClaims.payload.user_authentication, undefined);
    const until = (
      (await DB.prepare('SELECT expires_at FROM identity_nonce WHERE nonce_hash=?')
        .bind(hash(nonce))
        .first()) as any
    ).expires_at;
    assert.ok(keyClaims.payload.exp! <= until);
    assert.equal(
      (
        (await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?')
          .bind(hash(nonce))
          .first()) as any
      ).used,
      0,
      'attesting does not consume issuer credential nonce',
    );
    const raced = await challenge();
    const rb = await enrollment(raced);
    const results = await Promise.all([
      request(worker, 'attestation', rb),
      request(worker, 'attestation', rb),
    ]);
    assert.equal(
      results.filter((r) => r.status === 200).length,
      1,
      'concurrent redemption has one winner',
    );
    const expired = await challenge();
    const eb = await enrollment(expired);
    await DB.prepare(
      'UPDATE identity_attester_challenge SET expires_at=unixepoch()-1 WHERE challenge_hash=?',
    )
      .bind(hash(expired))
      .run();
    assert.equal((await request(worker, 'attestation', eb)).status, 400);
    const columns = await DB.prepare('PRAGMA table_info(identity_attester_challenge)').all();
    assert.ok(
      columns.results.every(
        (c: any) => !['certificate_chain', 'public_key', 'proof', 'attestation'].includes(c.name),
      ),
      'raw evidence/JWTs never persisted',
    );
  } finally {
    await harness.close();
  }
});
