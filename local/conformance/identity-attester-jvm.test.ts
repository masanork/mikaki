import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import { Miniflare, Response as RuntimeResponse, convertV4MiniflareOptions } from 'miniflare';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import { androidJvmVerifier } from './support/android-jvm-verifier.ts';
import { fixtureKey } from './support/android-attestation-fixture.ts';

const root = 'https://issuer.example';
const audience = `${root}/identity/attester`;
const client = 'native-fixture';
const secret = () => randomBytes(32).toString('base64url');
const hash = (s: string) => createHash('sha256').update(s).digest('base64url');

test('broker → private bridge → actual JVM verifier issues only verified, one-use client and holder attestations', async () => {
  const jvm = await androidJvmVerifier();
  let mf: Miniflare | undefined;
  let calls = 0;
  let verifierStatuses: number[] = [];
  try {
    const cert = async (name: string) =>
      (
        await readFile(
          new URL(`../../crates/identity/tests/fixtures/trust/${name}.der`, import.meta.url),
        )
      ).toString('base64');
    const chain = await Promise.all(['attester', 'intermediate'].map(cert));
    const signing = {
      jwk: JSON.stringify({ ...fixtureKey(5), kid: 'attester' }),
      chain,
      trust_anchors: [await cert('root')],
    };
    const build = new URL('../../crates/worker/build/', import.meta.url).pathname;
    const broker = convertV4MiniflareOptions({
      name: 'attester-broker',
      modules: true,
      scriptPath: `${build}index.js`,
      modulesRoot: build,
      compatibilityDate: '2026-10-02',
      bindings: {
        MIKAKI_ISSUER: root,
        IDENTITY_ENABLED: 'true',
        IDENTITY_WALLET_ENABLED: 'true',
        IDENTITY_HAIP_ENABLED: 'true',
        IDENTITY_ATTESTER_ENABLED: 'true',
        IDENTITY_ISSUER_JWK: JSON.stringify({ ...fixtureKey(4), kid: 'credential' }),
        IDENTITY_ATTESTER_SIGNING: JSON.stringify(signing),
        IDENTITY_ATTESTER_CLIENTS: JSON.stringify([
          { client_id: client, verifier_policy_hash: jvm.policy },
        ]),
      },
      d1Databases: { DB: 'attester-jvm' },
      ratelimits: {
        IDENTITY_RATE_LIMIT: { namespace_id: '1030', simple: { limit: 1000, period: 60 } },
      },
      serviceBindings: { IDENTITY_ANDROID_VERIFIER: 'android-verifier-bridge' },
    });
    broker.workers[0].config.manifest!.modules['index_bg.wasm'] = {
      type: 'wasm',
      contents: new Uint8Array(await readFile(`${build}index_bg.wasm`)),
    };
    const bridge = convertV4MiniflareOptions({
      name: 'android-verifier-bridge',
      modules: true,
      scriptPath: new URL(
        '../../services/android-attestation-verifier/bridge/worker.mjs',
        import.meta.url,
      ).pathname,
      compatibilityDate: '2026-10-02',
      bindings: {
        ANDROID_VERIFIER_URL: 'https://verifier.example/verify',
        ANDROID_VERIFIER_TOKEN: jvm.token,
      },
      outboundService: async (request) => {
        calls++;
        assert.equal(request.url, 'https://verifier.example/verify');
        assert.equal(request.headers.get('Authorization'), `Bearer ${jvm.token}`);
        assert.equal(request.headers.get('Cookie'), null);
        assert.equal(request.headers.get('OAuth-Client-Attestation'), null);
        // Transport adapter only: no synthetic verdicts, TLS/device trust not claimed by this test.
        const response = await fetch(jvm.url, {
          method: request.method,
          headers: Object.fromEntries(request.headers),
          body: Buffer.from(await request.arrayBuffer()),
          redirect: 'manual',
          signal: AbortSignal.timeout(7000),
        });
        verifierStatuses.push(response.status);
        return new RuntimeResponse(await response.arrayBuffer(), {
          status: response.status,
          headers: Object.fromEntries(response.headers),
        });
      },
    });
    broker.workers.push(bridge.workers[0]);
    mf = new Miniflare(broker);
    const db = await mf.getD1Database('DB', 'attester-broker');
    const migrations = new URL('../../crates/worker/migrations/', import.meta.url);
    for (const name of (await readdir(migrations)).filter((n) => n.endsWith('.sql')).sort()) {
      const statements = splitSqlQuery(await readFile(new URL(name, migrations), 'utf8'));
      await db.batch(statements.map((sql) => db.prepare(sql)));
    }
    const worker = await mf.getWorker('attester-broker');
    const fallback = await worker.fetch(
      'https://app.mikaki.org/identity/issuance/callback?code=private&state=private',
      { redirect: 'manual' },
    );
    assert.equal(fallback.status, 303);
    assert.equal(fallback.headers.get('Location'), '/native-link-help');
    assert.equal(fallback.headers.get('Cache-Control'), 'no-store');
    assert.equal(fallback.headers.get('Referrer-Policy'), 'no-referrer');
    assert.equal(await fallback.text(), '');
    const request = (path: string, body: unknown, headers = {}) =>
      worker.fetch(`${audience}/${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
      });
    const challenge = async (purpose = 'client', headers = {}, c_nonce?: string) => {
      const response = await request(
        'challenge',
        { client_id: client, purpose, ...(c_nonce ? { c_nonce } : {}) },
        headers,
      );
      assert.equal(response.status, 200, await response.clone().text());
      return ((await response.json()) as { challenge: string }).challenge;
    };
    const instance = await generateKeyPair('ES256', { extractable: true });
    const holder = await generateKeyPair('ES256', { extractable: true });
    const publicKey = await exportJWK(instance.publicKey);
    const holderPublic = await exportJWK(holder.publicKey);
    const enrollment = async (
      c: string,
      purpose = 'client',
      pair = instance,
      c_nonce?: string,
      options = {},
    ) => {
      const jwk = await exportJWK(pair.publicKey);
      const now = Math.floor(Date.now() / 1000);
      return {
        client_id: client,
        purpose,
        challenge: c,
        public_key: jwk,
        certificate_chain: await jvm.certificates(c, jwk, options),
        proof: await new SignJWT({
          iss: client,
          aud: audience,
          nonce: c,
          purpose,
          iat: now,
          exp: now + 60,
        })
          .setProtectedHeader({ typ: 'mikaki-wallet-attester-proof+jwt', alg: 'ES256', jwk })
          .sign(pair.privateKey),
        ...(c_nonce ? { c_nonce } : {}),
      };
    };
    const unused = async (c: string) =>
      assert.equal(
        await db
          .prepare('SELECT used FROM identity_attester_challenge WHERE challenge_hash=?')
          .bind(hash(c))
          .first('used'),
        0,
      );
    const c = await challenge();
    const body = await enrollment(c);
    const wrongApp = await enrollment(c, 'client', instance, undefined, { bad_app: true });
    assert.equal((await request('attestation', wrongApp)).status, 503);
    assert.equal(verifierStatuses.at(-1), 400, 'actual JVM policy rejects another package');
    await unused(c);
    const tampered = structuredClone(body);
    const der = Buffer.from(tampered.certificate_chain[0], 'base64');
    der[der.length - 1] ^= 1;
    tampered.certificate_chain[0] = der.toString('base64');
    assert.equal((await request('attestation', tampered)).status, 503);
    assert.equal(verifierStatuses.at(-1), 400, 'actual library rejects certificate signature');
    await unused(c);
    for (const mode of ['revoked', 'stale', 'unavailable'] as const) {
      await jvm.status(mode);
      assert.equal((await request('attestation', body)).status, 503, mode);
      await unused(c);
    }
    await jvm.status('good');
    const accepted = await request('attestation', body);
    assert.equal(accepted.status, 200, await accepted.clone().text());
    assert.equal(verifierStatuses.at(-1), 200);
    assert.equal(accepted.headers.get('Cache-Control'), 'no-store');
    const token = ((await accepted.json()) as { attestation: string }).attestation;
    const authority = createPublicKey(createPrivateKey({ key: fixtureKey(5), format: 'jwk' }));
    const claims = await jwtVerify(token, authority, { issuer: audience, subject: client });
    assert.equal(claims.protectedHeader.typ, 'oauth-client-attestation+jwt');
    assert.deepEqual(claims.protectedHeader.x5c, chain);
    assert.deepEqual(claims.payload.cnf, { jwk: publicKey });
    const headers = async () => {
      const now = Math.floor(Date.now() / 1000);
      return {
        'OAuth-Client-Attestation': token,
        'OAuth-Client-Attestation-PoP': await new SignJWT({
          iss: client,
          aud: audience,
          iat: now,
          exp: now + 60,
          jti: secret(),
        })
          .setProtectedHeader({ typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' })
          .sign(instance.privateKey),
      };
    };
    const beforeReplay = calls;
    assert.equal((await request('attestation', body)).status, 400);
    assert.equal(calls, beforeReplay, 'consumed challenge never reaches verifier');
    const response = await worker.fetch(`${root}/identity/issuer/nonce`, { method: 'POST' });
    assert.equal(response.status, 200);
    const nonce = ((await response.json()) as { c_nonce: string }).c_nonce;
    const hc = await challenge('holder', await headers(), nonce);
    const hb = await enrollment(hc, 'holder', holder, nonce, { remote: true });
    await jvm.status('revoked');
    assert.equal((await request('attestation', hb, await headers())).status, 503);
    await unused(hc);
    await jvm.status('good');
    const issued = await request('attestation', hb, await headers());
    assert.equal(issued.status, 200, await issued.clone().text());
    const holderToken = ((await issued.json()) as { attestation: string }).attestation;
    const holderClaims = await jwtVerify(holderToken, authority);
    assert.equal(holderClaims.protectedHeader.typ, 'key-attestation+jwt');
    assert.deepEqual(holderClaims.payload.attested_keys, [holderPublic]);
    assert.equal(holderClaims.payload.nonce, nonce);
    assert.equal(holderClaims.payload.iss, undefined);
    assert.equal(holderClaims.payload.key_storage, undefined);
    assert.equal(holderClaims.payload.user_authentication, undefined);
    assert.equal(
      await db
        .prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?')
        .bind(hash(nonce))
        .first('used'),
      0,
    );
    assert.equal((await request('attestation', hb, await headers())).status, 400);
    const raced = await challenge();
    const rb = await enrollment(raced, 'client', instance, undefined, { remote: true });
    const results = await Promise.all([request('attestation', rb), request('attestation', rb)]);
    assert.deepEqual(results.map((r) => r.status).sort(), [200, 400]);
    assert.ok(calls >= 10, 'both factory and remote chains actually reach JVM verification');
  } finally {
    await mf?.dispose();
    await jvm.stop();
  }
});
