import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';
import { Miniflare, Response as RuntimeResponse, convertV4MiniflareOptions } from 'miniflare';
import { fixtureKey } from './support/android-attestation-fixture.ts';
import { credentialPki } from './support/credential-pki.ts';

test('protected HAIP readiness validates issuer custody and exact verifier policy/freshness', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-haip-readiness-'));
  const cert = async (name: string) =>
    (
      await readFile(
        new URL(`../../crates/identity/tests/fixtures/trust/${name}.der`, import.meta.url),
      )
    ).toString('base64');
  const chain = await Promise.all(['attester', 'intermediate'].map(cert));
  const anchor = await cert('root');
  const certificates = await credentialPki(pathToFileURL(`${directory}/`), {
    ...fixtureKey(4),
    kid: 'issuer',
  });
  const { n, e } = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({
    format: 'jwk',
  });
  const now = Math.floor(Date.now() / 1000);
  const policy = randomBytes(32).toString('base64url');
  const token = randomBytes(32).toString('base64url');
  let mode = 'good';
  const build = new URL('../../crates/worker/build/', import.meta.url).pathname;
  const options = convertV4MiniflareOptions({
    modules: true,
    scriptPath: `${build}index.js`,
    modulesRoot: build,
    compatibilityDate: '2026-10-02',
    bindings: {
      MIKAKI_ISSUER: 'https://issuer.example',
      MIKAKI_READY_TOKEN: token,
      MIKAKI_DPOP_NONCE_MODE: 'required',
      IDENTITY_ENABLED: 'true',
      IDENTITY_WALLET_ENABLED: 'true',
      IDENTITY_HAIP_ENABLED: 'true',
      IDENTITY_ATTESTER_ENABLED: 'true',
      IDENTITY_ISSUER_JWK: JSON.stringify({ ...fixtureKey(4), kid: 'issuer' }),
      IDENTITY_CREDENTIAL_CERTIFICATES: JSON.stringify(certificates.certificates),
      IDENTITY_TRUSTED_KEYS: JSON.stringify([
        {
          id: 'synthetic-readiness',
          document_type: 'driving_license',
          n,
          e,
          subject_key_identifier: null,
          not_before: now - 60,
          not_after: now + 3600,
        },
      ]),
      IDENTITY_WALLET_CLIENTS: JSON.stringify([
        {
          client_id: 'fixture',
          name: 'Fixture',
          redirect_uri: 'https://wallet.example/callback',
          attesters: ['https://issuer.example/identity/attester'],
        },
      ]),
      IDENTITY_WALLET_ATTESTERS: JSON.stringify([
        { issuer: 'https://issuer.example/identity/attester', trust_anchors: [anchor] },
      ]),
      IDENTITY_KEY_ATTESTATION_TRUST: JSON.stringify({ trust_anchors: [anchor] }),
      IDENTITY_ATTESTER_SIGNING: JSON.stringify({
        jwk: JSON.stringify({ ...fixtureKey(5), kid: 'attester' }),
        chain,
        trust_anchors: [anchor],
      }),
      IDENTITY_ATTESTER_CLIENTS: JSON.stringify([
        { client_id: 'fixture', verifier_policy_hash: policy },
      ]),
    },
    serviceBindings: {
      IDENTITY_ANDROID_VERIFIER: async (request) => {
        assert.equal(request.url, 'https://android-verifier.internal/readyz');
        if (mode === 'unavailable') return new RuntimeResponse(null, { status: 503 });
        return RuntimeResponse.json({
          format: 'android-key-attestation-readiness-v1',
          client_id: 'fixture',
          verifier_policy_hash: mode === 'wrong-policy' ? 'other' : policy,
          status_valid_until: mode === 'stale' ? 1 : Math.floor(Date.now() / 1000) + 300,
        });
      },
    },
  });
  options.workers[0].config.manifest!.modules['index_bg.wasm'] = {
    type: 'wasm',
    contents: new Uint8Array(await readFile(`${build}index_bg.wasm`)),
  };
  const mf = new Miniflare(options);
  try {
    assert.equal((await mf.dispatchFetch('https://issuer.example/identity/ready')).status, 404);
    const request = () =>
      mf.dispatchFetch('https://issuer.example/identity/ready', {
        headers: { Authorization: `Bearer ${token}` },
      });
    assert.equal((await request()).status, 204);
    for (mode of ['wrong-policy', 'stale', 'unavailable'])
      assert.equal((await request()).status, 503, mode);
  } finally {
    await mf.dispose();
    await rm(directory, { recursive: true, force: true });
  }
});
