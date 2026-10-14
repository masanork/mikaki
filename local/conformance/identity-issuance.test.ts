import assert from 'node:assert/strict';
import {
  createHash,
  createECDH,
  createDecipheriv,
  diffieHellman,
  createPrivateKey,
  createPublicKey,
  randomBytes,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { inflateRawSync } from 'node:zlib';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import {
  CompactEncrypt,
  compactDecrypt,
  importJWK,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  jwtVerify,
  SignJWT,
} from 'jose';
import { verifyMdocIssuer, field } from './support/mdoc-test.ts';
import { receiveWithMultipaz } from './support/multipaz-wallet.ts';
import { identityFixture } from './support/identity-fixture.ts';
import { receiveWithRustEncryption } from './support/rust-issuance-wallet.ts';
import { withRustHaipWallet } from './support/rust-haip-wallet.ts';
import { withOfficialWalletSuite } from './support/official-wallet-suite.ts';
import { withNativePresentationHttp } from './support/native-presentation-http.ts';
import { issuedWalletVerifier } from './support/issued-wallet-presentation.ts';
import { androidAttestationFixture, fixtureKey } from './support/android-attestation-fixture.ts';
import { agePresentationVectors, verifyAgePresentations } from './support/age-presentation.ts';

const root = 'https://issuer.example';
const issuer = `${root}/identity/issuer`;
const hash = (value: string | Uint8Array) => createHash('sha256').update(value).digest('base64url');
const secret = () => randomBytes(32).toString('base64url');
test('discovery publishes age-only metadata and JWKS without accepting intake or issuing credentials', async () => {
  const key = await generateKeyPair('ES256', { extractable: true });
  const jwk = { ...(await exportJWK(key.privateKey)), kid: 'discovery-issuer' };
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.queues.consumers = [];
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.vars = {
    MIKAKI_ISSUER: root,
    IDENTITY_ENABLED: 'true',
    IDENTITY_ISSUANCE_ENABLED: 'false',
    IDENTITY_ISSUANCE_CLAIMS: '["age_over_18"]',
    IDENTITY_ISSUER_JWK: JSON.stringify(jwk),
  };
  const harness = await createTestHarness({
    workers: [
      { config },
      {
        config: {
          ...config,
          name: 'discovery-stale-trust',
          vars: {
            ...config.vars,
            IDENTITY_TRUSTED_KEYS: JSON.stringify(identityFixture().trust),
            IDENTITY_WALLET_ENABLED: 'true',
          },
        },
      },
    ],
  });
  try {
    await harness.listen();
    for (const name of ['mikaki-op-worker', 'discovery-stale-trust']) {
      const worker = harness.getWorker(name);
      await worker.applyD1Migrations('DB');
      const metadataResponse = await worker.fetch(
        `${root}/.well-known/openid-credential-issuer/identity/issuer`,
      );
      assert.equal(metadataResponse.status, 200);
      assert.equal(metadataResponse.headers.get('cache-control'), 'no-store');
      const metadata = (await metadataResponse.json()) as any;
      assert.equal(metadata.mikaki_issuance_enabled, false);
      assert.deepEqual(Object.keys(metadata.credential_configurations_supported), [
        'linked_document',
      ]);
      assert.deepEqual(
        metadata.credential_configurations_supported.linked_document.credential_metadata.claims.map(
          (claim: any) => claim.path,
        ),
        [['age_over_18']],
      );
      const keysResponse = await worker.fetch(`${issuer}/jwks`);
      assert.equal(keysResponse.status, 200);
      const keys = ((await keysResponse.json()) as any).keys;
      assert.equal(keys.length, 1);
      assert.equal(keys[0].kid, 'discovery-issuer');
      assert.equal(keys[0].d, undefined);
      assert.equal(keys[0].x, jwk.x);
      const oauthResponse = await worker.fetch(
        `${root}/.well-known/oauth-authorization-server/identity/issuer`,
      );
      assert.equal(oauthResponse.status, 200);
      assert.equal(((await oauthResponse.json()) as any).authorization_endpoint, undefined);
      assert.equal((await worker.fetch(`${issuer}/types/linked-document`)).status, 200);
      for (const [path, method] of [
        ['/identity/intake', 'POST'],
        ['/identity/approve', 'GET'],
        ['/identity/approve', 'POST'],
        ['/identity/poll', 'POST'],
        ['/identity/issuer/token', 'POST'],
        ['/identity/issuer/nonce', 'POST'],
        ['/identity/issuer/credential', 'POST'],
      ]) {
        const response = await worker.fetch(`${root}${path}`, { method });
        assert.equal(response.status, 503, path);
        assert.equal(((await response.json()) as any).error, 'issuer_unavailable');
      }
      assert.equal((await worker.fetch(`${issuer}/authorize`)).status, 404);
      assert.equal((await worker.fetch(`${issuer}/par`, { method: 'POST' })).status, 404);
      const { DB } = await worker.getEnv();
      for (const table of [
        'identity_nonce',
        'identity_transaction',
        'identity_document',
        'identity_wallet_grant',
      ]) {
        assert.equal(
          ((await DB.prepare(`SELECT count(*) AS count FROM ${table}`).first()) as any).count,
          0,
        );
      }
    }
  } finally {
    await harness.close();
  }
});

test(`workerd verifies both cards, issues holder-bound credentials through OID4VCI and independently verifies encrypted SD-JWT/mdoc OID4VP${process.env.MIKAKI_MULTIPAZ_CHECKOUT ? ' + pinned Multipaz SDK (DPoP nonce required)' : ''}`, async () => {
  const f = identityFixture();
  const ec = createECDH('prime256v1');
  ec.setPrivateKey(Buffer.alloc(32, 4));
  const point = ec.getPublicKey();
  const fixtureJwk = {
    kty: 'EC',
    crv: 'P-256',
    d: Buffer.alloc(32, 4).toString('base64url'),
    x: point.subarray(1, 33).toString('base64url'),
    y: point.subarray(33).toString('base64url'),
  };
  const privateKey = createPrivateKey({ key: fixtureJwk, format: 'jwk' });
  const op = { privateKey, publicKey: createPublicKey(privateKey) };
  const wallet = await generateKeyPair('ES256', { extractable: true });
  const holder = await exportJWK(wallet.publicKey);
  const privateJwk = { ...(await exportJWK(op.privateKey)), kid: 'document-issuer' };
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  // This identity-only multi-worker fixture does not exercise logout delivery.
  config.queues.consumers = [];
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.vars = {
    MIKAKI_ISSUER: root,
    IDENTITY_ENABLED: 'true',
    IDENTITY_TRUSTED_KEYS: JSON.stringify(f.trust),
    IDENTITY_ISSUER_JWK: JSON.stringify(privateJwk),
    IDENTITY_MDOC_CERT_DER: (
      await readFile(new URL('../../crates/identity/tests/fixtures/mdoc-ds.der', import.meta.url))
    ).toString('base64url'),
  };
  config.ratelimits = [
    { name: 'IDENTITY_RATE_LIMIT', namespace_id: '1030', simple: { limit: 1000, period: 60 } },
  ];
  const sdOnlyVars = { ...config.vars };
  delete sdOnlyVars.IDENTITY_MDOC_CERT_DER;
  const trustDeadline = Math.floor(Date.now() / 1000) + 90;
  const shortTrust = f.trust.map((k) => ({ ...k, not_after: trustDeadline }));
  const walletClient = {
    client_id: 'independent-wallet',
    name: 'Independent test wallet',
    redirect_uri: 'https://wallet.example/callback',
  };
  const otherWalletClient = {
    client_id: 'registered-other-wallet',
    name: 'Other registered wallet',
    redirect_uri: 'https://other-wallet.example/callback',
  };
  const walletVars = {
    ...config.vars,
    IDENTITY_WALLET_ENABLED: 'true',
    IDENTITY_WALLET_CLIENTS: JSON.stringify([walletClient, otherWalletClient]),
  };
  const attesterIssuer = `${root}/identity/attester`;
  const attesterChain = await Promise.all(
    ['attester', 'intermediate'].map(async (name) =>
      (
        await readFile(
          new URL(`../../crates/identity/tests/fixtures/trust/${name}.der`, import.meta.url),
        )
      ).toString('base64'),
    ),
  );
  const attesterRoot = (
    await readFile(new URL('../../crates/identity/tests/fixtures/trust/root.der', import.meta.url))
  ).toString('base64');
  const attesterEc = createECDH('prime256v1');
  attesterEc.setPrivateKey(Buffer.alloc(32, 5));
  const attesterPoint = attesterEc.getPublicKey();
  const attesterKey = createPrivateKey({
    format: 'jwk',
    key: {
      kty: 'EC',
      crv: 'P-256',
      d: Buffer.alloc(32, 5).toString('base64url'),
      x: attesterPoint.subarray(1, 33).toString('base64url'),
      y: attesterPoint.subarray(33).toString('base64url'),
    },
  });
  const signingCertificates = Object.fromEntries(
    await Promise.all(
      ['sd_jwt', 'mdoc'].map(async (purpose) => {
        const prefix = purpose === 'mdoc' ? 'mdoc' : 'sd';
        const read = async (part: string) =>
          (
            await readFile(
              new URL(
                `../../crates/identity/tests/fixtures/credential/${prefix}-${part}.der`,
                import.meta.url,
              ),
            )
          ).toString('base64');
        return [
          purpose,
          { chain: [await read('signer')], trust_anchors: [await read('ca')] },
        ] as const;
      }),
    ),
  );
  const certifiedVars = { ...walletVars };
  delete certifiedVars.IDENTITY_MDOC_CERT_DER;
  const issuerEncryption = await generateKeyPair('ECDH-ES', { extractable: true });
  const issuerEncryptionJwk = {
    ...(await exportJWK(issuerEncryption.privateKey)),
    kid: 'fixture-issuer-encryption',
    alg: 'ECDH-ES',
    use: 'enc',
  };
  const haipRedirect = `${walletClient.redirect_uri}?tenant=fixed%20tenant&channel=wallet`;
  const haipVars = {
    ...certifiedVars,
    IDENTITY_CREDENTIAL_CERTIFICATES: JSON.stringify(signingCertificates),
    IDENTITY_HAIP_ENABLED: 'true',
    IDENTITY_CREDENTIAL_ENCRYPTION_JWK: JSON.stringify(issuerEncryptionJwk),
    IDENTITY_KEY_ATTESTATION_TRUST: JSON.stringify({ trust_anchors: [attesterRoot] }),
    MIKAKI_DPOP_NONCE_MODE: 'required',
    IDENTITY_WALLET_CLIENTS: JSON.stringify([
      { ...walletClient, redirect_uri: haipRedirect, attesters: [attesterIssuer] },
    ]),
    IDENTITY_WALLET_ATTESTERS: JSON.stringify([
      { issuer: attesterIssuer, trust_anchors: [attesterRoot] },
    ]),
    IDENTITY_ATTESTER_ENABLED: 'true',
    IDENTITY_ATTESTER_CLIENTS: JSON.stringify([
      { client_id: walletClient.client_id, verifier_policy_hash: hash('fixture-verifier-policy') },
    ]),
    IDENTITY_ATTESTER_SIGNING: JSON.stringify({
      jwk: JSON.stringify({ ...fixtureKey(5), kid: 'attester' }),
      chain: attesterChain,
      trust_anchors: [attesterRoot],
    }),
  };
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      { config },
      {
        config: {
          ...config,
          name: 'identity-age-only',
          vars: {
            ...config.vars,
            IDENTITY_ISSUANCE_CLAIMS: JSON.stringify(['age_over_18']),
          },
        },
      },
      ...[false, true].map((changed) => ({
        config: {
          ...config,
          name: changed ? 'identity-age-batch-changed' : 'identity-age-batch',
          vars: {
            ...config.vars,
            IDENTITY_AGE_BATCH_ENABLED: 'true',
            IDENTITY_ISSUANCE_CLAIMS: JSON.stringify([changed ? 'age_over_20' : 'age_over_18']),
            IDENTITY_CREDENTIAL_ENCRYPTION_JWK: JSON.stringify(issuerEncryptionJwk),
          },
        },
      })),
      {
        config: {
          ...config,
          name: 'identity-invalid-claims',
          vars: {
            ...config.vars,
            IDENTITY_ISSUANCE_CLAIMS: JSON.stringify(['unknown']),
          },
        },
      },
      ...[false, true].map((changed) => ({
        config: {
          ...config,
          name: changed ? 'identity-haip-age-pool-changed' : 'identity-haip-age-pool',
          services: [
            { binding: 'IDENTITY_ANDROID_VERIFIER', service: 'identity-fixture-android-verifier' },
          ],
          vars: {
            ...haipVars,
            IDENTITY_HAIP_AGE_POOL_ENABLED: 'true',
            IDENTITY_ISSUANCE_CLAIMS: JSON.stringify([changed ? 'age_over_20' : 'age_over_18']),
          },
        },
      })),
      ...[false, true].map((changed) => ({
        config: {
          ...config,
          name: changed ? 'identity-haip-age-batch-changed' : 'identity-haip-age-batch',
          services: [
            { binding: 'IDENTITY_ANDROID_VERIFIER', service: 'identity-fixture-android-verifier' },
          ],
          vars: {
            ...haipVars,
            IDENTITY_HAIP_AGE_POOL_ENABLED: 'true',
            IDENTITY_HAIP_AGE_BATCH_ENABLED: 'true',
            IDENTITY_ISSUANCE_CLAIMS: JSON.stringify([changed ? 'age_over_20' : 'age_over_18']),
          },
        },
      })),
      {
        config: {
          ...config,
          name: 'identity-haip',
          vars: haipVars,
          services: [
            { binding: 'IDENTITY_ANDROID_VERIFIER', service: 'identity-fixture-android-verifier' },
          ],
        },
      },
      {
        config: {
          name: 'identity-fixture-android-verifier',
          main: new URL('./support/android-verifier-fixture.mjs', import.meta.url).pathname,
          compatibility_date: '2026-10-02',
          compatibility_flags: ['nodejs_compat'],
          vars: {
            FIXTURE_ROOT: attesterRoot,
            FIXTURE_POLICY_HASH: hash('fixture-verifier-policy'),
            FIXTURE_MODE: 'good',
          },
        },
      },
      ...['code=injected', '%73tate=injected', 'tenant=a&tenant=b', ''].map((query, i) => ({
        config: {
          ...config,
          name: `identity-haip-invalid-query-${i}`,
          vars: {
            ...haipVars,
            IDENTITY_WALLET_CLIENTS: JSON.stringify([
              {
                ...walletClient,
                redirect_uri: `${walletClient.redirect_uri}?${query}`,
                attesters: [attesterIssuer],
              },
            ]),
          },
        },
      })),
      {
        config: {
          ...config,
          name: 'identity-haip-key-trust-missing',
          vars: { ...haipVars, IDENTITY_KEY_ATTESTATION_TRUST: '' },
        },
      },
      {
        config: {
          ...config,
          name: 'identity-haip-key-trust-changed',
          vars: {
            ...haipVars,
            IDENTITY_KEY_ATTESTATION_TRUST: JSON.stringify({
              trust_anchors: (signingCertificates.sd_jwt as any).trust_anchors,
            }),
          },
        },
      },
      {
        config: {
          ...config,
          name: 'identity-haip-no-cert',
          vars: { ...haipVars, IDENTITY_CREDENTIAL_CERTIFICATES: '{}' },
        },
      },
      {
        config: {
          ...config,
          name: 'identity-haip-wrong-trust',
          vars: {
            ...haipVars,
            IDENTITY_CREDENTIAL_CERTIFICATES: JSON.stringify({
              ...signingCertificates,
              sd_jwt: {
                ...(signingCertificates.sd_jwt as any),
                trust_anchors: (signingCertificates.mdoc as any).trust_anchors,
              },
            }),
          },
        },
      },

      { config: { ...config, name: 'identity-wallet', vars: walletVars } },
      {
        config: {
          ...config,
          name: 'identity-wallet-nonce',
          vars: { ...walletVars, MIKAKI_DPOP_NONCE_MODE: 'required' },
        },
      },
      {
        config: {
          ...config,
          name: 'identity-wallet-changed',
          vars: {
            ...walletVars,
            IDENTITY_WALLET_CLIENTS: JSON.stringify([
              { ...walletClient, name: 'Changed wallet policy' },
            ]),
          },
        },
      },
      {
        config: {
          ...config,
          name: 'identity-short-trust',
          vars: { ...config.vars, IDENTITY_TRUSTED_KEYS: JSON.stringify(shortTrust) },
        },
      },
      { config: { ...config, name: 'identity-sd-only', vars: sdOnlyVars } },
      {
        config: {
          ...config,
          name: 'identity-disabled',
          vars: { ...config.vars, IDENTITY_ENABLED: 'false' },
        },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const disabled = harness.getWorker('identity-disabled');
    const sdOnly = harness.getWorker('identity-sd-only');
    const sdMetadata = await sdOnly.fetch(
      `${root}/.well-known/openid-credential-issuer/identity/issuer`,
    );
    assert.equal(sdMetadata.status, 200);
    const supported = ((await sdMetadata.json()) as any).credential_configurations_supported;
    assert.ok(supported.linked_document);
    assert.equal(supported.linked_document_mdoc, undefined);
    const unsupported = await sdOnly.fetch(`${issuer}/credential`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${secret()}` },
      body: JSON.stringify({
        credential_configuration_id: 'linked_document_mdoc',
        proofs: { jwt: ['fixture-proof'] },
      }),
    });
    assert.equal(unsupported.status, 400);
    assert.equal(((await unsupported.json()) as any).error, 'unknown_credential_configuration');

    assert.equal(
      (await disabled.fetch(`${root}/.well-known/openid-credential-issuer/identity/issuer`)).status,
      404,
    );
    assert.equal((await disabled.fetch(`${root}/identity/intake`, { method: 'POST' })).status, 404);
    const { DB } = await worker.getEnv();
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('passkey','owner',1)"),
      DB.prepare("INSERT INTO sso_session VALUES('sso','owner','passkey',1,?,0)").bind(now + 3600),
      DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(hash('owner-cookie'), now),
      DB.prepare("INSERT INTO account_security VALUES('other',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('other-passkey','other',1)"),
      DB.prepare("INSERT INTO sso_session VALUES('other-sso','other','other-passkey',1,?,0)").bind(
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('other-sso',?,?)").bind(hash('other-cookie'), now),
    ]);
    const post = (
      path: string,
      value: unknown,
      headers: Record<string, string> = {},
      target = worker,
    ) =>
      target.fetch(`${root}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(value),
      });
    const start = async (
      evidence: ReturnType<typeof f.makeLicense> | ReturnType<typeof f.makeMnc>,
      target = worker,
    ) => {
      const response = await post('/identity/intake', { evidence, holder_jwk: holder }, {}, target);
      assert.equal(response.status, 200, await response.clone().text());
      return (await response.json()) as {
        transaction_id: string;
        poll_secret: string;
        approval_url: string;
      };
    };
    const approve = async (
      tx: Awaited<ReturnType<typeof start>>,
      decision = 'approve',
      target = worker,
    ) => {
      assert.equal((await target.fetch(tx.approval_url)).status, 401);
      const page = await target.fetch(tx.approval_url, {
        headers: { Cookie: '__Host-op-sso=owner-cookie' },
      });
      assert.equal(page.status, 200, await page.clone().text());
      assert.equal(page.headers.get('cache-control'), 'no-store');
      const html = await page.text();
      const csrf = /name=csrf value='([^']+)'/.exec(html)![1];
      const request = (cookie: string, origin = root) =>
        target.fetch(`${root}/identity/approve`, {
          method: 'POST',
          headers: {
            Cookie: `__Host-op-sso=${cookie}`,
            Origin: origin,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({ tx: tx.transaction_id, csrf, decision }).toString(),
        });
      assert.equal((await request('owner-cookie', 'https://evil.example')).status, 403);
      assert.equal((await request('other-cookie')).status, 409);
      const response = await request('owner-cookie');
      assert.equal(response.status, 200, await response.clone().text());
      assert.equal((await request('owner-cookie')).status, 409);
    };
    const poll = (tx: Awaited<ReturnType<typeof start>>) => post('/identity/poll', tx);
    const ageOnly = harness.getWorker('identity-age-only');
    const ageMetadata = await ageOnly.fetch(
      `${root}/.well-known/openid-credential-issuer/identity/issuer`,
    );
    assert.equal(ageMetadata.status, 200);
    const ageConfigurations = ((await ageMetadata.json()) as any)
      .credential_configurations_supported;
    assert.deepEqual(
      ageConfigurations.linked_document.credential_metadata.claims.map((c: any) => c.path),
      [['age_over_18']],
    );
    assert.deepEqual(
      ageConfigurations.linked_document_mdoc.credential_metadata.claims.map((c: any) => c.path),
      [['app.tossa.mikaki.linked_document.1', 'age_over_18']],
    );
    const ageType = (await (await ageOnly.fetch(`${issuer}/types/linked-document`)).json()) as any;
    for (const claim of ageType.claims) {
      assert.deepEqual(Object.keys(claim.display[0]).sort(), ['label', 'locale']);
      assert.equal(claim.display[0].locale, 'ja');
      assert.ok(typeof claim.display[0].label === 'string' && claim.display[0].label.length > 0);
    }
    assert.ok(ageType.claims.some((c: any) => c.path[0] === 'age_over_20'));
    assert.equal(
      (
        await harness
          .getWorker('identity-invalid-claims')
          .fetch(`${root}/.well-known/openid-credential-issuer/identity/issuer`)
      ).status,
      503,
    );
    for (const evidence of [f.makeMnc(), f.makeLicense()]) {
      const receipts: Record<string, string> = {};
      for (const configuration of ['linked_document', 'linked_document_mdoc']) {
        const tx = await start(evidence, ageOnly);
        await approve(tx, 'approve', ageOnly);
        const offered = await post(
          '/identity/poll',
          { transaction_id: tx.transaction_id, poll_secret: tx.poll_secret },
          {},
          ageOnly,
        );
        assert.equal(offered.status, 200);
        const offer = ((await offered.json()) as any).credential_offer;
        const token = await ageOnly.fetch(`${issuer}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code':
              offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
                'pre-authorized_code'
              ],
          }).toString(),
        });
        assert.equal(token.status, 200);
        const access = ((await token.json()) as any).access_token;
        const nonce = (
          (await (await ageOnly.fetch(`${issuer}/nonce`, { method: 'POST' })).json()) as any
        ).c_nonce;
        const proof = await new SignJWT({ aud: issuer, iat: Math.floor(Date.now() / 1000), nonce })
          .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: holder })
          .sign(wallet.privateKey);
        const issued = await post(
          '/identity/issuer/credential',
          { credential_configuration_id: configuration, proofs: { jwt: [proof] } },
          { Authorization: `Bearer ${access}` },
          ageOnly,
        );
        assert.equal(issued.status, 200, await issued.clone().text());
        receipts[configuration] = ((await issued.json()) as any).credentials[0].credential;
      }
      const vectors = agePresentationVectors({
        sd: receipts.linked_document,
        mdoc: receipts.linked_document_mdoc,
        holder_private_jwk: { ...(await exportJWK(wallet.privateKey)), kid: 'fixture-holder' },
        issuer_kid: 'document-issuer',
      });
      await verifyAgePresentations(vectors, ['age_over_18']);
    }
    const batchWorker = harness.getWorker('identity-age-batch');
    const batchMetadata = (await (
      await batchWorker.fetch(`${root}/.well-known/openid-credential-issuer/identity/issuer`)
    ).json()) as any;
    assert.deepEqual(batchMetadata.mikaki_age_batch_intake, { batch_size: 8 });
    assert.equal(
      batchMetadata.batch_credential_issuance,
      undefined,
      'intake extension does not advertise HAIP batch support',
    );
    const batchKeys = await Promise.all(
      Array.from({ length: 8 }, () => generateKeyPair('ES256', { extractable: true })),
    );
    const batchHolders = await Promise.all(batchKeys.map((k) => exportJWK(k.publicKey)));
    for (const target of [worker, ageOnly, harness.getWorker('identity-haip')]) {
      assert.equal(
        (
          await post(
            '/identity/intake',
            {
              evidence: f.makeMnc(),
              holder_jwks: batchHolders.slice(0, 2),
              credential_configuration_id: 'linked_document',
            },
            {},
            target,
          )
        ).status,
        400,
      );
    }
    for (const keys of [
      [],
      batchHolders.slice(0, 1),
      [...batchHolders, batchHolders[0]],
      [batchHolders[0], batchHolders[0]],
    ]) {
      assert.equal(
        (
          await post(
            '/identity/intake',
            {
              evidence: f.makeMnc(),
              holder_jwks: keys,
              credential_configuration_id: 'linked_document',
            },
            {},
            batchWorker,
          )
        ).status,
        400,
      );
    }
    for (const decision of ['deny', 'link']) {
      const response = await post(
        '/identity/intake',
        {
          evidence: f.makeMnc(),
          holder_jwks: batchHolders.slice(0, 2),
          credential_configuration_id: 'linked_document',
        },
        {},
        batchWorker,
      );
      assert.equal(response.status, 200);
      const tx = (await response.json()) as any;
      await approve(tx, decision, batchWorker);
      const polled = await post(
        '/identity/poll',
        { transaction_id: tx.transaction_id, poll_secret: tx.poll_secret },
        {},
        batchWorker,
      );
      assert.equal(
        polled.status,
        decision === 'deny' ? 403 : 404,
        'denial/link-only approval grants no batch issuance',
      );
    }
    for (const configuration of ['linked_document', 'linked_document_mdoc']) {
      for (const size of [2, 8]) {
        const intake = await post(
          '/identity/intake',
          {
            evidence: size === 2 ? f.makeMnc() : f.makeLicense(),
            holder_jwks: batchHolders.slice(0, size),
            credential_configuration_id: configuration,
          },
          {},
          batchWorker,
        );
        assert.equal(intake.status, 200, await intake.clone().text());
        const started = (await intake.json()) as any;
        assert.equal(started.credential_count, size);
        assert.deepEqual(
          started.holder_thumbprints,
          await Promise.all(batchHolders.slice(0, size).map((key) => calculateJwkThumbprint(key))),
        );
        const page = await batchWorker.fetch(started.approval_url, {
          headers: { Cookie: '__Host-op-sso=owner-cookie' },
        });
        assert.equal(page.status, 200);
        const html = await page.text();
        assert.ok(
          html.includes(`証明書を${size}件`) &&
            html.includes(configuration === 'linked_document' ? 'SD-JWT' : 'mdoc') &&
            html.includes('18歳以上である'),
        );
        for (const thumbprint of started.holder_thumbprints) assert.ok(html.includes(thumbprint));
        // Withdrawal or a profile change invalidates the exact batch grant, even before approval.
        assert.equal(
          (
            await harness
              .getWorker('identity-age-batch-changed')
              .fetch(started.approval_url, { headers: { Cookie: '__Host-op-sso=owner-cookie' } })
          ).status,
          403,
        );
        // The failed request replaced the CSRF token; read a fresh review before submitting.
        await approve(started, 'approve', batchWorker);
        const offered = await post(
          '/identity/poll',
          { transaction_id: started.transaction_id, poll_secret: started.poll_secret },
          {},
          batchWorker,
        );
        const offer = ((await offered.json()) as any).credential_offer;
        const token = await batchWorker.fetch(`${issuer}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code':
              offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
                'pre-authorized_code'
              ],
          }).toString(),
        });
        assert.equal(token.status, 200);
        const access = ((await token.json()) as any).access_token;
        const nonce = (
          (await (await batchWorker.fetch(`${issuer}/nonce`, { method: 'POST' })).json()) as any
        ).c_nonce;
        const proofs = await Promise.all(
          batchKeys.slice(0, size).map((k, i) =>
            new SignJWT({ aud: issuer, iat: Math.floor(Date.now() / 1000), nonce })
              .setProtectedHeader({
                typ: 'openid4vci-proof+jwt',
                alg: 'ES256',
                jwk: batchHolders[i],
              })
              .sign(k.privateKey),
          ),
        );
        const wrongNonce = await new SignJWT({
          aud: issuer,
          iat: Math.floor(Date.now() / 1000),
          nonce: secret(),
        })
          .setProtectedHeader({
            typ: 'openid4vci-proof+jwt',
            alg: 'ES256',
            jwk: batchHolders[size - 1],
          })
          .sign(batchKeys[size - 1].privateKey);
        const request = { credential_configuration_id: configuration, proofs: { jwt: proofs } };
        const issue = (body = request, target = batchWorker) =>
          post('/identity/issuer/credential', body, { Authorization: `Bearer ${access}` }, target);
        for (const bad of [
          { ...request, proofs: { jwt: [...proofs.slice(0, -1), wrongNonce] } },
          { ...request, proofs: { jwt: [...proofs.slice(0, -1), 'invalid'] } },
          { ...request, proofs: { jwt: [...proofs, proofs[0]] } },
          { ...request, proofs: { jwt: proofs.slice(0, -1) } },
          { ...request, proofs: { jwt: [proofs[1], proofs[0], ...proofs.slice(2)] } },
          {
            ...request,
            credential_configuration_id:
              configuration === 'linked_document' ? 'linked_document_mdoc' : 'linked_document',
          },
        ]) {
          assert.equal((await issue(bad)).status, 400);
        }
        assert.equal(
          (await issue(request, ageOnly)).status,
          400,
          'flag withdrawal blocks issuance',
        );
        assert.equal(
          (await issue(request, harness.getWorker('identity-age-batch-changed'))).status,
          400,
          'changed attributes block issuance',
        );
        assert.equal(
          (
            (await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?')
              .bind(hash(nonce))
              .first()) as any
          ).used,
          0,
          'validation failure consumes no grant or nonce',
        );
        let received: any;
        if (size === 8) {
          const recipient = await generateKeyPair('ECDH-ES', { extractable: true });
          const jwk = {
            ...(await exportJWK(recipient.publicKey)),
            kid: 'batch-response',
            alg: 'ECDH-ES',
            use: 'enc',
          };
          const requestJwk = batchMetadata.credential_request_encryption.jwks.keys[0];
          const wire = await new CompactEncrypt(
            Buffer.from(
              JSON.stringify({
                ...request,
                credential_response_encryption: { jwk, enc: 'A256GCM' },
              }),
            ),
          )
            .setProtectedHeader({
              alg: 'ECDH-ES',
              enc: 'A256GCM',
              kid: requestJwk.kid,
              cty: 'json',
            })
            .encrypt(await importJWK(requestJwk, 'ECDH-ES'));
          const result = await batchWorker.fetch(`${issuer}/credential`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/jwt', Authorization: `Bearer ${access}` },
            body: wire,
          });
          assert.equal(result.status, 200, await result.clone().text());
          received = JSON.parse(
            Buffer.from(
              (await compactDecrypt(await result.text(), recipient.privateKey)).plaintext,
            ).toString(),
          );
        } else {
          const results = await Promise.all([issue(), issue()]);
          assert.equal(
            results.filter((r) => r.status === 200).length,
            1,
            'one atomic batch wins concurrent issuance',
          );
          assert.ok(results.every((r) => [200, 401, 409].includes(r.status)));
          received = await results.find((r) => r.status === 200)!.json();
        }
        assert.equal(received.credentials.length, size);
        const salts = new Set<string>();
        for (let i = 0; i < size; i++) {
          const credential = received.credentials[i].credential;
          if (configuration === 'linked_document') {
            const { payload } = await jwtVerify(credential.split('~')[0], op.publicKey, { issuer });
            assert.deepEqual((payload.cnf as any).jwk, batchHolders[i]);
            assert.ok((payload.exp as number) <= Math.floor(Date.now() / 1000) + 300);
            assert.equal(
              credential.split('~').slice(1).filter(Boolean).length,
              1,
              'the batch contains only its approved age claim',
            );
            const disclosure = JSON.parse(
              Buffer.from(credential.split('~')[1], 'base64url').toString(),
            );
            assert.equal(disclosure[1], 'age_over_18');
            assert.equal(disclosure[2], true);
            salts.add(disclosure[0]);
          } else {
            const verified = verifyMdocIssuer(
              credential,
              batchHolders[i],
              await exportJWK(op.publicKey),
            );
            assert.deepEqual(verified.values, { age_over_18: true });
          }
        }
        if (configuration === 'linked_document')
          assert.equal(salts.size, size, 'each credential has independent disclosure entropy');
        assert.equal(new Set(received.credentials.map((c: any) => c.credential)).size, size);
        assert.equal(
          (
            (await DB.prepare('SELECT state,access_hash FROM identity_transaction WHERE tx_id=?')
              .bind(started.transaction_id)
              .first()) as any
          ).state,
          'issued',
        );
        assert.equal(
          (
            (await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?')
              .bind(hash(nonce))
              .first()) as any
          ).used,
          1,
        );
        assert.equal(
          (await issue()).status,
          401,
          'no refill or second batch after successful/unknown delivery',
        );
      }
    }
    // A separate wallet owns its own private key: the original reading app key is never exported.
    const external = harness.getWorker('identity-wallet');
    const changedWallet = harness.getWorker('identity-wallet-changed');
    const externalKey = await generateKeyPair('ES256', { extractable: true });
    const externalHolder = await exportJWK(externalKey.publicKey);
    assert.notDeepEqual(externalHolder, holder);
    const authMetadata = await external.fetch(
      `${root}/.well-known/oauth-authorization-server/identity/issuer`,
    );
    const authSettings = (await authMetadata.json()) as any;
    assert.equal(authSettings.authorization_endpoint, `${issuer}/authorize`);
    assert.deepEqual(authSettings.code_challenge_methods_supported, ['S256']);
    assert.equal(authSettings.pushed_authorization_request_endpoint, `${issuer}/par`);
    assert.deepEqual(authSettings.dpop_signing_alg_values_supported, ['ES256']);
    assert.ok(authSettings.grant_types_supported.includes('authorization_code'));
    const ordinaryMetadata = (await (
      await worker.fetch(`${root}/.well-known/oauth-authorization-server/identity/issuer`)
    ).json()) as any;
    assert.equal(ordinaryMetadata.authorization_endpoint, undefined);
    assert.equal((await worker.fetch(`${issuer}/authorize`)).status, 404);
    const ownerHeaders = { Cookie: '__Host-op-sso=owner-cookie' };
    const beginWallet = async (configuration: string, overrides = {}, target = external) => {
      const verifier = secret();
      const state = 'wallet state / + & 日本語';
      const parameters = {
        response_type: 'code',
        client_id: walletClient.client_id,
        redirect_uri: walletClient.redirect_uri,
        scope: configuration,
        state,
        code_challenge: hash(verifier),
        code_challenge_method: 'S256',
        resource: issuer,
        ...overrides,
      };
      const url = `${issuer}/authorize?${new URLSearchParams(parameters)}`;
      const page = await target.fetch(url, { headers: ownerHeaders });
      return { page, html: await page.text(), url, verifier, state };
    };
    const consent = async (
      flow: Awaited<ReturnType<typeof beginWallet>>,
      document: string,
      decision = 'approve',
    ) => {
      assert.equal(flow.page.status, 200, flow.html);
      const html = flow.html;
      assert.ok(html.includes('Independent test wallet'));
      assert.ok(!html.includes('checked'));
      const grant = /name=grant value='([^']+)'/.exec(html)![1];
      const csrf = /name=csrf value='([^']+)'/.exec(html)![1];
      const submit = (patch = {}, cookie = 'owner-cookie', origin = root, target = external) =>
        target.fetch(`${issuer}/authorize`, {
          redirect: 'manual',
          method: 'POST',
          headers: {
            Cookie: `__Host-op-sso=${cookie}`,
            Origin: origin,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({ grant, csrf, document, decision, ...patch }).toString(),
        });
      assert.equal((await submit({}, 'owner-cookie', 'https://evil.example')).status, 403);
      assert.equal((await submit({}, 'other-cookie')).status, 409);
      assert.equal((await submit({ csrf: secret() })).status, 409);
      if (decision === 'approve') assert.equal((await submit({ document: secret() })).status, 409);
      assert.equal((await submit({}, 'owner-cookie', root, changedWallet)).status, 409);
      const response = await submit();
      assert.equal(response.status, 303, await response.clone().text());
      if (decision === 'approve') {
        const lifetime = await DB.prepare(
          'SELECT expires_at-unixepoch() AS remaining FROM identity_wallet_grant WHERE grant_id=?',
        )
          .bind(grant)
          .first('remaining');
        assert.ok(
          typeof lifetime === 'number' && lifetime >= 88 && lifetime <= 90,
          'public Wallet codes retain their 90-second lifetime',
        );
      }
      assert.equal((await submit()).status, 409);
      const callback = new URL(response.headers.get('location')!);
      assert.equal(callback.origin + callback.pathname, walletClient.redirect_uri);
      assert.equal(callback.searchParams.get('state'), flow.state);
      assert.equal(callback.searchParams.get('iss'), issuer);
      return { grant, flow, callback };
    };
    const walletToken = (
      flow: Awaited<ReturnType<typeof consent>>,
      patch = {},
      target = external,
    ) =>
      target.fetch(`${issuer}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: flow.callback.searchParams.get('code')!,
          client_id: walletClient.client_id,
          redirect_uri: walletClient.redirect_uri,
          code_verifier: flow.flow.verifier,
          ...patch,
        }).toString(),
      });
    const walletProof = (
      nonce: string,
      claims = {},
      key = externalKey.privateKey,
      jwk = externalHolder,
    ) =>
      new SignJWT({ aud: issuer, iat: Math.floor(Date.now() / 1000), nonce, ...claims })
        .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk })
        .sign(key);
    const walletIssue = (access: string, configuration: string, proof: string, target = external) =>
      post(
        '/identity/issuer/credential',
        { credential_configuration_id: configuration, proofs: { jwt: [proof] } },
        { Authorization: `Bearer ${access}` },
        target,
      );
    for (const configuration of ['linked_document', 'linked_document_mdoc']) {
      const linked = await start(f.makeMnc());
      await approve(linked, 'link');
      assert.equal(
        (
          await post('/identity/poll', {
            transaction_id: linked.transaction_id,
            poll_secret: linked.poll_secret,
          })
        ).status,
        404,
      );
      const document = linked.transaction_id;
      const initialCount = await DB.prepare('SELECT count(*) AS n FROM identity_document').first(
        'n',
      );
      assert.equal(
        (await beginWallet(configuration, { redirect_uri: 'https://evil.example/callback' })).page
          .status,
        400,
      );
      assert.equal(
        (await beginWallet(configuration, { code_challenge_method: 'plain' })).page.status,
        400,
      );
      assert.equal(
        (await beginWallet(configuration, { resource: 'https://evil.example' })).page.status,
        400,
      );
      assert.equal(
        (await beginWallet(configuration, { authorization_details: '[]' })).page.status,
        400,
      );
      assert.equal((await beginWallet('linked_document linked_document_mdoc')).page.status, 400);
      const pending = await beginWallet(configuration);
      assert.equal((await external.fetch(pending.url)).status, 401);
      assert.equal(
        (await external.fetch(`${pending.url}&client_id=evil`, { headers: ownerHeaders })).status,
        400,
      );
      const denied = await consent(await beginWallet(configuration), document, 'deny');
      assert.equal(denied.callback.searchParams.get('error'), 'access_denied');
      assert.equal(denied.callback.searchParams.get('code'), null);
      let flow = await consent(pending, document);
      assert.equal((await walletToken(flow, { code_verifier: secret() })).status, 400);
      assert.equal((await walletToken(flow, { client_id: 'another-wallet' })).status, 400);
      assert.equal(
        (await walletToken(flow, { redirect_uri: 'https://wallet.example/other' })).status,
        400,
      );
      assert.equal((await walletToken(flow, {}, changedWallet)).status, 400);
      for (const parameter of ['code', 'grant_type']) {
        const tokenForm = new URLSearchParams({
          grant_type: 'authorization_code',
          code: flow.callback.searchParams.get('code')!,
          client_id: walletClient.client_id,
          redirect_uri: walletClient.redirect_uri,
          code_verifier: flow.flow.verifier,
        });
        tokenForm.append(parameter, tokenForm.get(parameter)!);
        const duplicate = await external.fetch(`${issuer}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: tokenForm.toString(),
        });
        assert.equal(duplicate.status, 400);
      }
      const missingVerifier = await external.fetch(`${issuer}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: flow.callback.searchParams.get('code')!,
          client_id: walletClient.client_id,
          redirect_uri: walletClient.redirect_uri,
        }).toString(),
      });
      assert.equal(missingVerifier.status, 400);
      assert.equal(((await missingVerifier.json()) as any).error, 'invalid_grant');
      const tokenRace = await Promise.all([walletToken(flow), walletToken(flow)]);
      assert.deepEqual(tokenRace.map((r) => r.status).sort(), [200, 400]);
      const racedToken = (await tokenRace.find((r) => r.status === 200)!.json()) as any;
      assert.equal(racedToken.scope, configuration);
      assert.equal(
        (await walletIssue(racedToken.access_token, configuration, await walletProof(secret())))
          .status,
        401,
        'authenticated concurrent code reuse revokes even a single-credential grant',
      );
      flow = await consent(await beginWallet(configuration), document);
      const tokenResponse = await walletToken(flow);
      assert.equal(tokenResponse.status, 200);
      const token = (await tokenResponse.json()) as any;
      for (const patch of [
        { code_verifier: secret() },
        { client_id: 'another-wallet' },
        { redirect_uri: 'https://wallet.example/other' },
      ]) {
        assert.equal((await walletToken(flow, patch)).status, 400);
        assert.equal(
          await DB.prepare('SELECT state FROM identity_wallet_grant WHERE grant_id=?')
            .bind(flow.grant)
            .first('state'),
          'token',
        );
      }
      const nonce = (
        (await (await external.fetch(`${issuer}/nonce`, { method: 'POST' })).json()) as any
      ).c_nonce;
      const validProof = await walletProof(
        nonce,
        configuration === 'linked_document' ? { iss: walletClient.client_id } : {},
      );
      const unknownNonceProof = await walletProof('00000000-0000-4000-8000-000000000000');
      const forgedNonceProof = unknownNonceProof.split('.');
      forgedNonceProof[2] = Buffer.alloc(64).toString('base64url');
      for (const [requestBody, expectedError] of [
        [{ credential_configuration_id: configuration }, 'invalid_proof'],
        [{ credential_configuration_id: configuration, proofs: null }, 'invalid_proof'],
        [{ credential_configuration_id: configuration, proofs: 'jwt' }, 'invalid_proof'],
        [{ credential_configuration_id: configuration, proofs: {} }, 'invalid_proof'],
        [{ credential_configuration_id: configuration, proofs: { jwt: [42] } }, 'invalid_proof'],
        [
          {
            credential_configuration_id: configuration,
            proofs: { jwt: [validProof], unsupported: [] },
          },
          'invalid_proof',
        ],
        [{ credential_configuration_id: configuration, proofs: { jwt: [] } }, 'invalid_proof'],
        [
          { credential_configuration_id: configuration, proofs: { jwt: [validProof, validProof] } },
          'invalid_proof',
        ],
        [
          { credential_configuration_id: 'unknown', proofs: { jwt: [validProof] } },
          'unknown_credential_configuration',
        ],
        [
          { credential_identifier: 'unknown', proofs: { jwt: [validProof] } },
          'unknown_credential_identifier',
        ],
        [
          {
            credential_configuration_id: configuration,
            credential_identifier: 'unknown',
            proofs: { jwt: [validProof] },
          },
          'invalid_credential_request',
        ],
        [{ proofs: { jwt: [validProof] } }, 'invalid_credential_request'],
        [
          { credential_configuration_id: configuration, proofs: { jwt: [unknownNonceProof] } },
          'invalid_nonce',
        ],
        [
          {
            credential_configuration_id: configuration,
            proofs: { jwt: [forgedNonceProof.join('.')] },
          },
          'invalid_proof',
        ],
        [
          {
            credential_configuration_id: configuration,
            proofs: { jwt: [await walletProof(nonce, { nonce: undefined })] },
          },
          'invalid_proof',
        ],
      ] as const) {
        const rejection = await post(
          '/identity/issuer/credential',
          requestBody,
          { Authorization: `Bearer ${token.access_token}` },
          external,
        );
        assert.equal(rejection.status, 400);
        assert.equal(((await rejection.json()) as any).error, expectedError);
      }
      const duplicateProof = await external.fetch(`${issuer}/credential`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token.access_token}`,
        },
        body: `{"credential_configuration_id":${JSON.stringify(configuration)},"proofs":{"jwt":[${JSON.stringify(validProof)}],"jwt":[${JSON.stringify(validProof)}]}}`,
      });
      assert.equal(duplicateProof.status, 400);
      assert.equal(((await duplicateProof.json()) as any).error, 'invalid_proof');
      assert.equal(
        await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?')
          .bind(hash(nonce))
          .first('used'),
        0,
        'Rejected credential requests must preserve the valid holder nonce and token',
      );
      assert.equal(
        (
          await walletIssue(
            token.access_token,
            configuration,
            await walletProof(nonce, { iss: 'wrong-client' }),
          )
        ).status,
        400,
      );
      assert.equal(
        (
          await walletIssue(
            token.access_token,
            configuration,
            await walletProof(nonce, {}, wallet.privateKey, externalHolder),
          )
        ).status,
        400,
      );
      assert.equal(
        (await walletIssue(token.access_token, configuration, await walletProof(secret()))).status,
        400,
      );
      assert.equal(
        (await walletIssue(token.access_token, configuration, validProof, changedWallet)).status,
        401,
      );
      const otherConfiguration =
        configuration === 'linked_document' ? 'linked_document_mdoc' : 'linked_document';
      assert.equal(
        (await walletIssue(token.access_token, otherConfiguration, validProof)).status,
        401,
      );
      const issuanceRace = await Promise.all([
        walletIssue(token.access_token, configuration, validProof),
        walletIssue(token.access_token, configuration, validProof),
      ]);
      assert.equal(issuanceRace.filter((r) => r.status === 200).length, 1);
      assert.ok(
        issuanceRace
          .filter((r) => r.status !== 200)
          .every((r) => r.status === 409 || r.status === 401),
      );
      const receipt = ((await issuanceRace.find((r) => r.status === 200)!.json()) as any)
        .credentials[0].credential;
      if (configuration === 'linked_document') {
        const jwt = await jwtVerify(receipt.split('~')[0], op.publicKey);
        assert.deepEqual(jwt.payload.cnf, { jwk: externalHolder });
      } else {
        verifyMdocIssuer(receipt, externalHolder, await exportJWK(op.publicKey));
        const publicIssuer = await exportJWK(op.publicKey);
        assert.throws(() => verifyMdocIssuer(receipt, holder, publicIssuer));
      }
      const saved = await DB.prepare(
        'SELECT holder_json,access_hash FROM identity_wallet_grant WHERE grant_id=?',
      )
        .bind(flow.grant)
        .first();
      assert.deepEqual(JSON.parse(saved!.holder_json as string), externalHolder);
      assert.equal(saved!.access_hash, null);
      assert.equal(
        await DB.prepare('SELECT count(*) AS n FROM identity_document').first('n'),
        initialCount,
      );
      assert.equal(
        await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?')
          .bind(hash(nonce))
          .first('used'),
        1,
      );
      for (const expireStage of ['code', 'token', 'account']) {
        const expired = await consent(await beginWallet(configuration), document);
        if (expireStage === 'code') {
          await DB.prepare(
            'UPDATE identity_wallet_grant SET expires_at=unixepoch()-1 WHERE grant_id=?',
          )
            .bind(expired.grant)
            .run();
          assert.equal((await walletToken(expired)).status, 400);
        } else {
          const access = ((await (await walletToken(expired)).json()) as any).access_token;
          if (expireStage === 'token') {
            await DB.prepare(
              'UPDATE identity_wallet_grant SET token_expires_at=unixepoch()-1 WHERE grant_id=?',
            )
              .bind(expired.grant)
              .run();
          } else {
            await DB.prepare("UPDATE account_security SET active=0 WHERE account_id='owner'").run();
            await DB.prepare("UPDATE account_security SET active=1 WHERE account_id='owner'").run();
            assert.equal(
              await DB.prepare('SELECT count(*) AS n FROM identity_wallet_grant WHERE grant_id=?')
                .bind(expired.grant)
                .first('n'),
              0,
            );
          }
          assert.equal(
            (await walletIssue(access, configuration, await walletProof(nonce))).status,
            401,
          );
        }
      }
      for (const stage of ['offered', 'token']) {
        const fresh = await start(f.makeMnc());
        await approve(fresh);
        const unlinkDocument = fresh.transaction_id;
        const stale = await consent(await beginWallet(configuration), unlinkDocument);
        let access: string | undefined;
        if (stage === 'token')
          access = ((await (await walletToken(stale)).json()) as any).access_token;
        await DB.prepare(
          "UPDATE identity_document SET revoked=1,document_json='{}' WHERE document_id=?",
        )
          .bind(unlinkDocument)
          .run();
        assert.equal(
          await DB.prepare('SELECT count(*) AS n FROM identity_wallet_grant WHERE document_id=?')
            .bind(unlinkDocument)
            .first('n'),
          0,
        );
        if (access)
          assert.equal(
            (await walletIssue(access, configuration, await walletProof(nonce))).status,
            401,
          );
        else assert.equal((await walletToken(stale)).status, 400);
      }
    }
    let usedNonce: string | undefined;
    for (const [evidence, configuration] of [
      [f.makeLicense(), 'linked_document'],
      [f.makeMnc(), 'linked_document'],
      [f.makeLicense(), 'linked_document_mdoc'],
      [f.makeMnc(), 'linked_document_mdoc'],
    ] as const) {
      const tx = await start(evidence);
      assert.equal(
        (await post('/identity/poll', { transaction_id: tx.transaction_id, poll_secret: secret() }))
          .status,
        404,
      );
      assert.equal((await poll(tx)).status, 400); // strict body rejects unrelated approval_url
      const pollBody = { transaction_id: tx.transaction_id, poll_secret: tx.poll_secret };
      const pending = await post('/identity/poll', pollBody);
      assert.equal(pending.status, 200);
      assert.equal(((await pending.json()) as any).state, 'pending');
      await approve(tx);
      // Only poll secrets go to the issuer; approval URL is an app-side navigation value.
      const approved = await post('/identity/poll', pollBody);
      assert.equal(approved.status, 200);
      const offer = ((await approved.json()) as any).credential_offer;
      const code =
        offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
      const exchange = () =>
        worker.fetch(`${issuer}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': code,
          }).toString(),
        });
      const tokens = await Promise.all([exchange(), exchange()]);
      assert.deepEqual(tokens.map((r) => r.status).sort(), [200, 400]);
      const access = ((await tokens.find((r) => r.status === 200)!.json()) as any).access_token;
      assert.equal(
        (
          await post(
            '/identity/issuer/credential',
            { credential_configuration_id: 'linked_document', proofs: { jwt: [] } },
            { Authorization: `Bearer ${secret()}` },
          )
        ).status,
        400,
      );
      const nonceResponse = await worker.fetch(`${issuer}/nonce`, { method: 'POST' });
      assert.equal(nonceResponse.status, 200, await nonceResponse.clone().text());
      const nonce = ((await nonceResponse.json()) as any).c_nonce;
      const proof = (aud = issuer, key = wallet.privateKey, jwk = holder, cNonce = nonce) =>
        new SignJWT({ aud, iat: now, exp: now + 90, nonce: cNonce, jti: secret() })
          .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk })
          .sign(key);
      const issue = (proof: string) =>
        post(
          '/identity/issuer/credential',
          { credential_configuration_id: configuration, proofs: { jwt: [proof] } },
          { Authorization: `Bearer ${access}` },
        );
      assert.equal((await issue(await proof('https://evil.example'))).status, 400);
      const other = await generateKeyPair('ES256', { extractable: true });
      assert.equal(
        (await issue(await proof(issuer, other.privateKey, await exportJWK(other.publicKey))))
          .status,
        400,
      );
      if (usedNonce)
        assert.equal(
          (await issue(await proof(issuer, wallet.privateKey, holder, usedNonce))).status,
          400,
        );
      usedNonce = nonce;
      const validProof = await proof();
      const responses = await Promise.all([issue(validProof), issue(validProof)]);
      assert.equal(
        responses.filter((r) => r.status === 200).length,
        1,
        JSON.stringify(await Promise.all(responses.map((r) => r.clone().text()))),
      );
      const credential = ((await responses.find((r) => r.status === 200)!.json()) as any)
        .credentials[0].credential as string;
      if (configuration === 'linked_document_mdoc') {
        const verified = verifyMdocIssuer(credential, holder, await exportJWK(op.publicKey));
        assert.ok(verified.values.name);
        assert.ok(verified.values.address);
      } else {
        const [jwt, ...disclosures] = credential.split('~');
        const { payload } = await jwtVerify(jwt, op.publicKey, { issuer });
        assert.deepEqual(payload.cnf, { jwk: holder });
        assert.equal((payload.evidence as any).government_credential, false);
        assert.equal((payload.evidence as any).live_possession_verified, false);
        assert.equal(payload.exp! - payload.iat!, 300);
        assert.equal(payload.name, undefined);
        for (const d of disclosures.filter(Boolean)) {
          assert.ok((payload._sd as string[]).includes(hash(d)));
        }
      }
      const row = (await DB.prepare(
        'SELECT document_json FROM identity_document WHERE document_id=?',
      )
        .bind(tx.transaction_id)
        .first('document_json')) as string;
      assert.equal(row.includes('domicile'), false);
      assert.equal(row.includes('photo'), false);
      assert.equal(row.includes('signature'), false);
      assert.equal(row.includes('attributes'), true);
      assert.equal(
        (
          await post(
            '/identity/issuer/credential',
            { credential_configuration_id: 'linked_document', proofs: { jwt: [validProof] } },
            { Authorization: `Bearer ${secret()}` },
          )
        ).status,
        401,
      );
      const otherDelete = await worker.fetch(`${root}/identity/documents/${tx.transaction_id}`, {
        method: 'DELETE',
        headers: { Origin: root, Cookie: '__Host-op-sso=other-cookie' },
      });
      assert.equal(otherDelete.status, 404);
      const management = await worker.fetch(`${root}/identity`, {
        headers: { Cookie: '__Host-op-sso=owner-cookie' },
      });
      assert.equal(management.status, 200);
      const manageHtml = await management.text();
      assert.match(manageHtml, /紐付けを解除し属性を削除/);
      const deleteCsrf = new RegExp(
        `name=document value='${tx.transaction_id}'><input type=hidden name=csrf value='([^']+)'`,
      ).exec(manageHtml)![1];
      assert.equal(
        (
          await worker.fetch(`${root}/identity/erase`, {
            method: 'POST',
            headers: {
              Origin: root,
              Cookie: '__Host-op-sso=owner-cookie',
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({ document: tx.transaction_id, csrf: secret() }).toString(),
          })
        ).status,
        403,
      );
      const deleted =
        evidence.document_type === 'my_number_card'
          ? await worker.fetch(`${root}/identity/erase`, {
              method: 'POST',
              headers: {
                Origin: root,
                Cookie: '__Host-op-sso=owner-cookie',
                'Content-Type': 'application/x-www-form-urlencoded',
              },
              body: new URLSearchParams({
                document: tx.transaction_id,
                csrf: deleteCsrf,
              }).toString(),
              redirect: 'manual',
            })
          : await worker.fetch(`${root}/identity/documents/${tx.transaction_id}`, {
              method: 'DELETE',
              headers: { Origin: root, Cookie: '__Host-op-sso=owner-cookie' },
            });
      assert.equal(deleted.status, evidence.document_type === 'my_number_card' ? 303 : 200);
      assert.equal(
        await DB.prepare('SELECT document_json FROM identity_transaction WHERE tx_id=?')
          .bind(tx.transaction_id)
          .first('document_json'),
        '{}',
      );
      assert.equal(
        await DB.prepare('SELECT document_json FROM identity_document WHERE document_id=?')
          .bind(tx.transaction_id)
          .first('document_json'),
        '{}',
      );
    }
    // Erasure must invalidate grants before issuance, not merely scrub an issued row.
    for (const configuration of ['linked_document', 'linked_document_mdoc']) {
      for (const stage of ['approved', 'offered', 'token']) {
        const tx = await start(f.makeMnc());
        await approve(tx);
        const pollBody = { transaction_id: tx.transaction_id, poll_secret: tx.poll_secret };
        let code: string | undefined;
        let access: string | undefined;
        const exchange = () =>
          worker.fetch(`${issuer}/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
              'pre-authorized_code': code!,
            }).toString(),
          });
        if (stage !== 'approved') {
          const offerResponse = await post('/identity/poll', pollBody);
          assert.equal(offerResponse.status, 200);
          const offer = ((await offerResponse.json()) as any).credential_offer;
          code =
            offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
              'pre-authorized_code'
            ];
        }
        if (stage === 'token') {
          const token = await exchange();
          assert.equal(token.status, 200);
          access = ((await token.json()) as any).access_token;
        }
        const nonceResponse = await worker.fetch(`${issuer}/nonce`, { method: 'POST' });
        const nonce = ((await nonceResponse.json()) as any).c_nonce;
        const proof = await new SignJWT({
          aud: issuer,
          iat: now,
          exp: now + 90,
          nonce,
          jti: secret(),
        })
          .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: holder })
          .sign(wallet.privateKey);
        const erased = await worker.fetch(`${root}/identity/documents/${tx.transaction_id}`, {
          method: 'DELETE',
          headers: { Origin: root, Cookie: '__Host-op-sso=owner-cookie' },
        });
        assert.equal(erased.status, 200);
        assert.equal((await post('/identity/poll', pollBody)).status, 404);
        if (code) assert.equal((await exchange()).status, 400);
        if (access)
          assert.equal(
            (
              await post(
                '/identity/issuer/credential',
                {
                  credential_configuration_id: configuration,
                  proofs: { jwt: [proof] },
                },
                { Authorization: `Bearer ${access}` },
              )
            ).status,
            401,
          );
        const transaction = await DB.prepare(
          'SELECT document_json,offer_hash,access_hash,csrf_hash FROM identity_transaction WHERE tx_id=?',
        )
          .bind(tx.transaction_id)
          .first();
        assert.deepEqual(transaction, {
          document_json: '{}',
          offer_hash: null,
          access_hash: null,
          csrf_hash: null,
        });
        const document = await DB.prepare(
          'SELECT document_json,revoked FROM identity_document WHERE document_id=?',
        )
          .bind(tx.transaction_id)
          .first();
        assert.deepEqual(document, { document_json: '{}', revoked: 1 });
        assert.equal(
          await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?')
            .bind(hash(nonce))
            .first('used'),
          0,
        );
      }
    }
    for (const configuration of ['linked_document', 'linked_document_mdoc']) {
      for (const bound of ['linkage', 'trusted-key']) {
        const target = bound === 'trusted-key' ? harness.getWorker('identity-short-trust') : worker;
        const tx = await start(f.makeMnc(), target);
        await approve(tx, 'approve', target);
        const deadline =
          bound === 'trusted-key' ? trustDeadline : Math.floor(Date.now() / 1000) + 30;
        if (bound === 'linkage')
          await DB.prepare('UPDATE identity_document SET valid_until=? WHERE document_id=?')
            .bind(deadline, tx.transaction_id)
            .run();
        const approved = await post(
          '/identity/poll',
          { transaction_id: tx.transaction_id, poll_secret: tx.poll_secret },
          {},
          target,
        );
        assert.equal(approved.status, 200);
        const code = ((await approved.json()) as any).credential_offer.grants[
          'urn:ietf:params:oauth:grant-type:pre-authorized_code'
        ]['pre-authorized_code'];
        const token = await target.fetch(`${issuer}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': code,
          }).toString(),
        });
        assert.equal(token.status, 200);
        const access = ((await token.json()) as any).access_token;
        const nonceResponse = await target.fetch(`${issuer}/nonce`, { method: 'POST' });
        const nonce = ((await nonceResponse.json()) as any).c_nonce;
        const issuedAt = Math.floor(Date.now() / 1000);
        const proof = await new SignJWT({
          aud: issuer,
          iat: issuedAt,
          exp: issuedAt + 90,
          nonce,
          jti: secret(),
        })
          .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: holder })
          .sign(wallet.privateKey);
        const issued = await post(
          '/identity/issuer/credential',
          { credential_configuration_id: configuration, proofs: { jwt: [proof] } },
          { Authorization: `Bearer ${access}` },
          target,
        );
        assert.equal(issued.status, 200, await issued.clone().text());
        const credential = ((await issued.json()) as any).credentials[0].credential;
        if (configuration === 'linked_document') {
          const { payload } = await jwtVerify(credential.split('~')[0], op.publicKey, { issuer });
          assert.equal(payload.exp, deadline);
          assert.ok(payload.exp! - payload.iat! < 300);
        } else {
          const result = verifyMdocIssuer(credential, holder, await exportJWK(op.publicKey));
          assert.ok(result.mso instanceof Map);
          const validity = result.mso.get('validityInfo') as Map<
            string,
            { tag: number; value: string }
          >;
          assert.equal(Math.floor(Date.parse(validity.get('validUntil')!.value) / 1000), deadline);
        }
      }
    }
    const corrupt = f.makeLicense();
    corrupt.photo[10] ^= 1;
    assert.equal(
      (await post('/identity/intake', { evidence: corrupt, holder_jwk: holder })).status,
      422,
    );
    const pin1Only = f.makeLicense();
    pin1Only.domicile = [];
    pin1Only.photo = [];
    assert.equal(
      (await post('/identity/intake', { evidence: pin1Only, holder_jwk: holder })).status,
      422,
    );
    const denied = await start(f.makeMnc());
    await approve(denied, 'deny');
    assert.equal(
      (
        await post('/identity/poll', {
          transaction_id: denied.transaction_id,
          poll_secret: denied.poll_secret,
        })
      ).status,
      403,
    );
    const stale = await start(f.makeMnc());
    await approve(stale);
    const approved = await post('/identity/poll', {
      transaction_id: stale.transaction_id,
      poll_secret: stale.poll_secret,
    });
    const offer = ((await approved.json()) as any).credential_offer;
    await DB.prepare("UPDATE account_security SET epoch=2 WHERE account_id='owner'").run();
    const staleToken = await worker.fetch(`${issuer}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code':
          offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
            'pre-authorized_code'
          ],
      }).toString(),
    });
    assert.equal(staleToken.status, 400);
    const discovery = await worker.fetch(
      `${root}/.well-known/openid-credential-issuer/identity/issuer`,
    );
    assert.equal(discovery.status, 200);
    const keyset = await worker.fetch(`${issuer}/jwks`);
    assert.equal(keyset.status, 200);
    assert.equal(((await keyset.json()) as any).keys[0].d, undefined);
    // Exercise PAR and DPoP independently of the opt-in upstream SDK test.
    await DB.prepare("UPDATE account_security SET epoch=1 WHERE account_id='owner'").run();
    const parDocument = await start(f.makeMnc());
    await approve(parDocument, 'link');
    const verifier = secret();
    const state = secret();
    const parParameters = {
      response_type: 'code',
      client_id: walletClient.client_id,
      redirect_uri: walletClient.redirect_uri,
      scope: 'linked_document',
      state,
      code_challenge: hash(verifier),
      code_challenge_method: 'S256',
    };
    const push = (parameters = parParameters) =>
      external.fetch(`${issuer}/par`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(parameters).toString(),
      });
    assert.equal(
      (await push({ ...parParameters, redirect_uri: 'https://evil.example/callback' })).status,
      400,
    );
    const duplicatePar = new URLSearchParams(parParameters);
    duplicatePar.append('scope', 'linked_document_mdoc');
    assert.equal(
      (
        await external.fetch(`${issuer}/par`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: duplicatePar.toString(),
        })
      ).status,
      400,
    );
    const stalePar = await push();
    assert.equal(stalePar.status, 201);
    const staleUri = ((await stalePar.json()) as any).request_uri;
    await DB.prepare('UPDATE identity_wallet_par SET expires_at=unixepoch()-1 WHERE request_hash=?')
      .bind(hash(staleUri.split(':').at(-1)!))
      .run();
    const expiredReference = await external.fetch(
      `${issuer}/authorize?${new URLSearchParams({ client_id: walletClient.client_id, request_uri: staleUri, redirect_uri: 'https://evil.example/callback', state: 'substituted' })}`,
      { headers: ownerHeaders, redirect: 'manual' },
    );
    assert.equal(expiredReference.status, 303);
    const expiryCallback = new URL(expiredReference.headers.get('location')!);
    assert.equal(expiryCallback.origin + expiryCallback.pathname, walletClient.redirect_uri);
    assert.equal(expiryCallback.searchParams.get('error'), 'invalid_request_uri');
    assert.equal(expiryCallback.searchParams.get('state'), state);
    assert.equal(expiryCallback.searchParams.has('code'), false);
    const expiredWrongClient = await external.fetch(
      `${issuer}/authorize?${new URLSearchParams({ client_id: 'unknown', request_uri: staleUri })}`,
      { redirect: 'manual' },
    );
    assert.equal(expiredWrongClient.status, 400);
    assert.equal(expiredWrongClient.headers.get('location'), null);
    for (const scenario of ['expires-before-consent', 'denied'] as const) {
      const pushed = await push();
      assert.equal(pushed.status, 201);
      const uri = ((await pushed.json()) as any).request_uri;
      const requestHash = hash(uri.split(':').at(-1)!);
      const url = `${issuer}/authorize?${new URLSearchParams({ client_id: walletClient.client_id, request_uri: uri })}`;
      const page = await external.fetch(url, { headers: ownerHeaders });
      assert.equal(page.status, 200);
      const html = await page.text();
      if (scenario === 'expires-before-consent') {
        await DB.prepare(
          'UPDATE identity_wallet_par SET expires_at=unixepoch()-1 WHERE request_hash=?',
        )
          .bind(requestHash)
          .run();
      }
      const decision = await external.fetch(`${issuer}/authorize`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          ...ownerHeaders,
          Origin: root,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant: /name=grant value='([^']+)'/.exec(html)![1],
          csrf: /name=csrf value='([^']+)'/.exec(html)![1],
          document: parDocument.transaction_id,
          decision: scenario === 'denied' ? 'deny' : 'approve',
        }).toString(),
      });
      assert.equal(decision.status, scenario === 'denied' ? 303 : 409);
      assert.equal(
        await DB.prepare('SELECT used FROM identity_wallet_par WHERE request_hash=?')
          .bind(requestHash)
          .first('used'),
        scenario === 'denied' ? 1 : 0,
      );
      const retry = await external.fetch(url, { redirect: 'manual' });
      assert.equal(retry.status, 303);
      assert.equal(
        new URL(retry.headers.get('location')!).searchParams.get('error'),
        'invalid_request_uri',
      );
    }
    const pushed = await external.fetch(`${issuer}/par`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(parParameters).toString(),
    });
    assert.equal(pushed.status, 201, await pushed.clone().text());
    const pushedBody = (await pushed.json()) as any;
    const parUrl = `${issuer}/authorize?${new URLSearchParams({ client_id: walletClient.client_id, request_uri: pushedBody.request_uri })}`;
    assert.equal((await external.fetch(parUrl)).status, 401);
    const requestHash = hash(pushedBody.request_uri.split(':').at(-1)!);
    const parSnapshot = await DB.prepare('SELECT * FROM identity_wallet_par WHERE request_hash=?')
      .bind(requestHash)
      .first();
    const grantCount = await DB.prepare('SELECT count(*) AS n FROM identity_wallet_grant').first(
      'n',
    );
    const assertInvalidParReference = async (
      target: typeof external,
      clientId: string,
      label: string,
    ) => {
      const url = `${issuer}/authorize?${new URLSearchParams({ client_id: clientId, request_uri: pushedBody.request_uri })}`;
      const response = await target.fetch(url, {
        headers: { ...ownerHeaders, 'Accept-Language': 'en' },
        redirect: 'manual',
      });
      assert.equal(response.status, 400, label);
      assert.match(response.headers.get('content-type') ?? '', /^text\/html/i);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
      assert.match(response.headers.get('content-security-policy') ?? '', /default-src 'none'/);
      assert.equal(response.headers.get('location'), null, 'invalid PAR references never redirect');
      const html = await response.text();
      assert.match(html, /Invalid authorization request/);
      assert.match(html, /This authorization request link is invalid, expired, or already used/);
      assert.deepEqual(
        await DB.prepare('SELECT * FROM identity_wallet_par WHERE request_hash=?')
          .bind(requestHash)
          .first(),
        parSnapshot,
        'a wrong client must not consume or alter the stored PAR',
      );
      assert.equal(
        await DB.prepare('SELECT count(*) AS n FROM identity_wallet_grant').first('n'),
        grantCount,
        'a wrong client must not create an authorization grant',
      );
    };
    await assertInvalidParReference(
      external,
      otherWalletClient.client_id,
      'registered wrong client',
    );
    await assertInvalidParReference(external, 'unknown-wallet-client', 'unknown client');
    await assertInvalidParReference(changedWallet, walletClient.client_id, 'changed client policy');
    const parPage = await external.fetch(
      `${parUrl}&${new URLSearchParams({ scope: 'linked_document_mdoc', redirect_uri: 'https://evil.example/callback', state: 'substituted', code_challenge: secret() })}`,
      { headers: ownerHeaders },
    );
    assert.equal(parPage.status, 200);
    const parFlow = { page: parPage, html: await parPage.text(), url: parUrl, verifier, state };
    const secondPage = await external.fetch(parUrl, { headers: ownerHeaders });
    assert.equal(secondPage.status, 200, 'Opening PAR twice before approval must succeed');
    const secondHtml = await secondPage.text();
    const parHash = hash(pushedBody.request_uri.split(':').at(-1)!);
    assert.equal(
      await DB.prepare('SELECT used FROM identity_wallet_par WHERE request_hash=?')
        .bind(parHash)
        .first('used'),
      0,
    );
    const decisions = await Promise.all(
      [parFlow.html, secondHtml].map((html) =>
        external.fetch(`${issuer}/authorize`, {
          method: 'POST',
          redirect: 'manual',
          headers: {
            ...ownerHeaders,
            Origin: root,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            grant: /name=grant value='([^']+)'/.exec(html)![1],
            csrf: /name=csrf value='([^']+)'/.exec(html)![1],
            document: parDocument.transaction_id,
            decision: 'approve',
          }).toString(),
        }),
      ),
    );
    assert.deepEqual(
      decisions.map((r) => r.status).sort(),
      [303, 409],
      'Only one approval may consume a shared PAR',
    );
    const parConsent = {
      callback: new URL(decisions.find((r) => r.status === 303)!.headers.get('location')!),
    };
    assert.deepEqual(
      await DB.prepare('SELECT used,request_json FROM identity_wallet_par WHERE request_hash=?')
        .bind(parHash)
        .first(),
      { used: 1, request_json: '{}' },
    );
    const reused = await external.fetch(parUrl, { redirect: 'manual' });
    assert.equal(reused.status, 303);
    const reusedCallback = new URL(reused.headers.get('location')!);
    assert.equal(reusedCallback.searchParams.get('error'), 'invalid_request_uri');
    assert.equal(reusedCallback.searchParams.has('code'), false);
    assert.equal(
      parConsent.callback.origin + parConsent.callback.pathname,
      walletClient.redirect_uri,
    );
    assert.equal(parConsent.callback.searchParams.get('state'), state);
    const dpopKey = await generateKeyPair('ES256', { extractable: true });
    const dpopJwk = await exportJWK(dpopKey.publicKey);
    const dpopProof = (
      endpoint: string,
      access?: string,
      key = dpopKey.privateKey,
      jwk = dpopJwk,
    ) =>
      new SignJWT({
        htu: `${issuer}/${endpoint}`,
        htm: 'POST',
        iat: Math.floor(Date.now() / 1000),
        jti: secret(),
        ...(access ? { ath: hash(access) } : {}),
      })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk })
        .sign(key);
    const tokenRequest = (proof: string) =>
      external.fetch(`${issuer}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: proof },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: parConsent.callback.searchParams.get('code')!,
          client_id: walletClient.client_id,
          redirect_uri: walletClient.redirect_uri,
          code_verifier: verifier,
        }).toString(),
      });
    assert.equal((await tokenRequest(await dpopProof('credential'))).status, 400);
    const dpopTokenProof = await dpopProof('token');
    const dpopTokenResponse = await tokenRequest(dpopTokenProof);
    assert.equal(dpopTokenResponse.status, 200, await dpopTokenResponse.clone().text());
    const dpopToken = (await dpopTokenResponse.json()) as any;
    assert.equal(dpopToken.token_type, 'DPoP');
    assert.equal((await tokenRequest(dpopTokenProof)).status, 400);
    const parNonce = (
      (await (await external.fetch(`${issuer}/nonce`, { method: 'POST' })).json()) as any
    ).c_nonce;
    const parHolderProof = await walletProof(parNonce);
    assert.equal(
      (await walletIssue(dpopToken.access_token, 'linked_document', parHolderProof)).status,
      401,
    );
    const protectedIssue = (proof?: string, format = 'dc+sd-jwt') =>
      post(
        '/identity/issuer/credential',
        {
          credential_configuration_id: 'linked_document',
          format,
          vct: `${issuer}/types/linked-document`,
          proofs: { jwt: [parHolderProof] },
          ignored_extension: 'supported',
        },
        { Authorization: `DPoP ${dpopToken.access_token}`, ...(proof ? { DPoP: proof } : {}) },
        external,
      );
    assert.equal((await protectedIssue()).status, 401);
    assert.equal(
      (
        await protectedIssue(
          await dpopProof(
            'credential',
            dpopToken.access_token,
            externalKey.privateKey,
            externalHolder,
          ),
        )
      ).status,
      401,
    );
    assert.equal((await protectedIssue(await dpopProof('credential', secret()))).status, 401);
    const resourceProof = await dpopProof('credential', dpopToken.access_token);
    assert.equal((await protectedIssue(resourceProof, 'mso_mdoc')).status, 400);
    assert.equal((await protectedIssue(resourceProof)).status, 401);
    const protectedReceipt = await protectedIssue(
      await dpopProof('credential', dpopToken.access_token),
    );
    assert.equal(protectedReceipt.status, 200, await protectedReceipt.clone().text());
    const parReceipt = (await protectedReceipt.json()) as any;
    const { payload: parPayload } = await jwtVerify(
      parReceipt.credentials[0].credential.split('~')[0],
      op.publicKey,
      { issuer },
    );
    assert.deepEqual((parPayload.cnf as any).jwk, externalHolder);
    // HAIP issuance authenticates the instance at PAR and token; public wallet policy is isolated.
    const haip = harness.getWorker('identity-haip');
    for (const name of [
      'identity-haip-no-cert',
      'identity-haip-wrong-trust',
      'identity-haip-key-trust-missing',
    ]) {
      assert.equal(
        (
          await harness
            .getWorker(name)
            .fetch(`${root}/.well-known/openid-credential-issuer/identity/issuer`)
        ).status,
        503,
        'HAIP must not publish credential metadata with absent/untrusted signing chains',
      );
    }

    const attestedInstance = await generateKeyPair('ES256', { extractable: true });
    const otherInstance = await generateKeyPair('ES256', { extractable: true });
    async function clientHeaders(instance = attestedInstance, audience = issuer) {
      const at = Math.floor(Date.now() / 1000);
      return {
        'OAuth-Client-Attestation': await new SignJWT({
          iss: attesterIssuer,
          sub: walletClient.client_id,
          iat: at,
          exp: at + 300,
          cnf: { jwk: await exportJWK(instance.publicKey) },
        })
          .setProtectedHeader({
            typ: 'oauth-client-attestation+jwt',
            alg: 'ES256',
            x5c: attesterChain,
          })
          .sign(attesterKey),
        'OAuth-Client-Attestation-PoP': await new SignJWT({
          iss: walletClient.client_id,
          aud: audience,
          iat: at,
          exp: at + 300,
          jti: secret(),
        })
          .setProtectedHeader({ typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' })
          .sign(instance.privateKey),
      };
    }
    const haipMetadata = await haip.fetch(
      `${root}/.well-known/oauth-authorization-server/identity/issuer`,
    );
    assert.equal(haipMetadata.status, 200);
    const haipDiscovery = (await haipMetadata.json()) as any;
    assert.deepEqual(haipDiscovery.token_endpoint_auth_methods_supported, [
      'attest_jwt_client_auth',
    ]);
    assert.equal(haipDiscovery.require_pushed_authorization_requests, true);
    assert.equal(
      (
        await haip.fetch(`${issuer}/credential`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${secret()}`, 'Content-Type': 'application/json' },
          body: '{}',
        })
      ).status,
      401,
    );
    assert.deepEqual(haipDiscovery.grant_types_supported, ['authorization_code']);
    const haipPush = (
      headers: Record<string, string>,
      scope = 'linked_document',
      target = haip,
      overrides = {},
    ) =>
      target.fetch(`${issuer}/par`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
        body: new URLSearchParams({
          ...parParameters,
          redirect_uri: haipRedirect,
          scope,
          ignored_extension: 'supported',
          ...overrides,
        }).toString(),
      });
    for (let i = 0; i < 4; i++) {
      const invalid = harness.getWorker(`identity-haip-invalid-query-${i}`);
      const result = await invalid.fetch(
        `${root}/.well-known/oauth-authorization-server/identity/issuer`,
      );
      assert.equal(result.status, 500, 'ambiguous callback registration fails closed');
    }
    assert.equal((await haipPush({})).status, 400);
    assert.equal(
      (
        await haipPush(await clientHeaders(), 'linked_document', haip, {
          redirect_uri: `${walletClient.redirect_uri}?tenant=substituted&channel=wallet`,
        })
      ).status,
      400,
    );
    assert.equal(
      (await haipPush(await clientHeaders(attestedInstance, `${issuer}/token`))).status,
      400,
    );
    assert.equal((await haipPush(await clientHeaders(), 'linked_document', external)).status, 400);
    assert.equal(
      (
        await haip.fetch(`${issuer}/authorize?${new URLSearchParams(parParameters)}`, {
          headers: ownerHeaders,
        })
      ).status,
      400,
    );
    const keyAttestation = (
      nonce: string,
      keys = [externalHolder],
      patch = {},
      signer: Parameters<SignJWT['sign']>[0] = attesterKey,
    ) =>
      new SignJWT({
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        nonce,
        attested_keys: keys,
        ...patch,
      })
        .setProtectedHeader({ typ: 'key-attestation+jwt', alg: 'ES256', x5c: attesterChain })
        .sign(signer);
    const poolWorker = harness.getWorker('identity-haip-age-pool');
    const poolMetadata = (await (
      await poolWorker.fetch(`${root}/.well-known/openid-credential-issuer/identity/issuer`)
    ).json()) as any;
    assert.deepEqual(poolMetadata.mikaki_age_pool, { max_size: 8 });
    assert.equal(
      poolMetadata.batch_credential_issuance,
      undefined,
      'sequential receipt pool is not a wire batch',
    );
    for (const raw of [
      '{}',
      JSON.stringify({ size: 1, claims_json: '["age_over_18"]' }),
      JSON.stringify({ size: 9, claims_json: '["age_over_18"]' }),
      JSON.stringify({ size: 2, claims_json: '["birthdate"]' }),
      JSON.stringify({ size: 2, claims_json: '["age_over_18"]', mode: 'batch' }),
      JSON.stringify({ size: 2, claims_json: '["age_over_18"]', mode: 'unknown' }),
    ]) {
      assert.equal(
        (
          await haipPush(await clientHeaders(), 'linked_document', poolWorker, {
            mikaki_age_pool: raw,
            dpop_jkt: await calculateJwkThumbprint(dpopJwk),
          })
        ).status,
        400,
      );
    }
    assert.equal(
      (
        await haipPush(await clientHeaders(), 'linked_document', haip, {
          mikaki_age_pool: JSON.stringify({ size: 2, claims_json: '["age_over_18"]' }),
        })
      ).status,
      400,
      'disabled/old issuer rejects scoped pool',
    );
    for (const [mode, batchEnabled, proofShape] of [
      ['sequential', false, 'individual'],
      ['sequential', true, 'individual'],
      ['batch', true, 'individual'],
      ['batch', true, 'grouped'],
      ['batch', true, 'mixed'],
    ] as const) {
      const poolWorker = harness.getWorker(
        batchEnabled ? 'identity-haip-age-batch' : 'identity-haip-age-pool',
      );
      const metadata = (await (
        await poolWorker.fetch(`${root}/.well-known/openid-credential-issuer/identity/issuer`)
      ).json()) as any;
      assert.equal(metadata.batch_credential_issuance, undefined);
      assert.deepEqual(metadata.mikaki_age_batch, batchEnabled ? { batch_size: 8 } : undefined);
      for (const configuration of ['linked_document', 'linked_document_mdoc']) {
        for (const size of [2, 8]) {
          if (proofShape === 'mixed' && size === 2) continue;
          const budget = JSON.stringify({
            size,
            claims_json: '["age_over_18"]',
            ...(mode === 'batch' ? { mode } : {}),
          });
          const pushed = await haipPush(await clientHeaders(), configuration, poolWorker, {
            mikaki_age_pool: budget,
            dpop_jkt: await calculateJwkThumbprint(dpopJwk),
          });
          assert.equal(pushed.status, 201, await pushed.clone().text());
          const uri = ((await pushed.json()) as any).request_uri;
          const reviewUrl = `${issuer}/authorize?${new URLSearchParams({ client_id: walletClient.client_id, request_uri: uri })}`;
          assert.equal(
            (
              await poolWorker.fetch(
                `${reviewUrl}&mikaki_age_pool=${encodeURIComponent(JSON.stringify({ size: 8, claims_json: '["age_over_18"]' }))}`,
                { headers: ownerHeaders },
              )
            ).status,
            400,
            'browser cannot expand the frozen PAR budget',
          );
          const page = await poolWorker.fetch(reviewUrl, { headers: ownerHeaders });
          assert.equal(page.status, 200);
          const text = await page.text();
          assert.ok(text.includes(`証明書を${size}件`) && text.includes('18歳以上である'));
          assert.ok(text.includes(mode === 'batch' ? '全件を一括で受け取り' : '1件ずつ受け取り'));
          assert.ok(!text.includes('最大16件') && !text.includes('身分証の氏名・住所・生年月日'));
          const grant = /name=grant value='([^']+)'/.exec(text)![1];
          const approval = await poolWorker.fetch(`${issuer}/authorize`, {
            method: 'POST',
            redirect: 'manual',
            headers: {
              ...ownerHeaders,
              Origin: root,
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
              grant,
              csrf: /name=csrf value='([^']+)'/.exec(text)![1],
              document: parDocument.transaction_id,
              decision: 'approve',
            }).toString(),
          });
          assert.equal(approval.status, 303, await approval.clone().text());
          const code = new URL(approval.headers.get('location')!).searchParams.get('code')!;
          const dp = (endpoint: string, nonce?: string, access?: string) =>
            new SignJWT({
              htu: `${issuer}/${endpoint}`,
              htm: 'POST',
              iat: Math.floor(Date.now() / 1000),
              jti: secret(),
              ...(nonce ? { nonce } : {}),
              ...(access ? { ath: hash(access) } : {}),
            })
              .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk })
              .sign(dpopKey.privateKey);
          const exchange = async (nonce?: string) =>
            poolWorker.fetch(`${issuer}/token`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                ...(await clientHeaders()),
                DPoP: await dp('token', nonce),
              },
              body: new URLSearchParams({
                grant_type: 'authorization_code',
                code,
                client_id: walletClient.client_id,
                redirect_uri: haipRedirect,
                code_verifier: verifier,
              }).toString(),
            });
          const challenge = await exchange();
          assert.equal(challenge.status, 400);
          const token = await exchange(challenge.headers.get('dpop-nonce')!);
          assert.equal(token.status, 200, await token.clone().text());
          const access = ((await token.json()) as any).access_token;
          if (mode === 'batch') {
            const nonce = (
              (await (await poolWorker.fetch(`${issuer}/nonce`, { method: 'POST' })).json()) as any
            ).c_nonce;
            const keys = await Promise.all(
              Array.from({ length: size }, () => generateKeyPair('ES256', { extractable: true })),
            );
            const holders = await Promise.all(keys.map((k) => exportJWK(k.publicKey)));
            const proof = async (
              i: number,
              n = nonce,
              attested = true,
              role?: { jwk: any; privateKey: Parameters<SignJWT['sign']>[0] },
            ) => {
              const jwk = role?.jwk ?? holders[i];
              return new SignJWT({
                iss: walletClient.client_id,
                aud: issuer,
                iat: Math.floor(Date.now() / 1000),
                nonce: n,
              })
                .setProtectedHeader({
                  typ: 'openid4vci-proof+jwt',
                  alg: 'ES256',
                  jwk,
                  ...(attested
                    ? {
                        key_attestation: await keyAttestation(n, [jwk], {
                          exp: Math.floor(Date.now() / 1000) + 60,
                        }),
                      }
                    : {}),
                })
                .sign(role?.privateKey ?? keys[i].privateKey);
            };
            const proofs = await Promise.all(keys.map((_, i) => proof(i)));
            const recipient = await generateKeyPair('ECDH-ES', { extractable: true });
            const jwk = {
              ...(await exportJWK(recipient.publicKey)),
              kid: 'haip-batch-response',
              alg: 'ECDH-ES',
              use: 'enc',
            };
            const requestJwk = metadata.credential_request_encryption.jwks.keys[0];
            let rsNonce: string | undefined;
            const issue = async (values = proofs, target = poolWorker, type = 'jwt') => {
              const wire = await new CompactEncrypt(
                Buffer.from(
                  JSON.stringify({
                    credential_configuration_id: configuration,
                    proofs: { [type]: values },
                    credential_response_encryption: { jwk, enc: 'A256GCM' },
                  }),
                ),
              )
                .setProtectedHeader({
                  alg: 'ECDH-ES',
                  enc: 'A256GCM',
                  kid: requestJwk.kid,
                  cty: 'json',
                })
                .encrypt(await importJWK(requestJwk, 'ECDH-ES'));
              return target.fetch(`${issuer}/credential`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/jwt',
                  Authorization: `DPoP ${access}`,
                  DPoP: await dp('credential', rsNonce, access),
                },
                body: wire,
              });
            };
            assert.equal(
              (await issue([proofs[0]], haip)).status,
              401,
              'older policy cannot load batch grant',
            );
            assert.equal(
              (await issue([proofs[0]], harness.getWorker('identity-haip-age-pool'))).status,
              401,
              'batch flag withdrawal blocks grant',
            );
            assert.equal(
              (await issue(proofs, harness.getWorker('identity-haip-age-batch-changed'))).status,
              401,
              'profile change blocks grant',
            );
            const challenge = await issue();
            assert.equal(challenge.status, 401);
            rsNonce = challenge.headers.get('dpop-nonce')!;
            for (const values of [
              proofs.slice(0, -1),
              [...proofs, proofs[0]],
              [...proofs.slice(0, -1), proofs[0]],
              [...proofs.slice(0, -1), await proof(size - 1, secret())],
              [...proofs.slice(0, -1), await proof(size - 1, nonce, false)],
              [
                ...proofs.slice(0, -1),
                await proof(size - 1, nonce, true, {
                  jwk: dpopJwk,
                  privateKey: dpopKey.privateKey,
                }),
              ],
              [
                ...proofs.slice(0, -1),
                await proof(size - 1, nonce, true, {
                  jwk: await exportJWK(attestedInstance.publicKey),
                  privateKey: attestedInstance.privateKey,
                }),
              ],
            ]) {
              assert.equal(
                (await issue(values)).status,
                400,
                'any invalid member rejects the whole batch',
              );
            }
            const grouped = async (keys: typeof holders, n = nonce, patch = {}) =>
              keyAttestation(n, keys, { exp: Math.floor(Date.now() / 1000) + 60, ...patch });
            if (proofShape !== 'individual') {
              const extraKey = await exportJWK(
                (await generateKeyPair('ES256', { extractable: true })).publicKey,
              );
              const invalidLast = { ...holders[size - 1], x: 'invalid' };
              const privateLast = { ...holders[size - 1], d: 'private' };
              for (const values of [
                [await grouped([])],
                [await grouped(holders.slice(0, -1))],
                [await grouped([...holders, extraKey])],
                [await grouped([...holders.slice(0, -1), holders[0]])],
                [await grouped([...holders.slice(0, -1), invalidLast])],
                [await grouped([...holders.slice(0, -1), privateLast])],
                [await grouped(holders.slice(0, -1)), await grouped([holders[0]])],
                [await grouped(holders), await grouped([extraKey])],
                [await grouped(holders.slice(0, -1)), await grouped([holders[size - 1]], secret())],
                [
                  await grouped(holders.slice(0, -1)),
                  await grouped([holders[size - 1]], nonce, {
                    exp: Math.floor(Date.now() / 1000) - 1,
                  }),
                ],
                [
                  await grouped(holders.slice(0, -1)),
                  await keyAttestation(nonce, [holders[size - 1]], {}, op.privateKey),
                ],
                [await grouped([...holders.slice(0, -1), dpopJwk])],
                [
                  await grouped([
                    ...holders.slice(0, -1),
                    await exportJWK(attestedInstance.publicKey),
                  ]),
                ],
              ])
                assert.equal(
                  (await issue(values, poolWorker, 'attestation')).status,
                  400,
                  'any bad attested key/group rejects the entire batch',
                );
            }
            const proofType = proofShape === 'individual' && size === 8 ? 'jwt' : 'attestation';
            const values =
              proofShape === 'grouped'
                ? [await grouped(holders)]
                : proofShape === 'mixed'
                  ? await Promise.all(
                      [holders.slice(0, 1), holders.slice(1, 4), holders.slice(4)].map((h) =>
                        grouped(h),
                      ),
                    )
                  : size === 2
                    ? await Promise.all(holders.map((h) => grouped([h])))
                    : proofs;
            const issueApproved = () => issue(values, poolWorker, proofType);
            const unspent = async () => {
              const current = (await DB.prepare(
                'SELECT issuance_count,state,holder_json FROM identity_wallet_grant WHERE grant_id=?',
              )
                .bind(grant)
                .first()) as any;
              assert.equal(current.issuance_count, 0);
              assert.equal(current.state, 'token');
              assert.deepEqual(JSON.parse(current.holder_json).holders, []);
              assert.equal(
                (
                  (await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?')
                    .bind(hash(nonce))
                    .first()) as any
                ).used,
                0,
              );
            };
            await unspent();
            if (size === 2) {
              await DB.exec(
                `CREATE TRIGGER fixture_batch_close BEFORE UPDATE OF state ON identity_wallet_grant WHEN NEW.grant_id='${grant}' AND NEW.state='issued' BEGIN SELECT RAISE(ABORT,'fixture rollback'); END`,
              );
              assert.equal((await issueApproved()).status, 409);
              await unspent();
              await DB.exec('DROP TRIGGER fixture_batch_close');
            }
            const results = await Promise.all([issueApproved(), issueApproved()]);
            const resultDetails = (
              await Promise.all(
                results.map(async (r) => (r.status === 200 ? 'success' : await r.clone().text())),
              )
            ).join(',');
            assert.equal(results.filter((r) => r.status === 200).length, 1, resultDetails);
            assert.ok(results.every((r) => [200, 401, 409].includes(r.status)));
            const received = JSON.parse(
              Buffer.from(
                (
                  await compactDecrypt(
                    await results.find((r) => r.status === 200)!.text(),
                    recipient.privateKey,
                  )
                ).plaintext,
              ).toString(),
            );
            assert.equal(received.credentials.length, size);
            for (let i = 0; i < size; i++) {
              const credential = received.credentials[i].credential;
              if (configuration === 'linked_document') {
                const { payload } = await jwtVerify(credential.split('~')[0], op.publicKey, {
                  issuer,
                });
                assert.deepEqual((payload.cnf as any).jwk, holders[i]);
                assert.ok((payload.exp as number) <= Math.floor(Date.now() / 1000) + 60);
                assert.equal(
                  JSON.parse(Buffer.from(credential.split('~')[1], 'base64url').toString())[1],
                  'age_over_18',
                );
              } else
                assert.deepEqual(
                  verifyMdocIssuer(credential, holders[i], await exportJWK(op.publicKey)).values,
                  { age_over_18: true },
                );
            }
            const current = (await DB.prepare(
              'SELECT issuance_count,state,holder_json,access_hash FROM identity_wallet_grant WHERE grant_id=?',
            )
              .bind(grant)
              .first()) as any;
            assert.equal(current.issuance_count, 1);
            assert.equal(current.state, 'issued');
            assert.equal(current.access_hash, null);
            const binding = JSON.parse(current.holder_json);
            assert.equal(binding.age_pool_version, 2);
            assert.equal(binding.holders.length, size);
            assert.equal(new Set(binding.holders).size, size);
            assert.equal(
              (
                (await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?')
                  .bind(hash(nonce))
                  .first()) as any
              ).used,
              1,
            );
            assert.equal((await issueApproved()).status, 401, 'one batch closes the entire grant');
            continue;
          }
          let rsNonce: string | undefined;
          let previous:
            | {
                proof: string;
                nonce: string;
                privateKey: Parameters<SignJWT['sign']>[0];
                holder: typeof externalHolder;
              }
            | undefined;
          for (let slot = 0; slot < size; slot++) {
            const holderKeys = await generateKeyPair('ES256', { extractable: true });
            const holder = await exportJWK(holderKeys.publicKey);
            const nonce = (
              (await (await poolWorker.fetch(`${issuer}/nonce`, { method: 'POST' })).json()) as any
            ).c_nonce;
            const attestation = await keyAttestation(nonce, [holder], {
              exp: Math.floor(Date.now() / 1000) + 60,
            });
            const proof = await new SignJWT({
              iss: walletClient.client_id,
              aud: issuer,
              iat: Math.floor(Date.now() / 1000),
              nonce,
            })
              .setProtectedHeader({
                typ: 'openid4vci-proof+jwt',
                alg: 'ES256',
                jwk: holder,
                key_attestation: attestation,
              })
              .sign(holderKeys.privateKey);
            const issue = async (proofValue = proof, target = poolWorker) =>
              post(
                '/identity/issuer/credential',
                { credential_configuration_id: configuration, proofs: { jwt: [proofValue] } },
                { Authorization: `DPoP ${access}`, DPoP: await dp('credential', rsNonce, access) },
                target,
              );
            if (slot === 0) {
              assert.equal(
                (await issue(proof, haip)).status,
                401,
                'withdrawal/old policy cannot load the pool grant',
              );
              assert.equal(
                (await issue(proof, harness.getWorker('identity-haip-age-pool-changed'))).status,
                401,
                'profile change cannot load the pool grant',
              );
              const challenge = await issue();
              assert.equal(challenge.status, 401);
              rsNonce = challenge.headers.get('dpop-nonce')!;
              if (batchEnabled) {
                assert.equal(
                  (
                    await post(
                      '/identity/issuer/credential',
                      {
                        credential_configuration_id: configuration,
                        proofs: { jwt: [proof, proof] },
                      },
                      {
                        Authorization: `DPoP ${access}`,
                        DPoP: await dp('credential', rsNonce, access),
                      },
                      poolWorker,
                    )
                  ).status,
                  400,
                  'sequential consent cannot be expanded into a batch',
                );
              }
              if (size === 2 && slot === 0) {
                const group = await keyAttestation(nonce, [holder, externalHolder]);
                assert.equal(
                  (
                    await post(
                      '/identity/issuer/credential',
                      {
                        credential_configuration_id: configuration,
                        proofs: { attestation: [group] },
                      },
                      {
                        Authorization: `DPoP ${access}`,
                        DPoP: await dp('credential', rsNonce, access),
                      },
                      poolWorker,
                    )
                  ).status,
                  400,
                  'sequential consent still permits one attested key per operation',
                );
              }
              const noAttestation = await new SignJWT({
                iss: walletClient.client_id,
                aud: issuer,
                iat: Math.floor(Date.now() / 1000),
                nonce,
              })
                .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: holder })
                .sign(holderKeys.privateKey);
              assert.equal((await issue(noAttestation)).status, 400);
              for (const role of [
                { jwk: dpopJwk, privateKey: dpopKey.privateKey },
                {
                  jwk: await exportJWK(attestedInstance.publicKey),
                  privateKey: attestedInstance.privateKey,
                },
              ]) {
                const reusedRole = await new SignJWT({
                  iss: walletClient.client_id,
                  aud: issuer,
                  iat: Math.floor(Date.now() / 1000),
                  nonce,
                })
                  .setProtectedHeader({
                    typ: 'openid4vci-proof+jwt',
                    alg: 'ES256',
                    jwk: role.jwk,
                    key_attestation: await keyAttestation(nonce, [role.jwk]),
                  })
                  .sign(role.privateKey);
                assert.equal(
                  (await issue(reusedRole)).status,
                  400,
                  'pooled holder must be separate from client-instance and DPoP keys',
                );
              }
            }
            if (previous) {
              const reused = await new SignJWT({
                iss: walletClient.client_id,
                aud: issuer,
                iat: Math.floor(Date.now() / 1000),
                nonce,
              })
                .setProtectedHeader({
                  typ: 'openid4vci-proof+jwt',
                  alg: 'ES256',
                  jwk: previous.holder,
                  key_attestation: await keyAttestation(nonce, [previous.holder]),
                })
                .sign(previous.privateKey);
              assert.equal(
                (await issue(reused)).status,
                400,
                'even a fresh attestation cannot reuse a pooled holder key',
              );
            }
            if (previous)
              assert.equal(
                (await issue(previous.proof)).status,
                400,
                'consumed nonce/key cannot replenish another slot',
              );
            if (slot === size - 1 && size === 2) {
              // Force the second statement to abort: the first counter/nonce/key
              // write must roll back rather than leave a partially spent grant.
              await DB.exec(
                `CREATE TRIGGER fixture_pool_close BEFORE UPDATE OF state ON identity_wallet_grant WHEN NEW.grant_id='${grant}' AND NEW.state='issued' BEGIN SELECT RAISE(ABORT,'fixture rollback'); END`,
              );
              assert.equal((await issue()).status, 409);
              const rolled = (await DB.prepare(
                'SELECT issuance_count,state FROM identity_wallet_grant WHERE grant_id=?',
              )
                .bind(grant)
                .first()) as any;
              assert.deepEqual(rolled, { issuance_count: slot, state: 'token' });
              assert.equal(
                (
                  (await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?')
                    .bind(hash(nonce))
                    .first()) as any
                ).used,
                0,
              );
              await DB.exec('DROP TRIGGER fixture_pool_close');
            }
            const issued =
              slot === size - 1 && size === 8
                ? await Promise.all([issue(), issue()])
                : [await issue()];
            assert.equal(
              issued.filter((r) => r.status === 200).length,
              1,
              'each slot has one winner',
            );
            assert.ok(issued.every((r) => [200, 401, 409].includes(r.status)));
            const receipt = ((await issued.find((r) => r.status === 200)!.json()) as any)
              .credentials;
            assert.equal(receipt.length, 1);
            if (configuration === 'linked_document') {
              const credential = receipt[0].credential;
              const { payload } = await jwtVerify(credential.split('~')[0], op.publicKey, {
                issuer,
              });
              assert.deepEqual((payload.cnf as any).jwk, holder);
              assert.ok((payload.exp as number) <= Math.floor(Date.now() / 1000) + 60);
              assert.equal(
                JSON.parse(Buffer.from(credential.split('~')[1], 'base64url').toString())[1],
                'age_over_18',
              );
            } else {
              assert.deepEqual(
                verifyMdocIssuer(receipt[0].credential, holder, await exportJWK(op.publicKey))
                  .values,
                { age_over_18: true },
              );
            }
            const current = (await DB.prepare(
              'SELECT issuance_count,state,holder_json,access_hash FROM identity_wallet_grant WHERE grant_id=?',
            )
              .bind(grant)
              .first()) as any;
            assert.equal(current.issuance_count, slot + 1);
            assert.equal(current.state, slot === size - 1 ? 'issued' : 'token');
            const binding = JSON.parse(current.holder_json);
            assert.equal(binding.budget.size, size);
            assert.equal(binding.holders.length, slot + 1);
            assert.equal(new Set(binding.holders).size, slot + 1);
            assert.equal(
              (
                (await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?')
                  .bind(hash(nonce))
                  .first()) as any
              ).used,
              1,
            );
            previous = { proof, nonce, privateKey: holderKeys.privateKey, holder };
            if (slot === size - 1) {
              assert.equal(current.access_hash, null);
              assert.equal(
                (await issue()).status,
                401,
                'exact budget is closed below the legacy sixteen-slot ceiling',
              );
            }
          }
        }
      }
    }
    // The Rust wallet owns PKCE/state and all three private signing keys throughout.
    // The synthetic fixture attester only receives public keys and a nonce.
    for (const { configuration, poolMode } of ['linked_document', 'linked_document_mdoc'].flatMap(
      (configuration) => [
        { configuration, poolMode: undefined },
        { configuration, poolMode: 'sequential' },
        { configuration, poolMode: 'batch' },
      ],
    )) {
      const haip = harness.getWorker(
        poolMode === 'batch'
          ? 'identity-haip-age-batch'
          : poolMode === 'sequential'
            ? 'identity-haip-age-pool'
            : 'identity-haip',
      );
      const agePool = poolMode
        ? { size: 8, claims_json: '["age_over_18"]', mode: poolMode }
        : undefined;
      const metadata = await (
        await haip.fetch(`${root}/.well-known/openid-credential-issuer/identity/issuer`)
      ).json();
      const format = configuration === 'linked_document' ? 'dc+sd-jwt' : 'mso_mdoc';
      const credentialTrust = Object.fromEntries(
        Object.entries(signingCertificates).map(([purpose, value]) => [
          purpose,
          { trust_anchors: value.trust_anchors },
        ]),
      );
      const issuerPublic = await exportJWK(op.publicKey);
      await withNativePresentationHttp(async (http) => {
        const peer = await issuedWalletVerifier(
          format,
          issuer,
          issuerPublic,
          signingCertificates[configuration === 'linked_document' ? 'sd_jwt' : 'mdoc']
            .trust_anchors[0],
          http.uri('/response'),
          !!agePool,
        );
        const peers = agePool
          ? [
              peer,
              await issuedWalletVerifier(
                format,
                issuer,
                issuerPublic,
                signingCertificates[configuration === 'linked_document' ? 'sd_jwt' : 'mdoc']
                  .trust_anchors[0],
                http.uri('/response'),
                true,
              ),
            ]
          : [peer];
        if (agePool) assert.notEqual(peers[0].registry.client_id, peers[1].registry.client_id);
        const walletRun = async (official?: {
          registry: unknown;
          completion: unknown;
          present: (command: (value: unknown) => Promise<any>) => Promise<void>;
        }) => {
          await withRustHaipWallet(
            {
              issuer,
              attester: attesterIssuer,
              client: walletClient.client_id,
              callback: haipRedirect,
              configuration,
              metadata,
              ...(agePool ? { age_pool: agePool } : {}),
              client_trust: [{ issuer: attesterIssuer, trust_anchors: [attesterRoot] }],
              key_trust: { trust_anchors: [attesterRoot] },
              credential_trust: credentialTrust,
              issuer_key: issuerPublic,
              issuer_kid: privateJwk.kid,
              verifiers: [
                ...peers.map((p) => p.registry),
                ...(official ? [official.registry] : []),
              ],
              completion_uris: official ? [official.completion] : [],
            },
            async (keys, command) => {
              assert.notDeepEqual(keys.instance, keys.dpop);
              assert.notDeepEqual(keys.instance, keys.holder);
              assert.notDeepEqual(keys.dpop, keys.holder);
              const enroll = async (
                purpose: 'client' | 'holder',
                clientAttestation?: string,
                c_nonce?: string,
              ) => {
                const headers = async () =>
                  clientAttestation
                    ? command({ command: 'attester_headers', attestation: clientAttestation })
                    : {};
                const start = await haip.fetch(`${attesterIssuer}/challenge`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', ...(await headers()) },
                  body: JSON.stringify({
                    client_id: walletClient.client_id,
                    purpose,
                    ...(c_nonce ? { c_nonce } : {}),
                  }),
                });
                assert.equal(start.status, 200, await start.clone().text());
                const challenge = ((await start.json()) as any).challenge;
                const proof = await command({ command: 'enroll', purpose, challenge });
                const certificate_chain = androidAttestationFixture(challenge, proof.public_key);
                const response = await haip.fetch(`${attesterIssuer}/attestation`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', ...(await headers()) },
                  body: JSON.stringify({
                    ...proof,
                    certificate_chain,
                    ...(c_nonce ? { c_nonce } : {}),
                  }),
                });
                assert.equal(response.status, 200, await response.clone().text());
                return ((await response.json()) as any).attestation as string;
              };
              const clientAttestation = await enroll('client');
              const call = async (endpoint: 'par' | 'token', nonce?: string) => {
                const request = await command({
                  command: endpoint,
                  attestation: clientAttestation,
                  nonce,
                });
                return haip.fetch(`${issuer}/${endpoint}`, {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    ...request.headers,
                  },
                  body: new URLSearchParams(request.body).toString(),
                });
              };
              const parChallenge = await call('par');
              assert.equal(parChallenge.status, 400);
              assert.equal(((await parChallenge.json()) as any).error, 'use_dpop_nonce');
              const pushed = await call('par', parChallenge.headers.get('dpop-nonce')!);
              assert.equal(pushed.status, 201, await pushed.clone().text());
              const browser = await command({ command: 'pushed', response: await pushed.json() });
              const page = await haip.fetch(browser.url, { headers: ownerHeaders });
              assert.equal(page.status, 200);
              const text = await page.text();
              const approved = await haip.fetch(`${issuer}/authorize`, {
                method: 'POST',
                redirect: 'manual',
                headers: {
                  ...ownerHeaders,
                  Origin: root,
                  'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                  grant: /name=grant value='([^']+)'/.exec(text)![1],
                  csrf: /name=csrf value='([^']+)'/.exec(text)![1],
                  document: parDocument.transaction_id,
                  decision: 'approve',
                }).toString(),
              });
              assert.equal(approved.status, 303, await approved.clone().text());
              assert.equal(
                (await command({ command: 'callback', url: approved.headers.get('location') }))
                  .accepted,
                true,
              );
              const tokenChallenge = await call('token');
              assert.equal(tokenChallenge.status, 400);
              assert.equal(((await tokenChallenge.json()) as any).error, 'use_dpop_nonce');
              const token = await call('token', tokenChallenge.headers.get('dpop-nonce')!);
              assert.equal(token.status, 200, await token.clone().text());
              await command({ command: 'token_received', response: await token.json() });
              // Holder attestations last 60 seconds and credential expiry rounds down
              // to a minute. Mint early enough for the positive presentation cases,
              // using the real clock and retaining all production expiry checks.
              let minuteOffset = Date.now() % 60000;
              while (minuteOffset >= 30000) {
                await new Promise((resolve) => setTimeout(resolve, 60000 - minuteOffset));
                minuteOffset = Date.now() % 60000;
              }
              if (agePool) {
                assert.equal(keys.holders.length, agePool.size);
                assert.equal(
                  new Set(
                    await Promise.all(keys.holders.map((h: any) => calculateJwkThumbprint(h))),
                  ).size,
                  agePool.size,
                );
                let rsNonce: string | undefined;
                let issued: any;
                const commonNonce =
                  poolMode === 'batch'
                    ? (
                        (await (
                          await haip.fetch(`${issuer}/nonce`, { method: 'POST' })
                        ).json()) as any
                      ).c_nonce
                    : undefined;
                const issuePool = async (credential_nonce?: string, attestation?: string) => {
                  const request = await command({
                    command: 'credential',
                    credential_nonce,
                    attestation,
                    nonce: rsNonce,
                  });
                  return haip.fetch(`${issuer}/credential`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/jwt', ...request.headers },
                    body: request.body,
                  });
                };
                for (let index = 0; index < agePool.size; index++) {
                  const credentialNonce =
                    commonNonce ??
                    (
                      (await (
                        await haip.fetch(`${issuer}/nonce`, { method: 'POST' })
                      ).json()) as any
                    ).c_nonce;
                  const attestation = await enroll('holder', clientAttestation, credentialNonce);
                  if (poolMode === 'batch') {
                    assert.equal(
                      (
                        await command({
                          command: 'stage',
                          credential_nonce: credentialNonce,
                          attestation,
                        })
                      ).staged,
                      index + 1,
                    );
                    continue;
                  }
                  let response = await issuePool(credentialNonce, attestation);
                  if (response.status === 401) {
                    assert.equal(((await response.json()) as any).error, 'use_dpop_nonce');
                    rsNonce = response.headers.get('dpop-nonce')!;
                    response = await issuePool(credentialNonce, attestation);
                  }
                  assert.equal(response.status, 200, await response.clone().text());
                  issued = await command({ command: 'received', response: await response.text() });
                  assert.equal(issued.state, index + 1 === agePool.size ? 'received' : 'buffered');
                }
                if (poolMode === 'batch') {
                  const challenge = await issuePool();
                  assert.equal(challenge.status, 401);
                  assert.equal(((await challenge.json()) as any).error, 'use_dpop_nonce');
                  rsNonce = challenge.headers.get('dpop-nonce')!;
                  const response = await issuePool();
                  assert.equal(response.status, 200, await response.clone().text());
                  issued = await command({ command: 'received', response: await response.text() });
                }
                assert.equal(issued.credentials.length, agePool.size);
                for (let index = 0; index < agePool.size; index++) {
                  const credential = issued.credentials[index].credential;
                  if (format === 'dc+sd-jwt') {
                    const { payload } = await jwtVerify(credential.split('~')[0], op.publicKey, {
                      issuer,
                    });
                    assert.deepEqual((payload.cnf as any).jwk, keys.holders[index]);
                  } else
                    assert.deepEqual(
                      verifyMdocIssuer(credential, keys.holders[index], issuerPublic).values,
                      { age_over_18: true },
                    );
                  const verifier = peers[index % peers.length];
                  const signed = await verifier.request();
                  const presented = await command({
                    command: 'present',
                    index,
                    request: signed.jwt,
                    consent: true,
                  });
                  assert.equal(presented.state, 'presented');
                  http.onResponse(async (response) => {
                    assert.deepEqual(
                      await verifier.accept(response, signed.claims, keys.holders[index]),
                      { age_over_18: true },
                    );
                  });
                  assert.deepEqual(
                    await http.command({
                      command: 'deliver',
                      uri: http.uri('/response'),
                      response: presented.response,
                    }),
                    { status: 200 },
                  );
                  const nextRequest = await peers[(index + 1) % peers.length].request();
                  assert.deepEqual(
                    await command({
                      command: 'present',
                      index,
                      request: nextRequest.jwt,
                      consent: true,
                    }),
                    { state: 'rejected' },
                    'volatile host slot is used once; native durable retirement is qualified separately',
                  );
                }
                return;
              }
              const credentialNonce = (
                (await (await haip.fetch(`${issuer}/nonce`, { method: 'POST' })).json()) as any
              ).c_nonce;
              const attestation = await enroll('holder', clientAttestation, credentialNonce);
              const issue = async (nonce?: string) => {
                const request = await command({
                  command: 'credential',
                  credential_nonce: credentialNonce,
                  attestation,
                  nonce,
                });
                return haip.fetch(`${issuer}/credential`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/jwt', ...request.headers },
                  body: request.body,
                });
              };
              const challenge = await issue();
              assert.equal(challenge.status, 401);
              assert.equal(((await challenge.json()) as any).error, 'use_dpop_nonce');
              const response = await issue(challenge.headers.get('dpop-nonce')!);
              assert.equal(response.status, 200, await response.clone().text());
              assert.match(response.headers.get('content-type')!, /application\/jwt/);
              const issued = await command({
                command: 'received',
                response: await response.text(),
              });
              assert.equal(issued.credentials.length, 1);
              const credential = issued.credentials[0].credential;
              let credentialExpiresAt: number;
              if (configuration === 'linked_document') {
                const { payload } = await jwtVerify(credential.split('~')[0], op.publicKey, {
                  issuer,
                });
                assert.deepEqual((payload.cnf as any).jwk, keys.holder);
                assert.equal(typeof payload.exp, 'number');
                credentialExpiresAt = payload.exp!;
              } else {
                const { mso } = verifyMdocIssuer(
                  credential,
                  keys.holder,
                  await exportJWK(op.publicKey),
                );
                const until = field(field(mso, 'validityInfo'), 'validUntil') as {
                  tag: number;
                  value: string;
                };
                assert.equal(until.tag, 0);
                credentialExpiresAt = Math.floor(Date.parse(until.value) / 1000);
              }
              assert.ok(Number.isFinite(credentialExpiresAt));
              for (const authorities of [
                [{ type: 'aki', values: [secret()] }],
                [{ type: 'openid_federation', values: ['https://no-fetch.example'] }],
              ]) {
                const unmatched = await peer.request(authorities);
                assert.deepEqual(
                  await command({ command: 'present', request: unmatched.jwt, consent: true }),
                  { state: 'rejected' },
                  'nonmatching authority cannot produce a presentation',
                );
              }
              const denied = await peer.request();
              assert.deepEqual(
                await command({ command: 'present', request: denied.jwt, consent: false }),
                { state: 'rejected' },
              );
              assert.deepEqual(
                await command({ command: 'present', request: denied.jwt, consent: true }),
                { state: 'rejected' },
                'declined request is consumed',
              );
              const request = await peer.request(undefined, {
                omitState: true,
                omitTimestamps: true,
              });
              const invalid = request.jwt.split('.');
              invalid[2] = `${invalid[2][0] === 'A' ? 'B' : 'A'}${invalid[2].slice(1)}`;
              assert.deepEqual(
                await command({ command: 'present', request: invalid.join('.'), consent: true }),
                { state: 'rejected' },
              );
              const badRetrieval = await command({ command: 'request_uri' });
              assert.equal(badRetrieval.method, 'post');
              const wrongNonce = await peer.requestForWallet(badRetrieval.form, true);
              assert.deepEqual(
                await command({ command: 'present', request: wrongNonce.jwt, consent: true }),
                { state: 'rejected' },
                'validly signed response cannot substitute the wallet retrieval nonce',
              );
              const retrieval = await command({ command: 'request_uri' });
              http.onRequest((form) => peer.requestForWallet(form));
              const fetched = await http.command({
                command: 'retrieve',
                uri: http.uri('/request'),
                form: retrieval.form,
              });
              assert.ok(fetched.jwt, `Native request retrieval: ${JSON.stringify(fetched)}`);
              const retrieved = http.requests.at(-1)!;
              assert.equal(fetched.jwt, retrieved.jwt);

              const presented = await command({
                command: 'present',
                request: retrieved.jwt,
                consent: true,
              });
              assert.equal(presented.state, 'presented');
              let values: any;
              http.onResponse(async (response) => {
                values = await peer.accept(response, retrieved.claims, keys.holder);
              });
              assert.deepEqual(
                await http.command({
                  command: 'deliver',
                  uri: http.uri('/response'),
                  response: presented.response,
                }),
                { status: 200 },
              );

              assert.equal(values.name, '試験 太郎');
              await assert.rejects(
                peer.accept(presented.response, retrieved.claims, keys.instance),
              );
              const tampered = presented.response.split('.');
              tampered[3] = `${tampered[3][0] === 'A' ? 'B' : 'A'}${tampered[3].slice(1)}`;
              await assert.rejects(peer.accept(tampered.join('.'), retrieved.claims, keys.holder));
              await assert.rejects(
                peer.accept(
                  presented.response,
                  { ...retrieved.claims, nonce: secret() },
                  keys.holder,
                ),
              );
              assert.deepEqual(
                await command({ command: 'present', request: retrieved.jwt, consent: true }),
                { state: 'rejected' },
                'accepted request cannot be presented twice',
              );
              const invalidBatchContext = await command({ command: 'request_uri' });
              const invalidBatch = await peer.requestForWallet(
                invalidBatchContext.form,
                false,
                true,
                true,
              );
              assert.deepEqual(
                await command({ command: 'present', request: invalidBatch.jwt, consent: true }),
                { state: 'rejected' },
                'a mismatched authority on a later query cannot leak a partial presentation',
              );
              const batchContext = await command({ command: 'request_uri' });
              const batch = await peer.requestForWallet(batchContext.form, false, true);
              const batchResponse = await command({
                command: 'present',
                request: batch.jwt,
                consent: true,
              });
              assert.equal(
                batchResponse.state,
                'presented',
                `all required same-credential queries must be presented atomically (${format}, ${credentialExpiresAt - Math.floor(Date.now() / 1000)}s before expiry)`,
              );
              assert.equal(
                (await peer.accept(batchResponse.response, batch.claims, keys.holder)).name,
                '試験 太郎',
              );
              assert.deepEqual(
                await command({ command: 'present', request: batch.jwt, consent: true }),
                { state: 'rejected' },
                'the entire batch is consumed once',
              );
              if (official) {
                await official.present(command);
                // The pre-suite batch already proves recovery after authority/replay rejection.
                // HAIP receipt validity is capped by the short-lived attestation and minute
                // rounding. Suite execution may legitimately outlast it; never relax validation.
                const remaining = credentialExpiresAt - Math.floor(Date.now() / 1000);
                if (remaining > 0 && remaining <= 2)
                  await new Promise((resolve) => setTimeout(resolve, remaining * 1000 + 1000));
                const expired = credentialExpiresAt <= Math.floor(Date.now() / 1000);
                const freshContext = await command({ command: 'request_uri' });
                const fresh = await peer.requestForWallet(freshContext.form);
                const recovered = await command({
                  command: 'present',
                  request: fresh.jwt,
                  consent: true,
                });
                if (expired) {
                  assert.deepEqual(
                    recovered,
                    { state: 'rejected' },
                    'expired receipt must stay rejected',
                  );
                } else {
                  assert.equal(recovered.state, 'presented');
                  assert.equal(
                    (await peer.accept(recovered.response, fresh.claims, keys.holder)).name,
                    '試験 太郎',
                  );
                }
              }
            },
          );
        };
        if (!agePool && process.env.MIKAKI_OIDF_WALLET_SUITE === '1') {
          await withOfficialWalletSuite(
            format,
            issuer,
            signingCertificates[configuration === 'linked_document' ? 'sd_jwt' : 'mdoc']
              .trust_anchors[0],
            walletRun,
          );
        } else await walletRun();
      });
    }
    for (const configuration of ['linked_document', 'linked_document_mdoc']) {
      const parAuth = await clientHeaders();
      const parDpop = (nonce?: string) =>
        new SignJWT({
          htu: `${issuer}/par`,
          htm: 'POST',
          iat: Math.floor(Date.now() / 1000),
          jti: secret(),
          ...(nonce ? { nonce } : {}),
        })
          .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk })
          .sign(dpopKey.privateKey);
      let pushed: Awaited<ReturnType<typeof haipPush>>;
      let replayProof: string | undefined;
      if (configuration === 'linked_document') {
        const challenge = await haipPush({ ...parAuth, DPoP: await parDpop() }, configuration);
        assert.equal(challenge.status, 400);
        assert.equal(((await challenge.json()) as any).error, 'use_dpop_nonce');
        const nonce = challenge.headers.get('dpop-nonce')!;
        assert.equal(
          (
            await haipPush(
              { ...(await clientHeaders()), DPoP: await parDpop(nonce) },
              configuration,
              haip,
              {
                dpop_jkt: await calculateJwkThumbprint(externalHolder),
              },
            )
          ).status,
          400,
          'Conflicting PAR DPoP header and parameter must be rejected',
        );
        const proof = await parDpop(nonce);
        pushed = await haipPush({ ...parAuth, DPoP: proof }, configuration);
        replayProof = proof;
      } else {
        pushed = await haipPush(parAuth, configuration, haip, {
          dpop_jkt: await calculateJwkThumbprint(dpopJwk),
        });
      }
      const pushedBody = await pushed.text();
      assert.equal(pushed.status, 201, pushedBody);
      if (replayProof) {
        assert.equal(
          (await haipPush({ ...(await clientHeaders()), DPoP: replayProof }, configuration)).status,
          400,
          'PAR DPoP replay must fail',
        );
      }
      assert.equal((await haipPush(parAuth, configuration)).status, 400, 'PAR PoP replay');
      const uri = JSON.parse(pushedBody).request_uri;
      const page = await haip.fetch(
        `${issuer}/authorize?${new URLSearchParams({ client_id: walletClient.client_id, request_uri: uri })}`,
        { headers: ownerHeaders },
      );
      assert.equal(page.status, 200);
      const text = await page.text();
      assert.match(text, /120秒以内に最大16件/, 'owner sees issuance budget before approval');
      const approved = await haip.fetch(`${issuer}/authorize`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          ...ownerHeaders,
          Origin: root,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant: /name=grant value='([^']+)'/.exec(text)![1],
          csrf: /name=csrf value='([^']+)'/.exec(text)![1],
          document: parDocument.transaction_id,
          decision: 'approve',
        }).toString(),
      });
      assert.equal(approved.status, 303, await approved.clone().text());
      const haipCallback = new URL(approved.headers.get('location')!);
      assert.equal(haipCallback.searchParams.get('tenant'), 'fixed tenant');
      assert.equal(haipCallback.searchParams.get('channel'), 'wallet');
      assert.equal(haipCallback.searchParams.getAll('code').length, 1);
      const code = haipCallback.searchParams.get('code')!;
      const lifetime = await DB.prepare(
        'SELECT expires_at-unixepoch() AS remaining FROM identity_wallet_grant WHERE code_hash=?',
      )
        .bind(hash(code))
        .first('remaining');
      assert.ok(
        typeof lifetime === 'number' && lifetime >= 58 && lifetime <= 60,
        'HAIP codes expire within FAPI’s 60-second maximum',
      );
      const exchange = (
        headers: Record<string, string>,
        exchangeCode = code,
        codeVerifier = verifier,
      ) =>
        haip.fetch(`${issuer}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: exchangeCode,
            ...(configuration === 'linked_document' ? { client_id: walletClient.client_id } : {}),
            redirect_uri: haipRedirect,
            code_verifier: codeVerifier,
            ignored_extension: 'supported',
          }).toString(),
        });
      assert.equal((await exchange({})).status, 400);
      assert.equal((await exchange(await clientHeaders())).status, 400, 'DPoP required');
      const tokenAuth = await clientHeaders();
      const challenge = await exchange({ ...tokenAuth, DPoP: await dpopProof('token') });
      assert.equal(challenge.status, 400);
      assert.equal(((await challenge.json()) as any).error, 'use_dpop_nonce');
      const nonce = challenge.headers.get('dpop-nonce')!;
      const nonceDpop = () =>
        new SignJWT({
          htu: `${issuer}/token`,
          htm: 'POST',
          iat: Math.floor(Date.now() / 1000),
          jti: secret(),
          nonce,
        })
          .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk })
          .sign(dpopKey.privateKey);
      const wrongKeyProof = await new SignJWT({
        htu: `${issuer}/token`,
        htm: 'POST',
        iat: Math.floor(Date.now() / 1000),
        jti: secret(),
        nonce,
      })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: externalHolder })
        .sign(externalKey.privateKey);
      const wrongKey = await exchange({ ...(await clientHeaders()), DPoP: wrongKeyProof });
      assert.equal(wrongKey.status, 400);
      assert.equal(
        ((await wrongKey.json()) as any).error,
        'invalid_grant',
        'Token key must match the key bound at PAR',
      );
      const forgedAuth = await clientHeaders();
      const signedParts = forgedAuth['OAuth-Client-Attestation'].split('.');
      signedParts[2] = Buffer.alloc(64).toString('base64url');
      assert.equal(
        (
          await exchange({
            ...forgedAuth,
            'OAuth-Client-Attestation': signedParts.join('.'),
            DPoP: await nonceDpop(),
          })
        ).status,
        400,
        'Unverified subject cannot authorize a token exchange',
      );
      assert.equal(
        (await exchange({ ...(await clientHeaders(otherInstance)), DPoP: await nonceDpop() }))
          .status,
        400,
        'PAR instance must match token instance',
      );
      assert.equal(
        (await exchange({ ...parAuth, DPoP: await nonceDpop() })).status,
        400,
        'PAR PoP cannot be replayed at token',
      );
      const token = await exchange({ ...tokenAuth, DPoP: await nonceDpop() });
      assert.equal(token.status, 200, await token.clone().text());
      const haipToken = (await token.json()) as any;
      assert.equal(haipToken.token_type, 'DPoP');
      const holderNonce = (
        (await (await haip.fetch(`${issuer}/nonce`, { method: 'POST' })).json()) as any
      ).c_nonce;
      const holderProof = await new SignJWT({
        aud: issuer,
        iss: walletClient.client_id,
        iat: Math.floor(Date.now() / 1000),
        nonce: holderNonce,
      })
        .setProtectedHeader({
          typ: 'openid4vci-proof+jwt',
          key_attestation: await keyAttestation(holderNonce),
          alg: 'ES256',
          jwk: {
            ...externalHolder,
            kid: 'wallet-proof',
            alg: 'ES256',
            use: 'sig',
            key_ops: ['verify'],
          },
        })
        .sign(externalKey.privateKey);
      const issue = async (
        nonce?: string,
        proof = holderProof,
        scheme = 'DPoP',
        access = haipToken.access_token,
        proofType: 'jwt' | 'attestation' = 'jwt',
        target = haip,
      ) =>
        target.fetch(`${issuer}/credential`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `${scheme} ${access}`,
            DPoP: await new SignJWT({
              htu: `${issuer}/credential`,
              htm: 'POST',
              iat: Math.floor(Date.now() / 1000),
              jti: secret(),
              ath: hash(access),
              ...(nonce ? { nonce } : {}),
            })
              .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk })
              .sign(dpopKey.privateKey),
          },
          body: JSON.stringify({
            credential_configuration_id: configuration,
            proofs: { [proofType]: [proof] },
            ignored_extension: true,
          }),
        });
      const resourceChallenge = await issue();
      assert.equal(resourceChallenge.status, 401);
      const receipt = await issue(resourceChallenge.headers.get('dpop-nonce')!);
      assert.equal(receipt.status, 200, await receipt.clone().text());
      const credential = ((await receipt.json()) as any).credentials[0].credential;
      if (configuration === 'linked_document') {
        const { payload } = await jwtVerify(credential.split('~')[0], op.publicKey, { issuer });
        assert.deepEqual((payload.cnf as any).jwk, externalHolder);
      } else {
        verifyMdocIssuer(credential, externalHolder, await exportJWK(op.publicKey));
      }

      const rsNonce = resourceChallenge.headers.get('dpop-nonce')!;
      assert.equal((await issue(rsNonce)).status, 400, 'holder proof nonce remains one use');
      const freshHolderProof = async () => {
        const cNonce = (
          (await (await haip.fetch(`${issuer}/nonce`, { method: 'POST' })).json()) as any
        ).c_nonce;
        return new SignJWT({
          aud: issuer,
          iss: walletClient.client_id,
          iat: Math.floor(Date.now() / 1000),
          nonce: cNonce,
        })
          .setProtectedHeader({
            typ: 'openid4vci-proof+jwt',
            alg: 'ES256',
            jwk: externalHolder,
            key_attestation: await keyAttestation(cNonce),
          })
          .sign(externalKey.privateKey);
      };
      const grantBudget = async () =>
        DB.prepare(
          'SELECT issuance_limit,issuance_count,state,access_hash,token_expires_at FROM identity_wallet_grant WHERE access_hash=?',
        )
          .bind(hash(haipToken.access_token))
          .first() as Promise<any>;
      const changedTrust = await issue(
        rsNonce,
        await freshHolderProof(),
        'DPoP',
        haipToken.access_token,
        'jwt',
        harness.getWorker('identity-haip-key-trust-changed'),
      );
      assert.equal(
        changedTrust.status,
        401,
        'attester-policy change invalidates already approved grants',
      );
      const initialBudget = await grantBudget();
      assert.equal(initialBudget.issuance_limit, 16);
      assert.equal(initialBudget.issuance_count, 1, 'rejected proof must not consume budget');
      assert.equal(
        (await issue(rsNonce, await freshHolderProof(), 'Bearer')).status,
        401,
        'HAIP cannot downgrade',
      );
      const sharedProof = await freshHolderProof();
      const nonceRace = await Promise.all([
        issue(rsNonce, sharedProof),
        issue(rsNonce, sharedProof),
      ]);
      assert.equal(
        nonceRace.filter((r) => r.status === 200).length,
        1,
        'same holder nonce has only one winner even with spare capacity',
      );
      assert.equal((await grantBudget()).issuance_count, 2);
      const attestedNonce = (
        (await (await haip.fetch(`${issuer}/nonce`, { method: 'POST' })).json()) as any
      ).c_nonce;
      const direct = (proof: string) =>
        issue(rsNonce, proof, 'DPoP', haipToken.access_token, 'attestation');
      const badAttestations = [
        await keyAttestation(attestedNonce, [externalHolder], {}, externalKey.privateKey),
        await keyAttestation('wrong-nonce'),
        await keyAttestation(attestedNonce, [externalHolder], {
          exp: Math.floor(Date.now() / 1000) - 1,
        }),
        await keyAttestation(attestedNonce, [externalHolder, dpopJwk]),
      ];
      for (const bad of badAttestations) {
        const rejected = await direct(bad);
        assert.equal(rejected.status, 400);
        assert.equal(
          ((await rejected.json()) as any).error,
          bad === badAttestations[1] ? 'invalid_nonce' : 'invalid_proof',
        );
      }
      const missingAttestation = await new SignJWT({
        aud: issuer,
        iss: walletClient.client_id,
        iat: Math.floor(Date.now() / 1000),
        nonce: attestedNonce,
      })
        .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: externalHolder })
        .sign(externalKey.privateKey);
      assert.equal(
        (await issue(rsNonce, missingAttestation)).status,
        400,
        'HAIP does not silently downgrade to unattested proof',
      );
      assert.equal(
        (await grantBudget()).issuance_count,
        2,
        'invalid attestations do not consume slots',
      );
      const directReceipt = await direct(await keyAttestation(attestedNonce));
      assert.equal(directReceipt.status, 200, await directReceipt.clone().text());
      const directCredential = ((await directReceipt.json()) as any).credentials[0].credential;
      if (configuration === 'linked_document') {
        const { payload } = await jwtVerify(directCredential.split('~')[0], op.publicKey, {
          issuer,
        });
        assert.deepEqual((payload.cnf as any).jwk, externalHolder);
      } else {
        verifyMdocIssuer(directCredential, externalHolder, await exportJWK(op.publicKey));
      }
      assert.equal(
        (await direct(await keyAttestation(attestedNonce))).status,
        400,
        'standalone attestation nonce is one use',
      );
      const encryptionMetadata = (await (
        await haip.fetch(`${root}/.well-known/openid-credential-issuer/identity/issuer`)
      ).json()) as any;
      const requestJwk = encryptionMetadata.credential_request_encryption.jwks.keys[0];
      assert.equal(requestJwk.d, undefined, 'discovery never exposes the private recipient key');
      const requestKey = await importJWK(requestJwk, 'ECDH-ES');
      const responseKey = await generateKeyPair('ECDH-ES', { extractable: true });
      const responseJwk = {
        ...(await exportJWK(responseKey.publicKey)),
        kid: 'fixture-wallet-recipient',
        alg: 'ECDH-ES',
        use: 'enc',
      };
      const encryptedIssue = async (
        proof: string,
        enc: string,
        recipient = responseJwk,
        headerPatch = {},
        corrupt = false,
        plain = false,
        zip?: string,
      ) => {
        const body = JSON.stringify({
          credential_configuration_id: configuration,
          proofs: { jwt: [proof] },
          credential_response_encryption: { jwk: recipient, enc, ...(zip ? { zip } : {}) },
        });
        let wire = await new CompactEncrypt(Buffer.from(body))
          .setProtectedHeader({
            alg: 'ECDH-ES',
            enc: 'A256GCM',
            kid: requestJwk.kid,
            cty: 'json',
            ...headerPatch,
          })
          .encrypt(requestKey);
        if (corrupt) {
          const parts = wire.split('.');
          const tag = Buffer.from(parts[4], 'base64url');
          tag[0] ^= 1;
          parts[4] = tag.toString('base64url');
          wire = parts.join('.');
        }
        return haip.fetch(`${issuer}/credential`, {
          method: 'POST',
          headers: {
            'Content-Type': plain ? 'application/json' : 'application/jwt',
            Authorization: `DPoP ${haipToken.access_token}`,
            DPoP: await new SignJWT({
              htu: `${issuer}/credential`,
              htm: 'POST',
              iat: Math.floor(Date.now() / 1000),
              jti: secret(),
              ath: hash(haipToken.access_token),
              nonce: rsNonce,
            })
              .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk })
              .sign(dpopKey.privateKey),
          },
          body: plain ? body : wire,
        });
      };
      const retryProof = await freshHolderProof();
      for (const reject of [
        () => encryptedIssue(retryProof, 'unsupported'),
        () => encryptedIssue(retryProof, 'A256GCM', { ...responseJwk, alg: 'unsupported' }),
        () => encryptedIssue(retryProof, 'A256GCM', responseJwk, { kid: 'wrong-key' }),
        () => encryptedIssue(retryProof, 'A256GCM', responseJwk, {}, true),
        () => encryptedIssue(retryProof, 'A256GCM', responseJwk, {}, false, true),
        () => encryptedIssue(retryProof, 'A256GCM', responseJwk, {}, false, false, 'unsupported'),
      ]) {
        const rejected = await reject();
        assert.equal(rejected.status, 400);
        assert.match(rejected.headers.get('content-type')!, /application\/json/);
        assert.equal(((await rejected.json()) as any).error, 'invalid_encryption_parameters');
      }
      assert.equal(
        (await grantBudget()).issuance_count,
        3,
        'bad encryption never consumes nonce or slots',
      );
      for (let i = 0; i < 12; i++) {
        if (i === 3) {
          const proof = await freshHolderProof();
          const issued = await receiveWithRustEncryption(
            encryptionMetadata,
            {
              credential_configuration_id: configuration,
              proofs: { jwt: [proof] },
            },
            async (wire) => {
              const response = await haip.fetch(`${issuer}/credential`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/jwt',
                  Authorization: `DPoP ${haipToken.access_token}`,
                  DPoP: await new SignJWT({
                    htu: `${issuer}/credential`,
                    htm: 'POST',
                    iat: Math.floor(Date.now() / 1000),
                    jti: secret(),
                    ath: hash(haipToken.access_token),
                    nonce: rsNonce,
                  })
                    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk })
                    .sign(dpopKey.privateKey),
                },
                body: wire,
              });
              assert.equal(response.status, 200, await response.clone().text());
              assert.match(response.headers.get('content-type')!, /application\/jwt/);
              return response.text();
            },
          );
          assert.equal(issued.credentials.length, 1);
          const credential = issued.credentials[0].credential;
          if (configuration === 'linked_document') {
            const { payload } = await jwtVerify(credential.split('~')[0], op.publicKey, { issuer });
            assert.deepEqual((payload.cnf as any).jwk, externalHolder);
          } else verifyMdocIssuer(credential, externalHolder, await exportJWK(op.publicKey));
          continue;
        }
        if (i < 3) {
          const enc = i === 0 ? 'A128GCM' : 'A256GCM';
          const result = await encryptedIssue(
            i === 0 ? retryProof : await freshHolderProof(),
            enc,
            responseJwk,
            {},
            false,
            false,
            i === 2 ? 'DEF' : undefined,
          );
          assert.equal(result.status, 200, await result.clone().text());
          assert.match(result.headers.get('content-type')!, /application\/jwt/);
          assert.equal(result.headers.get('cache-control'), 'no-store');
          const wire = await result.text();
          if (i === 2) {
            // Independent Node/OpenSSL ECDH + GCM and zlib, including protected zip as AAD.
            const parts = wire.split('.');
            const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
            assert.equal(header.zip, 'DEF');
            assert.equal(header.alg, 'ECDH-ES');
            assert.equal(header.enc, enc);
            assert.equal(header.kid, responseJwk.kid);
            assert.equal(parts[1], '');
            const shared = diffieHellman({
              privateKey: createPrivateKey({
                key: await exportJWK(responseKey.privateKey),
                format: 'jwk',
              }),
              publicKey: createPublicKey({ key: header.epk, format: 'jwk' }),
            });
            const length = (n: number) => {
              const b = Buffer.alloc(4);
              b.writeUInt32BE(n);
              return b;
            };
            const cek = createHash('sha256')
              .update(
                Buffer.concat([
                  length(1),
                  shared,
                  length(enc.length),
                  Buffer.from(enc),
                  length(0),
                  length(0),
                  length(256),
                ]),
              )
              .digest();
            const decrypt = (value: string) => {
              const p = value.split('.');
              const aes = createDecipheriv('aes-256-gcm', cek, Buffer.from(p[2], 'base64url'));
              aes.setAAD(Buffer.from(p[0]));
              aes.setAuthTag(Buffer.from(p[4], 'base64url'));
              return Buffer.concat([aes.update(Buffer.from(p[3], 'base64url')), aes.final()]);
            };
            const credential = JSON.parse(
              inflateRawSync(decrypt(wire), { maxOutputLength: 65536 }).toString(),
            ).credentials[0].credential;
            if (configuration === 'linked_document') {
              const { payload } = await jwtVerify(credential.split('~')[0], op.publicKey, {
                issuer,
              });
              assert.deepEqual((payload.cnf as any).jwk, externalHolder);
            } else verifyMdocIssuer(credential, externalHolder, await exportJWK(op.publicKey));
            const changed = [...parts];
            const tag = Buffer.from(changed[4], 'base64url');
            tag[0] ^= 1;
            changed[4] = tag.toString('base64url');
            assert.throws(() => decrypt(changed.join('.')));
            continue;
          }
          const decrypted = await compactDecrypt(wire, responseKey.privateKey, {
            keyManagementAlgorithms: ['ECDH-ES'],
            contentEncryptionAlgorithms: [enc],
          });
          assert.equal(decrypted.protectedHeader.kid, responseJwk.kid);
          const encryptedCredential = JSON.parse(Buffer.from(decrypted.plaintext).toString())
            .credentials[0].credential;
          if (configuration === 'linked_document') {
            const { payload } = await jwtVerify(encryptedCredential.split('~')[0], op.publicKey, {
              issuer,
            });
            assert.deepEqual((payload.cnf as any).jwk, externalHolder);
          } else {
            verifyMdocIssuer(encryptedCredential, externalHolder, await exportJWK(op.publicKey));
          }
          const changedTag = wire.split('.');
          const tag = Buffer.from(changedTag[4], 'base64url');
          tag[0] ^= 1;
          changedTag[4] = tag.toString('base64url');
          await assert.rejects(compactDecrypt(changedTag.join('.'), responseKey.privateKey));
          await assert.rejects(compactDecrypt(wire, issuerEncryption.privateKey));
          continue;
        }

        const repeated = await issue(rsNonce, await freshHolderProof(), i % 2 ? 'dPoP' : 'dpop');
        assert.equal(repeated.status, 200, await repeated.clone().text());
      }
      const beforeFinal = await grantBudget();
      assert.equal(beforeFinal.issuance_count, 15);
      assert.equal(
        beforeFinal.token_expires_at,
        initialBudget.token_expires_at,
        'issuance must not extend token lifetime',
      );
      const finalProofs = await Promise.all([freshHolderProof(), freshHolderProof()]);
      const raced = await Promise.all(finalProofs.map((proof) => issue(rsNonce, proof)));
      assert.equal(
        raced.filter((r) => r.status === 200).length,
        1,
        'different valid holder nonces cannot overspend the last slot',
      );
      assert.equal(await grantBudget(), null, 'exhausted access token is erased');
      const exhausted = (await DB.prepare(
        'SELECT issuance_count,state FROM identity_wallet_grant WHERE grant_id=?',
      )
        .bind(/name=grant value='([^']+)'/.exec(text)![1])
        .first()) as any;
      assert.equal(exhausted.issuance_count, 16);
      assert.equal(
        (await issue(rsNonce, await freshHolderProof())).status,
        401,
        'cannot exceed approved budget',
      );

      assert.equal(
        (await exchange({ ...(await clientHeaders()), DPoP: await nonceDpop() })).status,
        400,
        'code is one use',
      );
      // A second approval exercises replay while its multi-issuance token is live.
      const replayPar = await haipPush(await clientHeaders(), configuration, haip, {
        dpop_jkt: await calculateJwkThumbprint(dpopJwk),
      });
      assert.equal(replayPar.status, 201);
      const replayUri = ((await replayPar.json()) as any).request_uri;
      const replayPage = await haip.fetch(
        `${issuer}/authorize?${new URLSearchParams({ client_id: walletClient.client_id, request_uri: replayUri })}`,
        { headers: ownerHeaders },
      );
      const replayHtml = await replayPage.text();
      const replayApproval = await haip.fetch(`${issuer}/authorize`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          ...ownerHeaders,
          Origin: root,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant: /name=grant value='([^']+)'/.exec(replayHtml)![1],
          csrf: /name=csrf value='([^']+)'/.exec(replayHtml)![1],
          document: parDocument.transaction_id,
          decision: 'approve',
        }).toString(),
      });
      assert.equal(replayApproval.status, 303);
      const replayCode = new URL(replayApproval.headers.get('location')!).searchParams.get('code')!;
      const replayTokenResponse = await exchange(
        { ...(await clientHeaders()), DPoP: await nonceDpop() },
        replayCode,
      );
      assert.equal(replayTokenResponse.status, 200);
      const replayAccess = ((await replayTokenResponse.json()) as any).access_token;
      assert.equal(
        (
          await exchange(
            { ...(await clientHeaders()), DPoP: await nonceDpop() },
            replayCode,
            secret(),
          )
        ).status,
        400,
      );
      const substituteSender = await new SignJWT({
        htu: `${issuer}/token`,
        htm: 'POST',
        iat: Math.floor(Date.now() / 1000),
        jti: secret(),
        nonce,
      })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: externalHolder })
        .sign(externalKey.privateKey);
      assert.equal(
        (await exchange({ ...(await clientHeaders()), DPoP: substituteSender }, replayCode)).status,
        400,
      );
      const stillLive = await issue(rsNonce, await freshHolderProof(), 'DPoP', replayAccess);
      assert.equal(stillLive.status, 200, 'wrong verifier or sender cannot revoke another grant');
      assert.equal(
        (await exchange({ ...(await clientHeaders()), DPoP: await nonceDpop() }, replayCode))
          .status,
        400,
      );
      assert.equal(
        (await issue(rsNonce, await freshHolderProof(), 'DPoP', replayAccess)).status,
        401,
        'authenticated code replay revokes remaining issuance authority',
      );
    }
    if (process.env.MIKAKI_MULTIPAZ_CHECKOUT) {
      await DB.prepare("UPDATE account_security SET epoch=1 WHERE account_id='owner'").run();
      const linked = await start(f.makeMnc());
      await approve(linked, 'link');
      await receiveWithMultipaz(
        harness.getWorker('identity-wallet-nonce'),
        linked.transaction_id,
        await exportJWK(op.publicKey),
      );
    }
  } finally {
    await harness.close();
  }
});
