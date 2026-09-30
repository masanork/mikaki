import assert from 'node:assert/strict';
import { exportJWK, generateKeyPair } from 'jose';
import { FixtureVerifier, digest, formResponse, newRequest, unlockKey } from '../oid4vp/probe.ts';
import {
  IssuerFixture,
  importResponse,
  jsonResponse,
  makeProof,
  profile,
  receiveOffer,
  type Transport,
} from './probe.ts';

type Scenario = {
  id: string;
  layer: 'independent-issuer' | 'issuer-policy' | 'wallet';
  run: () => Promise<void>;
};
const codeRequest = (i: IssuerFixture, txCode = i.txCode) =>
  new Request(profile.tokenEndpoint, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: profile.grantType,
      'pre-authorized_code': (i.offer.grants as Record<string, Record<string, string>>)[
        profile.grantType
      ]!['pre-authorized_code']!,
      tx_code: txCode,
    }),
  });
async function authorized(i: IssuerFixture) {
  const response = await i.transport(codeRequest(i));
  assert.ok(response.status === 200, 'Fixture exchange must succeed');
  const body: { access_token: string } = await response.json();
  const nonce = async () => {
    const response = await i.transport(new Request(profile.nonceEndpoint, { method: 'POST' }));
    const body: { c_nonce: string } = await response.json();
    assert.ok(response.headers.get('cache-control') === 'no-store', 'Nonce must not be cached');
    return body.c_nonce;
  };
  const holder = await generateKeyPair('ES256', { extractable: true });
  return {
    token: body.access_token,
    nonce,
    privateKey: await exportJWK(holder.privateKey),
    publicKey: await exportJWK(holder.publicKey),
  };
}
const credentialRequest = (token: string, proof: string, overrides: Record<string, unknown> = {}) =>
  new Request(profile.credentialEndpoint, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      credential_configuration_id: profile.configurationId,
      proofs: { jwt: [proof] },
      ...overrides,
    }),
  });
async function errorIs(response: Response, expected: string) {
  const value: { error?: unknown } = await response.json();
  assert.ok(
    !response.ok && value.error === expected,
    'Issuer must return the expected content-free denial',
  );
}
const receive = async (
  i: IssuerFixture,
  transport: Transport = i.transport,
  offer: unknown = i.offer,
) =>
  receiveOffer({
    offer,
    transport,
    approved: true,
    txCode: i.txCode,
    issuerPublic: i.issuerPublic,
    key: await unlockKey(),
  });

export const scenarios: Scenario[] = [
  ...(['issuance-token-scope', 'unadvertised-refresh-token', 'cacheable-nonce'] as const).map(
    (id): Scenario => ({
      id,
      layer: 'wallet',
      async run() {
        const i = await IssuerFixture.create();
        const transport: Transport = async (request) => {
          const response = await i.transport(request);
          if (request.url === profile.tokenEndpoint && id !== 'cacheable-nonce') {
            const body: Record<string, unknown> = await response.json();
            if (id === 'issuance-token-scope') body.scope = 'vault.write';
            else body.refresh_token = 'unsupported-fixture-token';
            return jsonResponse(body);
          }
          if (request.url === profile.nonceEndpoint && id === 'cacheable-nonce')
            return Response.json(await response.json());
          return response;
        };
        await assert.rejects(
          receive(i, transport),
          'Unsupported authority or cached nonce must fail',
        );
        assert.ok(i.issued === 0, 'Receipt must fail before credential issuance');
      },
    }),
  ),
  {
    id: 'receipt-encryption-and-presentation',
    layer: 'independent-issuer',
    async run() {
      const i = await IssuerFixture.create();
      const key = await unlockKey();
      let original = '';
      const transport: Transport = async (request) => {
        assert.ok(request.redirect === 'error', 'Wallet must disable redirects before disclosure');
        const response = await i.transport(request);
        if (request.url === profile.credentialEndpoint && response.ok) {
          const body: { credentials: { credential: string }[] } = await response.clone().json();
          original = body.credentials[0]!.credential;
        }
        return response;
      };
      const wallet = await receiveOffer({
        offer: i.offer,
        txCode: i.txCode,
        approved: true,
        transport,
        issuerPublic: i.issuerPublic,
        key,
      });
      assert.ok(
        wallet && i.issued === 1,
        'Independent issuer protocol path must issue one instance',
      );
      assert.ok(
        (await wallet.original(key)) === original,
        'Receipt must preserve exact signed issuer bytes',
      );
      await assert.rejects(wallet.original(await unlockKey()), 'Wrong wrapping key must fail');
      const request = newRequest();
      const envelope = await wallet.present(request, true, key);
      const decision = await new FixtureVerifier(request, i.issuerPublic, async (hash) =>
        hash === digest(original.split('~')[0]!) ? 'good' : 'unknown',
      ).receive(formResponse(envelope));
      assert.ok(
        decision.accepted,
        'Received credential must present to the independent VP verifier',
      );
    },
  },
  {
    id: 'receipt-cancellation',
    layer: 'wallet',
    async run() {
      const i = await IssuerFixture.create();
      const result = await receiveOffer({
        offer: null,
        txCode: '',
        approved: false,
        transport: i.transport,
        issuerPublic: i.issuerPublic,
        key: await unlockKey(),
      });
      assert.ok(
        result === null && i.requests === 0 && i.issued === 0,
        'Cancellation must not exchange codes or contact issuer',
      );
    },
  },
  ...(
    ['untrusted-offer-issuer', 'unoffered-configuration', 'unsupported-offer-grant'] as const
  ).map((id): Scenario => ({
    id,
    layer: 'wallet',
    async run() {
      const i = await IssuerFixture.create();
      const offer = structuredClone(i.offer);
      if (id === 'untrusted-offer-issuer') offer.credential_issuer = 'https://attacker.mikaki.test';
      if (id === 'unoffered-configuration') offer.credential_configuration_ids = ['other'];
      if (id === 'unsupported-offer-grant') offer.grants = { authorization_code: {} };
      await assert.rejects(receive(i, i.transport, offer), 'Unsupported offer must fail');
      assert.ok(i.requests === 0, 'Bad offer must not disclose a code or trigger discovery');
    },
  })),
  ...(
    [
      'metadata-issuer-mismatch',
      'metadata-endpoint-substitution',
      'metadata-proof-downgrade',
      'unsupported-encryption',
      'authorization-server-substitution',
      'redirect-metadata',
    ] as const
  ).map((id): Scenario => ({
    id,
    layer: 'wallet',
    async run() {
      const i = await IssuerFixture.create();
      const transport: Transport = async (request) => {
        if (request.url === profile.metadataEndpoint) {
          if (id === 'redirect-metadata')
            return Response.redirect('https://attacker.mikaki.test', 302);
          const metadata = structuredClone(i.metadata.credentialIssuer);
          if (id === 'metadata-issuer-mismatch')
            metadata.credential_issuer = 'https://attacker.mikaki.test';
          if (id === 'metadata-endpoint-substitution')
            metadata.credential_endpoint = 'https://attacker.mikaki.test/credential';
          if (id === 'metadata-proof-downgrade')
            delete metadata.credential_configurations_supported[profile.configurationId]!
              .proof_types_supported;
          if (id === 'unsupported-encryption')
            metadata.credential_response_encryption = {
              encryption_required: true,
              alg_values_supported: ['ECDH-ES'],
              enc_values_supported: ['A256GCM'],
            };
          return jsonResponse(metadata);
        }
        if (
          request.url === profile.authorizationMetadataEndpoint &&
          id === 'authorization-server-substitution'
        )
          return jsonResponse({
            ...i.metadata.authorizationServers[0],
            token_endpoint: 'https://attacker.mikaki.test/token',
          });
        return i.transport(request);
      };
      await assert.rejects(receive(i, transport), 'Unsupported discovery must fail');
      assert.ok(
        i.issued === 0 && i.requests === 0,
        'Substituted metadata must fail before token exchange',
      );
    },
  })),
  {
    id: 'transaction-code-attempt-limit',
    layer: 'issuer-policy',
    async run() {
      const i = await IssuerFixture.create();
      const wrong = i.txCode === '000000' ? '000001' : '000000';
      for (let n = 0; n < 3; n++)
        await errorIs(await i.transport(codeRequest(i, wrong)), 'invalid_grant');
      await errorIs(await i.transport(codeRequest(i)), 'invalid_grant');
      assert.ok(i.issued === 0, 'Transaction-code exhaustion must invalidate the offer');
    },
  },
  {
    id: 'code-replay-and-concurrency',
    layer: 'issuer-policy',
    async run() {
      const i = await IssuerFixture.create();
      const results = await Promise.all([i.transport(codeRequest(i)), i.transport(codeRequest(i))]);
      assert.ok(
        results.filter((r) => r.status === 200).length === 1,
        'Pre-authorized code must have one winner',
      );
      await errorIs(await i.transport(codeRequest(i)), 'invalid_grant');
    },
  },
  {
    id: 'expired-code-and-token',
    layer: 'issuer-policy',
    async run() {
      let time = Math.floor(Date.now() / 1000);
      const i = await IssuerFixture.create(() => time);
      const a = await authorized(i);
      const nonce = await a.nonce();
      time += 121;
      await errorIs(
        await i.transport(credentialRequest(a.token, await makeProof(a.privateKey, nonce))),
        'invalid_token',
      );
      const j = await IssuerFixture.create(() => time);
      time += 91;
      await errorIs(await j.transport(codeRequest(j)), 'invalid_grant');
    },
  },
  ...(
    [
      'wrong-proof-nonce',
      'wrong-proof-audience',
      'wrong-proof-type',
      'wrong-proof-signature',
    ] as const
  ).map((id): Scenario => ({
    id,
    layer: 'independent-issuer',
    async run() {
      const i = await IssuerFixture.create();
      const a = await authorized(i);
      const nonce = await a.nonce();
      const other = await generateKeyPair('ES256', { extractable: true });
      const proof = await makeProof(
        a.privateKey,
        id === 'wrong-proof-nonce' ? 'wrong-nonce' : nonce,
        id === 'wrong-proof-audience' ? { aud: 'https://other.mikaki.test' } : {},
        id === 'wrong-proof-type'
          ? { typ: 'JWT' }
          : id === 'wrong-proof-signature'
            ? { jwk: await exportJWK(other.publicKey) }
            : {},
      );
      await assert.rejects(
        i.verifyProof(proof, nonce),
        'Independent issuer library must reject proof',
      );
      await errorIs(
        await i.transport(credentialRequest(a.token, proof)),
        id === 'wrong-proof-nonce' ? 'invalid_nonce' : 'invalid_proof',
      );
      assert.ok(i.issued === 0, 'Invalid proof must not issue');
    },
  })),
  ...(
    [
      'anonymous-proof-issuer',
      'proof-iat-future',
      'proof-iat-stale',
      'private-key-in-header',
    ] as const
  ).map((id): Scenario => ({
    id,
    layer: 'issuer-policy',
    async run() {
      const i = await IssuerFixture.create();
      const a = await authorized(i);
      const nonce = await a.nonce();
      const overrides =
        id === 'anonymous-proof-issuer'
          ? { iss: 'wallet-client' }
          : id === 'proof-iat-future'
            ? { iat: Math.floor(Date.now() / 1000) + 120 }
            : id === 'proof-iat-stale'
              ? { iat: Math.floor(Date.now() / 1000) - 120 }
              : {};
      const proof = await makeProof(
        a.privateKey,
        nonce,
        overrides,
        id === 'private-key-in-header' ? { jwk: a.privateKey } : {},
      );
      await errorIs(await i.transport(credentialRequest(a.token, proof)), 'invalid_proof');
    },
  })),
  {
    id: 'nonce-replay-expiry-and-retry',
    layer: 'issuer-policy',
    async run() {
      let time = Math.floor(Date.now() / 1000);
      const i = await IssuerFixture.create(() => time);
      const a = await authorized(i);
      const nonce = await a.nonce();
      const wrong = await makeProof(a.privateKey, nonce, { aud: 'https://other.mikaki.test' });
      await errorIs(await i.transport(credentialRequest(a.token, wrong)), 'invalid_proof');
      await errorIs(
        await i.transport(credentialRequest(a.token, await makeProof(a.privateKey, nonce))),
        'invalid_nonce',
      );
      const expired = await a.nonce();
      time += 61;
      await errorIs(
        await i.transport(credentialRequest(a.token, await makeProof(a.privateKey, expired))),
        'invalid_nonce',
      );
      const fresh = await a.nonce();
      const response = await i.transport(
        credentialRequest(a.token, await makeProof(a.privateKey, fresh, { iat: time })),
      );
      assert.ok(
        response.ok && i.issued === 1,
        'Fresh nonce may retry while the issuance token remains valid',
      );
    },
  },
  {
    id: 'credential-one-winner-and-token-replay',
    layer: 'issuer-policy',
    async run() {
      const i = await IssuerFixture.create();
      const a = await authorized(i);
      const proofs = await Promise.all([a.nonce(), a.nonce()]);
      const responses = await Promise.all(
        proofs.map(async (nonce) =>
          i.transport(credentialRequest(a.token, await makeProof(a.privateKey, nonce))),
        ),
      );
      assert.ok(
        responses.filter((r) => r.ok).length === 1 && i.issued === 1,
        'Distinct nonce concurrency still permits one issuance',
      );
      await errorIs(
        await i.transport(
          credentialRequest(a.token, await makeProof(a.privateKey, await a.nonce())),
        ),
        'invalid_token',
      );
    },
  },
  ...(
    [
      'unapproved-configuration',
      'legacy-request-proof',
      'multiple-holder-proofs',
      'mixed-request-identifiers',
      'invalid-access-token',
    ] as const
  ).map((id): Scenario => ({
    id,
    layer: 'issuer-policy',
    async run() {
      const i = await IssuerFixture.create();
      const a = await authorized(i);
      const proof = await makeProof(a.privateKey, await a.nonce());
      const overrides: Record<string, unknown> =
        id === 'unapproved-configuration'
          ? { credential_configuration_id: 'other' }
          : id === 'legacy-request-proof'
            ? { proofs: undefined, proof: { proof_type: 'jwt', jwt: proof } }
            : id === 'multiple-holder-proofs'
              ? { proofs: { jwt: [proof, proof] } }
              : id === 'mixed-request-identifiers'
                ? { credential_identifier: 'other' }
                : {};
      await errorIs(
        await i.transport(
          credentialRequest(
            id === 'invalid-access-token' ? 'wrong-token' : a.token,
            proof,
            overrides,
          ),
        ),
        id === 'unapproved-configuration'
          ? 'unknown_credential_configuration'
          : id === 'invalid-access-token'
            ? 'invalid_token'
            : id === 'multiple-holder-proofs'
              ? 'invalid_proof'
              : 'invalid_request',
      );
      assert.ok(i.issued === 0, 'Unapproved request must not issue');
    },
  })),
  ...(
    [
      'legacy-response',
      'deferred-response',
      'multiple-credentials',
      'wrong-response-type',
      'wrong-credential-holder',
      'untrusted-credential-key',
      'wrong-credential-type',
      'expired-credential',
      'future-credential-iat',
      'duplicate-disclosure',
    ] as const
  ).map((id): Scenario => ({
    id,
    layer: 'wallet',
    async run() {
      const i = await IssuerFixture.create();
      const a = await authorized(i);
      const key = await unlockKey();
      const other = await generateKeyPair('ES256', { extractable: true });
      let artifact = await i.signedArtifact(
        id === 'wrong-credential-holder' ? await exportJWK(other.publicKey) : a.publicKey,
        id === 'wrong-credential-type'
          ? { vct: 'https://issuer.mikaki.test/other/v1' }
          : id === 'expired-credential'
            ? { exp: Math.floor(Date.now() / 1000) - 10 }
            : id === 'future-credential-iat'
              ? { iat: Math.floor(Date.now() / 1000) + 120 }
              : {},
      );
      if (id === 'duplicate-disclosure') {
        const parts = artifact.split('~');
        parts[2] = parts[1]!;
        artifact = parts.join('~');
      }
      const body =
        id === 'legacy-response'
          ? { credential: artifact }
          : id === 'deferred-response'
            ? { transaction_id: 'synthetic', interval: 1 }
            : {
                credentials:
                  id === 'multiple-credentials'
                    ? [{ credential: artifact }, { credential: artifact }]
                    : [{ credential: artifact }],
              };
      const response =
        id === 'wrong-response-type'
          ? new Response(JSON.stringify(body), { headers: { 'content-type': 'text/plain' } })
          : jsonResponse(body, id === 'deferred-response' ? 202 : 200);
      await assert.rejects(
        importResponse(
          response,
          a.privateKey,
          id === 'untrusted-credential-key' ? await exportJWK(other.publicKey) : i.issuerPublic,
          key,
        ),
        'Invalid issuance response must never create a stored wallet',
      );
    },
  })),
];
