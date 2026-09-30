import assert from 'node:assert/strict';
import { decodeJwt, importJWK, SignJWT, UnsecuredJWT, type JWK } from 'jose';
import {
  DpopGate,
  DpopIssuanceFixture,
  dpopKey,
  dpopReceiptTransport,
  proofHeaders,
} from './probe.ts';
import {
  IssuerFixture,
  jsonResponse,
  makeProof,
  profile,
  receiveOffer,
  type Transport,
} from '../oid4vci/probe.ts';
import { FixtureVerifier, formResponse, newRequest, unlockKey } from '../oid4vp/probe.ts';

type Scenario = {
  id: string;
  layer: 'protocol-and-gate' | 'replay-policy' | 'issuance' | 'wallet';
  run: () => Promise<void>;
};
const time = () => Math.floor(Date.now() / 1000);
const nonce = 'synthetic-dpop-server-nonce';
const token = 'SyntheticTokenMixedCase';
const target = `${profile.credentialEndpoint}?tracking=one`;
async function setup(resource = true) {
  const key = await dpopKey();
  const request = new Request(resource ? target : profile.tokenEndpoint, {
    method: 'POST',
    headers: resource ? { authorization: `DPoP ${token}` } : {},
  });
  const options = {
    nonce,
    accessToken: resource ? token : undefined,
    expectedJkt: resource ? key.jkt : undefined,
  };
  const signed = async (
    payload: Record<string, unknown> = {},
    header: Record<string, unknown> = {},
    signingKey = key.privateJwk,
  ) => {
    const jwt = await new SignJWT({
      jti: 'synthetic-proof-id',
      iat: time(),
      htm: 'POST',
      htu: resource ? profile.credentialEndpoint : profile.tokenEndpoint,
      nonce,
      ...(resource ? { ath: (await import('../oid4vp/probe.ts')).digest(token) } : {}),
      ...payload,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: key.publicJwk, ...header })
      .sign(await importJWK(signingKey, 'ES256'));
    const headers = new Headers(request.headers);
    headers.set('dpop', jwt);
    return new Request(request, { headers });
  };
  return { key, request, options, signed, gate: new DpopGate() };
}
const negativePayloads: Array<[string, Record<string, unknown>]> = [
  ['wrong-method', { htm: 'GET' }],
  ['wrong-origin', { htu: 'https://attacker.test/credential' }],
  ['wrong-path', { htu: profile.tokenEndpoint }],
  ['query-in-htu', { htu: target }],
  ['missing-nonce', { nonce: undefined }],
  ['wrong-nonce', { nonce: 'wrong' }],
  ['missing-ath', { ath: undefined }],
  ['wrong-ath', { ath: 'wrong' }],
  ['missing-iat', { iat: undefined }],
  ['fractional-iat', { iat: time() + 0.5 }],
  ['missing-jti', { jti: undefined }],
  ['empty-jti', { jti: '' }],
  ['control-jti', { jti: 'bad\nidentifier' }],
];

export const scenarios: Scenario[] = [
  ...negativePayloads.map(([id, payload]): Scenario => ({
    id,
    layer: 'protocol-and-gate',
    async run() {
      const s = await setup();
      await assert.rejects(s.gate.verify(await s.signed(payload), s.options));
    },
  })),
  {
    id: 'independently-signed-resource-proof',
    layer: 'protocol-and-gate',
    async run() {
      const s = await setup();
      assert.equal((await s.gate.verify(await s.signed(), s.options)).jkt, s.key.jkt);
    },
  },
  {
    id: 'owf-generated-token-proof',
    layer: 'protocol-and-gate',
    async run() {
      const s = await setup(false);
      const h = await proofHeaders(s.key.privateJwk, s.request, { nonce });
      assert.equal(
        (await s.gate.verify(new Request(s.request, { headers: h }), s.options)).jkt,
        s.key.jkt,
      );
    },
  },
  ...(['symmetric-algorithm', 'unsigned-proof'] as const).map((id) => ({
    id,
    layer: 'protocol-and-gate' as const,
    async run() {
      const s = await setup(false);
      const payload = {
        jti: 'synthetic-proof-id',
        iat: time(),
        htm: 'POST',
        htu: profile.tokenEndpoint,
        nonce,
      };
      const secret = new Uint8Array(32).fill(1);
      const symmetricJwk = { kty: 'oct' as const, k: Buffer.from(secret).toString('base64url') };
      const compact =
        id === 'unsigned-proof'
          ? new UnsecuredJWT(payload).encode()
          : await new SignJWT(payload)
              .setProtectedHeader({
                alg: 'HS256',
                typ: 'dpop+jwt',
                jwk: symmetricJwk,
              })
              .sign(secret);
      await assert.rejects(
        s.gate.verify(new Request(s.request, { headers: { dpop: compact } }), s.options),
      );
    },
  })),
  {
    id: 'query-not-signed',
    layer: 'protocol-and-gate',
    async run() {
      const s = await setup();
      const r = await s.signed();
      assert.equal(
        (
          await s.gate.verify(
            new Request(`${profile.credentialEndpoint}?tracking=other#fragment`, {
              method: r.method,
              headers: r.headers,
            }),
            s.options,
          )
        ).jkt,
        s.key.jkt,
      );
    },
  },
  ...(['wrong-typ', 'private-jwk', 'unsupported-critical-header', 'bad-signature'] as const).map(
    (id): Scenario => ({
      id,
      layer: 'protocol-and-gate',
      async run() {
        const s = await setup();
        const other = await dpopKey();
        const header =
          id === 'wrong-typ'
            ? { typ: 'openid4vci-proof+jwt' }
            : id === 'private-jwk'
              ? { jwk: s.key.privateJwk }
              : id === 'unsupported-critical-header'
                ? { crit: ['b64'], b64: true }
                : {};
        if (id === 'unsupported-critical-header') {
          // Independent signer supports this extension; the gate must refuse it.
          await assert.rejects(s.gate.verify(await s.signed({}, header), s.options));
        } else
          await assert.rejects(
            s.gate.verify(
              await s.signed(
                {},
                header,
                id === 'bad-signature' ? other.privateJwk : s.key.privateJwk,
              ),
              s.options,
            ),
          );
      },
    }),
  ),
  ...([-71, -70, -10, 10, 11, 61] as const).map((offset) => ({
    id: `iat-offset-${offset}`,
    layer: 'protocol-and-gate' as const,
    async run() {
      const s = await setup();
      const current = time();
      const gate = new DpopGate(() => current);
      const r = await s.signed({ iat: current + offset });
      if (offset < -70 || offset > 10) await assert.rejects(gate.verify(r, s.options));
      else assert.equal((await gate.verify(r, s.options)).jkt, s.key.jkt);
    },
  })),
  ...(
    [
      'bearer-downgrade',
      'token-case-change',
      'duplicate-authorization',
      'duplicate-proof',
      'missing-proof',
      'oversized-proof',
      'http-transport',
    ] as const
  ).map((id) => ({
    id,
    layer: 'protocol-and-gate' as const,
    async run() {
      const s = await setup();
      const signed = await s.signed();
      const headers = new Headers(signed.headers);
      if (id === 'bearer-downgrade') headers.set('authorization', `Bearer ${token}`);
      if (id === 'token-case-change') headers.set('authorization', `DPoP ${token.toLowerCase()}`);
      if (id === 'duplicate-authorization') headers.append('authorization', `DPoP ${token}`);
      if (id === 'duplicate-proof') headers.append('dpop', headers.get('dpop')!);
      if (id === 'missing-proof') headers.delete('dpop');
      if (id === 'oversized-proof') headers.set('dpop', `${'a'.repeat(8192)}.aa.aa`);
      const request = new Request(
        id === 'http-transport' ? target.replace('https:', 'http:') : target,
        { method: 'POST', headers },
      );
      await assert.rejects(s.gate.verify(request, s.options));
    },
  })),
  {
    id: 'scheme-case-insensitivity',
    layer: 'protocol-and-gate',
    async run() {
      const s = await setup();
      const signed = await s.signed();
      signed.headers.set('authorization', `dPoP ${token}`);
      assert.equal((await s.gate.verify(signed, s.options)).jkt, s.key.jkt);
    },
  },
  {
    id: 'wrong-token-or-key-binding',
    layer: 'protocol-and-gate',
    async run() {
      const s = await setup();
      const signed = await s.signed();
      const other = await dpopKey();
      await assert.rejects(s.gate.verify(signed, { ...s.options, expectedJkt: other.jkt }));
      signed.headers.set('authorization', 'DPoP other-token');
      await assert.rejects(s.gate.verify(signed, { ...s.options, accessToken: 'other-token' }));
    },
  },
  {
    id: 'authorization-code-key-binding',
    layer: 'protocol-and-gate',
    async run() {
      const s = await setup(false);
      const signed = await s.signed();
      const other = await dpopKey();
      await assert.rejects(s.gate.verify(signed, { ...s.options, expectedJkt: other.jkt }));
      assert.equal(
        (await s.gate.verify(signed, { ...s.options, expectedJkt: s.key.jkt })).jkt,
        s.key.jkt,
      );
    },
  },
  {
    id: 'one-winner-concurrent-replay',
    layer: 'replay-policy',
    async run() {
      const s = await setup();
      const signed = await s.signed();
      const results = await Promise.allSettled([
        s.gate.verify(signed, s.options),
        s.gate.verify(signed, s.options),
      ]);
      assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
      await assert.rejects(s.gate.verify(signed, s.options));
    },
  },
  {
    id: 'forged-signature-does-not-poison-jti',
    layer: 'replay-policy',
    async run() {
      const s = await setup();
      const other = await dpopKey();
      await assert.rejects(s.gate.verify(await s.signed({}, {}, other.privateJwk), s.options));
      assert.equal((await s.gate.verify(await s.signed(), s.options)).jkt, s.key.jkt);
    },
  },
  {
    id: 'same-jti-different-key',
    layer: 'replay-policy',
    async run() {
      const s = await setup(false);
      const other = await setup(false);
      await s.gate.verify(await s.signed(), s.options);
      assert.equal((await s.gate.verify(await other.signed(), other.options)).jkt, other.key.jkt);
    },
  },
  {
    id: 'ledger-capacity-and-expiry',
    layer: 'replay-policy',
    async run() {
      const s = await setup(false);
      let current = time();
      const gate = new DpopGate(() => current, 1);
      await gate.verify(await s.signed({ iat: current }), s.options);
      await assert.rejects(
        gate.verify(await s.signed({ jti: 'another', iat: current }), s.options),
      );
      current += 71;
      await gate.verify(await s.signed({ iat: current }), s.options);
    },
  },
  {
    id: 'dpop-receipt-encrypted-import-and-presentation',
    layer: 'issuance',
    async run() {
      const issuer = await IssuerFixture.create();
      const endpoint = new DpopIssuanceFixture(issuer);
      const sender = await dpopKey();
      const wrapping = await unlockKey();
      const observed: string[] = [];
      const wire: Transport = async (request) => {
        if (request.url === profile.credentialEndpoint) {
          observed.push(request.headers.get('authorization')!.split(' ')[0]!);
          assert.ok(request.headers.has('dpop'));
        }
        return endpoint.transport(request);
      };
      const wallet = await receiveOffer({
        offer: issuer.offer,
        txCode: issuer.txCode,
        approved: true,
        transport: await dpopReceiptTransport(wire, sender.privateJwk),
        issuerPublic: issuer.issuerPublic,
        key: wrapping,
      });
      assert.ok(wallet);
      assert.deepEqual(observed, ['DPoP']);
      assert.equal(issuer.issued, 1);
      const request = newRequest();
      const presented = await wallet.present(request, true, wrapping);
      const credential = decodeJwt(presented.vp_token!.membership[0]!.split('~')[0]!);
      assert.notDeepEqual((credential.cnf as { jwk: JWK }).jwk, sender.publicJwk);
      assert.equal(
        (
          await new FixtureVerifier(request, issuer.issuerPublic, async () => 'good').receive(
            formResponse(presented),
          )
        ).accepted,
        true,
      );
    },
  },
  ...(['metadata-downgrade', 'token-type-downgrade'] as const).map((id) => ({
    id,
    layer: 'wallet' as const,
    async run() {
      const issuer = await IssuerFixture.create();
      const endpoint = new DpopIssuanceFixture(issuer);
      const sender = await dpopKey();
      let exchanges = 0;
      const wire: Transport = async (request) => {
        if (request.url === profile.tokenEndpoint) exchanges++;
        const response = await endpoint.transport(request);
        if (id === 'metadata-downgrade' && request.url === profile.authorizationMetadataEndpoint)
          return jsonResponse({
            ...(await response.json()),
            dpop_signing_alg_values_supported: undefined,
          });
        if (id === 'token-type-downgrade' && request.url === profile.tokenEndpoint && response.ok)
          return jsonResponse({ ...(await response.json()), token_type: 'Bearer' });
        return response;
      };
      await assert.rejects(
        receiveOffer({
          offer: issuer.offer,
          txCode: issuer.txCode,
          approved: true,
          transport: await dpopReceiptTransport(wire, sender.privateJwk),
          issuerPublic: issuer.issuerPublic,
          key: await unlockKey(),
        }),
      );
      assert.equal(issuer.issued, 0);
      if (id === 'metadata-downgrade') assert.equal(exchanges, 0);
    },
  })),
];
