import assert from 'node:assert/strict';
import { SignJWT, generateKeyPair, jwtVerify } from 'jose';
import { verifyAuthorizationResponse } from '@openeudi/openid4vp';
import {
  FixtureVerifier,
  FixtureWallet,
  digest,
  fixture,
  formResponse,
  newRequest,
  profile,
  query,
  unlockKey,
  type Envelope,
  type PresentationRequest,
  type Status,
} from './probe.ts';

type Fixture = Awaited<ReturnType<typeof fixture>>;
type Scenario = {
  id: string;
  layer: 'independent-verifier' | 'wallet' | 'verifier-policy';
  run: () => Promise<void>;
};
const accepted = async (f: Fixture, r: PresentationRequest, e: Envelope, status: Status = 'good') =>
  new FixtureVerifier(r, f.issuerPublic, async (hash) =>
    hash === digest(f.issuerJwt) ? status : 'unknown',
  ).receive(formResponse(e));

// Deliberately bypass owner policy to exercise the independent verifier against a hostile wallet.
async function hostilePresentation(
  f: Fixture,
  r: PresentationRequest,
  options: {
    nonce?: string;
    audience?: string;
    wrongKey?: boolean;
    missingBinding?: boolean;
    hash?: string;
    disclosures?: string[];
    issuerJwt?: string;
    typ?: string;
    issuedAt?: number;
  } = {},
): Promise<Envelope> {
  const selected = options.disclosures ?? [f.artifact.split('~')[1]!];
  const sdJwt = `${options.issuerJwt ?? f.issuerJwt}~${selected.join('~')}~`;
  if (options.missingBinding) return { state: r.state, vp_token: { membership: [sdJwt] } };
  const holder = options.wrongKey ? await generateKeyPair('ES256') : f.holder;
  const kbJwt = await new SignJWT({
    nonce: options.nonce ?? r.nonce,
    sd_hash: options.hash ?? digest(sdJwt),
  })
    .setProtectedHeader({ alg: 'ES256', typ: options.typ ?? 'kb+jwt' })
    .setAudience(options.audience ?? r.client_id)
    .setIssuedAt(options.issuedAt ?? Math.floor(Date.now() / 1000))
    .sign(holder.privateKey);
  return { state: r.state, vp_token: { membership: [sdJwt + kbJwt] } };
}

async function independentlyValid(
  f: Fixture,
  r: PresentationRequest,
  e: Envelope,
): Promise<boolean> {
  try {
    return (
      await verifyAuthorizationResponse({ state: e.state, vp_token: e.vp_token! }, query, {
        trustedCertificates: [],
        trustedIssuerJwks: [f.issuerPublic],
        nonce: r.nonce,
        audience: r.client_id,
        requireKeyBinding: true,
        allowedAlgorithms: ['ES256'],
        expectedDocType: profile.vct,
      })
    ).valid;
  } catch {
    return false;
  }
}

const validFixture = async () => {
  const f = await fixture();
  const r = newRequest();
  const e = await f.wallet!.present(r, true, f.key);
  return { f, r, e };
};

export const scenarios: Scenario[] = [
  {
    id: 'selective-disclosure-accepted',
    layer: 'independent-verifier',
    async run() {
      const { f, r, e } = await validFixture();
      assert.ok(await independentlyValid(f, r, e), 'Independent verifier must accept');
      assert.ok((await accepted(f, r, e)).accepted, 'Policy must accept');
      const pieces = e.vp_token!.membership[0]!.split('~');
      assert.ok(pieces.length === 3, 'Only one disclosure is presented');
      const disclosure: unknown[] = JSON.parse(
        Buffer.from(pieces[1]!, 'base64url').toString('utf8'),
      );
      assert.ok(
        disclosure[1] === 'membership_active' && disclosure[2] === true,
        'Only requested claim is disclosed',
      );
      const verified = await jwtVerify(pieces[0]!, f.issuer.publicKey);
      assert.ok(
        !('name' in verified.payload) && !('member_number' in verified.payload),
        'Hidden values are absent from issuer payload',
      );
    },
  },
  ...(
    [
      'wrong-nonce',
      'wrong-audience',
      'wrong-holder-key',
      'missing-holder-binding',
      'wrong-sd-hash',
      'unanchored-disclosure',
      'altered-disclosure',
    ] as const
  ).map((id): Scenario => ({
    id,
    layer: 'independent-verifier',
    async run() {
      const f = await fixture();
      const r = newRequest();
      const original = f.artifact.split('~')[1]!;
      const altered: unknown[] = JSON.parse(Buffer.from(original, 'base64url').toString('utf8'));
      altered[2] = false;
      const e = await hostilePresentation(f, r, {
        ...(id === 'wrong-nonce' ? { nonce: 'another-nonce' } : {}),
        ...(id === 'wrong-audience' ? { audience: 'another-verifier' } : {}),
        ...(id === 'wrong-holder-key' ? { wrongKey: true } : {}),
        ...(id === 'missing-holder-binding' ? { missingBinding: true } : {}),
        ...(id === 'wrong-sd-hash' ? { hash: 'not-the-presentation-hash' } : {}),
        ...(id === 'unanchored-disclosure'
          ? {
              disclosures: [
                Buffer.from(JSON.stringify(['synthetic-salt', 'membership_active', true])).toString(
                  'base64url',
                ),
              ],
            }
          : {}),
        ...(id === 'altered-disclosure'
          ? { disclosures: [Buffer.from(JSON.stringify(altered)).toString('base64url')] }
          : {}),
      });
      assert.ok(!(await independentlyValid(f, r, e)), 'Independent verifier must reject');
      assert.ok((await accepted(f, r, e)).gate === 'credential', 'Policy must reject credential');
    },
  })),
  ...(['expired-credential', 'wrong-credential-type', 'inactive-membership'] as const).map(
    (id): Scenario => ({
      id,
      layer: 'independent-verifier',
      async run() {
        const f = await fixture({
          ...(id === 'expired-credential' ? { expiry: Math.floor(Date.now() / 1000) - 10 } : {}),
          ...(id === 'wrong-credential-type' ? { vct: 'https://issuer.mikaki.test/other/v1' } : {}),
          ...(id === 'inactive-membership' ? { active: false } : {}),
        });
        const r = newRequest();
        const e = await hostilePresentation(f, r);
        assert.ok(
          !(await independentlyValid(f, r, e)),
          'Independent verifier must reject type/value/expiry',
        );
        assert.ok((await accepted(f, r, e)).gate === 'credential', 'Policy must reject credential');
      },
    }),
  ),
  {
    id: 'untrusted-issuer-key',
    layer: 'independent-verifier',
    async run() {
      const { f, r, e } = await validFixture();
      const other = await fixture();
      assert.ok(
        !(await independentlyValid(other, r, e)),
        'Independent verifier must reject untrusted signer',
      );
      assert.ok(
        (await accepted(other, r, e)).gate === 'credential',
        'Policy must reject untrusted signer',
      );
      // A valid signature under a pinned key does not authenticate an arbitrary iss URI.
      const renamed = await fixture({ issuer: 'https://untrusted.mikaki.test' });
      const forged = await hostilePresentation(renamed, r);
      assert.ok(
        (await accepted(renamed, r, forged)).gate === 'credential',
        'Policy must pin issuer identity',
      );
    },
  },
  {
    id: 'original-artifact-and-annotation-separation',
    layer: 'wallet',
    async run() {
      const { f } = await validFixture();
      f.wallet!.annotation = 'An editable owner annotation';
      assert.ok(
        (await f.wallet!.original(f.key)) === f.artifact,
        'Import and annotation preserve exact issuer bytes',
      );
      await assert.rejects(f.wallet!.original(await unlockKey()), 'Wrong unlock key must fail');
      const otherHolder = await fixture();
      await assert.rejects(
        FixtureWallet.import(f.artifact, otherHolder.holderPrivate, f.issuerPublic, f.key),
        'Import must bind dedicated holder key',
      );
    },
  },
  {
    id: 'owner-cancellation',
    layer: 'wallet',
    async run() {
      const f = await fixture();
      const r = newRequest();
      const cancelled = await f.wallet!.present(r, false, await unlockKey());
      assert.ok(
        cancelled.error === 'access_denied' && !cancelled.vp_token,
        'Cancellation must disclose no presentation and need no unlock',
      );
      const verifier = new FixtureVerifier(r, f.issuerPublic, async () => 'good');
      assert.ok(
        (await verifier.receive(formResponse(cancelled))).gate === 'cancelled',
        'Verifier must record cancellation',
      );
      const e = await f.wallet!.present(r, true, f.key);
      assert.ok(
        (await verifier.receive(formResponse(e))).gate === 'session',
        'Cancelled session must not resume',
      );
    },
  },
  ...(
    [
      'overbroad-query',
      'unregistered-verifier',
      'wrong-response-uri',
      'unsupported-response-mode',
    ] as const
  ).map((id): Scenario => ({
    id,
    layer: 'wallet',
    async run() {
      const f = await fixture();
      const r = newRequest();
      if (id === 'overbroad-query') r.dcql_query.credentials[0]!.claims!.push({ path: ['name'] });
      if (id === 'unregistered-verifier') r.client_id = 'unknown-verifier';
      if (id === 'wrong-response-uri') r.response_uri = 'https://attacker.mikaki.test/response';
      if (id === 'unsupported-response-mode')
        Object.assign(r, { response_mode: 'direct_post.jwt' });
      await assert.rejects(
        f.wallet!.present(r, true, f.key),
        'Wallet must reject unsupported request before disclosure',
      );
    },
  })),
  {
    id: 'replay-and-concurrent-submission',
    layer: 'verifier-policy',
    async run() {
      const { f, r, e } = await validFixture();
      const verifier = new FixtureVerifier(r, f.issuerPublic, async () => 'good');
      const results = await Promise.all([
        verifier.receive(formResponse(e)),
        verifier.receive(formResponse(e)),
      ]);
      assert.ok(
        results.filter((d) => d.accepted).length === 1,
        'Concurrent submissions must have one winner',
      );
      assert.ok(
        (await verifier.receive(formResponse(e))).gate === 'session',
        'Accepted presentation must not replay',
      );
    },
  },
  {
    id: 'state-and-session-expiry',
    layer: 'verifier-policy',
    async run() {
      const { f, r, e } = await validFixture();
      assert.ok(
        (await accepted(f, r, { ...e, state: 'wrong-state' })).gate === 'session',
        'State must match',
      );
      assert.ok(
        (
          await new FixtureVerifier(r, f.issuerPublic, async () => 'good', 0).receive(
            formResponse(e),
          )
        ).gate === 'session',
        'Expired session must fail',
      );
    },
  },
  ...(['revoked-credential', 'unknown-status', 'status-outage'] as const).map((id): Scenario => ({
    id,
    layer: 'verifier-policy',
    async run() {
      const { f, r, e } = await validFixture();
      const verifier = new FixtureVerifier(r, f.issuerPublic, async () => {
        if (id === 'status-outage') throw new Error('Synthetic outage');
        return id === 'revoked-credential' ? 'revoked' : 'unknown';
      });
      assert.ok(!(await verifier.receive(formResponse(e))).accepted, 'Status must fail closed');
    },
  })),
  {
    id: 'status-rechecked-per-presentation',
    layer: 'verifier-policy',
    async run() {
      const f = await fixture();
      let status: Status = 'good';
      const lookup = async () => status;
      const r1 = newRequest();
      const e1 = await f.wallet!.present(r1, true, f.key);
      assert.ok(
        (await new FixtureVerifier(r1, f.issuerPublic, lookup).receive(formResponse(e1))).accepted,
        'Initial good status must accept',
      );
      status = 'revoked';
      const r2 = newRequest();
      const e2 = await f.wallet!.present(r2, true, f.key);
      assert.ok(
        (await new FixtureVerifier(r2, f.issuerPublic, lookup).receive(formResponse(e2))).gate ===
          'status',
        'New presentation must recheck status',
      );
    },
  },
  {
    id: 'response-envelope-and-transport',
    layer: 'verifier-policy',
    async run() {
      const { f, r, e } = await validFixture();
      const body = new URLSearchParams({
        state: r.state,
        vp_token: JSON.stringify({ another_query: e.vp_token!.membership }),
      });
      const verifier = () => new FixtureVerifier(r, f.issuerPublic, async () => 'good');
      assert.ok(
        (await verifier().receive(new Request(profile.responseUri, { method: 'POST', body })))
          .gate === 'envelope',
        'Query ID must match',
      );
      body.set('vp_token', JSON.stringify(e.vp_token));
      body.append('vp_token', JSON.stringify(e.vp_token));
      assert.ok(
        (await verifier().receive(new Request(profile.responseUri, { method: 'POST', body })))
          .gate === 'envelope',
        'Duplicate VP field must fail',
      );
      assert.ok(
        (await verifier().receive(new Request(profile.responseUri))).gate === 'transport',
        'GET must fail',
      );
      assert.ok(
        (
          await verifier().receive(
            new Request('https://other.mikaki.test/response', { method: 'POST', body }),
          )
        ).gate === 'transport',
        'Wrong endpoint must fail',
      );
    },
  },
  {
    id: 'holder-proof-time-and-type',
    layer: 'verifier-policy',
    async run() {
      const f = await fixture();
      const r = newRequest();
      for (const options of [
        { typ: 'JWT' },
        { issuedAt: Math.floor(Date.now() / 1000) - 120 },
        { issuedAt: Math.floor(Date.now() / 1000) + 120 },
      ]) {
        const e = await hostilePresentation(f, r, options);
        assert.ok(
          (await accepted(f, r, e)).gate === 'credential',
          'Holder proof must have current iat and kb+jwt type',
        );
      }
    },
  },
  {
    id: 'excess-disclosure',
    layer: 'verifier-policy',
    async run() {
      const { f, r } = await validFixture();
      const e = await hostilePresentation(f, r, {
        disclosures: f.artifact.split('~').slice(1, -1),
      });
      assert.ok(
        (await accepted(f, r, e)).gate === 'credential',
        'Bounded policy must reject excess disclosure',
      );
    },
  },
  {
    id: 'failed-proof-consumes-session',
    layer: 'verifier-policy',
    async run() {
      const { f, r, e } = await validFixture();
      const verifier = new FixtureVerifier(r, f.issuerPublic, async () => 'good');
      const wrong = await hostilePresentation(f, r, { wrongKey: true });
      assert.ok(!(await verifier.receive(formResponse(wrong))).accepted, 'Bad proof must fail');
      assert.ok(
        (await verifier.receive(formResponse(e))).gate === 'session',
        'Consumed request must require a fresh session',
      );
    },
  },
];
