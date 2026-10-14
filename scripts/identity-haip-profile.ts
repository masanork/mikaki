/** Source-bound, purpose-separated development HAIP selection. Never log private inputs. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { identityIssuerPublicKey, assertDedicatedIdentityKey } from './identity-issuer-key.ts';

const root = new URL('../', import.meta.url);
const read = (path: string) => JSON.parse(readFileSync(new URL(path, root), 'utf8'));
export function identityHaipSelection() {
  const pki = read('crates/worker/config/identity-haip-labpki.public.json');
  const verifier = read('services/android-attestation-verifier/policy.production.json');
  const bridge = read('services/android-attestation-verifier/bridge/wrangler.production.jsonc');
  const client = pki.wallet_configuration.client_id;
  assert.equal(verifier.client_id, client);
  assert.equal(bridge.vars.ANDROID_VERIFIER_CLIENT_ID, client);
  assert.match(bridge.vars.ANDROID_VERIFIER_POLICY_HASH, /^[A-Za-z0-9_-]{43}$/);
  const policyHash = bridge.vars.ANDROID_VERIFIER_POLICY_HASH as string;
  const digest = createHash('sha256')
    .update(JSON.stringify({ pki, verifier, policyHash }))
    .digest('hex');
  return {
    pki,
    bridge,
    digest,
    vars: {
      IDENTITY_ACTIVATION_PROFILE: 'operator-card-haip-age',
      IDENTITY_WALLET_ENABLED: 'true',
      IDENTITY_HAIP_ENABLED: 'true',
      IDENTITY_ATTESTER_ENABLED: 'true',
      IDENTITY_CREDENTIAL_CERTIFICATES: JSON.stringify(pki.credential_certificates),
      IDENTITY_WALLET_ATTESTERS: JSON.stringify(pki.wallet_configuration.client_trust),
      IDENTITY_KEY_ATTESTATION_TRUST: JSON.stringify(pki.wallet_configuration.key_trust),
      IDENTITY_WALLET_CLIENTS: JSON.stringify([
        {
          client_id: client,
          name: 'Mikaki Android Lab Wallet',
          redirect_uri: 'https://app.mikaki.org/identity/issuance/callback',
          attesters: pki.wallet_configuration.client_trust.map((t: { issuer: string }) => t.issuer),
        },
      ]),
      IDENTITY_ATTESTER_CLIENTS: JSON.stringify([
        { client_id: client, verifier_policy_hash: policyHash },
      ]),
      IDENTITY_HAIP_POLICY_SHA256: digest,
      MIKAKI_DPOP_NONCE_MODE: 'required',
    },
  };
}

function privateKey(raw: string, encryption = false) {
  const value = JSON.parse(raw);
  assert.equal(raw.trim(), JSON.stringify(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [...['kty', 'crv', 'x', 'y', 'd', 'kid'], ...(encryption ? ['alg', 'use'] : [])].sort(),
  );
  if (encryption) {
    assert.equal(value.alg, 'ECDH-ES');
    assert.equal(value.use, 'enc');
  }
  const { kty, crv, x, y, d, kid } = value;
  return identityIssuerPublicKey(JSON.stringify({ kty, crv, x, y, d, kid }));
}

export function assertIdentityHaipSecrets(secrets: Record<string, string>) {
  try {
    const { pki } = identityHaipSelection();
    const issuer = privateKey(secrets.IDENTITY_ISSUER_JWK!);
    const at = JSON.parse(secrets.IDENTITY_ATTESTER_SIGNING!);
    assert.equal(secrets.IDENTITY_ATTESTER_SIGNING!.trim(), JSON.stringify(at));
    assert.deepEqual(Object.keys(at).sort(), ['chain', 'jwk', 'trust_anchors']);
    assert.deepEqual(at.chain, pki.attester.chain);
    assert.deepEqual(at.trust_anchors, pki.attester.trust_anchors);
    const attester = privateKey(at.jwk);
    const encryption = privateKey(secrets.IDENTITY_CREDENTIAL_ENCRYPTION_JWK!, true);
    const coordinates = (v: { public_jwk: { kty: string; crv: string; x: string; y: string } }) => {
      const { kty, crv, x, y } = v.public_jwk;
      return { kty, crv, x, y };
    };
    assert.deepEqual(coordinates(issuer), pki.issuer_jwk);
    assert.deepEqual(coordinates(attester), pki.attester_jwk);
    assert.equal(new Set([issuer.thumbprint, attester.thumbprint, encryption.thumbprint]).size, 3);
    for (const [name, encrypted] of [
      ['IDENTITY_ATTESTER_SIGNING', false],
      ['IDENTITY_CREDENTIAL_ENCRYPTION_JWK', true],
    ] as const) {
      const raw = encrypted ? secrets[name]! : at.jwk;
      const { kty, crv, x, y, d, kid } = JSON.parse(raw);
      assertDedicatedIdentityKey(
        JSON.stringify({ kty, crv, x, y, d, kid }),
        secrets.OP_PRIVATE_JWK!,
      );
    }
  } catch {
    throw new Error('HAIP private custody does not match the reviewed public profile');
  }
}
