import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  assertIdentityHaipMetadata,
  passportFields,
  passportPolicyFingerprint,
} from './check-identity-haip-production.ts';
const now = 1_792_627_200;
function fixture(passport = true) {
  const proof_types_supported = { jwt: { key_attestations_required: {} }, attestation: {} };
  const card = (format: string) => ({
    format,
    credential_metadata: { claims: [{ path: ['age_over_18'] }] },
    proof_types_supported,
  });
  return {
    credential_request_encryption: { encryption_required: true },
    credential_response_encryption: { encryption_required: true },
    credential_configurations_supported: {
      linked_document: card('dc+sd-jwt'),
      linked_document_mdoc: card('mso_mdoc'),
      ...(passport
        ? {
            passport_dg1: {
              format: 'dc+sd-jwt',
              scope: 'passport_dg1',
              vct: 'https://auth.mikaki.org/identity/issuer/types/passport-dg1',
              credential_metadata: { claims: passportFields.map((f) => ({ path: [f] })) },
              proof_types_supported,
              passport_evidence_policy: {
                fingerprint: passportPolicyFingerprint(),
                valid_until: now + 60,
              },
            },
          }
        : {}),
    },
  };
}
test('production smoke distinguishes exact age and passport profiles and preserves HAIP requirements', () => {
  assertIdentityHaipMetadata(fixture(), true, now);
  const reordered = fixture();
  reordered.credential_configurations_supported = Object.fromEntries(
    Object.entries(reordered.credential_configurations_supported).reverse(),
  ) as typeof reordered.credential_configurations_supported;
  assertIdentityHaipMetadata(reordered, true, now);
  assertIdentityHaipMetadata(fixture(false), false, now);
  assert.throws(() => assertIdentityHaipMetadata(fixture(), false, now));
  assert.throws(() => assertIdentityHaipMetadata(fixture(false), true, now));
  const changes: ((m: any) => void)[] = [
    (m) => {
      m.credential_configurations_supported.linked_document.credential_metadata.claims = [
        { path: ['birthdate'] },
      ];
    },
    (m) => {
      m.credential_configurations_supported.passport_dg1.credential_metadata.claims.push({
        path: ['document_number'],
      });
    },
    (m) => {
      m.credential_configurations_supported.passport_dg1.vct =
        'https://other.example/types/passport-dg1';
    },
    (m) => {
      m.credential_configurations_supported.passport_dg1.passport_evidence_policy.valid_until = now;
    },
    (m) => {
      m.credential_configurations_supported.passport_dg1.passport_evidence_policy.fingerprint =
        'x'.repeat(43);
    },
    (m) => {
      // Previous SHA-1-compatible policy with the same anchors/CRL is not this policy.
      m.credential_configurations_supported.passport_dg1.passport_evidence_policy.fingerprint =
        'JgN0G554r6Uwq3moFcjxmIrBntr5dqUOaJNX8dPlQL4';
    },
    (m) => {
      delete m.credential_configurations_supported.passport_dg1.proof_types_supported.attestation;
    },
    (m) => {
      m.credential_request_encryption.encryption_required = false;
    },
    (m) => {
      m.credential_response_encryption.encryption_required = false;
    },
  ];
  for (const change of changes) {
    const m = structuredClone(fixture());
    change(m);
    assert.throws(() => assertIdentityHaipMetadata(m, true, now));
  }
});
