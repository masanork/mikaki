/** Verify the selected live HAIP profile without uploading evidence or issuing credentials. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { identityHaipSelection } from './identity-haip-profile.ts';

export const passportFields = [
  'name_mrz',
  'issuing_state',
  'nationality',
  'birth_date_mrz',
  'expiry_date_mrz',
  'sex_mrz',
] as const;
export function passportPolicyFingerprint() {
  const digest = createHash('sha256').update('mikaki-passport-dg1-policy-v1\0');
  for (const name of [
    'jpn-2013.der',
    'jpn-2015.der',
    'jpn-2019.der',
    'jpn-2024.der',
    'jpn-20260914.crl',
  ]) {
    const bytes = readFileSync(
      new URL(`../crates/identity/src/passport/trust/${name}`, import.meta.url),
    );
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    digest.update(length).update(bytes);
  }
  return digest.digest('base64url');
}
export function assertIdentityHaipMetadata(
  metadata: Record<string, any>,
  passportEnabled: boolean,
  now = Math.floor(Date.now() / 1000),
) {
  const issuer = 'https://auth.mikaki.org/identity/issuer';
  const configurations = metadata.credential_configurations_supported;
  assert.deepEqual(
    Object.keys(configurations).sort(),
    [
      'linked_document',
      'linked_document_mdoc',
      ...(passportEnabled ? ['passport_dg1'] : []),
    ].sort(),
  );
  assert.equal(configurations.linked_document.format, 'dc+sd-jwt');
  assert.equal(configurations.linked_document_mdoc.format, 'mso_mdoc');
  for (const [id, c] of Object.entries(configurations) as [string, Record<string, any>][]) {
    const claims = c.credential_metadata.claims as { path: string[] }[];
    if (id === 'passport_dg1') {
      assert.equal(c.format, 'dc+sd-jwt');
      assert.equal(c.scope, id);
      assert.equal(c.vct, `${issuer}/types/passport-dg1`);
      assert.deepEqual(
        claims.map((c) => c.path),
        passportFields.map((f) => [f]),
      );
      assert.equal(c.passport_evidence_policy.fingerprint, passportPolicyFingerprint());
      assert.ok(
        Number.isSafeInteger(c.passport_evidence_policy.valid_until) &&
          c.passport_evidence_policy.valid_until > now,
      );
    } else {
      assert.equal(claims.length, 1);
      assert.equal(claims[0]!.path.at(-1), 'age_over_18');
    }
    assert.ok(c.proof_types_supported.jwt.key_attestations_required);
    assert.ok(c.proof_types_supported.attestation);
  }
  assert.equal(metadata.credential_request_encryption.encryption_required, true);
  assert.equal(metadata.credential_response_encryption.encryption_required, true);
}

export async function checkIdentityHaipProduction(options: {
  readyToken: string;
  expectedCommit?: string;
  expectedVersion?: string;
  passportEnabled?: boolean;
}) {
  const root = 'https://auth.mikaki.org';
  const issuer = `${root}/identity/issuer`;
  const get = async (url: string, authorized = false) => {
    const response = await fetch(url, {
      headers: authorized ? { Authorization: `Bearer ${options.readyToken}` } : {},
      redirect: 'manual',
      signal: AbortSignal.timeout(15000),
    });
    assert.equal(response.status, authorized ? 204 : 200, 'HAIP endpoint is unavailable');
    return authorized ? undefined : response.json();
  };
  const version = await get(`${root}/version`);
  if (options.expectedCommit) assert.equal(version.source_commit, options.expectedCommit);
  if (options.expectedVersion) assert.equal(version.version_id, options.expectedVersion);
  assert.equal(version.source_clean, true);
  const [metadata, oauth, jwks] = await Promise.all([
    get(`${root}/.well-known/openid-credential-issuer/identity/issuer`),
    get(`${root}/.well-known/oauth-authorization-server/identity/issuer`),
    get(`${issuer}/jwks`),
  ]);
  assert.equal(metadata.credential_issuer, issuer);
  assert.equal(metadata.mikaki_trust_profile, 'operator-confirmed-card-test');
  assert.equal(metadata.mikaki_issuer_root_chain_verified, false);
  assert.deepEqual(oauth.grant_types_supported, ['authorization_code']);
  assert.deepEqual(oauth.token_endpoint_auth_methods_supported, ['attest_jwt_client_auth']);
  assert.equal(oauth.require_pushed_authorization_requests, true);
  assert.deepEqual(oauth.code_challenge_methods_supported, ['S256']);
  assert.deepEqual(oauth.dpop_signing_alg_values_supported, ['ES256']);
  assert.equal(oauth['pre-authorized_grant_anonymous_access_supported'], false);
  assert.equal(oauth.pushed_authorization_request_endpoint, `${issuer}/par`);
  assert.ok(metadata.credential_request_encryption.jwks.keys.length === 1);
  assert.ok(metadata.credential_response_encryption.alg_values_supported.includes('ECDH-ES'));
  assertIdentityHaipMetadata(metadata, options.passportEnabled ?? false);
  assert.equal(jwks.keys.length, 1);
  const { kty, crv, x, y } = jwks.keys[0];
  assert.equal('d' in jwks.keys[0], false);
  assert.deepEqual({ kty, crv, x, y }, identityHaipSelection().pki.issuer_jwk);
  await get(`${root}/identity/ready`, true);
  await get(`${root}/ready`, true);
  return {
    issuer,
    checked_at: new Date().toISOString(),
    source_commit: version.source_commit,
    version_id: version.version_id,
    profile: 'operator-card-haip-age',
    authorization_code_only: true,
    attestation_and_dpop_advertised: true,
    issuer_and_android_verifier_readiness: true,
    claims: ['age_over_18'],
    passport_profile: options.passportEnabled ? 'passport_dg1' : 'disabled',
    passport_device_issuance: 'not_run',
    qualification: 'public-metadata-and-protected-readiness',
    native_device_issuance: 'not_run',
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const config = JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));
    if (config.vars.IDENTITY_ACTIVATION_PROFILE !== 'operator-card-haip-age') {
      console.log('HAIP is not selected by this source revision');
    } else {
      const result = await checkIdentityHaipProduction({
        readyToken: process.env.MIKAKI_READY_TOKEN!,
        passportEnabled: config.vars.IDENTITY_PASSPORT_ENABLED === 'true',
        expectedCommit: process.env.MIKAKI_EXPECTED_SOURCE_COMMIT,
        expectedVersion: process.env.MIKAKI_EXPECTED_VERSION_ID,
      });
      mkdirSync('artifacts', { recursive: true });
      writeFileSync('artifacts/identity-haip-production-smoke.json', `${JSON.stringify(result)}\n`);
      console.log(JSON.stringify(result));
    }
  } catch {
    console.error(
      'Selected HAIP production verification failed; no credentials or private inputs were logged',
    );
    process.exitCode = 1;
  }
}
