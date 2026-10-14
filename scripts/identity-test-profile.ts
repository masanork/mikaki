/** First-party age-only activation. Trust provenance is an operator decision, not key validation. */
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

type Config = {
  vars: Record<string, string>;
  secrets?: { required: string[] };
  services?: { binding: string }[];
  ratelimits?: { name: string; namespace_id: string; simple: { limit: number; period: number } }[];
};
type TrustedKey = {
  id: string;
  document_type: 'driving_license';
  n: string;
  e: string;
  subject_key_identifier: string;
  not_before: number;
  not_after: number;
};

export function identityTestTrust(raw: string, now = Math.floor(Date.now() / 1000)) {
  try {
    assert.ok(Buffer.byteLength(raw) <= 16384);
    const keys: unknown = JSON.parse(raw);
    // Exact compact JSON excludes duplicate members without interpreting ambiguous policies.
    assert.equal(raw.trim(), JSON.stringify(keys));
    assert.ok(Array.isArray(keys) && keys.length > 0 && keys.length <= 16);
    const ids = new Set<string>();
    const fields = [
      'id',
      'document_type',
      'n',
      'e',
      'subject_key_identifier',
      'not_before',
      'not_after',
    ];
    for (const value of keys) {
      assert.ok(value && typeof value === 'object' && !Array.isArray(value));
      assert.deepEqual(Object.keys(value).sort(), [...fields].sort());
      const key = value as TrustedKey;
      assert.ok(
        typeof key.id === 'string' && key.id.length > 0 && Buffer.byteLength(key.id) <= 128,
      );
      assert.ok(!ids.has(key.id));
      ids.add(key.id);
      // My Number DF31 intake and other profiles require their separate reviewed decision.
      assert.equal(key.document_type, 'driving_license');
      assert.ok(typeof key.n === 'string' && /^[A-Za-z0-9_-]{342}$/.test(key.n));
      const modulus = Buffer.from(key.n, 'base64url');
      assert.ok(modulus.length === 256 && modulus[0]! >= 128 && (modulus[255]! & 1) === 1);
      assert.equal(modulus.toString('base64url'), key.n);
      assert.equal(key.e, 'AQAB');
      assert.ok(
        typeof key.subject_key_identifier === 'string' &&
          /^[A-Za-z0-9_-]{43}$/.test(key.subject_key_identifier) &&
          Buffer.from(key.subject_key_identifier, 'base64url').toString('base64url') ===
            key.subject_key_identifier,
      );
      assert.ok(Number.isSafeInteger(key.not_before) && Number.isSafeInteger(key.not_after));
      assert.ok(key.not_before >= 0 && key.not_before <= now && now < key.not_after);
      const publicKey = createPublicKey({ key: { kty: 'RSA', n: key.n, e: key.e }, format: 'jwk' });
      assert.equal(publicKey.asymmetricKeyDetails?.modulusLength, 2048);
    }
    return {
      policy_sha256: createHash('sha256').update(raw.trim()).digest('hex'),
      document_type: 'driving_license' as const,
      key_count: keys.length,
      valid_until: Math.min(...(keys as TrustedKey[]).map((key) => key.not_after)),
    };
  } catch {
    throw new Error(
      'Invalid Identity test trust: use compact JSON with live RSA-2048 licence keys and canonical EF07/B6 identifiers',
    );
  }
}

export function productionIdentityTestProfile(config: Config) {
  const required = config.secrets?.required ?? [];
  const names = Object.keys(config.vars)
    .filter((name) => name.startsWith('IDENTITY_'))
    .sort();
  const selected = required.includes('IDENTITY_ISSUER_JWK');
  const withTrust = required.includes('IDENTITY_TRUSTED_KEYS');
  if (!selected && !names.length && !withTrust) return 'absent' as const;
  assert.ok(selected, 'Identity profile requires dedicated signing custody');
  assert.equal(
    config.vars.IDENTITY_ISSUANCE_CLAIMS,
    '["age_over_18"]',
    'Identity test profile must be age-only',
  );
  const enabled = config.vars.IDENTITY_ENABLED === 'true';
  assert.ok(
    enabled || config.vars.IDENTITY_ENABLED === 'false',
    'Identity profile requires explicit activation',
  );
  assert.deepEqual(
    names,
    enabled
      ? ['IDENTITY_ENABLED', 'IDENTITY_ISSUANCE_CLAIMS', 'IDENTITY_TRUST_POLICY_SHA256']
      : ['IDENTITY_ENABLED', 'IDENTITY_ISSUANCE_CLAIMS'],
    'Identity test profile must not activate other Identity capabilities',
  );
  assert.equal(withTrust, enabled, 'Identity activation requires selected card-trust custody');
  if (enabled)
    assert.match(
      config.vars.IDENTITY_TRUST_POLICY_SHA256!,
      /^[a-f0-9]{64}$/,
      'Identity activation requires the reviewed trust digest',
    );
  const limits = config.ratelimits?.filter((item) => item.name === 'IDENTITY_RATE_LIMIT');
  assert.ok(
    limits?.length === 1 &&
      limits[0]!.namespace_id === '1031' &&
      limits[0]!.simple.limit === 30 &&
      limits[0]!.simple.period === 60,
    'Identity profile requires the reviewed production rate limit',
  );
  assert.ok(
    !config.services?.some((item) => item.binding.startsWith('IDENTITY_')),
    'Identity test profile must not add an attester service',
  );
  return enabled ? ('first-party-age' as const) : ('prepared' as const);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [trustFile, ...extra] = process.argv.slice(2);
    assert.ok(
      trustFile && !extra.length,
      'Usage: node scripts/identity-test-profile.ts TRUST_POLICY_FILE',
    );
    const trust = identityTestTrust(readFileSync(trustFile, 'utf8'));
    console.log(
      JSON.stringify({
        ...trust,
        required_secret: 'IDENTITY_TRUSTED_KEYS',
        activation_vars: {
          IDENTITY_ENABLED: 'true',
          IDENTITY_ISSUANCE_CLAIMS: '["age_over_18"]',
          IDENTITY_TRUST_POLICY_SHA256: trust.policy_sha256,
        },
        provenance_review_required: true,
      }),
    );
  } catch {
    console.error('Identity trust preflight failed; no policy contents were logged');
    process.exitCode = 1;
  }
}
