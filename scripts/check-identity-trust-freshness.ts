/** Read-only early warning for source-selected trust. No secret inputs or renewal authority. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { productionIdentityTestProfile } from './identity-test-profile.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const publicBundle = 'crates/worker/config/identity-haip-labpki.public.json';
export const warningSeconds = 48 * 60 * 60;
const pkiDeadlines = [
  'sd_jwt_valid_until',
  'mdoc_valid_until',
  'attester_valid_until',
  'wallet_sd_jwt_valid_until',
  'wallet_mdoc_valid_until',
] as const;
const negativeChecks = [
  'revoked_signing_certificate',
  'wrong_trust_anchor',
  'wrong_certificate_purpose',
  'root_in_x5c',
  'wrong_signing_key',
  'expired_attester',
  'expired_credential_crl',
];
type Config = Parameters<typeof productionIdentityTestProfile>[0];

function timestamp(value: unknown): asserts value is number {
  assert.ok(
    typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value < 253402300800,
    'Invalid trust timestamp',
  );
}

/** These public records describe reviewed deadlines; they never authorize a policy. */
export function selectedCardTrustDeadline(policySha256: string, registry: unknown): number {
  assert.match(policySha256, /^[a-f0-9]{64}$/);
  const record = registry as { format: string; policies: Record<string, unknown>[] };
  assert.deepEqual(Object.keys(record).sort(), ['format', 'policies']);
  assert.equal(record.format, 'mikaki-card-trust-deadlines-v1');
  assert.ok(
    Array.isArray(record.policies) && record.policies.length > 0 && record.policies.length <= 16,
  );
  const deadlines = new Map<string, number>();
  for (const policy of record.policies) {
    assert.deepEqual(Object.keys(policy).sort(), ['policy_sha256', 'valid_until']);
    assert.ok(typeof policy.policy_sha256 === 'string');
    assert.match(policy.policy_sha256, /^[a-f0-9]{64}$/);
    assert.ok(!deadlines.has(policy.policy_sha256), 'Duplicate policy deadline');
    timestamp(policy.valid_until);
    deadlines.set(policy.policy_sha256, policy.valid_until);
  }
  const selected = deadlines.get(policySha256);
  assert.ok(selected !== undefined, 'Selected card policy has no reviewed deadline');
  return selected;
}

export function identityTrustFreshness(options: {
  config: Config;
  registry: unknown;
  pki: Record<string, unknown>;
  bundleSha256: string;
  now: number;
}) {
  const { config, registry, pki, bundleSha256, now } = options;
  timestamp(now);
  // Also bind the public PKI, verifier and derived production vars using the existing profile check.
  assert.equal(productionIdentityTestProfile(config), 'operator-card-haip-age');
  assert.match(bundleSha256, /^[a-f0-9]{64}$/);
  assert.equal(pki.format, 'mikaki-haip-labpki-check-v1');
  assert.equal(pki.qualification, 'development-pki-validation-only');
  assert.equal(pki.public_bundle_sha256, bundleSha256);
  timestamp(pki.checked_at);
  assert.ok(pki.checked_at <= now && now - pki.checked_at <= 600, 'Stale PKI validation');
  assert.equal(pki.wallet_configuration_valid, true);
  assert.ok(Array.isArray(pki.negative_checks));
  assert.deepEqual([...pki.negative_checks].sort(), [...negativeChecks].sort());
  const cardDigest = config.vars.IDENTITY_TRUST_POLICY_SHA256!;
  const cardDeadline = selectedCardTrustDeadline(cardDigest, registry);
  const values: [string, unknown][] = [
    ['operator_card_approval', cardDeadline],
    ...pkiDeadlines.map((name): [string, unknown] => [name, pki[name]]),
  ];
  const deadlines = values.map(([name, value]) => {
    timestamp(value);
    const remaining = value - now;
    return {
      name,
      valid_until: value,
      valid_until_utc: new Date(value * 1000).toISOString(),
      remaining_seconds: remaining,
      status: remaining <= 0 ? 'expired' : remaining <= warningSeconds ? 'expiring' : 'healthy',
    };
  });
  return {
    format: 'mikaki-identity-trust-freshness-v1',
    checked_at: now,
    warning_seconds: warningSeconds,
    public_bundle_sha256: bundleSha256,
    card_policy_sha256: cardDigest,
    status: deadlines.every((item) => item.status === 'healthy') ? 'healthy' : 'attention_required',
    earliest_valid_until: Math.min(...deadlines.map((item) => item.valid_until)),
    deadlines,
    qualification: 'source-selected-public-pki-and-recorded-approval-only',
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    assert.equal(process.argv.length, 2, 'This check takes no arguments');
    const startedAt = Math.floor(Date.now() / 1000);
    const source = spawnSync('git', ['rev-parse', 'HEAD'], {
      cwd: root,
      encoding: 'utf8',
      timeout: 10_000,
    });
    assert.equal(source.status, 0);
    const sourceCommit = source.stdout.trim();
    assert.match(sourceCommit, /^[a-f0-9]{40}$/);
    const status = spawnSync('git', ['status', '--porcelain'], {
      cwd: root,
      encoding: 'utf8',
      timeout: 10_000,
    });
    assert.equal(status.status, 0);
    const config = JSON.parse(
      readFileSync(resolve(root, 'crates/worker/wrangler.production.jsonc'), 'utf8'),
    );
    const registry = JSON.parse(
      readFileSync(
        resolve(root, 'crates/worker/config/identity-card-trust-deadlines.public.json'),
        'utf8',
      ),
    );
    const bytes = readFileSync(resolve(root, publicBundle));
    const result = spawnSync(
      'cargo',
      [
        'run',
        '-p',
        'mikaki-identity',
        '--locked',
        '--quiet',
        '--example',
        'check_haip_pki',
        '--',
        publicBundle,
      ],
      { cwd: root, encoding: 'utf8', timeout: 300_000, maxBuffer: 1024 * 1024 },
    );
    assert.ok(
      !result.error && !result.signal && result.status === 0,
      'Public PKI validation failed',
    );
    const pki = JSON.parse(result.stdout);
    assert.ok(pki.checked_at >= startedAt, 'PKI validation predates this invocation');
    const report = identityTrustFreshness({
      config,
      registry,
      pki,
      bundleSha256: createHash('sha256').update(bytes).digest('hex'),
      now: Math.floor(Date.now() / 1000),
    });
    console.log(
      JSON.stringify(
        { ...report, source_commit: sourceCommit, source_clean: status.stdout === '' },
        null,
        2,
      ),
    );
    for (const item of report.deadlines.filter((item) => item.status !== 'healthy')) {
      console.error(
        `::error title=Identity trust deadline::${item.name} is ${item.status}; deadline ${item.valid_until_utc}. Review renewal and promotion before this deadline.`,
      );
    }
    if (report.status !== 'healthy') process.exitCode = 1;
  } catch {
    console.log(
      JSON.stringify({
        format: 'mikaki-identity-trust-freshness-v1',
        checked_at: Math.floor(Date.now() / 1000),
        status: 'invalid',
      }),
    );
    console.error(
      '::error title=Identity trust validation::Public PKI validation or the source-selected trust deadline failed validation. Run check_haip_pki and review the selected policy record.',
    );
    process.exitCode = 1;
  }
}
