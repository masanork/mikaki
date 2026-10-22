import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import {
  identityTrustFreshness,
  selectedCardTrustDeadline,
  warningSeconds,
} from './check-identity-trust-freshness.ts';

const config = JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));
const registry = JSON.parse(
  readFileSync('crates/worker/config/identity-card-trust-deadlines.public.json', 'utf8'),
);
const bundleSha256 = createHash('sha256')
  .update(readFileSync('crates/worker/config/identity-haip-labpki.public.json'))
  .digest('hex');
const original = '0bf9e8cd3d2916034333f669cfafbd3a2b0c55e3ba954020de2d4bea81dde207';
const renewal = '51bae1540d65288588ab4f307d6f5376470a113e2586349f91d9b0315139b116';
const renewedUntil = 1793223827;
const now = renewedUntil - 4 * 86400;
const names = [
  'sd_jwt_valid_until',
  'mdoc_valid_until',
  'attester_valid_until',
  'wallet_sd_jwt_valid_until',
  'wallet_mdoc_valid_until',
];

function inputs() {
  const selected = structuredClone(config);
  selected.vars.IDENTITY_TRUST_POLICY_SHA256 = renewal;
  return {
    config: selected,
    registry: structuredClone(registry),
    pki: {
      format: 'mikaki-haip-labpki-check-v1',
      qualification: 'development-pki-validation-only',
      public_bundle_sha256: bundleSha256,
      checked_at: now,
      wallet_configuration_valid: true,
      negative_checks: [
        'wrong_certificate_purpose',
        'revoked_signing_certificate',
        'expired_credential_crl',
        'wrong_trust_anchor',
        'root_in_x5c',
        'wrong_signing_key',
        'expired_attester',
      ],
      ...Object.fromEntries(names.map((name) => [name, renewedUntil])),
    } as Record<string, unknown>,
    bundleSha256,
    now,
  };
}

test('only the selected policy deadline applies; an unselected renewal cannot hide an expired approval', () => {
  assert.equal(selectedCardTrustDeadline(original, registry), 1792588479);
  assert.equal(selectedCardTrustDeadline(renewal, registry), renewedUntil);
  const options = inputs();
  const healthy = identityTrustFreshness(options);
  assert.equal(healthy.status, 'healthy');
  assert.equal(healthy.deadlines.length, 6);
  assert.equal(healthy.earliest_valid_until, renewedUntil);
  options.config.vars.IDENTITY_TRUST_POLICY_SHA256 = original;
  const expired = identityTrustFreshness(options);
  assert.equal(expired.status, 'attention_required');
  assert.deepEqual(
    expired.deadlines.filter((item) => item.status !== 'healthy').map((item) => item.name),
    ['operator_card_approval'],
  );
  assert.equal(expired.deadlines[0]!.status, 'expired');
});

test('each Issuer, Wallet and approval deadline fails at the 48-hour boundary and at expiry', () => {
  assert.equal(warningSeconds, 172800);
  for (const name of ['operator_card_approval', ...names]) {
    for (const [remaining, status] of [
      [warningSeconds + 1, 'healthy'],
      [warningSeconds, 'expiring'],
      [1, 'expiring'],
      [0, 'expired'],
      [-1, 'expired'],
    ] as const) {
      const options = inputs();
      if (name === 'operator_card_approval')
        options.registry.policies.find(
          (p: { policy_sha256: string }) => p.policy_sha256 === renewal,
        ).valid_until = now + remaining;
      else options.pki[name] = now + remaining;
      const report = identityTrustFreshness(options);
      assert.equal(report.deadlines.find((item) => item.name === name)!.status, status, name);
      assert.equal(report.status, status === 'healthy' ? 'healthy' : 'attention_required', name);
    }
  }
});

test('unknown policies, duplicate or incomplete records and malformed deadlines fail closed', () => {
  for (const value of [
    null,
    {},
    { ...registry, private_input: 'never-log-this' },
    { ...registry, format: 'other' },
    { ...registry, policies: [] },
    { ...registry, policies: [...registry.policies, registry.policies[0]] },
    ...[NaN, Infinity, -1, 0, 1.5, '1793223827', 253402300800].map((valid_until) => ({
      ...registry,
      policies: [{ policy_sha256: renewal, valid_until }],
    })),
    {
      ...registry,
      policies: [{ policy_sha256: renewal, valid_until: renewedUntil, n: 'unexpected-key' }],
    },
  ])
    assert.throws(() => selectedCardTrustDeadline(renewal, value));
  assert.throws(() => selectedCardTrustDeadline('0'.repeat(64), registry));
  assert.throws(() => selectedCardTrustDeadline('not-a-digest', registry));
});

test('a stale, incomplete or substituted PKI report and mismatched source settings cannot report healthy', () => {
  const mutations = [
    { checked_at: now + 1 },
    { checked_at: now - 601 },
    { public_bundle_sha256: '0'.repeat(64) },
    { public_bundle_sha256: undefined },
    { format: 'other' },
    { qualification: 'production-qualified' },
    { wallet_configuration_valid: false },
    { negative_checks: [] },
    { negative_checks: [...(inputs().pki.negative_checks as string[]), 'expired_attester'] },
    ...names.flatMap((name) => [undefined, NaN, -1, 'future'].map((value) => ({ [name]: value }))),
  ];
  for (const mutation of mutations) {
    const options = inputs();
    Object.assign(options.pki, mutation);
    assert.throws(() => identityTrustFreshness(options));
  }
  for (const mutation of [
    { IDENTITY_HAIP_POLICY_SHA256: '0'.repeat(64) },
    { IDENTITY_TRUST_POLICY_SHA256: '0'.repeat(64) },
    { IDENTITY_ENABLED: 'false' },
  ]) {
    const options = inputs();
    Object.assign(options.config.vars, mutation);
    assert.throws(() => identityTrustFreshness(options));
  }
});

test('CLI fails when the validator fails or returns an invalid report without echoing its output', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-trust-cli-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  mkdirSync(join(directory, 'bin'));
  const cargo = join(directory, 'bin', 'cargo');
  const command = resolve('scripts/check-identity-trust-freshness.ts');
  for (const body of [
    "process.stderr.write('never-log-this-private-input');process.exit(1)",
    "process.stdout.write('never-log-this-private-input')",
    "process.stdout.write('{}')",
  ]) {
    writeFileSync(cargo, `#!${process.execPath}\n${body}\n`, { mode: 0o700 });
    const result = spawnSync(process.execPath, [command], {
      env: { ...process.env, CARGO_HOME: directory },
      encoding: 'utf8',
      timeout: 10_000,
    });
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stdout).status, 'invalid');
    assert.ok(!`${result.stdout}${result.stderr}`.includes('never-log-this-private-input'));
  }
  for (const cargoHome of ['./relative-installation', '']) {
    const invalidHome = spawnSync(process.execPath, [command], {
      env: { ...process.env, CARGO_HOME: cargoHome },
      encoding: 'utf8',
      timeout: 10_000,
    });
    assert.equal(invalidHome.status, 1);
    assert.equal(JSON.parse(invalidHome.stdout).status, 'invalid');
  }
});

test('PATH shadowing cannot replace system Git or Cargo from the selected absolute installation', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-trust-path-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const installation = join(directory, 'rust');
  mkdirSync(join(installation, 'bin'), { recursive: true });
  const shadowed = join(directory, 'shadow-executed');
  for (const name of ['git', 'cargo']) {
    writeFileSync(
      join(directory, name),
      `#!${process.execPath}\nimport {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(shadowed)},'shadowed');process.exit(1);\n`,
      { mode: 0o700 },
    );
  }
  const pki = inputs().pki;
  // This fixture tests process selection only. Actual PKI validation is exercised
  // separately by the real current-time command and the Rust CI invocation.
  writeFileSync(
    join(installation, 'bin', 'cargo'),
    `#!${process.execPath}\nconst report=${JSON.stringify(pki)};report.checked_at=Math.floor(Date.now()/1000);console.log(JSON.stringify(report));\n`,
    { mode: 0o700 },
  );
  const result = spawnSync(
    process.execPath,
    [resolve('scripts/check-identity-trust-freshness.ts')],
    {
      env: { ...process.env, CARGO_HOME: installation, PATH: `${directory}:${process.env.PATH}` },
      encoding: 'utf8',
      timeout: 10_000,
    },
  );
  assert.equal(existsSync(shadowed), false);
  const report = JSON.parse(result.stdout);
  assert.notEqual(report.status, 'invalid', result.stderr);
  assert.match(report.source_commit, /^[a-f0-9]{40}$/);
});
