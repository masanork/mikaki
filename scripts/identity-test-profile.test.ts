import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { identityTestTrust } from './identity-test-profile.ts';

const now = Math.floor(Date.now() / 1000);
const publicKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({
  format: 'jwk',
});
export function testCardTrust() {
  return [
    {
      id: 'synthetic-licence-issuer',
      document_type: 'driving_license',
      n: publicKey.n!,
      e: publicKey.e!,
      subject_key_identifier: Buffer.alloc(32, 7).toString('base64url'),
      not_before: now - 60,
      not_after: now + 3600,
    },
  ];
}

test('trust preflight binds exact live licence policy and returns only a digest and validity bounds', () => {
  const raw = JSON.stringify(testCardTrust());
  assert.deepEqual(identityTestTrust(raw, now), {
    policy_sha256: createHash('sha256').update(raw).digest('hex'),
    document_type: 'driving_license',
    key_count: 1,
    valid_until: now + 3600,
  });
  assert.deepEqual(identityTestTrust(raw + '\n', now), identityTestTrust(raw, now));
});

test('ambiguous, private, expired, unsupported and malformed trust cannot authorize deployment', () => {
  const keys = testCardTrust();
  const raw = JSON.stringify(keys);
  const mutations = [
    { document_type: 'my_number_card' },
    { not_after: now },
    { not_before: now + 1 },
    { not_before: -1 },
    { not_after: Number.MAX_SAFE_INTEGER + 1 },
    { id: '' },
    { id: '界'.repeat(43) },
    { n: keys[0]!.n + '=' },
    { n: Buffer.alloc(256, 1).toString('base64url') },
    { n: Buffer.alloc(256, 128).toString('base64url') },
    { e: 'Aw' },
    { subject_key_identifier: keys[0]!.subject_key_identifier + '=' },
    { subject_key_identifier: null },
    { d: 'private-policy-do-not-log' },
  ];
  for (const value of [
    '',
    'null',
    '[]',
    '{}',
    'private-policy-do-not-log',
    raw.repeat(100),
    JSON.stringify(keys, null, 2),
    raw.replace('"document_type":', '"id":"shadowed","document_type":'),
    JSON.stringify([...keys, ...keys]),
    ...mutations.map((mutation) => JSON.stringify([{ ...keys[0], ...mutation }])),
  ])
    assert.throws(
      () => identityTestTrust(value, now),
      (error: unknown) =>
        error instanceof Error &&
        error.message.startsWith('Invalid Identity test trust') &&
        !error.message.includes('private-policy-do-not-log') &&
        error.cause === undefined,
    );
});

test('CLI fails without exposing policy material and never modifies its input', () => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-identity-trust-'));
  try {
    const file = join(directory, 'policy.json');
    writeFileSync(file, 'private-policy-do-not-log');
    const result = spawnSync(process.execPath, ['scripts/identity-test-profile.ts', file], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.ok(!result.stderr.includes('private-policy-do-not-log'));
    writeFileSync(file, JSON.stringify(testCardTrust()));
    const valid = spawnSync(process.execPath, ['scripts/identity-test-profile.ts', file], {
      encoding: 'utf8',
    });
    assert.equal(valid.status, 0);
    const report = JSON.parse(valid.stdout);
    assert.equal(report.provenance_review_required, true);
    assert.equal(report.activation_vars.IDENTITY_TRUST_POLICY_SHA256, report.policy_sha256);
    assert.ok(!valid.stdout.includes(publicKey.n!));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
