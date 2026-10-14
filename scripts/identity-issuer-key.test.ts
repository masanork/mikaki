import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  assertDedicatedIdentityKey,
  identityIssuerPublicKey,
  writeIdentityIssuerKey,
} from './identity-issuer-key.ts';

function testIssuerKey() {
  const { kty, crv, x, y, d } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  }).privateKey.export({ format: 'jwk' });
  return JSON.stringify({ kty, crv, x, y, d, kid: 'synthetic-identity-test' });
}

test('issuer generation writes an exclusive private file and reports only verifiable public material', () => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-identity-key-'));
  try {
    const path = join(directory, 'keys', 'issuer.jwk.json');
    const command = fileURLToPath(new URL('./identity-issuer-key.ts', import.meta.url));
    const result = spawnSync(process.execPath, [command, path], { encoding: 'utf8' });
    assert.equal(result.status, 0);
    const raw = readFileSync(path, 'utf8');
    const privateJwk = JSON.parse(raw);
    const report = JSON.parse(result.stdout);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(statSync(join(directory, 'keys')).mode & 0o777, 0o700);
    assert.deepEqual(identityIssuerPublicKey(raw), {
      public_jwk: report.public_jwk,
      thumbprint: report.thumbprint,
    });
    assert.equal('d' in report.public_jwk, false);
    assert.ok(!result.stdout.includes(privateJwk.d));
    assert.equal(result.stderr, '');
    const message = Buffer.from('independent issuer key check');
    const signature = sign('sha256', message, { key: privateJwk, format: 'jwk' });
    assert.ok(
      verify(
        'sha256',
        message,
        createPublicKey({ key: report.public_jwk, format: 'jwk' }),
        signature,
      ),
    );
    assert.throws(() => writeIdentityIssuerKey(path), /EEXIST/);
    assert.equal(readFileSync(path, 'utf8'), raw);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('key preflight rejects malformed, ambiguous and mismatched private material with redacted errors', () => {
  const raw = testIssuerKey();
  const key = JSON.parse(raw);
  const other = JSON.parse(testIssuerKey());
  for (const value of [
    '',
    'private-do-not-log',
    '[]',
    'null',
    raw.repeat(20),
    JSON.stringify({ ...key, d: other.d }),
    JSON.stringify({ ...key, x: other.x }),
    JSON.stringify({ ...key, d: 'A'.repeat(43) }),
    JSON.stringify({ ...key, d: key.d + '=' }),
    JSON.stringify({ ...key, kid: '' }),
    JSON.stringify({ ...key, kid: '界'.repeat(43) }),
    JSON.stringify({ ...key, alg: 'ES256' }),
    raw.replace('"crv":"P-256"', '"crv":"P-384"'),
    raw.replace('"kty":"EC"', '"kty":"EC","kty":"EC"'),
  ]) {
    assert.throws(
      () => identityIssuerPublicKey(value),
      (error: unknown) =>
        error instanceof Error &&
        error.message === 'Invalid dedicated Identity issuer key' &&
        error.cause === undefined,
    );
  }
});

test('signing roles cannot share a public key even with a different kid', () => {
  const raw = testIssuerKey();
  assertDedicatedIdentityKey(raw, testIssuerKey());
  assert.throws(
    () => assertDedicatedIdentityKey(raw, JSON.stringify({ ...JSON.parse(raw), kid: 'OP' })),
    /distinct/,
  );
  const other = JSON.parse(testIssuerKey());
  assert.throws(
    () => assertDedicatedIdentityKey(raw, JSON.stringify({ ...other, d: JSON.parse(raw).d })),
    /distinct/,
  );
  assert.throws(
    () => assertDedicatedIdentityKey(raw, 'private-do-not-log'),
    (error: unknown) =>
      error instanceof Error &&
      !error.message.includes('private-do-not-log') &&
      error.cause === undefined,
  );
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({
    format: 'jwk',
  });
  assertDedicatedIdentityKey(raw, JSON.stringify(rsa));
});
