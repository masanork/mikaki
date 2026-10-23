import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { messagingIssuerPublicKey, writeMessagingIssuerKey } from './messaging-issuer-key.ts';

function key() {
  const { kty, crv, x, d } = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
  return { kty, crv, x: x!, d: d! };
}

test('Chat issuer public identity verifies independent Ed25519 signatures and runtime key ID', () => {
  const jwk = key();
  const report = messagingIssuerPublicKey(JSON.stringify(jwk), jwk.x);
  const data = Buffer.from('independent Chat issuer check');
  const signature = sign(null, data, { key: jwk, format: 'jwk' });
  assert.ok(
    verify(null, data, createPublicKey({ key: report.public_jwk, format: 'jwk' }), signature),
  );
  assert.equal(
    report.key_id,
    createHash('sha256').update(Buffer.from(jwk.x, 'base64url')).digest('base64url'),
  );
  assert.equal(JSON.stringify(report).includes(jwk.d), false);
});

test('malformed, ambiguous, mismatched and wrong-role keys fail with redacted errors', () => {
  const jwk = key(),
    other = key(),
    raw = JSON.stringify(jwk);
  for (const value of [
    '',
    'DO_NOT_LOG_PRIVATE_MATERIAL',
    'null',
    '[]',
    raw.repeat(10),
    JSON.stringify({ ...jwk, x: other.x }),
    JSON.stringify({ ...jwk, d: other.d }),
    JSON.stringify({ ...jwk, d: jwk.d + '=' }),
    JSON.stringify({ ...jwk, x: 'a'.repeat(43) }),
    JSON.stringify({ ...jwk, alg: 'EdDSA' }),
    JSON.stringify({ ...jwk, crv: 'X25519' }),
    JSON.stringify({ ...jwk, kty: 'EC' }),
    raw.replace('"kty":"OKP"', '"kty":"OKP","kty":"OKP"'),
  ]) {
    assert.throws(
      () => messagingIssuerPublicKey(value),
      (error: unknown) =>
        error instanceof Error &&
        error.message === 'Invalid Chat issuer key or public-key mismatch' &&
        error.cause === undefined,
    );
  }
  assert.throws(() => messagingIssuerPublicKey(raw, other.x), /mismatch/);
  assert.throws(() => messagingIssuerPublicKey(raw, ''), /mismatch/);
  assert.throws(() => messagingIssuerPublicKey(raw, jwk.x + '='), /mismatch/);
});

test('key generation uses an exclusive private file and emits public material only', () => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-chat-key-'));
  try {
    const path = join(directory, 'custody', 'issuer.json');
    const result = spawnSync(process.execPath, ['scripts/messaging-issuer-key.ts', path], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 0);
    assert.equal(result.stderr, '');
    const raw = readFileSync(path, 'utf8'),
      jwk = JSON.parse(raw),
      report = JSON.parse(result.stdout);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(statSync(join(directory, 'custody')).mode & 0o777, 0o700);
    assert.equal(result.stdout.includes(jwk.d), false);
    assert.equal(report.public_jwk.x, jwk.x);
    assert.throws(() => writeMessagingIssuerKey(path), /EEXIST/);
    assert.equal(readFileSync(path, 'utf8'), raw);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
