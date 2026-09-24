import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { importJWK, jwtVerify, SignJWT, base64url } from 'jose';

const require = createRequire(import.meta.url);
const wasm = require('./es256/pkg/mikaki_es256_probe.js');
const binary = fileURLToPath(new URL('es256/target/debug/fixture', import.meta.url));
const native = (...args: string[]) => execFileSync(binary, args, { encoding: 'utf8' }).trim();
const publicJwk = JSON.parse(wasm.fixture_public_jwk());
const publicKey = await importJWK(publicJwk, 'ES256');
// Public RFC 6979 fixture, not an operational private key.
const fixtureKey = await importJWK(
  {
    ...publicJwk,
    d: base64url.encode(
      Buffer.from('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721', 'hex'),
    ),
  },
  'ES256',
);
const now = 1893456000;
const claims = {
  iss: 'https://issuer.invalid',
  aud: 'fixture-client',
  sub: 'fixture-sub',
  iat: now,
  exp: now + 300,
};
const options = {
  algorithms: ['ES256'],
  issuer: claims.iss,
  audience: claims.aud,
  currentDate: new Date(now * 1000),
  clockTolerance: 0,
};
const encode = (value: unknown) => base64url.encode(JSON.stringify(value));
const input = `${encode({ alg: 'ES256', typ: 'JWT' })}.${encode(claims)}`;

test('actual Wasm execution matches the independent RFC 6979 known answer', () => {
  assert.equal(wasm.known_answer_matches(), true);
});

test('Native and Wasm signatures match and jose/WebCrypto accepts both', async () => {
  const signature = wasm.fixture_sign(input);
  assert.equal(native('sign', input), signature);
  assert.equal(base64url.decode(signature).length, 64);
  const result = await jwtVerify(`${input}.${signature}`, publicKey, options);
  assert.equal(result.payload.sub, claims.sub);
});

test('jose/WebCrypto signature verifies in Native and Wasm Rust', async () => {
  const token = await new SignJWT(claims).setProtectedHeader({ alg: 'ES256' }).sign(fixtureKey);
  const [header, payload, signature] = token.split('.');
  const signingInput = `${header}.${payload}`;
  assert.equal(wasm.fixture_verify(signingInput, signature), true);
  assert.equal(native('verify', signingInput, signature), 'true');
});

test('changed payload is rejected by all verifiers', async () => {
  const signature = wasm.fixture_sign(input);
  const changed = `${input.split('.')[0]}.${encode({ ...claims, sub: 'attacker' })}`;
  assert.equal(wasm.fixture_verify(changed, signature), false);
  assert.equal(native('verify', changed, signature), 'false');
  await assert.rejects(jwtVerify(`${changed}.${signature}`, publicKey, options), {
    code: 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
  });
});

test('wrong algorithm is rejected rather than chosen from an untrusted header', async () => {
  const changed = `${encode({ alg: 'RS256' })}.${encode(claims)}`;
  await assert.rejects(jwtVerify(`${changed}.${wasm.fixture_sign(changed)}`, publicKey, options), {
    code: 'ERR_JOSE_ALG_NOT_ALLOWED',
  });
});

test('correct signature does not override expiry, issuer, or audience', async () => {
  for (const modified of [
    { ...claims, exp: now },
    { ...claims, iss: 'https://other.invalid' },
    { ...claims, aud: 'other-client' },
  ]) {
    const signingInput = `${encode({ alg: 'ES256' })}.${encode(modified)}`;
    const token = `${signingInput}.${wasm.fixture_sign(signingInput)}`;
    await assert.rejects(jwtVerify(token, publicKey, options));
  }
});
