import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { base64url, exportJWK, generateKeyPair, SignJWT } from 'jose';

const require = createRequire(import.meta.url);
const wasm = require('./jose-custom/pkg/sakimori_jose_custom_probe.js');
const binary = fileURLToPath(new URL('jose-custom/target/debug/fixture', import.meta.url));
const issuer = 'https://issuer.invalid';
const audience = 'probe-client';
const native = (algorithm, token, jwk) => execFileSync(
  binary,
  [`verify-${algorithm.toLowerCase()}`, token, JSON.stringify(jwk)],
  { encoding: 'utf8' },
).trim() === 'true';
const nativeClaims = (algorithm, token, jwk, expectedIssuer = issuer, expectedAudience = audience) => execFileSync(
  binary,
  [`verify-${algorithm.toLowerCase()}-claims`, token, JSON.stringify(jwk), expectedIssuer, expectedAudience],
  { encoding: 'utf8' },
).trim() === 'true';

async function esPair(kid) {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const jwk = { ...await exportJWK(publicKey), alg: 'ES256', kid };
  return { privateKey, jwk };
}

async function tokenFor(algorithm, privateKey, kid, sub = 'custom-provider', {
  tokenIssuer = issuer,
  tokenAudience = audience,
  exp = Math.floor(Date.now() / 1000) + 300,
} = {}) {
  let jwt = new SignJWT({ sub }).setProtectedHeader({ alg: algorithm, kid, typ: 'JWT' });
  if (tokenIssuer !== null) jwt = jwt.setIssuer(tokenIssuer);
  if (tokenAudience !== null) jwt = jwt.setAudience(tokenAudience);
  if (exp !== null) jwt = jwt.setExpirationTime(exp);
  return jwt.sign(privateKey);
}

test('ES256 custom CryptoProvider verifies the same independent signature in Native and Wasm', async () => {
  const pair = await esPair('custom-es256');
  const token = await tokenFor('ES256', pair.privateKey, pair.jwk.kid);
  assert.equal(wasm.verify_es256(token, JSON.stringify(pair.jwk)), true);
  assert.equal(native('ES256', token, pair.jwk), true);

  const [header, payload, signature] = token.split('.');
  const tampered = `${header}.${base64url.encode(JSON.stringify({ sub: 'tampered' }))}.${signature}`;
  assert.equal(wasm.verify_es256(tampered, JSON.stringify(pair.jwk)), false);
  assert.equal(native('ES256', tampered, pair.jwk), false);
});

test('custom ES256 verifier rejects a token signed by a retired key', async () => {
  const oldPair = await esPair('old-key');
  const newPair = await esPair('new-key');
  const oldToken = await tokenFor('ES256', oldPair.privateKey, oldPair.jwk.kid, 'old');
  const newToken = await tokenFor('ES256', newPair.privateKey, newPair.jwk.kid, 'new');

  assert.equal(wasm.verify_es256(oldToken, JSON.stringify(oldPair.jwk)), true);
  assert.equal(wasm.verify_es256(newToken, JSON.stringify(newPair.jwk)), true);
  assert.equal(wasm.verify_es256(oldToken, JSON.stringify(newPair.jwk)), false);

  const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
  const rsaJwk = { ...await exportJWK(publicKey), alg: 'RS256', kid: 'rsa-key' };
  const rsaToken = await new SignJWT({ sub: 'rsa' })
    .setProtectedHeader({ alg: 'RS256', kid: rsaJwk.kid, typ: 'JWT' })
    .sign(privateKey);
  assert.equal(wasm.verify_es256(rsaToken, JSON.stringify(rsaJwk)), false);
});

test('custom provider converts RSA JWK n/e and verifies RS256 in Native and Wasm', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
  const jwk = { ...await exportJWK(publicKey), alg: 'RS256', kid: 'custom-rs256' };
  const token = await tokenFor('RS256', privateKey, jwk.kid, 'custom-rsa');
  assert.equal(wasm.verify_rs256(token, JSON.stringify(jwk)), true);
  assert.equal(native('RS256', token, jwk), true);

  const [header, payload, signature] = token.split('.');
  const tampered = `${header}.${base64url.encode(JSON.stringify({ sub: 'tampered' }))}.${signature}`;
  assert.equal(wasm.verify_rs256(tampered, JSON.stringify(jwk)), false);
  assert.equal(native('RS256', tampered, jwk), false);
  assert.equal(wasm.verify_es256(token, JSON.stringify(jwk)), false);
});

test('custom provider applies issuer, audience, expiry, and duplicate-claim checks', async () => {
  for (const algorithm of ['ES256', 'RS256']) {
    const pair = algorithm === 'ES256'
      ? await esPair(`claims-${algorithm}`)
      : await (async () => {
        const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
        return { privateKey, jwk: { ...await exportJWK(publicKey), alg: 'RS256', kid: `claims-${algorithm}` } };
      })();
    const token = await tokenFor(algorithm, pair.privateKey, pair.jwk.kid);
    const wasmVerify = wasm[`verify_${algorithm.toLowerCase()}_claims`];

    assert.equal(wasmVerify(token, JSON.stringify(pair.jwk), issuer, audience), true);
    assert.equal(nativeClaims(algorithm, token, pair.jwk), true);
    const invalidCases = [
      { tokenIssuer: 'https://wrong.invalid' },
      { tokenAudience: 'other-client' },
      { exp: Math.floor(Date.now() / 1000) - 120 },
      { tokenIssuer: null },
      { tokenAudience: null },
      { exp: null },
    ];
    for (const invalidCase of invalidCases) {
      const invalidToken = await tokenFor(algorithm, pair.privateKey, pair.jwk.kid, 'invalid', invalidCase);
      assert.equal(wasmVerify(invalidToken, JSON.stringify(pair.jwk), issuer, audience), false);
      assert.equal(nativeClaims(algorithm, invalidToken, pair.jwk), false);
    }

    const [header, payload, signature] = token.split('.');
    const duplicate = base64url.encode(
      `{"sub":"first","sub":"second","iss":"${issuer}","aud":"${audience}","exp":${Math.floor(Date.now() / 1000) + 300}}`,
    );
    const duplicateToken = `${header}.${duplicate}.${signature}`;
    assert.equal(wasmVerify(duplicateToken, JSON.stringify(pair.jwk), issuer, audience), false);
    assert.equal(nativeClaims(algorithm, duplicateToken, pair.jwk), false);
    assert.notEqual(payload, duplicate);
  }
});
