import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { base64url, CompactSign, exportJWK, generateKeyPair, SignJWT } from 'jose';

const require = createRequire(import.meta.url);
const wasm = require('./jose/pkg/mikaki_jose_probe.js');
const binary = fileURLToPath(new URL('jose/target/debug/fixture', import.meta.url));
const issuer = 'https://issuer.invalid';
const audience = 'probe-client';
const native = (algorithm: string, token: string, jwk: unknown) =>
  execFileSync(binary, [`verify-${algorithm.toLowerCase()}`, token, JSON.stringify(jwk)], {
    encoding: 'utf8',
  }).trim() === 'true';
const nativeClaims = (
  algorithm: string,
  token: string,
  jwk: unknown,
  expectedIssuer = issuer,
  expectedAudience = audience,
) =>
  execFileSync(
    binary,
    [
      `verify-${algorithm.toLowerCase()}-claims`,
      token,
      JSON.stringify(jwk),
      expectedIssuer,
      expectedAudience,
    ],
    { encoding: 'utf8' },
  ).trim() === 'true';

async function makePair(algorithm: string) {
  const options = algorithm === 'RS256' ? { modulusLength: 2048 } : undefined;
  const { publicKey, privateKey } = await generateKeyPair(algorithm, options);
  const jwk = { ...(await exportJWK(publicKey)), alg: algorithm, kid: `key-${algorithm}` };
  return { publicKey, privateKey, jwk };
}

async function makeToken(
  algorithm: string,
  privateKey: Parameters<SignJWT['sign']>[0],
  kid: string,
  {
    sub = 'probe-subject',
    tokenIssuer = issuer,
    tokenAudience = audience,
    exp = Math.floor(Date.now() / 1000) + 300,
  }: {
    sub?: string;
    tokenIssuer?: string | null;
    tokenAudience?: string | null;
    exp?: number | null;
  } = {},
) {
  let jwt = new SignJWT({ sub }).setProtectedHeader({ alg: algorithm, kid, typ: 'JWT' });
  if (tokenIssuer !== null) jwt = jwt.setIssuer(tokenIssuer);
  if (tokenAudience !== null) jwt = jwt.setAudience(tokenAudience);
  if (exp !== null) jwt = jwt.setExpirationTime(exp);
  return jwt.sign(privateKey);
}

for (const algorithm of ['ES256', 'RS256']) {
  test(`${algorithm}: jose-signed token verifies in Native and Wasm`, async () => {
    const { privateKey, jwk } = await makePair(algorithm);
    const token = await makeToken(algorithm, privateKey, jwk.kid);
    const wasmVerify = algorithm === 'ES256' ? wasm.verify_es256 : wasm.verify_rs256;

    assert.equal(wasmVerify(token, JSON.stringify(jwk)), true);
    assert.equal(native(algorithm, token, jwk), true);
    assert.equal(
      wasm[`verify_${algorithm.toLowerCase()}_claims`](
        token,
        JSON.stringify(jwk),
        issuer,
        audience,
      ),
      true,
    );
    assert.equal(nativeClaims(algorithm, token, jwk), true);

    const [header, payload, signature] = token.split('.');
    const changedPayload = base64url.encode(JSON.stringify({ sub: 'changed-subject' }));
    const tampered = `${header}.${changedPayload}.${signature}`;
    assert.equal(wasmVerify(tampered, JSON.stringify(jwk)), false);
    assert.equal(native(algorithm, tampered, jwk), false);

    const wrongAlgorithmVerify = algorithm === 'ES256' ? wasm.verify_rs256 : wasm.verify_es256;
    assert.equal(wrongAlgorithmVerify(token, JSON.stringify(jwk)), false);
  });

  test(`${algorithm}: issuer, audience, expiry, and duplicate claims are checked`, async () => {
    const { privateKey, jwk } = await makePair(algorithm);
    const wasmVerifyClaims = wasm[`verify_${algorithm.toLowerCase()}_claims`];
    const cases = [
      { tokenIssuer: 'https://other.invalid' },
      { tokenAudience: 'other-client' },
      { exp: Math.floor(Date.now() / 1000) - 120 },
      { tokenIssuer: null },
      { tokenAudience: null },
      { exp: null },
    ];

    for (const overrides of cases) {
      const token = await makeToken(algorithm, privateKey, jwk.kid, overrides);
      assert.equal(wasmVerifyClaims(token, JSON.stringify(jwk), issuer, audience), false);
      assert.equal(nativeClaims(algorithm, token, jwk), false);
    }

    const exp = Math.floor(Date.now() / 1000) + 300;
    const duplicatePayload = new TextEncoder().encode(
      `{"sub":"first","sub":"second","iss":"${issuer}","aud":"${audience}","exp":${exp}}`,
    );
    const duplicateToken = await new CompactSign(duplicatePayload)
      .setProtectedHeader({ alg: algorithm, kid: jwk.kid, typ: 'JWT' })
      .sign(privateKey);
    assert.equal(wasmVerifyClaims(duplicateToken, JSON.stringify(jwk), issuer, audience), false);
    assert.equal(nativeClaims(algorithm, duplicateToken, jwk), false);
  });

  test(`${algorithm}: replacing a verification key retires tokens from the old key`, async () => {
    const oldPair = await makePair(algorithm);
    const newPair = await makePair(algorithm);
    const oldToken = await makeToken(algorithm, oldPair.privateKey, oldPair.jwk.kid, {
      sub: 'old-key',
    });
    const newToken = await makeToken(algorithm, newPair.privateKey, newPair.jwk.kid, {
      sub: 'new-key',
    });
    const wasmVerify = algorithm === 'ES256' ? wasm.verify_es256 : wasm.verify_rs256;

    assert.equal(wasmVerify(oldToken, JSON.stringify(oldPair.jwk)), true);
    assert.equal(wasmVerify(newToken, JSON.stringify(newPair.jwk)), true);
    assert.equal(wasmVerify(oldToken, JSON.stringify(newPair.jwk)), false);
    assert.equal(native(algorithm, oldToken, newPair.jwk), false);
  });
}

test('malformed JWK and malformed compact token fail closed', () => {
  assert.equal(wasm.verify_es256('not.a.jwt', '{}'), false);
  assert.equal(wasm.verify_rs256('not.a.jwt', '{'), false);
});
