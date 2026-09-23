import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

process.env.WRANGLER_WRITE_LOGS ??= 'false';
const { unstable_dev } = await import('wrangler');
const require = createRequire(import.meta.url);
const verifier = require('../jose-custom/pkg/mikaki_jose_custom_probe.js');
const config = fileURLToPath(new URL('wrangler.jsonc', import.meta.url));
const script = fileURLToPath(new URL('build/worker/shim.mjs', import.meta.url));
const worker = await unstable_dev(script, {
  config,
  envFiles: [],
  experimental: { disableDevRegistry: true },
  ip: '127.0.0.1',
  local: true,
  logLevel: 'error',
  persist: false,
});

try {
  const setup = await worker.fetch('/setup', { method: 'POST' });
  assert.equal(setup.status, 200);

  const atomicResponse = await worker.fetch('/atomicity');
  assert.equal(atomicResponse.status, 200);
  assert.deepEqual(await atomicResponse.json(), {
    batch_rejected: true,
    rows_after_failure: 0,
    first_primary_value: 1,
  });

  const exchanges = await Promise.all(['first', 'second'].map(async (id) => {
    const response = await worker.fetch(`/exchange/${id}`, { method: 'POST' });
    assert.equal(response.status, 200);
    return response.json();
  }));
  assert.equal(exchanges.filter(({ accepted }) => accepted).length, 1);

  const codeReports = await Promise.all([worker.fetch('/code'), worker.fetch('/code')]);
  const issuedCodes = await Promise.all(codeReports.map(async (response) => {
    assert.equal(response.status, 200);
    return response.json();
  }));
  const [firstCode, secondCode] = issuedCodes;
  assert.match(firstCode.code, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(firstCode.expires_at, 1050);
  assert.equal(firstCode.digest, createHash('sha256').update(Buffer.from(firstCode.code, 'base64url')).digest('base64url'));
  assert.notEqual(firstCode.code, secondCode.code);

  const signedResponse = await worker.fetch('/sign');
  assert.equal(signedResponse.status, 200);
  const { token, jwk } = await signedResponse.json();
  const publicJwk = JSON.stringify({ ...JSON.parse(jwk), alg: 'ES256' });
  assert.equal(verifier.verify_es256(token, publicJwk), true);
  const [header, payload, signature] = token.split('.');
  const changed = `${header}.${payload.slice(0, -1)}${payload.endsWith('A') ? 'B' : 'A'}.${signature}`;
  assert.equal(verifier.verify_es256(changed, publicJwk), false);

  const rsaKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  console.log('workers-rs: generated synthetic RSA test key');
  const rsaPrivateJwk = { ...rsaKeys.privateKey.export({ format: 'jwk' }), kid: 'workerd-rs256-probe' };
  const rsaPublicJwk = { ...rsaKeys.publicKey.export({ format: 'jwk' }), kid: 'workerd-rs256-probe' };
  const rsaResponse = await worker.fetch('/sign-rs256', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ private: JSON.stringify(rsaPrivateJwk), public: JSON.stringify(rsaPublicJwk) }),
  });
  console.log('workers-rs: RS256 worker response received');
  assert.equal(rsaResponse.status, 200);
  const { token: rsaToken, jwk: rsaJwk } = await rsaResponse.json();
  assert.equal(verifier.verify_rs256(rsaToken, rsaJwk), true);
  const [rsaHeader, rsaPayload, rsaSignature] = rsaToken.split('.');
  const changedRsa = `${rsaHeader}.${rsaPayload}.${rsaSignature.slice(0, -1)}${rsaSignature.endsWith('A') ? 'B' : 'A'}`;
  assert.equal(verifier.verify_rs256(changedRsa, rsaJwk), false);

  console.log('workers-rs: D1 atomicity, ES256/RS256 WebCrypto signing, Rust JWK/JWS validation, and OIDC code preparation passed');
} finally {
  await worker.stop();
}

const adapterConfig = fileURLToPath(new URL('../../../crates/worker/wrangler.jsonc', import.meta.url));
const adapterScript = fileURLToPath(new URL('../../../crates/worker/build/worker/shim.mjs', import.meta.url));
const adapter = await unstable_dev(adapterScript, {
  config: adapterConfig,
  envFiles: [],
  experimental: { disableDevRegistry: true },
  ip: '127.0.0.1',
  local: true,
  logLevel: 'error',
  persist: false,
});
try {
  const health = await adapter.fetch('/health');
  assert.equal(health.status, 200);
  assert.equal(await health.text(), 'ok');
  assert.equal((await adapter.fetch('/not-a-route')).status, 404);
  console.log('mikaki-worker: Rust Cloudflare adapter health route passed in local workerd');
} finally {
  await adapter.stop();
}
