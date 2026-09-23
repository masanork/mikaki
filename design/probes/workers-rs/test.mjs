import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

process.env.WRANGLER_WRITE_LOGS ??= 'false';
const { unstable_dev } = await import('wrangler');
const require = createRequire(import.meta.url);
const verifier = require('../jose-custom/pkg/sakimori_jose_custom_probe.js');
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

  const signedResponse = await worker.fetch('/sign');
  assert.equal(signedResponse.status, 200);
  const { token, jwk } = await signedResponse.json();
  const publicJwk = JSON.stringify({ ...JSON.parse(jwk), alg: 'ES256' });
  assert.equal(verifier.verify_es256(token, publicJwk), true);
  const [header, payload, signature] = token.split('.');
  const changed = `${header}.${payload.slice(0, -1)}${payload.endsWith('A') ? 'B' : 'A'}.${signature}`;
  assert.equal(verifier.verify_es256(changed, publicJwk), false);

  console.log('workers-rs: D1 rollback, first-primary read, one-time exchange, and async WebCrypto JWS passed');
} finally {
  await worker.stop();
}
