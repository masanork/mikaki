import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

process.env.WRANGLER_WRITE_LOGS ??= 'false';
const { unstable_dev } = await import('wrangler');

const require = createRequire(import.meta.url);
const wasm = require('./jose-custom/pkg/mikaki_jose_custom_probe.js');
const workerScript = fileURLToPath(new URL('async-signer-worker.mjs', import.meta.url));
const worker = await unstable_dev(workerScript, {
  compatibilityDate: '2026-09-22',
  compatibilityFlags: ['nodejs_compat'],
  experimental: { disableDevRegistry: true },
  ip: '127.0.0.1',
  local: true,
  logLevel: 'error',
  persist: false,
});
try {
  const response = await worker.fetch();
  assert.equal(response.status, 200);
  const { token, jwk } = await response.json();
  const publicJwk = JSON.stringify({ ...jwk, alg: 'ES256' });
  assert.equal(wasm.verify_es256(token, publicJwk), true);

  const [header, payload, signature] = token.split('.');
  const changed = `${header}.${payload.slice(0, -1)}${payload.endsWith('A') ? 'B' : 'A'}.${signature}`;
  assert.equal(wasm.verify_es256(changed, publicJwk), false);
  console.log('workerd async ES256 signature verified in Rust Wasm; payload tampering rejected');
} finally {
  await worker.stop();
}
