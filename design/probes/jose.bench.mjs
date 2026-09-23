import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { base64url, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { performance } from 'node:perf_hooks';

const require = createRequire(import.meta.url);
const wasm = require('./jose/pkg/mikaki_jose_probe.js');
const customWasm = require('./jose-custom/pkg/mikaki_jose_custom_probe.js');
const binary = fileURLToPath(new URL('jose/target/release/fixture', import.meta.url));
const customBinary = fileURLToPath(new URL('jose-custom/target/release/fixture', import.meta.url));
const iterations = Number(process.env.JOSE_BENCH_ITERATIONS ?? 10_000);
if (!Number.isInteger(iterations) || iterations < 1) {
  throw new Error('JOSE_BENCH_ITERATIONS must be a positive integer');
}

for (const algorithm of ['ES256', 'RS256']) {
  const options = algorithm === 'RS256' ? { modulusLength: 2048 } : undefined;
  const { publicKey, privateKey } = await generateKeyPair(algorithm, options);
  const jwk = { ...await exportJWK(publicKey), alg: algorithm, kid: `bench-${algorithm}` };
  const token = await new SignJWT({ sub: 'benchmark-subject' })
    .setProtectedHeader({ alg: algorithm, kid: jwk.kid })
    .setIssuer('https://issuer.invalid')
    .setAudience('benchmark-client')
    .setExpirationTime(Math.floor(Date.now() / 1000) + 300)
    .sign(privateKey);
  const wasmVerify = algorithm === 'ES256' ? wasm.verify_es256 : wasm.verify_rs256;
  const customVerify = algorithm === 'ES256' ? customWasm.verify_es256 : customWasm.verify_rs256;
  const jwkJson = JSON.stringify(jwk);

  for (let index = 0; index < 500; index += 1) wasmVerify(token, jwkJson);
  const wasmStart = performance.now();
  for (let index = 0; index < iterations; index += 1) wasmVerify(token, jwkJson);
  const wasmNs = ((performance.now() - wasmStart) * 1e6) / iterations;
  const nativeNs = Number(execFileSync(binary, [
    `bench-${algorithm.toLowerCase()}`, token, jwkJson, String(iterations),
  ], { encoding: 'utf8' }).trim());
  for (let index = 0; index < 500; index += 1) customVerify(token, jwkJson);
  const customWasmStart = performance.now();
  for (let index = 0; index < iterations; index += 1) customVerify(token, jwkJson);
  const customWasmNs = ((performance.now() - customWasmStart) * 1e6) / iterations;
  const customNativeNs = Number(execFileSync(customBinary, [
    `bench-${algorithm.toLowerCase()}`, token, jwkJson, String(iterations),
  ], { encoding: 'utf8' }).trim());
  console.log(`${algorithm} (${iterations} verifies): built-in ${nativeNs.toFixed(0)}/${wasmNs.toFixed(0)} ns/op Native/Wasm, custom ${customNativeNs.toFixed(0)}/${customWasmNs.toFixed(0)} ns/op`);
}
