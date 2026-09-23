import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import nist from './nist-acvp-fixtures.json' with { type: 'json' };

const require = createRequire(import.meta.url);
const probe = require('./pkg/mikaki_pqc_probe.js');
const bytes = await readFile(new URL('./pkg/mikaki_pqc_probe_bg.wasm', import.meta.url));
assert.equal(probe.self_test(), true);
const hex = (value) => Uint8Array.from(Buffer.from(value, 'hex'));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const kemSeed = Buffer.concat([hex(nist.mlKemKeygen.d), hex(nist.mlKemKeygen.z)]);
const kemKeys = ml_kem768.keygen(kemSeed);
assert.equal(sha256(kemKeys.publicKey), nist.mlKemKeygen.ekSha256);
assert.equal(sha256(kemKeys.secretKey), nist.mlKemKeygen.dkSha256);
const nistEncap = ml_kem768.encapsulate(hex(nist.mlKemEncap.ek), hex(nist.mlKemEncap.m));
assert.equal(sha256(nistEncap.cipherText), nist.mlKemEncap.cSha256);
assert.deepEqual(nistEncap.sharedSecret, hex(nist.mlKemEncap.k));

const dsaKeys = ml_dsa65.keygen(hex(nist.mlDsaKeygen.seed));
assert.equal(sha256(dsaKeys.publicKey), nist.mlDsaKeygen.pkSha256);
assert.equal(sha256(dsaKeys.secretKey), nist.mlDsaKeygen.skSha256);
const nistSignature = ml_dsa65.sign(hex(nist.mlDsaSiggen.message), hex(nist.mlDsaSiggen.sk), {
  context: hex(nist.mlDsaSiggen.context),
  extraEntropy: false,
});
assert.equal(sha256(nistSignature), nist.mlDsaSiggen.signatureSha256);

const fixtureKemKeys = ml_kem768.keygen(new Uint8Array(64).fill(0x41));
assert.deepEqual(probe.fixture_kem_public_key(), fixtureKemKeys.publicKey);
const fixtureKem = ml_kem768.encapsulate(fixtureKemKeys.publicKey, new Uint8Array(32).fill(0x42));
assert.deepEqual(probe.fixture_kem_ciphertext(), fixtureKem.cipherText);
assert.deepEqual(probe.fixture_kem_shared_secret(), fixtureKem.sharedSecret);
assert.deepEqual(
  ml_kem768.decapsulate(probe.fixture_kem_ciphertext(), fixtureKemKeys.secretKey),
  probe.fixture_kem_shared_secret(),
);

const fixtureDsaKeys = ml_dsa65.keygen(new Uint8Array(32).fill(0x43));
const fixtureMessage = new TextEncoder().encode('mikaki-pqc-probe-v1');
assert.deepEqual(probe.fixture_dsa_public_key(), fixtureDsaKeys.publicKey);
assert.equal(
  ml_dsa65.verify(probe.fixture_dsa_signature(), fixtureMessage, fixtureDsaKeys.publicKey),
  true,
);
assert.equal(
  ml_dsa65.verify(
    probe.fixture_dsa_signature(),
    new TextEncoder().encode('mikaki-pqc-probe-v2'),
    fixtureDsaKeys.publicKey,
  ),
  false,
);
const times = [];
for (let sample = 0; sample < 10; sample++) {
  const start = performance.now();
  assert.equal(probe.self_test(), true);
  times.push(performance.now() - start);
}
times.sort((left, right) => left - right);
console.log(
  JSON.stringify({
    result: 'pass',
    wasm_bytes: bytes.length,
    wasm_gzip_bytes: gzipSync(bytes, { mtime: 0 } as import('node:zlib').ZlibOptions).length,
    kem_signature_and_vault_hpke_median_ms: (times[4] + times[5]) / 2,
  }),
);
