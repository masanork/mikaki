// Independent HPKE base-mode key schedule for a public Vault fixture.
// This is test code, not the browser or claim Worker implementation.
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHash, createHmac } from 'node:crypto';
import { createRequire } from 'node:module';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import fixture from './hpke-envelope-fixture.json' with { type: 'json' };

const require = createRequire(import.meta.url);
const rust = require('./pkg/mikaki_pqc_probe.js');
const utf8 = (text: string) => Buffer.from(text, 'utf8');
const concat = (...parts: Uint8Array[]) => Buffer.concat(parts);
const u64 = (value: bigint) => {
  const result = Buffer.alloc(8);
  result.writeBigUInt64BE(value);
  return result;
};
const lengthPrefix = (...parts: Uint8Array[]) =>
  concat(
    ...parts.flatMap((part) => {
      assert.ok(part.length <= 65535);
      const length = Buffer.alloc(2);
      length.writeUInt16BE(part.length);
      return [length, part];
    }),
  );
const sha256 = (data: Uint8Array) => createHash('sha256').update(data).digest();

const seed = Buffer.alloc(64, 0x71);
const dataKey = Buffer.alloc(32, 0x51);
const keys = ml_kem768.keygen(seed);
const keyId = sha256(keys.publicKey);
const suite = Buffer.from([0, 0x41, 0, 1, 0, 2]);
const version = Buffer.from([1]);
const generation = u64(1n);
const info = lengthPrefix(
  utf8('mikaki-vault-recipient-envelope-v1-draft04'),
  version,
  suite,
  utf8('userinfo'),
  keyId,
  generation,
);
const aad = lengthPrefix(
  utf8('https://mikaki.example'),
  utf8('test-account-1'),
  utf8('name'),
  u64(9n),
  utf8('userinfo'),
  utf8('oidc.userinfo.name'),
  sha256(utf8('test-vault-ciphertext')),
);

// RFC 9180 sections 4 and 5: SHA-256 HKDF with HPKE labels and suite ID.
const hpkeSuite = concat(utf8('HPKE'), suite);
const extract = (salt: Uint8Array, ikm: Uint8Array) =>
  createHmac('sha256', salt.length ? salt : Buffer.alloc(32))
    .update(ikm)
    .digest();
const expand = (prk: Uint8Array, context: Uint8Array, size: number) => {
  const chunks: Buffer[] = [];
  let previous = Buffer.alloc(0);
  for (let counter = 1; chunks.length * 32 < size; counter++) {
    assert.ok(counter <= 255);
    previous = createHmac('sha256', prk)
      .update(concat(previous, context, Buffer.from([counter])))
      .digest();
    chunks.push(previous);
  }
  return concat(...chunks).subarray(0, size);
};
const labeledExtract = (salt: Uint8Array, label: string, ikm: Uint8Array) =>
  extract(salt, concat(utf8('HPKE-v1'), hpkeSuite, utf8(label), ikm));
const labeledExpand = (prk: Uint8Array, label: string, context: Uint8Array, size: number) => {
  const length = Buffer.alloc(2);
  length.writeUInt16BE(size);
  return expand(prk, concat(length, utf8('HPKE-v1'), hpkeSuite, utf8(label), context), size);
};
const schedule = (sharedSecret: Uint8Array, contextInfo: Uint8Array) => {
  const empty = Buffer.alloc(0);
  const pskIdHash = labeledExtract(empty, 'psk_id_hash', empty);
  const infoHash = labeledExtract(empty, 'info_hash', contextInfo);
  const scheduleContext = concat(Buffer.from([0]), pskIdHash, infoHash);
  const secret = labeledExtract(sharedSecret, 'secret', empty);
  return {
    key: labeledExpand(secret, 'key', scheduleContext, 32),
    nonce: labeledExpand(secret, 'base_nonce', scheduleContext, 12),
  };
};
const seal = (sharedSecret: Uint8Array, plaintext: Uint8Array) => {
  const { key, nonce } = schedule(sharedSecret, info);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  return concat(cipher.update(plaintext), cipher.final(), cipher.getAuthTag());
};
const open = (sharedSecret: Uint8Array, ciphertext: Uint8Array) => {
  assert.equal(ciphertext.length, 48);
  const { key, nonce } = schedule(sharedSecret, info);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(ciphertext.subarray(32));
  return concat(decipher.update(ciphertext.subarray(0, 32)), decipher.final());
};
const frame = (enc: Uint8Array, ct: Uint8Array) =>
  concat(utf8('MKVE'), version, suite, keyId, generation, enc, ct);

// RustCrypto HPKE sender -> noble ML-KEM and Node crypto receiver.
const rustFrame = Buffer.from(rust.fixture_vault_envelope_frame());
assert.equal(rustFrame.length, 1187);
assert.deepEqual(rustFrame.subarray(0, 51), frame(Buffer.alloc(0), Buffer.alloc(0)));
const rustEnc = rustFrame.subarray(51, 1139);
const rustCt = rustFrame.subarray(1139);
const rustShared = ml_kem768.decapsulate(rustEnc, keys.secretKey);
assert.deepEqual(open(rustShared, rustCt), dataKey);
assert.equal(rust.fixture_vault_envelope_opens(rustFrame), true);

// noble ML-KEM and Node crypto sender -> RustCrypto HPKE receiver.
const nobleKem = ml_kem768.encapsulate(keys.publicKey, Buffer.alloc(32, 0x42));
const nobleFrame = frame(nobleKem.cipherText, seal(nobleKem.sharedSecret, dataKey));
assert.deepEqual(Buffer.from(fixture.seed, 'base64url'), seed);
assert.deepEqual(Buffer.from(fixture.frame, 'base64url'), nobleFrame);
assert.equal(rust.fixture_vault_envelope_opens(nobleFrame), true);

for (const offset of [4, 10, 11, 43, 51, 1139, 1186]) {
  const changed = Buffer.from(nobleFrame);
  changed[offset] ^= 1;
  assert.equal(rust.fixture_vault_envelope_opens(changed), false, `offset ${offset}`);
}
assert.equal(rust.fixture_vault_envelope_opens(nobleFrame.subarray(0, -1)), false);
assert.equal(rust.fixture_vault_envelope_opens(concat(nobleFrame, Buffer.from([0]))), false);
const changedCt = Buffer.from(rustCt);
changedCt[0] ^= 1;
assert.throws(() => open(rustShared, changedCt));

console.log('Vault HPKE AES-256-GCM fixture opens in both RustCrypto and noble/Node');
