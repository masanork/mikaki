/** Measured execution of the exact boundary on Node's independent native provider.
 * Workerd compatibility/flag behavior stays covered by claim-native-crypto.test.ts. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  nativeSha256,
  nativePublicKey,
  nativeOpenHpke,
  nativeDecryptAes,
} from '../../crates/userinfo-claim-worker/src/native_crypto.ts';
const root = fileURLToPath(new URL('../..', import.meta.url));
const decode = (s) => Buffer.from(s, 'base64url');
const text = (s) => Buffer.from(s);
const u64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};
const context = (...parts) =>
  Buffer.concat(
    parts.flatMap((part) => {
      const size = Buffer.alloc(2);
      size.writeUInt16BE(part.length);
      return [size, part];
    }),
  );

async function runtime() {
  const call = async (operation, inputs, mutate = false, observeAt) => {
    const bytes = inputs.map((input) => new Uint8Array(input));
    const retained = [];
    const originalImport = crypto.subtle.importKey;
    if (observeAt !== undefined)
      crypto.subtle.importKey = async function (format, key, ...rest) {
        retained.push(key);
        if (retained.length === observeAt) throw new Error('injected import failure');
        return originalImport.call(this, format, key, ...rest);
      };
    let output = null;
    try {
      const fn = {
        hash: nativeSha256,
        public: nativePublicKey,
        hpke: nativeOpenHpke,
        aes: nativeDecryptAes,
      }[operation];
      const pending = fn(...bytes);
      if (mutate) for (const input of bytes) input.fill(0);
      output = Buffer.from(await pending);
    } catch {
      /* Expected malformed-input or injected provider failure. */
    } finally {
      crypto.subtle.importKey = originalImport;
    }
    if (observeAt !== undefined)
      assert.ok(
        retained.length > 0 && retained.every((key) => key.every((x) => x === 0)),
        `${operation}: private import buffers must be erased`,
      );
    return output;
  };
  return { call, close: async () => {} };
}
test('Node native provider independently opens the shipped HPKE fixture and clears secret buffers', async () => {
  const fixture = JSON.parse(
    await readFile(`${root}/design/probes/pqc/record-userinfo-fixture.json`, 'utf8'),
  );
  const nist = JSON.parse(
    await readFile(`${root}/design/probes/pqc/nist-acvp-fixtures.json`, 'utf8'),
  );
  const { call, close } = await runtime();
  try {
    const seed = decode(fixture.seed),
      frame = decode(fixture.frame),
      p = fixture.source;
    const publicKey = await call('public', [seed], true);
    assert.deepEqual(publicKey, decode(fixture.recipient.public_key));
    const vector = nist.mlKemKeygen;
    const nistKey = await call('public', [Buffer.from(vector.d + vector.z, 'hex')]);
    assert.ok(nistKey);
    assert.equal(createHash('sha256').update(nistKey).digest('hex'), vector.ekSha256);
    assert.deepEqual(
      await call('hash', [publicKey], true),
      createHash('sha256').update(publicKey).digest(),
    );
    assert.equal(await call('public', [seed.subarray(1)]), null);
    const info = context(
      text('mikaki-vault-record-recipient-envelope-v2-draft04'),
      Buffer.from([2]),
      frame.subarray(5, 11),
      text('userinfo'),
      frame.subarray(11, 43),
      u64(1),
    );
    const aad = context(
      text('2'),
      text(p.origin),
      text(p.owner_id),
      text(p.vault_id),
      text(p.collection_id),
      text(p.record_id),
      text(p.kind),
      u64(p.revision),
      decode(p.ciphertext_sha256),
      u64(fixture.authority.key_generation),
      u64(fixture.authority.owner_key_revision),
      text('userinfo'),
      text('oidc.userinfo.name'),
    );
    const inputs = [seed, frame.subarray(51, 1139), info, aad, frame.subarray(1139)];
    const results = await Promise.all(Array.from({ length: 8 }, () => call('hpke', inputs, true)));
    const key = results[0];
    assert.ok(key);
    assert.equal(key.length, 32);
    for (const result of results) assert.deepEqual(result, key);
    // Retain the actual key views passed to Web Crypto, on success and after
    // failure at each ML-KEM/HMAC/AES import, then require them to be cleared.
    assert.deepEqual(await call('public', [seed], false, 0), publicKey);
    assert.equal(await call('public', [seed], false, 1), null);
    for (let failureAt = 0; failureAt <= 7; failureAt++) {
      assert.deepEqual(await call('hpke', inputs, false, failureAt), failureAt === 0 ? key : null);
    }
    for (const index of [0, 1, 2, 3, 4]) {
      const changed = inputs.map((x) => Buffer.from(x));
      changed[index][0] ^= 1;
      assert.equal(await call('hpke', changed), null, `input ${index} substitution`);
    }
    assert.equal(
      await call('hpke', [seed, frame.subarray(51, 1138), info, aad, frame.subarray(1139)]),
      null,
    );
    const body = decode(fixture.ciphertext);
    const bodyAad = context(
      text('mikaki-vault-record-content'),
      text('2'),
      text(p.origin),
      text(p.owner_id),
      text(p.vault_id),
      text(p.collection_id),
      text(p.record_id),
      text(p.kind),
      text(String(p.revision)),
    );
    const plain = await call('aes', [key, body.subarray(1, 13), bodyAad, body.subarray(13)], true);
    assert.equal(plain?.toString('utf8'), fixture.name);
    assert.deepEqual(
      await call('aes', [key, body.subarray(1, 13), bodyAad, body.subarray(13)], false, 0),
      plain,
    );
    assert.equal(
      await call('aes', [key, body.subarray(1, 13), bodyAad, body.subarray(13)], false, 1),
      null,
    );
    const changed = Buffer.from(body);
    changed[13] ^= 1;
    assert.equal(
      await call('aes', [key, changed.subarray(1, 13), bodyAad, changed.subarray(13)]),
      null,
    );
  } finally {
    await close();
  }
});
