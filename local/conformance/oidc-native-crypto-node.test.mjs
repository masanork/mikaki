/** Exact shipped bridge on Node's independent native provider, not workerd coverage. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { nativeVerifyEs256 } from '../../crates/oidc/src/native_es256.ts';

const fixture = JSON.parse(
  await readFile(new URL('../../crates/oidc/testdata/es256-rfc6979.json', import.meta.url), 'utf8'),
);
const bytes = (key) => new Uint8Array(Buffer.from(fixture[key], 'base64url'));
const message = () => new TextEncoder().encode(fixture.message);

async function override(method, implementation, run) {
  const original = Object.getOwnPropertyDescriptor(crypto.subtle, method);
  Object.defineProperty(crypto.subtle, method, { value: implementation, configurable: true });
  try {
    await run();
  } finally {
    if (original) Object.defineProperty(crypto.subtle, method, original);
    else delete crypto.subtle[method];
  }
}

test('native OIDC ES256 boundary with the RFC 6979 P-256/SHA-256 fixture', async (t) => {
  const verify = () => nativeVerifyEs256(bytes('public_key'), bytes('signature'), message());
  await t.test('33/65-byte SEC1 and both S values verify; substitutions fail', async () => {
    for (const key of ['public_key', 'compressed_public_key']) {
      for (const signature of ['signature', 'alternate_signature']) {
        assert.equal(await nativeVerifyEs256(bytes(key), bytes(signature), message()), true);
        assert.equal(
          await nativeVerifyEs256(bytes(key), bytes(signature), new Uint8Array()),
          false,
        );
      }
    }
    const negatedPoint = bytes('compressed_public_key');
    negatedPoint[0] = 2;
    assert.equal(await nativeVerifyEs256(negatedPoint, bytes('signature'), message()), false);
    const signature = bytes('signature');
    signature[5] ^= 1;
    assert.equal(await nativeVerifyEs256(bytes('public_key'), signature, message()), false);
    for (const invalid of [new Uint8Array(64), new Uint8Array(64).fill(255)])
      assert.equal(await nativeVerifyEs256(bytes('public_key'), invalid, message()), false);
  });
  await t.test('all buffers are snapshotted before await, including concurrent calls', async () => {
    const pending = Array.from({ length: 8 }, () => {
      const key = bytes('public_key'),
        signature = bytes('signature'),
        input = message();
      const result = nativeVerifyEs256(key, signature, input);
      key.fill(0);
      signature.fill(0);
      input.fill(0);
      return result;
    });
    assert.deepEqual(await Promise.all(pending), Array(8).fill(true));
  });
  await t.test('invalid SEC1 shapes and non-P1363 lengths fail before import', async () => {
    for (const key of [
      new Uint8Array(),
      new Uint8Array(32),
      new Uint8Array(33),
      new Uint8Array(64),
      new Uint8Array(65),
    ])
      await assert.rejects(nativeVerifyEs256(key, bytes('signature'), message()), /encoding/);
    for (const signature of [
      new Uint8Array(),
      new Uint8Array(63),
      new Uint8Array(65),
      new Uint8Array(70).fill(0x30),
    ])
      await assert.rejects(
        nativeVerifyEs256(bytes('public_key'), signature, message()),
        /encoding/,
      );
    for (const key of [new Uint8Array(65), new Uint8Array(33).fill(255)]) {
      key[0] = key.length === 65 ? 4 : 3;
      await assert.rejects(nativeVerifyEs256(key, bytes('signature'), message()));
    }
  });
  await t.test('provider import/verify errors propagate without a reference fallback', async () => {
    for (const method of ['importKey', 'verify'])
      await override(
        method,
        () => {
          throw new Error('injected native failure');
        },
        async () => {
          await assert.rejects(verify(), /injected native failure/);
        },
      );
  });
  await t.test('unexpected key capabilities fail closed', async () => {
    for (const key of [
      { extractable: true, type: 'public', usages: ['verify'] },
      { extractable: false, type: 'private', usages: ['verify'] },
      { extractable: false, type: 'public', usages: [] },
      { extractable: false, type: 'public', usages: ['verify', 'sign'] },
      { extractable: false, type: 'public', usages: ['sign'] },
    ])
      await override(
        'importKey',
        async () => key,
        async () => {
          await assert.rejects(verify(), /verification key/);
        },
      );
  });
  await t.test('only a boolean true is a successful provider result', async () => {
    for (const value of [false, 1, 'true', null, undefined])
      await override(
        'verify',
        async () => value,
        async () => assert.equal(await verify(), false),
      );
  });
});
