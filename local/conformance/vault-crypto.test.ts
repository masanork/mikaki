import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeBase64Url, encodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';

test('canonical base64url codec matches standard vectors and round-trips binary lengths', () => {
  const vectors = [
    [[], ''],
    [[0], 'AA'],
    [[0xff], '_w'],
    [[0xfb, 0xff], '-_8'],
    [[0, 1, 2], 'AAEC'],
    [[255, 254, 253], '__79'],
  ] as const;
  for (const [values, encoded] of vectors) {
    const bytes = new Uint8Array(values);
    assert.equal(encodeBase64Url(bytes), encoded);
    assert.deepEqual(decodeBase64Url(encoded), bytes);
  }

  for (const length of [2, 4, 8191, 8192, 8193, 16385]) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    assert.deepEqual(decodeBase64Url(encodeBase64Url(bytes)), bytes);
  }
});

test('base64url decoder rejects padding, nonalphabet bytes, invalid lengths and noncanonical tail bits', () => {
  for (const value of ['a=', '+/==', '/', 'A', 'AA=', 'AA\n', 'AB']) {
    assert.throws(
      () => decodeBase64Url(value),
      `accepted invalid base64url ${JSON.stringify(value)}`,
    );
  }
});
