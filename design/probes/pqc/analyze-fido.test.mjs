import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { encode } from 'cborg';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { analyze } from './analyze-fido.mjs';

const b64 = (value) => Buffer.from(value).toString('base64url');
const hash = (value) => createHash('sha256').update(value).digest();
const origin = 'http://localhost:8789';

function transcript(algorithm) {
  const credentialId = Buffer.alloc(32, 0x60);
  const challenge = Buffer.alloc(32, 0x61);
  const rpHash = hash(Buffer.from('localhost'));
  const signing =
    algorithm === -49
      ? ml_dsa65.keygen(new Uint8Array(32).fill(0x62))
      : generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const key =
    algorithm === -49
      ? new Map([
          [1, 7],
          [3, -49],
          [-1, signing.publicKey],
        ])
      : (() => {
          const jwk = signing.publicKey.export({ format: 'jwk' });
          return new Map([
            [1, 2],
            [3, -7],
            [-1, 1],
            [-2, Buffer.from(jwk.x, 'base64url')],
            [-3, Buffer.from(jwk.y, 'base64url')],
          ]);
        })();
  const registrationData = Buffer.concat([
    rpHash,
    Buffer.from([0x41, 0, 0, 0, 0]),
    Buffer.alloc(16),
    Buffer.from([0, credentialId.length]),
    credentialId,
    Buffer.from(encode(key)),
  ]);
  const assertionData = Buffer.concat([rpHash, Buffer.from([0x01, 0, 0, 0, 1])]);
  const client = (type) =>
    Buffer.from(JSON.stringify({ type, challenge: b64(challenge), origin, crossOrigin: false }));
  const signed = Buffer.concat([assertionData, hash(client('webauthn.get'))]);
  const signature =
    algorithm === -49
      ? ml_dsa65.sign(signed, signing.secretKey)
      : sign('sha256', signed, signing.privateKey);
  return {
    probe: 'mikaki-fido-pqc-v1',
    origin,
    requestedAlgorithm: algorithm,
    registrationChallenge: b64(challenge),
    registration: {
      id: b64(credentialId),
      publicKeyAlgorithm: algorithm,
      attestationObject: b64(
        encode(
          new Map([
            ['fmt', 'none'],
            ['authData', registrationData],
            ['attStmt', new Map()],
          ]),
        ),
      ),
      clientDataJSON: b64(client('webauthn.create')),
    },
    assertionChallenge: b64(challenge),
    assertion: {
      id: b64(credentialId),
      authenticatorData: b64(assertionData),
      clientDataJSON: b64(client('webauthn.get')),
      signature: b64(signature),
    },
  };
}

for (const algorithm of [-49, -7]) {
  test(`local FIDO analyzer verifies ${algorithm} and rejects changed signatures`, () => {
    const value = transcript(algorithm);
    assert.deepEqual(analyze(value).status, 'verified');
    const changed = Buffer.from(value.assertion.signature, 'base64url');
    changed[0] ^= 1;
    value.assertion.signature = b64(changed);
    assert.throws(() => analyze(value), /signature invalid/);
  });
}

test('local FIDO analyzer rejects a changed challenge', () => {
  const value = transcript(-49);
  value.assertionChallenge = b64(Buffer.alloc(32, 0x63));
  assert.throws(() => analyze(value), /client data mismatch/);
});
