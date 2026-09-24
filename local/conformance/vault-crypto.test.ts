import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  decodeBase64Url,
  encodeBase64Url,
  openAttribute,
  parseOwnerEnvelope,
  sealAttribute,
} from '../../crates/worker/ui/vault-crypto.ts';

const origin = 'https://mikaki.tossa.app';
const attribute = 'name';
const bytes = (length: number) => crypto.getRandomValues(new Uint8Array(length));

test('owner can open a sealed attribute, with exact revision and context', async () => {
  const credential = bytes(32);
  const prfInput = bytes(32);
  const prfOutput = bytes(32);
  const plaintext = new TextEncoder().encode('例の名前');
  const sealed = await sealAttribute(
    plaintext,
    prfOutput,
    credential,
    prfInput,
    origin,
    attribute,
    1,
  );
  const envelope = parseOwnerEnvelope(sealed.owner_envelope);
  assert.deepEqual(envelope.credentialId, credential);
  assert.deepEqual(envelope.prfInput, prfInput);
  assert.deepEqual(
    await openAttribute(sealed, prfOutput, credential, origin, attribute, 1),
    plaintext,
  );
  await assert.rejects(openAttribute(sealed, bytes(32), credential, origin, attribute, 1));
  await assert.rejects(openAttribute(sealed, prfOutput, bytes(32), origin, attribute, 1));
  await assert.rejects(openAttribute(sealed, prfOutput, credential, origin, 'email', 1));
  await assert.rejects(
    openAttribute(sealed, prfOutput, credential, 'https://other.example', attribute, 1),
  );
  await assert.rejects(openAttribute(sealed, prfOutput, credential, origin, attribute, 2));
  const changed = decodeBase64Url(sealed.ciphertext);
  changed[changed.length - 1] ^= 1;
  await assert.rejects(
    openAttribute(
      { ...sealed, ciphertext: encodeBase64Url(changed) },
      prfOutput,
      credential,
      origin,
      attribute,
      1,
    ),
  );
  const wrap = decodeBase64Url(sealed.owner_envelope);
  wrap[wrap.length - 1] ^= 1;
  await assert.rejects(
    openAttribute(
      { ...sealed, owner_envelope: encodeBase64Url(wrap) },
      prfOutput,
      credential,
      origin,
      attribute,
      1,
    ),
  );
});

test('owner envelope rejects malformed and noncanonical encodings', () => {
  assert.throws(() => parseOwnerEnvelope('a='));
  assert.throws(() => parseOwnerEnvelope(encodeBase64Url(bytes(200))));
});
