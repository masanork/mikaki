import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  decodeBase64Url,
  encodeBase64Url,
  openAttribute,
  parseOwnerEnvelope,
  sealAttribute,
  transferAttribute,
} from '../../crates/worker/ui/vault-crypto.ts';

const origin = 'https://auth.mikaki.org';
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

test('passkey transfer creates a verified fresh revision and cannot reuse the source key', async () => {
  const source = bytes(32),
    target = bytes(32);
  const sourcePrf = bytes(32),
    targetPrf = bytes(32),
    targetInput = bytes(32);
  const value = new TextEncoder().encode('saved value, not an unsaved edit');
  const saved = await sealAttribute(value, sourcePrf, source, bytes(32), origin, attribute, 1);
  const transferred = await transferAttribute(
    saved,
    sourcePrf,
    targetPrf,
    target,
    targetInput,
    origin,
    attribute,
    1,
  );
  assert.notEqual(saved.ciphertext, transferred.ciphertext);
  assert.deepEqual(parseOwnerEnvelope(transferred.owner_envelope).credentialId, target);
  assert.deepEqual(
    await openAttribute(transferred, targetPrf, target, origin, attribute, 2),
    value,
  );
  await assert.rejects(openAttribute(transferred, sourcePrf, source, origin, attribute, 2));
  await assert.rejects(openAttribute(transferred, targetPrf, target, origin, attribute, 1));
  await assert.rejects(
    transferAttribute(saved, bytes(32), targetPrf, target, targetInput, origin, attribute, 1),
  );
  await assert.rejects(
    transferAttribute(saved, sourcePrf, targetPrf, source, targetInput, origin, attribute, 1),
  );
  assert.deepEqual(await openAttribute(saved, sourcePrf, source, origin, attribute, 1), value);
});
