// Synthetic challenge-bearing certificate signed by the fixture intermediate.
// This does not make claims about Android software/hardware/app identity.
import { createECDH, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { JWK } from 'jose';
const cert = (name: string) =>
  readFileSync(
    new URL(`../../../crates/identity/tests/fixtures/trust/${name}.der`, import.meta.url),
  );
export function fixtureKey(n: number) {
  const ec = createECDH('prime256v1');
  ec.setPrivateKey(Buffer.alloc(32, n));
  const point = ec.getPublicKey();
  return {
    kty: 'EC',
    crv: 'P-256',
    x: point.subarray(1, 33).toString('base64url'),
    y: point.subarray(33).toString('base64url'),
    d: Buffer.alloc(32, n).toString('base64url'),
  };
}
function tlv(tag: number, bytes: Uint8Array): Buffer {
  return Buffer.concat([
    Buffer.from(
      bytes.length < 128 ? [tag, bytes.length] : [tag, 0x82, bytes.length >> 8, bytes.length & 255],
    ),
    bytes,
  ]);
}
function children(bytes: Buffer): Buffer[] {
  const items = [];
  let i = 0;
  while (i < bytes.length) {
    const start = i++;
    let len = bytes[i++];
    if (len & 128) {
      const count = len & 127;
      len = 0;
      for (let j = 0; j < count; j++) len = len * 256 + bytes[i++];
    }
    i += len;
    if (i > bytes.length) throw Error('invalid fixture DER');
    items.push(bytes.subarray(start, i));
  }
  return items;
}
function content(bytes: Buffer): Buffer {
  const n = bytes[1] & 128 ? 2 + (bytes[1] & 127) : 2;
  return bytes.subarray(n);
}
export function androidAttestationFixture(challenge: string, key: JWK) {
  const certificate = children(content(cert('attester')));
  const tbs = children(content(certificate[0]));
  const publicKey = key.d
    ? createPublicKey(createPrivateKey({ key, format: 'jwk' }))
    : createPublicKey({ key, format: 'jwk' });
  tbs[6] = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const description = tlv(
    0x30,
    Buffer.concat([
      Buffer.from([2, 1, 4, 10, 1, 1, 2, 1, 4, 10, 1, 1]),
      tlv(4, Buffer.from(challenge, 'base64url')),
      Buffer.from([4, 0, 0x30, 0, 0x30, 0]),
    ]),
  );
  const oid = Buffer.from('060a2b06010401d679020111', 'hex');
  const extension = tlv(0x30, Buffer.concat([oid, tlv(4, description)]));
  const position = tbs.findIndex((b) => b[0] === 0xa3);
  tbs[position] = tlv(
    0xa3,
    tlv(0x30, Buffer.concat([...children(content(content(tbs[position]))), extension])),
  );
  const signed = tlv(0x30, Buffer.concat(tbs));
  const intermediate = createPrivateKey({ key: fixtureKey(8), format: 'jwk' });
  const signature = sign('sha256', signed, intermediate);
  const leaf = tlv(
    0x30,
    Buffer.concat([signed, certificate[1], tlv(3, Buffer.concat([Buffer.from([0]), signature]))]),
  );
  return [leaf, cert('intermediate'), cert('root')].map((b) => b.toString('base64'));
}
