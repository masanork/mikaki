import {
  createHash,
  generateKeyPairSync,
  privateEncrypt,
  constants,
  randomBytes,
  sign,
} from 'node:crypto';

function tlv(tag: number, value: Uint8Array): Buffer {
  return Buffer.concat([
    Buffer.from(
      value.length < 128 ? [tag, value.length] : [tag, 0x82, value.length >> 8, value.length & 255],
    ),
    value,
  ]);
}

// Independent Node crypto fixtures: NPA uses a raw SHA-256 digest inside RSA padding,
// whereas the My Number input-support signature uses SHA-256 DigestInfo.
export function identityFixture() {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicKey = rsa.publicKey.export({ format: 'jwk' });
  const ski = randomBytes(32);
  const now = Math.floor(Date.now() / 1000);
  const trust = (document_type: string) => ({
    id: `fixture-${document_type}`,
    document_type,
    n: publicKey.n,
    e: publicKey.e,
    subject_key_identifier: ski.toString('base64url'),
    not_before: now - 60,
    not_after: now + 3600,
  });
  const makeLicense = () => {
    const fields = Buffer.concat([
      tlv(0x11, Buffer.from([0x78])),
      tlv(0x12, Buffer.from([0x30, 0x22])),
      tlv(0x17, Buffer.from([0x30, 0x22])),
      tlv(0x16, Buffer.from('4020228')),
      tlv(0x1b, Buffer.from('5120101')),
    ]);
    const attributes = Buffer.alloc(880, 255);
    fields.copy(attributes);
    const domicile = Buffer.alloc(82, 255),
      photo = Buffer.alloc(2005);
    const digest = createHash('sha256').update(attributes).update(domicile).update(photo).digest();
    const signature = Buffer.alloc(578, 255);
    Buffer.concat([
      tlv(
        0xb1,
        privateEncrypt({ key: rsa.privateKey, padding: constants.RSA_PKCS1_PADDING }, digest),
      ),
      tlv(0xb6, ski),
    ]).copy(signature);
    return {
      document_type: 'driving_license',
      attributes: [...attributes],
      domicile: [...domicile],
      photo: [...photo],
      signature: [...signature],
    };
  };
  const makeMnc = () => {
    const attributes = Buffer.concat(
      [
        [0x22, '試験 太郎'],
        [0x23, '東京都'],
        [0x24, '19900228'],
        [0x25, '1'],
      ].map(([tag, text]) =>
        Buffer.concat([
          Buffer.from([0xdf, Number(tag), Buffer.byteLength(String(text))]),
          Buffer.from(String(text)),
        ]),
      ),
    );
    const message = Buffer.concat([
      Buffer.from([0xdf, 0x31, 32]),
      Buffer.alloc(32, 11),
      Buffer.from([0xdf, 0x32, 32]),
      createHash('sha256').update(attributes).digest(),
    ]);
    const inner = Buffer.concat([
      message,
      Buffer.from([0xdf, 0x33, 0x82, 1, 0]),
      sign('sha256', message, rsa.privateKey),
    ]);
    return {
      document_type: 'my_number_card',
      attributes: [...attributes],
      signature: [
        ...Buffer.concat([
          Buffer.from([0xff, 0x30, 0x82, inner.length >> 8, inner.length & 255]),
          inner,
        ]),
      ],
      domicile: [],
      photo: [],
    };
  };
  return { trust: [trust('driving_license'), trust('my_number_card')], makeLicense, makeMnc };
}
