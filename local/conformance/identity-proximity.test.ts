import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import {
  createECDH,
  createHash,
  hkdfSync,
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import {
  encodeCbor as enc,
  decodeCbor as dec,
  field,
  embedded,
  verifyMdocIssuer,
  type Cbor,
} from './support/mdoc-test.ts';
const run = (packet?: Buffer, profile?: string, hr?: Buffer) =>
  JSON.parse(
    execFileSync(
      'cargo',
      [
        'run',
        '-q',
        '-p',
        'mikaki-identity',
        '--example',
        'proximity_fixture',
        '--offline',
        '--locked',
        ...(packet || profile
          ? [
              '--',
              packet?.toString('base64url') ?? '-',
              ...(profile ? [profile] : []),
              ...(hr ? [hr.toString('base64url')] : []),
            ]
          : []),
      ],
      { encoding: 'utf8', maxBuffer: 100_000 },
    ),
  );
const tag = (v: Cbor): Cbor => ({ tag: 24, value: enc(v) });
const map = (entries: [Cbor, Cbor][]) => new Map<Cbor, Cbor>(entries);
const sha = (b: Buffer) => createHash('sha256').update(b).digest();
function vector(f: ReturnType<typeof run>, mode = '') {
  const engagement = Buffer.from(f.engagement, 'base64url');
  const reader = createECDH('prime256v1');
  reader.setPrivateKey(Buffer.alloc(32, 6));
  const point = reader.getPublicKey();
  const readerKey = map([
    [1, 2],
    [-1, 1],
    [-2, point.subarray(1, 33)],
    [-3, point.subarray(33)],
  ]);
  const deviceKey = embedded((field(dec(engagement), 1) as Cbor[])[1]);
  const devicePoint = Buffer.concat([
    Buffer.from([4]),
    field(deviceKey, -2) as Buffer,
    field(deviceKey, -3) as Buffer,
  ]);
  const shared = reader.computeSecret(devicePoint);
  const transcript: Cbor = [
    tag(dec(engagement)),
    tag(readerKey),
    f.handover_select && mode !== 'qr-downgrade'
      ? [
          Buffer.from(f.handover_select, 'base64url'),
          mode === 'static-downgrade'
            ? null
            : f.handover_request
              ? Buffer.from(f.handover_request, 'base64url')
              : null,
        ]
      : null,
  ];
  const salt = sha(mode === 'raw-salt' ? enc(transcript) : enc(tag(transcript)));
  const skReader = Buffer.from(hkdfSync('sha256', shared, salt, Buffer.from('SKReader'), 32));
  const skDevice = Buffer.from(hkdfSync('sha256', shared, salt, Buffer.from('SKDevice'), 32));
  const items = tag(
    map([
      ['docType', 'app.tossa.mikaki.linked_document.1'],
      [
        'nameSpaces',
        map([
          [
            'app.tossa.mikaki.linked_document.1',
            map([
              [mode === 'unknown-claim' ? 'unknown' : 'name', true],
              ['birthdate', false],
            ]),
          ],
        ]),
      ],
    ]),
  );
  const auth = enc(
    tag([
      'ReaderAuthentication',
      mode === 'wrong-transcript' ? [null, null, null] : transcript,
      items,
    ]),
  );
  const protectedHeader = enc(map([[1, -7]]));
  const signingJwk = { ...f.reader_jwk, d: Buffer.alloc(32, 4).toString('base64url') };
  const signature = sign('sha256', enc(['Signature1', protectedHeader, Buffer.alloc(0), auth]), {
    key: createPrivateKey({ key: signingJwk, format: 'jwk' }),
    dsaEncoding: 'ieee-p1363',
  });
  if (mode === 'bad-signature') signature[0] ^= 1;
  const certificate = readFileSync(
    'crates/identity/tests/fixtures/' +
      (mode === 'wrong-certificate-purpose' ? 'mdoc-ds.der' : 'mdoc-reader.der'),
  );
  let chain: Cbor = certificate;
  if (mode === 'certificate' || mode === 'certificate-tampered') {
    const intermediate = readFileSync('crates/identity/tests/fixtures/trust/intermediate.der');
    if (mode === 'certificate-tampered') intermediate[intermediate.length - 1] ^= 1;
    chain = [readFileSync('crates/identity/tests/fixtures/trust/reader.der'), intermediate];
  }
  const readerAuth: Cbor = [protectedHeader, map([[33, chain]]), null, signature];
  const request = enc(
    map([
      ['version', '1.0'],
      [
        'docRequests',
        [
          map([
            ['itemsRequest', items],
            ['readerAuth', readerAuth],
          ]),
        ],
      ],
    ]),
  );
  const iv = Buffer.alloc(12);
  iv.writeUInt32BE(mode === 'wrong-counter' ? 2 : 1, 8);
  const cipher = createCipheriv('aes-256-gcm', skReader, iv);
  const encrypted = Buffer.concat([cipher.update(request), cipher.final(), cipher.getAuthTag()]);
  if (mode === 'tampered') encrypted[0] ^= 1;
  return {
    packet: enc(
      map([
        ['eReaderKey', tag(readerKey)],
        ['data', encrypted],
      ]),
    ),
    skDevice,
    transcript,
  };
}
test('independent ECDH/HKDF/AES-GCM reader verifies native mdoc QR session and selective DeviceSignature', () => {
  const f = run();
  const v = vector(f);
  const result = run(v.packet);
  assert.equal(result.error, undefined);
  assert.equal(result.consumed, true);
  assert.deepEqual(result.fields, ['name', 'birthdate']);
  assert.deepEqual(result.retained_fields, ['name']);
  const data = field(dec(Buffer.from(result.packet, 'base64url')), 'data') as Buffer;
  const iv = Buffer.alloc(12);
  iv.writeUInt32BE(1, 4);
  iv.writeUInt32BE(1, 8);
  const decipher = createDecipheriv('aes-256-gcm', v.skDevice, iv);
  decipher.setAuthTag(data.subarray(-16));
  const response = dec(Buffer.concat([decipher.update(data.subarray(0, -16)), decipher.final()]));
  const docs = field(response, 'documents') as Cbor[];
  assert.equal(docs.length, 1);
  const signed = field(docs[0], 'issuerSigned');
  const partial = verifyMdocIssuer(enc(signed).toString('base64url'), f.holder_jwk, f.issuer_jwk);
  assert.deepEqual(partial.values, { name: 'Fixture Person', birthdate: '1990-02-28' });
  const device = field(docs[0], 'deviceSigned');
  const signature = field(field(device, 'deviceAuth'), 'deviceSignature') as Cbor[];
  const payload = enc(
    tag([
      'DeviceAuthentication',
      v.transcript,
      'app.tossa.mikaki.linked_document.1',
      field(device, 'nameSpaces'),
    ]),
  );
  const key = createPublicKey({ key: f.holder_jwk, format: 'jwk' });
  assert.equal(
    verify(
      'sha256',
      enc(['Signature1', signature[0], Buffer.alloc(0), payload]),
      { key, dsaEncoding: 'ieee-p1363' },
      signature[3] as Buffer,
    ),
    true,
  );
  const wrong = enc(
    tag([
      'DeviceAuthentication',
      [null, null, null],
      'app.tossa.mikaki.linked_document.1',
      field(device, 'nameSpaces'),
    ]),
  );
  assert.equal(
    verify(
      'sha256',
      enc(['Signature1', signature[0], Buffer.alloc(0), wrong]),
      { key, dsaEncoding: 'ieee-p1363' },
      signature[3] as Buffer,
    ),
    false,
  );
});
test('bad session salt, counter, ciphertext, ReaderAuthentication and claims consume the session', () => {
  const f = run();
  for (const mode of [
    'raw-salt',
    'wrong-counter',
    'tampered',
    'wrong-transcript',
    'bad-signature',
    'unknown-claim',
    'wrong-certificate-purpose',
  ]) {
    const result = run(vector(f, mode).packet);
    assert.equal(typeof result.error, 'string', mode);
    assert.equal(result.consumed, true, mode);
    assert.equal(result.packet, undefined, mode);
  }
  const unknown = run(vector(f).packet, 'untrusted');
  assert.equal(unknown.error, 'untrusted_reader');
  assert.equal(unknown.consumed, true);
  const result = run(Buffer.from([0xa0]));
  assert.equal(typeof result.error, 'string');
  assert.equal(result.consumed, true);
});

test('NFC static handover preserves exact NDEF bytes and refuses QR transcript substitution', () => {
  const f = run(undefined, 'nfc');
  assert.ok(f.handover_select);
  const bytes = Buffer.from(f.handover_select, 'base64url');
  const records: { kind: string; id: string; payload: Buffer }[] = [];
  for (let pos = 0; pos < bytes.length;) {
    const flags = bytes[pos++],
      typeLength = bytes[pos++];
    assert.ok(flags & 16);
    const length = bytes[pos++],
      idLength = flags & 8 ? bytes[pos++] : 0;
    const kind = bytes.subarray(pos, pos + typeLength).toString();
    pos += typeLength;
    const id = bytes.subarray(pos, pos + idLength).toString();
    pos += idLength;
    const payload = bytes.subarray(pos, pos + length);
    pos += length;
    records.push({ kind, id, payload });
  }
  assert.deepEqual(
    records.map((r) => r.kind),
    ['Hs', 'iso.org:18013:deviceengagement', 'application/vnd.bluetooth.le.oob'],
  );
  assert.equal(records[0].payload[0], 0x15);
  assert.deepEqual(
    records[0].payload.subarray(1),
    Buffer.from([0xd1, 2, 9, 0x61, 0x63, 1, 1, 0x30, 1, 4, 0x6d, 0x64, 0x6f, 0x63]),
  );
  assert.equal(records[1].id, 'mdoc');
  assert.deepEqual(records[1].payload, Buffer.from(f.engagement, 'base64url'));
  assert.equal(records[2].id, '0');
  assert.deepEqual(
    records[2].payload,
    Buffer.concat([
      Buffer.from([2, 0x1c, 0, 17, 7]),
      Buffer.from(Array.from({ length: 16 }, (_, i) => 15 - i)),
    ]),
  );
  const engagement = dec(records[1].payload);
  assert.ok(engagement instanceof Map);
  assert.equal(engagement.has(2), false);
  const v = vector(f);
  const result = run(v.packet, 'nfc');
  assert.equal(result.error, undefined);
  assert.equal(result.consumed, true);
  const data = field(dec(Buffer.from(result.packet, 'base64url')), 'data') as Buffer;
  const iv = Buffer.alloc(12);
  iv.writeUInt32BE(1, 4);
  iv.writeUInt32BE(1, 8);
  const decipher = createDecipheriv('aes-256-gcm', v.skDevice, iv);
  decipher.setAuthTag(data.subarray(-16));
  const response = dec(Buffer.concat([decipher.update(data.subarray(0, -16)), decipher.final()]));
  const doc = (field(response, 'documents') as Cbor[])[0];
  const device = field(doc, 'deviceSigned');
  const signature = field(field(device, 'deviceAuth'), 'deviceSignature') as Cbor[];
  const payload = enc(
    tag([
      'DeviceAuthentication',
      v.transcript,
      'app.tossa.mikaki.linked_document.1',
      field(device, 'nameSpaces'),
    ]),
  );
  assert.equal(
    verify(
      'sha256',
      enc(['Signature1', signature[0], Buffer.alloc(0), payload]),
      { key: createPublicKey({ key: f.holder_jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
      signature[3] as Buffer,
    ),
    true,
  );
  const wrong = run(vector(f, 'qr-downgrade').packet, 'nfc');
  assert.equal(wrong.error, 'session_authentication_failed');
  assert.equal(wrong.consumed, true);
  const qr = run(v.packet);
  assert.equal(qr.error, 'session_authentication_failed');
  assert.equal(qr.consumed, true);
});

test('QR NFC retrieval advertises bounded APDUs and binds the NFC-only engagement to encryption', () => {
  const f = run(undefined, 'qr_nfc');
  assert.equal(f.handover_select, null);
  const engagement = dec(Buffer.from(f.engagement, 'base64url'));
  assert.deepEqual(field(engagement, 2), [
    [
      1,
      1,
      new Map([
        [0, 255],
        [1, 256],
      ]),
    ],
  ]);
  const packet = vector(f).packet;
  const result = run(packet, 'qr_nfc');
  assert.equal(result.error, undefined);
  assert.equal(result.consumed, true);
  const cross = run(packet);
  assert.equal(cross.error, 'session_authentication_failed');
  assert.equal(cross.consumed, true);
});

function handoverRequest(role = 0, long = false): Buffer {
  const record = (flags: number, type: string, id: string, payload: Buffer): Buffer => {
    const length = Buffer.alloc(long ? 4 : 1);
    if (long) length.writeUInt32BE(payload.length);
    else length[0] = payload.length;
    return Buffer.concat([
      Buffer.from([flags | (long ? 0 : 16) | (id ? 8 : 0), type.length]),
      length,
      ...(id ? [Buffer.from([id.length])] : []),
      Buffer.from(type),
      Buffer.from(id),
      payload,
    ]);
  };
  const collision = record(0x81, 'cr', '', Buffer.from([0x12, 0x34]));
  const ac = record(0x41, 'ac', '', Buffer.from([1, 1, 0x30, 0]));
  return Buffer.concat([
    record(0x81, 'Hr', '', Buffer.concat([Buffer.from([0x15]), collision, ac])),
    record(0x42, 'application/vnd.bluetooth.le.oob', '0', Buffer.from([2, 0x1c, role])),
  ]);
}
test('negotiated NFC binds exact Hr/Hs bytes and rejects static downgrade and changed negotiation', () => {
  for (const long of [false, true]) {
    const hr = handoverRequest(0, long);
    const f = run(undefined, 'nfc_negotiated', hr);
    assert.equal(f.error, undefined);
    const v = vector(f);
    const result = run(v.packet, 'nfc_negotiated', hr);
    assert.equal(result.error, undefined);
    assert.equal(result.consumed, true);
    const data = field(dec(Buffer.from(result.packet, 'base64url')), 'data') as Buffer;
    const iv = Buffer.alloc(12);
    iv.writeUInt32BE(1, 4);
    iv.writeUInt32BE(1, 8);
    const cipher = createDecipheriv('aes-256-gcm', v.skDevice, iv);
    cipher.setAuthTag(data.subarray(-16));
    const response = dec(Buffer.concat([cipher.update(data.subarray(0, -16)), cipher.final()]));
    const device = field((field(response, 'documents') as Cbor[])[0], 'deviceSigned');
    const signature = field(field(device, 'deviceAuth'), 'deviceSignature') as Cbor[];
    const payload = enc(
      tag([
        'DeviceAuthentication',
        v.transcript,
        'app.tossa.mikaki.linked_document.1',
        field(device, 'nameSpaces'),
      ]),
    );
    assert.equal(
      verify(
        'sha256',
        enc(['Signature1', signature[0], Buffer.alloc(0), payload]),
        { key: createPublicKey({ key: f.holder_jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
        signature[3] as Buffer,
      ),
      true,
    );
    for (const mode of ['static-downgrade', 'qr-downgrade']) {
      const wrong = run(vector(f, mode).packet, 'nfc_negotiated', hr);
      assert.equal(wrong.error, 'session_authentication_failed');
      assert.equal(wrong.consumed, true);
    }
    const changed = Buffer.from(hr);
    changed[long ? 17 : 11] ^= 1; // collision-resolution random bytes
    const altered = run(v.packet, 'nfc_negotiated', changed);
    assert.equal(altered.error, 'session_authentication_failed');
    assert.equal(altered.packet, undefined);
    const missing = run(v.packet, 'nfc_negotiated');
    assert.equal(missing.error, 'handover_required');
    assert.equal(missing.consumed, true);
  }
  const invalid: Buffer[] = [];
  for (const [position, value] of [
    [0, 0x11],
    [0, 0xb1],
    [5, 0x14],
    [18, 0],
    [20, 0x31],
  ] as const) {
    const hr = handoverRequest();
    hr[position] = value;
    invalid.push(hr);
  }
  const noRole = handoverRequest();
  noRole[noRole.length - 2] = 9;
  invalid.push(noRole);
  for (const bad of [
    ...invalid,
    handoverRequest(1),
    handoverRequest(4),
    Buffer.from([0xa0]),
    handoverRequest().subarray(0, -1),
    Buffer.alloc(4095),
  ]) {
    const result = run(undefined, 'nfc_negotiated', bad);
    assert.equal(typeof result.error, 'string');
    assert.equal(result.packet, undefined);
    assert.equal(result.consumed, true);
  }
});

function nfcHandoverRequest(payload = Buffer.from('010201ff03020100', 'hex')): Buffer {
  const ac = Buffer.from([0xd1, 2, 6, 0x61, 0x63, 1, 3, 0x6e, 0x66, 0x63, 0]);
  const kind = Buffer.from('iso.org:18013:nfc');
  return Buffer.concat([
    Buffer.from([0x91, 2, ac.length + 1, 0x48, 0x72, 0x15]),
    ac,
    Buffer.from([0x5c, kind.length, payload.length, 3]),
    kind,
    Buffer.from('nfc'),
    payload,
  ]);
}
test('negotiated NFC data carrier binds Hr/Hs and rejects inadequate APDU limits or BLE offers', () => {
  const hr = nfcHandoverRequest();
  const f = run(undefined, 'nfc_negotiated_data', hr);
  assert.equal(f.error, undefined);
  const hs = Buffer.from(f.handover_select, 'base64url');
  assert.ok(hs.includes(Buffer.from('iso.org:18013:nfc')));
  assert.equal(hs.includes(Buffer.from('application/vnd.bluetooth.le.oob')), false);
  assert.deepEqual(hs.subarray(-8), Buffer.from('010201ff03020100', 'hex'));
  const engagement = dec(Buffer.from(f.engagement, 'base64url'));
  assert.ok(engagement instanceof Map);
  assert.equal(engagement.has(2), false);
  const v = vector(f);
  const result = run(v.packet, 'nfc_negotiated_data', hr);
  assert.equal(result.error, undefined);
  assert.equal(result.consumed, true);
  const data = field(dec(Buffer.from(result.packet, 'base64url')), 'data') as Buffer;
  const iv = Buffer.alloc(12);
  iv.writeUInt32BE(1, 4);
  iv.writeUInt32BE(1, 8);
  const cipher = createDecipheriv('aes-256-gcm', v.skDevice, iv);
  cipher.setAuthTag(data.subarray(-16));
  const response = dec(Buffer.concat([cipher.update(data.subarray(0, -16)), cipher.final()]));
  const device = field((field(response, 'documents') as Cbor[])[0], 'deviceSigned');
  const signature = field(field(device, 'deviceAuth'), 'deviceSignature') as Cbor[];
  const payload = enc(
    tag([
      'DeviceAuthentication',
      v.transcript,
      'app.tossa.mikaki.linked_document.1',
      field(device, 'nameSpaces'),
    ]),
  );
  assert.equal(
    verify(
      'sha256',
      enc(['Signature1', signature[0], Buffer.alloc(0), payload]),
      { key: createPublicKey({ key: f.holder_jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
      signature[3] as Buffer,
    ),
    true,
  );
  for (const mode of ['qr-downgrade', 'static-downgrade']) {
    const bad = run(vector(f, mode).packet, 'nfc_negotiated_data', hr);
    assert.equal(bad.error, 'session_authentication_failed');
    assert.equal(bad.consumed, true);
  }
  for (const payload of [
    '010201fe03020100',
    '010201ff0202ff',
    '020201ff03020100',
    '010201ff03010100',
    '010201ff0302010000',
    '010201ff',
  ]) {
    const bad = run(
      undefined,
      'nfc_negotiated_data',
      nfcHandoverRequest(Buffer.from(payload, 'hex')),
    );
    assert.equal(typeof bad.error, 'string');
    assert.equal(bad.consumed, true);
  }
  const large = nfcHandoverRequest(Buffer.from('01030101000402010000', 'hex'));
  assert.equal(run(undefined, 'nfc_negotiated_data', large).error, undefined);
  for (const [profile, offer] of [
    ['nfc_negotiated', hr],
    ['nfc_negotiated_data', handoverRequest()],
  ] as const) {
    const wrong = run(undefined, profile, offer);
    assert.equal(wrong.error, 'unsupported_handover');
    assert.equal(wrong.consumed, true);
  }
});

test('independent encrypted ReaderAuthentication uses registered CA trust without a key-only fallback', () => {
  const f = run();
  const accepted = run(vector(f, 'certificate').packet, 'certificate');
  assert.equal(accepted.error, undefined);
  assert.deepEqual(accepted.fields, ['name', 'birthdate']);
  for (const mode of ['certificate-tampered', 'valid']) {
    const rejected = run(vector(f, mode).packet, 'certificate');
    assert.ok(rejected.error);
    assert.equal(rejected.consumed, true);
    assert.equal(rejected.packet, undefined);
  }
});

test('CRL-required encrypted reader request fails closed on revoked, stale or unknown status', () => {
  const f = run(undefined, 'crl');
  const packet = vector(f, 'certificate').packet;
  const accepted = run(packet, 'crl');
  assert.equal(accepted.error, undefined);
  assert.deepEqual(accepted.fields, ['name', 'birthdate']);
  for (const [profile, error] of [
    ['crl-revoked', 'certificate_revoked'],
    ['crl-stale', 'crl_stale'],
    ['crl-missing', 'certificate_status_unknown'],
  ]) {
    const rejected = run(packet, profile);
    assert.equal(rejected.error, error);
    assert.equal(rejected.packet, undefined);
    assert.equal(rejected.consumed, true);
  }
});
