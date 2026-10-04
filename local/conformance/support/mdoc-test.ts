// Independent, fixture-only CBOR codec. Not used by production code or untrusted input.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify, X509Certificate } from 'node:crypto';
export type Cbor =
  | number
  | string
  | Buffer
  | null
  | boolean
  | Cbor[]
  | Map<Cbor, Cbor>
  | { tag: number; value: Cbor };
export function encodeCbor(v: Cbor): Buffer {
  const head = (major: number, n: number) =>
    n < 24
      ? Buffer.from([major * 32 + n])
      : n < 256
        ? Buffer.from([major * 32 + 24, n])
        : n < 65536
          ? Buffer.from([major * 32 + 25, n >> 8, n & 255])
          : Buffer.from([major * 32 + 26, n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  if (v === null) return Buffer.from([0xf6]);
  if (typeof v === 'boolean') return Buffer.from([v ? 0xf5 : 0xf4]);
  if (typeof v === 'number') return head(v < 0 ? 1 : 0, v < 0 ? -1 - v : v);
  if (typeof v === 'string') {
    const b = Buffer.from(v);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(encodeCbor)]);
  if (v instanceof Map)
    return Buffer.concat([
      head(5, v.size),
      ...[...v].flatMap(([k, v]) => [encodeCbor(k), encodeCbor(v)]),
    ]);
  return Buffer.concat([head(6, v.tag), encodeCbor(v.value)]);
}
export function decodeCbor(bytes: Buffer): Cbor {
  let pos = 0;
  function read(depth = 0): Cbor {
    assert.ok(depth < 20 && pos < bytes.length);
    const h = bytes[pos++],
      major = h >> 5,
      ai = h & 31;
    let n = ai;
    if (ai >= 24) {
      assert.ok(ai <= 26);
      const size = 1 << (ai - 24);
      n = bytes.readUIntBE(pos, size);
      pos += size;
    }
    if (major === 0) return n;
    if (major === 1) return -1 - n;
    if (major === 2 || major === 3) {
      assert.ok(pos + n <= bytes.length);
      const b = bytes.subarray(pos, pos + n);
      pos += n;
      return major === 2 ? b : b.toString('utf8');
    }
    if (major === 4) return Array.from({ length: n }, () => read(depth + 1));
    if (major === 5) {
      const m = new Map<Cbor, Cbor>();
      for (let i = 0; i < n; i++) m.set(read(depth + 1), read(depth + 1));
      return m;
    }
    if (major === 6) return { tag: n, value: read(depth + 1) };
    if (h === 0xf6) return null;
    if (h === 0xf4) return false;
    if (h === 0xf5) return true;
    throw new Error('unsupported fixture CBOR');
  }
  const v = read();
  assert.equal(pos, bytes.length);
  return v;
}
export function field(v: Cbor, key: Cbor): Cbor {
  assert.ok(v instanceof Map);
  assert.ok(v.has(key));
  return v.get(key)!;
}
export function embedded(v: Cbor): Cbor {
  assert.ok(
    v !== null && typeof v === 'object' && 'tag' in v && v.tag === 24 && Buffer.isBuffer(v.value),
  );
  return decodeCbor(v.value);
}
export function verifyMdocIssuer(
  encoded: string,
  holder: Record<string, unknown>,
  issuerJwk: Record<string, unknown>,
) {
  const signed = decodeCbor(Buffer.from(encoded, 'base64url'));
  const auth = field(signed, 'issuerAuth');
  assert.ok(Array.isArray(auth) && auth.length === 4);
  assert.deepEqual(decodeCbor(auth[0] as Buffer), new Map([[1, -7]]));
  const certificate = new X509Certificate(field(auth[1], 33) as Buffer);
  const key = createPublicKey({ key: issuerJwk, format: 'jwk' });
  assert.deepEqual(
    certificate.publicKey.export({ format: 'der', type: 'spki' }),
    key.export({ format: 'der', type: 'spki' }),
  );
  const input = encodeCbor(['Signature1', auth[0], Buffer.alloc(0), auth[2]]);
  assert.equal(
    verify('sha256', input, { key, dsaEncoding: 'ieee-p1363' }, auth[3] as Buffer),
    true,
  );
  const mso = embedded(decodeCbor(auth[2] as Buffer));
  assert.equal(field(mso, 'docType'), 'app.tossa.mikaki.linked_document.1');
  const device = field(field(mso, 'deviceKeyInfo'), 'deviceKey');
  assert.deepEqual(field(device, -2), Buffer.from(holder.x as string, 'base64url'));
  assert.deepEqual(field(device, -3), Buffer.from(holder.y as string, 'base64url'));
  const namespace = 'app.tossa.mikaki.linked_document.1';
  const items = field(field(signed, 'nameSpaces'), namespace);
  assert.ok(Array.isArray(items));
  const digests = field(field(mso, 'valueDigests'), namespace);
  const values: Record<string, Cbor> = {};
  for (const item of items) {
    const decoded = embedded(item);
    const digest = createHash('sha256').update(encodeCbor(item)).digest();
    assert.deepEqual(field(digests, field(decoded, 'digestID')), digest);
    values[field(decoded, 'elementIdentifier') as string] = field(decoded, 'elementValue');
  }
  return { mso, values, signed };
}
