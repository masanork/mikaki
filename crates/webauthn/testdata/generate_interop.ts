/** Independent Node.js WebAuthn fixtures. Run with `node generate_interop.ts`.
 * Only public keys, messages, and signatures are written to disk.
 */
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';

type Cbor = number | string | Uint8Array | Cbor[] | Map<Cbor, Cbor>;
const utf8 = (value: string) => Buffer.from(value);
const hash = (value: Uint8Array) => createHash('sha256').update(value).digest();
const b64 = (value: Uint8Array) => Buffer.from(value).toString('base64url');
const bytes = (value: string) => Buffer.from(value, 'base64url');
const concat = (...values: Uint8Array[]) => Buffer.concat(values);

function head(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 256) return Buffer.from([(major << 5) | 24, length]);
  if (length < 65536) {
    const out = Buffer.alloc(3);
    out[0] = (major << 5) | 25;
    out.writeUInt16BE(length, 1);
    return out;
  }
  throw new Error('fixture CBOR value is too large');
}

function cbor(value: Cbor): Buffer {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('fixture CBOR integer is invalid');
    return value >= 0 ? head(0, value) : head(1, -value - 1);
  }
  if (typeof value === 'string') return concat(head(3, utf8(value).length), utf8(value));
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  if (Array.isArray(value)) return concat(head(4, value.length), ...value.map(cbor));
  return concat(
    head(5, value.size),
    ...[...value].flatMap(([key, entry]) => [cbor(key), cbor(entry)]),
  );
}

const map = (entries: [Cbor, Cbor][]) => new Map<Cbor, Cbor>(entries);
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const jwk = publicKey.export({ format: 'jwk' });
if (!jwk.x || !jwk.y) throw new Error('EC key is missing coordinates');
const cose = cbor(
  map([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, bytes(jwk.x)],
    [-3, bytes(jwk.y)],
  ]),
);
const challenge = b64(Buffer.alloc(32, 3));
const origin = 'https://login.example';
const rpId = 'login.example';
const credentialId = Buffer.from([1, 2, 3]);
const context = {
  challenge,
  origin,
  rp_id: rpId,
  max_bytes: 65536,
  max_depth: 8,
  algorithms: [-7],
};
const client = (type: string) =>
  utf8(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
const authHeader = (flags: number, counter: number) => {
  const count = Buffer.alloc(4);
  count.writeUInt32BE(counter);
  return concat(hash(utf8(rpId)), Buffer.from([flags]), count);
};
const registrationAuth = concat(
  authHeader(0x45, 0),
  Buffer.alloc(16, 9),
  Buffer.from([0, credentialId.length]),
  credentialId,
  cose,
);
const registrationClient = client('webauthn.create');
const signature = sign('sha256', concat(registrationAuth, hash(registrationClient)), privateKey);

function registration(format: string, statement: Map<Cbor, Cbor>, auth = registrationAuth) {
  return {
    id: b64(credentialId),
    client_data: b64(registrationClient),
    attestation: b64(
      cbor(
        map([
          ['fmt', format],
          ['attStmt', statement],
          ['authData', auth],
        ]),
      ),
    ),
  };
}

const none = registration('none', map([]));
const self = registration(
  'packed',
  map([
    ['alg', -7],
    ['sig', signature],
  ]),
);
const badSignature = Buffer.from(signature);
badSignature[badSignature.length - 1] ^= 1;
const registrations = [
  { name: 'Node none', ok: true, kind: 'none', context, response: none },
  { name: 'Node packed self', ok: true, kind: 'self', context, response: self },
  {
    name: 'Node packed invalid signature',
    ok: false,
    context,
    response: registration(
      'packed',
      map([
        ['alg', -7],
        ['sig', badSignature],
      ]),
    ),
  },
  {
    name: 'Node wrong challenge',
    ok: false,
    context: { ...context, challenge: b64(Buffer.alloc(32, 4)) },
    response: none,
  },
  {
    name: 'Node wrong RP ID',
    ok: false,
    context: { ...context, rp_id: 'other.example' },
    response: none,
  },
  {
    name: 'Node required trust rejects self',
    ok: false,
    context: { ...context, attestation_policy: 'required_trusted' },
    response: self,
  },
];

const assertionAuth = authHeader(0x05, 1);
const assertionClient = client('webauthn.get');
const assertionSignature = sign('sha256', concat(assertionAuth, hash(assertionClient)), privateKey);
const stored = {
  id: b64(credentialId),
  public_key: b64(cose),
  user_handle: b64(utf8('account')),
  counter: 0,
  backup_eligible: false,
};
function assertion(signatureBytes: Uint8Array) {
  return {
    id: b64(credentialId),
    client_data: b64(assertionClient),
    authenticator_data: b64(assertionAuth),
    signature: b64(signatureBytes),
    user_handle: b64(utf8('account')),
  };
}
const badAssertion = Buffer.from(assertionSignature);
badAssertion[badAssertion.length - 1] ^= 1;
const assertions = [
  {
    name: 'Node ES256 assertion',
    ok: true,
    context,
    stored,
    response: assertion(assertionSignature),
  },
  {
    name: 'Node invalid assertion signature',
    ok: false,
    context,
    stored,
    response: assertion(badAssertion),
  },
  {
    name: 'Node stale counter',
    ok: false,
    context,
    stored: { ...stored, counter: 1 },
    response: assertion(assertionSignature),
  },
];

const path = new URL('./interop-node.json', import.meta.url);
writeFileSync(path, JSON.stringify({ registrations, assertions }) + '\n');
console.log(`Wrote ${path.pathname}`);
