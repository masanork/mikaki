import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { decode, decodeFirst } from 'cborg';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const ORIGIN = 'http://localhost:8789';
const RP_ID = 'localhost';
const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest();
const encode = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

function base64url(value: unknown) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('invalid base64url');
  }
  const bytes = Buffer.from(value, 'base64url');
  if (encode(bytes) !== value) throw new Error('noncanonical base64url');
  return bytes;
}

function clientData(encoded: string, type: string, challenge: string) {
  const bytes = base64url(encoded);
  const value = JSON.parse(bytes.toString('utf8'));
  if (
    value.type !== type ||
    value.challenge !== challenge ||
    value.origin !== ORIGIN ||
    value.crossOrigin === true
  ) {
    throw new Error('client data mismatch');
  }
  return bytes;
}

function authenticatorData(bytes: Buffer, attested: boolean) {
  if (bytes.length < 37 || !bytes.subarray(0, 32).equals(sha256(Buffer.from(RP_ID)))) {
    throw new Error('RP ID hash mismatch');
  }
  const flags = bytes[32];
  if (!(flags & 0x01) || Boolean(flags & 0x40) !== attested) {
    throw new Error('authenticator flags mismatch');
  }
  return { flags, signCount: bytes.readUInt32BE(33) };
}

function coseKey(attestation: string, credentialId: Buffer) {
  const decoded = decode(base64url(attestation), { useMaps: true });
  const authData = Buffer.from(decoded.get('authData') ?? []);
  const { flags } = authenticatorData(authData, true);
  if (authData.length < 55) throw new Error('attested credential data truncated');
  const credentialLength = authData.readUInt16BE(53);
  const start = 55 + credentialLength;
  if (credentialLength === 0 || start >= authData.length) {
    throw new Error('credential data length invalid');
  }
  if (!authData.subarray(55, start).equals(credentialId)) {
    throw new Error('credential ID mismatch');
  }
  const [key, remainder] = decodeFirst(authData.subarray(start), { useMaps: true });
  if (!(key instanceof Map)) {
    throw new Error('COSE key invalid');
  }
  if (flags & 0x80) {
    if (remainder.length === 0) throw new Error('extensions missing');
    decode(remainder, { useMaps: true });
  } else if (remainder.length !== 0) {
    throw new Error('unexpected credential data');
  }
  return { key, aaguid: authData.subarray(37, 53).toString('hex') };
}

function publicKey(key: Map<number, unknown>, algorithm: number) {
  if (key.get(3) !== algorithm) throw new Error('COSE algorithm mismatch');
  if (algorithm === -49) {
    const bytes = key.get(-1);
    if (key.get(1) !== 7 || !(bytes instanceof Uint8Array) || bytes.length !== 1952) {
      throw new Error('ML-DSA-65 COSE key invalid');
    }
    return bytes;
  }
  if (algorithm === -7) {
    const x = key.get(-2);
    const y = key.get(-3);
    if (
      key.get(1) !== 2 ||
      key.get(-1) !== 1 ||
      !(x instanceof Uint8Array) ||
      !(y instanceof Uint8Array) ||
      x.length !== 32 ||
      y.length !== 32
    ) {
      throw new Error('ES256 COSE key invalid');
    }
    return createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: encode(x), y: encode(y) },
      format: 'jwk',
    });
  }
  throw new Error('unexpected algorithm');
}

type Transcript = {
  probe: string;
  origin: string;
  requestedAlgorithm: number;
  registrationChallenge: string;
  assertionChallenge: string;
  registrationError?: Record<string, unknown>;
  registration?: {
    id: string;
    publicKeyAlgorithm: number;
    attestationObject: string;
    clientDataJSON: string;
  };
  assertion?: {
    id: string;
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
  };
};

export function analyze(transcript: Transcript) {
  if (transcript?.probe !== 'mikaki-fido-pqc-v1' || transcript.origin !== ORIGIN) {
    throw new Error('probe origin mismatch');
  }
  if (transcript.registrationError) {
    return { status: 'registration_error', ...transcript.registrationError };
  }
  const registration = transcript.registration;
  const algorithm = transcript.requestedAlgorithm;
  if (!registration || ![-49, -7].includes(algorithm)) throw new Error('registration missing');
  clientData(registration.clientDataJSON, 'webauthn.create', transcript.registrationChallenge);
  const credentialId = base64url(registration.id);
  const { key, aaguid } = coseKey(registration.attestationObject, credentialId);
  if (registration.publicKeyAlgorithm !== algorithm) {
    throw new Error('browser selected unexpected algorithm');
  }
  const verifier = publicKey(key, algorithm);
  if (!transcript.assertion) {
    return { status: 'registered_without_assertion', algorithm, aaguid };
  }
  const assertion = transcript.assertion;
  if (!base64url(assertion.id).equals(credentialId))
    throw new Error('assertion credential mismatch');
  const clientBytes = clientData(
    assertion.clientDataJSON,
    'webauthn.get',
    transcript.assertionChallenge,
  );
  const authData = base64url(assertion.authenticatorData);
  const { flags, signCount } = authenticatorData(authData, false);
  const signed = Buffer.concat([authData, sha256(clientBytes)]);
  const signature = base64url(assertion.signature);
  const valid =
    algorithm === -49
      ? ml_dsa65.verify(signature, signed, verifier as Uint8Array)
      : verify('sha256', signed, verifier as ReturnType<typeof createPublicKey>, signature);
  if (!valid) throw new Error('assertion signature invalid');
  return { status: 'verified', algorithm, aaguid, flags, signCount };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const path = process.argv[2];
  if (!path) throw new Error('usage: node design/probes/pqc/analyze-fido.ts result.json');
  const transcript = JSON.parse(await readFile(path, 'utf8'));
  console.log(JSON.stringify(analyze(transcript)));
}
