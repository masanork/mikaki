/** Dedicated test-issuer custody. Private material is written only to a new mode-0600 file. */
import {
  createECDH,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
} from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function identityIssuerPublicKey(raw: string) {
  let scalar: Buffer | undefined;
  try {
    if (raw.length > 4096) throw new Error();
    const value = JSON.parse(raw);
    const fields = ['kty', 'crv', 'x', 'y', 'd', 'kid'];
    if (!value || fields.some((field) => typeof value[field] !== 'string')) throw new Error();
    const { kty, crv, x, y, d, kid } = value as Record<string, string>;
    // The generator's exact encoding also excludes duplicate JSON members and extra JOSE fields.
    if (raw.trim() !== JSON.stringify({ kty, crv, x, y, d, kid })) throw new Error();
    if (kty !== 'EC' || crv !== 'P-256' || !kid || Buffer.byteLength(kid) > 128) throw new Error();
    for (const coordinate of [x, y, d])
      if (
        !/^[A-Za-z0-9_-]{43}$/.test(coordinate) ||
        Buffer.from(coordinate, 'base64url').toString('base64url') !== coordinate
      )
        throw new Error();
    scalar = Buffer.from(d, 'base64url');
    const key = createECDH('prime256v1');
    key.setPrivateKey(scalar);
    const point = key.getPublicKey();
    if (
      point.subarray(1, 33).toString('base64url') !== x ||
      point.subarray(33).toString('base64url') !== y
    )
      throw new Error();
    const publicJwk = { kty, crv, x, y, kid };
    const thumbprint = createHash('sha256')
      .update(JSON.stringify({ crv, kty, x, y }))
      .digest('base64url');
    return { public_jwk: publicJwk, thumbprint };
  } catch {
    // Never attach the JSON parser/OpenSSL exception or the submitted JWK.
    throw new Error('Invalid dedicated Identity issuer key');
  } finally {
    scalar?.fill(0);
  }
}

export function assertDedicatedIdentityKey(raw: string, opRaw: string) {
  const identity = identityIssuerPublicKey(raw);
  try {
    const configured = JSON.parse(opRaw);
    const op = createPublicKey(createPrivateKey({ key: configured, format: 'jwk' })).export({
      format: 'jwk',
    });
    if (op.kty !== 'RSA' && !(op.kty === 'EC' && op.crv === 'P-256')) throw new Error();
    if (op.kty === 'EC') {
      const { kty, crv, x, y, d } = configured;
      const checked = identityIssuerPublicKey(
        JSON.stringify({ kty, crv, x, y, d, kid: 'op-role-check' }),
      );
      if (
        checked.public_jwk.x === identity.public_jwk.x &&
        checked.public_jwk.y === identity.public_jwk.y
      )
        throw new Error();
    }
  } catch {
    throw new Error('Identity issuer key must be distinct from a valid OP signing key');
  }
}

export function writeIdentityIssuerKey(output: string) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const { kty, crv, x, y, d } = privateKey.export({ format: 'jwk' });
  const raw = JSON.stringify({ kty, crv, x, y, d, kid: `mikaki-identity-test-${randomUUID()}` });
  const report = identityIssuerPublicKey(raw);
  const path = resolve(output);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${raw}\n`, { flag: 'wx', mode: 0o600 });
  return { file: path, ...report };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [output, ...extra] = process.argv.slice(2);
  if (!output || extra.length)
    throw new Error('Usage: node scripts/identity-issuer-key.ts OUTPUT_FILE');
  console.log(JSON.stringify(writeIdentityIssuerKey(output)));
}
