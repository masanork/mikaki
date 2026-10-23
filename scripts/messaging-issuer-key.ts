/** Dedicated Chat issuer custody. Never print or overwrite private key material. */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function chatPublicKey(value: unknown): asserts value is string {
  if (
    typeof value !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/.test(value) ||
    Buffer.from(value, 'base64url').toString('base64url') !== value
  )
    throw new Error('Invalid Chat issuer public key');
}

export function messagingIssuerPublicKey(raw: string, expected?: string) {
  let seed: Buffer | undefined;
  try {
    if (typeof raw !== 'string' || raw.length > 512) throw new Error();
    const { kty, crv, x, d } = JSON.parse(raw);
    // Exact canonical JSON rejects duplicates, extra JOSE fields and other key roles.
    if (raw.trim() !== JSON.stringify({ kty, crv, x, d })) throw new Error();
    if (kty !== 'OKP' || crv !== 'Ed25519') throw new Error();
    chatPublicKey(x);
    chatPublicKey(d);
    seed = Buffer.from(d, 'base64url');
    const derived = createPublicKey(
      createPrivateKey({ key: { kty, crv, x, d }, format: 'jwk' }),
    ).export({ format: 'jwk' });
    if (derived.x !== x) throw new Error();
    if (expected !== undefined) {
      chatPublicKey(expected);
      if (x !== expected) throw new Error();
    }
    return {
      public_jwk: { kty: 'OKP' as const, crv: 'Ed25519' as const, x },
      thumbprint: createHash('sha256').update(JSON.stringify({ crv, kty, x })).digest('base64url'),
      key_id: createHash('sha256').update(Buffer.from(x, 'base64url')).digest('base64url'),
    };
  } catch {
    // Parser/OpenSSL/assertion errors must never carry the submitted private JWK.
    throw new Error('Invalid Chat issuer key or public-key mismatch');
  } finally {
    seed?.fill(0);
  }
}

export function writeMessagingIssuerKey(output: string) {
  const { kty, crv, x, d } = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
  const raw = JSON.stringify({ kty, crv, x, d });
  const report = messagingIssuerPublicKey(raw);
  const path = resolve(output);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${raw}\n`, { flag: 'wx', mode: 0o600 });
  return { file: path, ...report };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [output, ...extra] = process.argv.slice(2);
    if (!output || extra.length) throw new Error();
    console.log(JSON.stringify(writeMessagingIssuerKey(output)));
  } catch {
    console.error('Chat key generation failed; use a new private output file.');
    process.exitCode = 1;
  }
}
