/** Provision a dedicated recipient secret without printing private material. */
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { agentKeyId } from '../crates/worker/ui/agent-crypto.ts';

const [output, ...extra] = process.argv.slice(2);
if (!output || extra.length)
  throw new Error('Usage: node scripts/agent-recipient-key.ts OUTPUT_FILE');
const keys = await crypto.subtle.generateKey(
  {
    name: 'RSA-OAEP',
    modulusLength: 3072,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  },
  true,
  ['encrypt', 'decrypt'],
);
const privateJwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
const publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
const path = resolve(output);
await mkdir(dirname(path), { recursive: true, mode: 0o700 });
await writeFile(path, JSON.stringify({ AGENT_PRIVATE_JWK: JSON.stringify(privateJwk) }) + '\n', {
  mode: 0o600,
  flag: 'wx',
});
console.log(
  JSON.stringify({ file: path, key_id: await agentKeyId(publicJwk), public_jwk: publicJwk }),
);
