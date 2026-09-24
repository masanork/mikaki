/** Emit a source-reviewed CycloneDX 1.7 cryptography inventory. */
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
type Asset = [
  name: string,
  assetType: 'algorithm' | 'related-crypto-material',
  properties: Record<string, unknown>,
  source: string,
  marker: string,
];
const ASSETS: Asset[] = [
  [
    'ML-KEM-768 Vault recipient encapsulation',
    'algorithm',
    { primitive: 'kem', algorithmFamily: 'ML-KEM', cryptoFunctions: ['encapsulate'] },
    'crates/worker/ui/vault-recipient-envelope.ts',
    'ml_kem768.encapsulate',
  ],
  [
    'AES-256-GCM Vault recipient key wrap',
    'algorithm',
    { primitive: 'ae', algorithmFamily: 'AES', cryptoFunctions: ['encrypt'] },
    'crates/worker/ui/vault-recipient-envelope.ts',
    'crypto.subtle.encrypt',
  ],
  [
    'ES256',
    'algorithm',
    { primitive: 'signature', algorithmFamily: 'ECDSA', cryptoFunctions: ['sign', 'verify'] },
    'crates/oidc/src/signing.rs',
    'alg: "ES256"',
  ],
  [
    'RS256',
    'algorithm',
    {
      primitive: 'signature',
      algorithmFamily: 'RSASSA-PKCS1',
      cryptoFunctions: ['sign', 'verify'],
    },
    'crates/oidc/src/signing.rs',
    'alg: Some("RS256".into())',
  ],
  [
    'SHA-256',
    'algorithm',
    { primitive: 'hash', algorithmFamily: 'SHA-2', cryptoFunctions: ['digest'] },
    'crates/oidc/src/code.rs',
    'Sha256::digest',
  ],
  [
    'Ed25519 verifier',
    'algorithm',
    { primitive: 'signature', algorithmFamily: 'EdDSA', cryptoFunctions: ['verify'] },
    'crates/webauthn/src/key.rs',
    'Ed25519',
  ],
  [
    'OP signing private key binding',
    'related-crypto-material',
    { type: 'private-key', id: 'OP_PRIVATE_JWK', securedBy: { mechanism: 'Software' } },
    'crates/worker/src/lib.rs',
    '.secret("OP_PRIVATE_JWK")',
  ],
  [
    'OP signing public keys',
    'related-crypto-material',
    { type: 'public-key', id: 'signing_key.public_jwk' },
    'crates/worker/migrations/0001_oidc_initial.sql',
    'public_jwk TEXT NOT NULL',
  ],
];
const CLAIM_ASSETS: Asset[] = [
  [
    'AES-256-GCM Vault name validation',
    'algorithm',
    { primitive: 'ae', algorithmFamily: 'AES', cryptoFunctions: ['decrypt'] },
    'crates/userinfo-claim-worker/src/envelope.rs',
    'Aes256Gcm::new_from_slice',
  ],
  [
    'ML-KEM-768 Vault recipient decapsulation',
    'algorithm',
    { primitive: 'kem', algorithmFamily: 'ML-KEM', cryptoFunctions: ['decapsulate'] },
    'crates/userinfo-claim-worker/src/envelope.rs',
    'setup_receiver::<AesGcm256, HkdfSha256, MlKem768>',
  ],
  [
    'ML-KEM-768',
    'algorithm',
    { primitive: 'kem', algorithmFamily: 'ML-KEM', cryptoFunctions: ['keygen'] },
    'crates/userinfo-claim-worker/src/lib.rs',
    'DecapsulationKey::<MlKem768>::from_seed',
  ],
  [
    'SHA-256 recipient key ID',
    'algorithm',
    { primitive: 'hash', algorithmFamily: 'SHA-2', cryptoFunctions: ['digest'] },
    'crates/userinfo-claim-worker/src/lib.rs',
    'Sha256::digest',
  ],
  [
    'UserInfo ML-KEM private seed binding',
    'related-crypto-material',
    { type: 'private-key', id: 'VAULT_USERINFO_MLKEM_*', securedBy: { mechanism: 'Software' } },
    'crates/userinfo-claim-worker/src/lib.rs',
    'env.secret_store(&row.secret_ref)',
  ],
  [
    'UserInfo recipient public keys',
    'related-crypto-material',
    { type: 'public-key', id: 'vault_recipient_key.public_key' },
    'crates/worker/migrations/0007_vault_recipient_keys.sql',
    'public_key BLOB NOT NULL',
  ],
];

function uuid5Url(value: string): string {
  const namespace = Buffer.from('6ba7b8119dad11d180b400c04fd430c8', 'hex');
  const bytes = createHash('sha1').update(namespace).update(value).digest();
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export async function buildCbom(component: 'worker' | 'userinfo-claim-worker' = 'worker') {
  const assets = component === 'worker' ? ASSETS : CLAIM_ASSETS;
  const revision =
    process.env.GITHUB_SHA ||
    execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
  const epoch = process.env.SOURCE_DATE_EPOCH;
  const timestamp = new Date(epoch ? Number(epoch) * 1000 : Date.now())
    .toISOString()
    .replace('.000Z', 'Z');
  const components = [];
  for (const [name, assetType, properties, source, marker] of assets) {
    if (!(await readFile(resolve(ROOT, source), 'utf8')).includes(marker)) {
      throw new Error(`CBOM source marker missing: ${name} (${source})`);
    }
    const cryptoProperties = {
      assetType,
      [assetType === 'algorithm' ? 'algorithmProperties' : 'relatedCryptoMaterialProperties']:
        properties,
    };
    components.push({
      type: 'cryptographic-asset',
      name,
      'bom-ref': `crypto:${name.toLowerCase().replaceAll(' ', '-')}`,
      cryptoProperties,
      properties: [{ name: 'mikaki:source', value: source }],
    });
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    serialNumber: `urn:uuid:${uuid5Url(`mikaki-${component}-cbom:${revision}`)}`,
    version: 1,
    metadata: {
      timestamp,
      component: { type: 'application', name: `mikaki-${component}`, version: revision },
    },
    components,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (
    (args.length !== 0 && args.length !== 2) ||
    (args.length === 2 &&
      (args[0] !== '--component' || !['worker', 'userinfo-claim-worker'].includes(args[1])))
  ) {
    throw new Error('usage: node scripts/build_cbom.ts [--component worker|userinfo-claim-worker]');
  }
  const component = (args[1] ?? 'worker') as 'worker' | 'userinfo-claim-worker';
  console.log(JSON.stringify(await buildCbom(component), null, 2));
}
