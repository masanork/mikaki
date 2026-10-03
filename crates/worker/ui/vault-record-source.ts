// Explicit, immutable source identity. A format-1 attribute is never a v2 record.
import { decodeBase64Url, encodeBase64Url } from './vault-crypto.ts';

export type VaultAttributeSource = Readonly<{
  storage_version: 1;
  origin: string;
  owner_id: string;
  attribute_id: 'name' | 'owner_note';
  revision: number;
  ciphertext_sha256: string;
}>;
export type VaultRecordSource = Readonly<{
  storage_version: 2;
  origin: string;
  owner_id: string;
  vault_id: string;
  collection_id: 'personal';
  record_id: 'name' | 'owner_note';
  kind: 'name' | 'owner_note';
  revision: number;
  ciphertext_sha256: string;
}>;
export type VaultSource = VaultAttributeSource | VaultRecordSource;
// These are live authority fences, not content revisions or content AAD.
export type VaultRecordAuthority = Readonly<{
  key_generation: number;
  owner_key_revision: number;
}>;

function object(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  )
    throw new Error('Invalid Vault source');
  return value as Record<string, unknown>;
}
function identifier(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value))
    throw new Error('Invalid Vault source identifier');
  return value;
}
function positive(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1)
    throw new Error('Invalid Vault source revision');
  return value;
}
function target(value: unknown): 'name' | 'owner_note' {
  if (value !== 'name' && value !== 'owner_note') throw new Error('Unsupported Vault source');
  return value;
}
export function parseVaultSource(value: unknown): VaultSource {
  if (!value || typeof value !== 'object' || !('storage_version' in value))
    throw new Error('Explicit Vault storage version required');
  const version = value.storage_version;
  if (version !== 1 && version !== 2) throw new Error('Unsupported Vault source version');
  const input = object(value, [
    'storage_version',
    'origin',
    'owner_id',
    ...(version === 1 ? ['attribute_id'] : ['vault_id', 'collection_id', 'record_id', 'kind']),
    'revision',
    'ciphertext_sha256',
  ]);
  if (typeof input['origin'] !== 'string') throw new Error('Invalid Vault source origin');
  const origin = new URL(input['origin']);
  if (origin.protocol !== 'https:' || origin.origin !== input['origin'])
    throw new Error('Invalid Vault source origin');
  if (
    typeof input['ciphertext_sha256'] !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/.test(input['ciphertext_sha256']) ||
    decodeBase64Url(input['ciphertext_sha256']).length !== 32
  )
    throw new Error('Invalid Vault source digest');
  const common = {
    origin: origin.origin,
    owner_id: identifier(input['owner_id']),
  };
  const content = {
    revision: positive(input['revision']),
    ciphertext_sha256: input['ciphertext_sha256'],
  };
  if (version === 1)
    return Object.freeze({
      storage_version: 1,
      ...common,
      attribute_id: target(input['attribute_id']),
      ...content,
    });
  const record = target(input['record_id']);
  if (input['collection_id'] !== 'personal' || input['kind'] !== record)
    throw new Error('Unsupported Vault source target');
  return Object.freeze({
    storage_version: 2,
    ...common,
    vault_id: identifier(input['vault_id']),
    collection_id: 'personal',
    record_id: record,
    kind: record,
    ...content,
  });
}
export function parseVaultRecordSource(value: unknown): VaultRecordSource {
  const source = parseVaultSource(value);
  if (source.storage_version !== 2) throw new Error('Vault record source required');
  return source;
}
export function parseVaultRecordAuthority(value: unknown): VaultRecordAuthority {
  const input = object(value, ['key_generation', 'owner_key_revision']);
  return Object.freeze({
    key_generation: positive(input['key_generation']),
    owner_key_revision: positive(input['owner_key_revision']),
  });
}
export function equalVaultSource(left: VaultSource, right: VaultSource): boolean {
  return JSON.stringify(parseVaultSource(left)) === JSON.stringify(parseVaultSource(right));
}
export async function vaultCiphertextDigest(ciphertext: string): Promise<string> {
  // Digest the actual stored bytes, never the base64url text or key envelope.
  if (typeof ciphertext !== 'string' || ciphertext.length > 32768)
    throw new Error('Invalid Vault ciphertext size');
  const bytes = decodeBase64Url(ciphertext);
  if (bytes.length < 29 || bytes.length > 24576) throw new Error('Invalid Vault ciphertext size');
  return encodeBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}
