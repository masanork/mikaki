// Selected v2 plaintext receives an independent transport key. No owner/content key enters here.
import { agentKeyId, type AgentDocument, type AgentRecipient } from './agent-crypto.ts';
import { decodeBase64Url, encodeBase64Url } from './vault-crypto.ts';
import {
  parseVaultRecordAuthority,
  parseVaultRecordSource,
  type VaultRecordAuthority,
  type VaultRecordSource,
} from './vault-record-source.ts';

export type RecordAgentBinding = Readonly<{
  owner: string;
  grant_id: string;
  key_id: string;
  resource: string;
  expires_at: number;
  source: VaultRecordSource;
  authority: VaultRecordAuthority;
}>;
export type RecordAgentEnvelope = Readonly<{
  version: 2;
  wrapped_key: string;
  nonce: string;
  ciphertext: string;
}>;

export function recordAgentBinding(value: RecordAgentBinding): RecordAgentBinding {
  const source = parseVaultRecordSource(value.source);
  const authority = parseVaultRecordAuthority(value.authority);
  const resource = new URL(value.resource);
  if (
    Object.keys(value).length !== 7 ||
    value.owner !== source.owner_id ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.grant_id) ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.key_id) ||
    resource.protocol !== 'https:' ||
    resource.pathname !== '/mcp' ||
    resource.search ||
    resource.hash ||
    resource.href !== value.resource ||
    !Number.isSafeInteger(value.expires_at) ||
    value.expires_at < 1
  )
    throw new Error('Invalid record snapshot binding');
  return Object.freeze({
    owner: value.owner,
    grant_id: value.grant_id,
    key_id: value.key_id,
    resource: value.resource,
    expires_at: value.expires_at,
    source,
    authority,
  });
}
function context(binding: RecordAgentBinding): Uint8Array<ArrayBuffer> {
  const b = recordAgentBinding(binding);
  return new Uint8Array(
    new TextEncoder().encode(JSON.stringify(['mikaki-agent-record-snapshot', 2, b])),
  );
}
export async function sealRecordAgentSnapshot(
  documents: readonly AgentDocument[],
  recipient: AgentRecipient,
  binding: RecordAgentBinding,
): Promise<RecordAgentEnvelope> {
  const b = recordAgentBinding(binding);
  const label = context(b);
  // Copy all caller-controlled input before the first asynchronous boundary.
  const publicKey = { ...recipient.public_jwk };
  const keyId = recipient.key_id,
    resource = recipient.resource;
  if (documents.length !== 1 || documents[0]?.id !== b.source.record_id)
    throw new Error('Exactly one selected record required');
  const plaintext = new TextEncoder().encode(JSON.stringify(documents));
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  try {
    if (plaintext.length > 24576) throw new Error('Agent snapshot too large');
    if ((await agentKeyId(publicKey)) !== keyId || b.key_id !== keyId || b.resource !== resource)
      throw new Error('Agent recipient mismatch');
    const recipientKey = await crypto.subtle.importKey(
      'jwk',
      publicKey,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt'],
    );
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: label },
        key,
        plaintext,
      ),
    );
    const wrapped = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'RSA-OAEP', label }, recipientKey, rawKey),
    );
    return Object.freeze({
      version: 2,
      wrapped_key: encodeBase64Url(wrapped),
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(ciphertext),
    });
  } finally {
    rawKey.fill(0);
    plaintext.fill(0);
  }
}
export async function openRecordAgentSnapshot(
  value: RecordAgentEnvelope,
  privateKey: CryptoKey,
  binding: RecordAgentBinding,
): Promise<unknown> {
  const label = context(binding);
  if (Object.keys(value).length !== 4 || value.version !== 2)
    throw new Error('Invalid record snapshot envelope');
  const wrapped = decodeBase64Url(value.wrapped_key),
    nonce = decodeBase64Url(value.nonce),
    ciphertext = decodeBase64Url(value.ciphertext);
  if (
    wrapped.length < 256 ||
    wrapped.length > 512 ||
    nonce.length !== 12 ||
    ciphertext.length < 16 ||
    ciphertext.length > 24592
  )
    throw new Error('Invalid record snapshot envelope');
  const raw = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'RSA-OAEP', label }, privateKey, wrapped),
  );
  try {
    if (raw.length !== 32) throw new Error('Invalid agent key');
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: label },
        key,
        ciphertext,
      ),
    );
    try {
      return JSON.parse(
        new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(plaintext),
      );
    } finally {
      plaintext.fill(0);
    }
  } finally {
    raw.fill(0);
  }
}
