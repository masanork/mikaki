// One-operation proof encryption: only the new revision's content key crosses this boundary.
import { agentKeyId, type AgentRecipient } from './agent-crypto.ts';
import { encodeBase64Url, decodeBase64Url } from './vault-crypto.ts';
import { parseRecordNoteTarget, type RecordNoteTarget } from './vault-record-approval.ts';
import {
  parseVaultRecordSource,
  parseVaultRecordAuthority,
  type VaultRecordSource,
  type VaultRecordAuthority,
} from './vault-record-source.ts';
import type { RecordAgentEnvelope } from './agent-record-crypto.ts';

export type ApprovedRecordProofBinding = Readonly<{
  owner: string;
  grant_id: string;
  key_id: string;
  resource: string;
  expires_at: number;
  proposal_id: string;
  request_hash: string;
  operation_id: string;
  candidate_sha256: string;
  target: RecordNoteTarget;
  authority: VaultRecordAuthority;
  candidate_source: VaultRecordSource;
}>;
export function approvedRecordProofBinding(
  value: ApprovedRecordProofBinding,
): ApprovedRecordProofBinding {
  const target = parseRecordNoteTarget(value.target),
    source = parseVaultRecordSource(value.candidate_source),
    authority = parseVaultRecordAuthority(value.authority);
  const resource = new URL(value.resource);
  if (
    Object.keys(value).length !== 12 ||
    ![
      value.grant_id,
      value.key_id,
      value.proposal_id,
      value.request_hash,
      value.operation_id,
      value.candidate_sha256,
    ].every((id) => /^[A-Za-z0-9_-]{43}$/.test(id)) ||
    value.owner !== target.owner_id ||
    source.owner_id !== value.owner ||
    source.origin !== target.origin ||
    source.vault_id !== target.vault_id ||
    source.collection_id !== target.collection_id ||
    source.record_id !== target.record_id ||
    source.kind !== target.kind ||
    source.revision !== target.revision + 1 ||
    resource.protocol !== 'https:' ||
    resource.pathname !== '/mcp' ||
    resource.href !== value.resource ||
    resource.search ||
    resource.hash ||
    !Number.isSafeInteger(value.expires_at) ||
    value.expires_at < 1
  )
    throw new Error('Invalid approved-record proof binding');
  return Object.freeze({
    owner: value.owner,
    grant_id: value.grant_id,
    key_id: value.key_id,
    resource: value.resource,
    expires_at: value.expires_at,
    proposal_id: value.proposal_id,
    request_hash: value.request_hash,
    operation_id: value.operation_id,
    candidate_sha256: value.candidate_sha256,
    target,
    authority,
    candidate_source: source,
  });
}
function context(binding: ApprovedRecordProofBinding): Uint8Array<ArrayBuffer> {
  return new Uint8Array(
    new TextEncoder().encode(
      JSON.stringify(['mikaki-approved-record-proof', 2, approvedRecordProofBinding(binding)]),
    ),
  );
}
export async function sealApprovedRecordProof(
  dataKey: Uint8Array<ArrayBuffer>,
  recipient: AgentRecipient,
  value: ApprovedRecordProofBinding,
): Promise<RecordAgentEnvelope> {
  if (dataKey.length !== 32) throw new Error('Invalid candidate content key');
  const binding = approvedRecordProofBinding(value),
    label = context(binding),
    plaintext = dataKey.slice();
  const jwk = { ...recipient.public_jwk },
    keyId = recipient.key_id,
    resource = recipient.resource;
  const raw = crypto.getRandomValues(new Uint8Array(32));
  try {
    if (
      binding.key_id !== keyId ||
      binding.resource !== resource ||
      (await agentKeyId(jwk)) !== keyId
    )
      throw new Error('Proof recipient mismatch');
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt'],
    );
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: label },
        key,
        plaintext,
      ),
    );
    const wrapped = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'RSA-OAEP', label }, publicKey, raw),
    );
    return Object.freeze({
      version: 2,
      wrapped_key: encodeBase64Url(wrapped),
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(ciphertext),
    });
  } finally {
    raw.fill(0);
    plaintext.fill(0);
  }
}
// Service-only receiver. The returned key can decrypt only the candidate revision;
// caller must clear it after exact AAD/schema/approved-byte verification.
export async function openApprovedRecordProof(
  envelope: RecordAgentEnvelope,
  privateKey: CryptoKey,
  binding: ApprovedRecordProofBinding,
): Promise<Uint8Array<ArrayBuffer>> {
  const label = context(binding);
  if (
    Object.keys(envelope).length !== 4 ||
    envelope.version !== 2 ||
    envelope.ciphertext.length !== 64 ||
    envelope.nonce.length !== 16 ||
    envelope.wrapped_key.length < 342 ||
    envelope.wrapped_key.length > 683
  )
    throw new Error('Invalid approved-record proof');
  const wrapped = decodeBase64Url(envelope.wrapped_key),
    nonce = decodeBase64Url(envelope.nonce),
    ciphertext = decodeBase64Url(envelope.ciphertext);
  if (
    wrapped.length < 256 ||
    wrapped.length > 512 ||
    nonce.length !== 12 ||
    ciphertext.length !== 48
  )
    throw new Error('Invalid approved-record proof');
  const raw = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'RSA-OAEP', label }, privateKey, wrapped),
  );
  try {
    if (raw.length !== 32) throw new Error('Invalid proof transport key');
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    const content = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: label },
        key,
        ciphertext,
      ),
    );
    if (content.length !== 32) {
      content.fill(0);
      throw new Error('Invalid candidate content key');
    }
    return content;
  } finally {
    raw.fill(0);
  }
}
