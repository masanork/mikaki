import { parseApprovedRecordNote, type ApprovedRecordNote } from './vault-record-approval.ts';
import { sealApprovedRecordProof } from './agent-record-proof.ts';
import type { AgentRecipient } from './agent-crypto.ts';
import type { RecordAgentEnvelope } from './agent-record-crypto.ts';
// Candidate v2 owner-key format. Not wired to production Vault storage/UI.
import { decodeBase64Url, encodeBase64Url } from './vault-crypto.ts';
import { sealRecordUserInfoDataKey } from './vault-record-recipient-envelope.ts';
import type { RecordUserInfoRecipient } from './recipient-directory-v2.ts';
import {
  parseVaultRecordSource,
  parseVaultRecordAuthority,
  vaultCiphertextDigest,
  type VaultRecordSource,
  type VaultRecordAuthority,
} from './vault-record-source.ts';

type Bytes = Uint8Array<ArrayBuffer>;
export type OwnerKeyContext = Readonly<{
  origin: string;
  ownerId: string;
  vaultId: string;
  keyGeneration: number;
}>;
export type OwnerKeyEnvelope = Readonly<{
  format_version: 2;
  kind: 'owner-key';
  credential_id: string;
  prf_input: string;
  salt: string;
  nonce: string;
  wrapped_key: string;
}>;
export type OwnerRecordContext = Readonly<{
  collectionId: string;
  recordId: string;
  kind: string;
  revision: number;
}>;
export type OwnerRecord = Readonly<{
  format_version: 2;
  ciphertext: string;
  key_envelope: string;
}>;
const KEY = 32;
const NONCE = 12;
const TAG = 16;
export const OWNER_KEY_SUITE = 'PRF-HKDF-SHA256-AES256GCM-v2';
// This first contract covers bounded records, not large SQLite images.
export const OWNER_RECORD_MAX_BYTES = 24 * 1024;
const random = (length: number): Bytes => crypto.getRandomValues(new Uint8Array(length));
function concat(...parts: Bytes[]): Bytes {
  const bytes = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
}
function positive(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('invalid generation/revision');
}
function id(value: string): void {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value))
    throw new Error('invalid identifier');
}
export function ownerKeyContext(value: OwnerKeyContext): OwnerKeyContext {
  const url = new URL(value.origin);
  if (url.protocol !== 'https:' || url.origin !== value.origin) throw new Error('invalid origin');
  id(value.ownerId);
  id(value.vaultId);
  positive(value.keyGeneration);
  return Object.freeze({
    origin: value.origin,
    ownerId: value.ownerId,
    vaultId: value.vaultId,
    keyGeneration: value.keyGeneration,
  });
}
function recordContext(value: OwnerRecordContext): OwnerRecordContext {
  id(value.collectionId);
  id(value.recordId);
  id(value.kind);
  positive(value.revision);
  return Object.freeze({ ...value });
}
// UTF-8 fields prefixed by their unsigned big-endian 16-bit byte length.
function fields(parts: string[]): Bytes {
  return concat(
    ...parts.map((part) => {
      const bytes = new TextEncoder().encode(part);
      if (bytes.length > 65535) throw new Error('context too long');
      const prefix = new Uint8Array(2);
      new DataView(prefix.buffer).setUint16(0, bytes.length);
      return concat(prefix, bytes);
    }),
  );
}
function contextFields(context: OwnerKeyContext): string[] {
  const c = ownerKeyContext(context);
  return ['2', c.origin, c.ownerId, c.vaultId, String(c.keyGeneration)];
}
function wrapContext(
  purpose: string,
  context: OwnerKeyContext,
  credential: Bytes,
  input: Bytes,
): Bytes {
  return fields([
    purpose,
    ...contextFields(context),
    encodeBase64Url(credential),
    encodeBase64Url(input),
  ]);
}
function recordAad(purpose: string, context: OwnerKeyContext, item: OwnerRecordContext): Bytes {
  const r = recordContext(item);
  const c = ownerKeyContext(context);
  // Content identity stays stable when only the parent wrapping key rotates.
  const ownerFields =
    purpose === 'mikaki-vault-record-content'
      ? ['2', c.origin, c.ownerId, c.vaultId]
      : contextFields(c);
  return fields([purpose, ...ownerFields, r.collectionId, r.recordId, r.kind, String(r.revision)]);
}
function decode(value: string, min: number, max = min): Bytes {
  if (typeof value !== 'string' || value.length > Math.ceil((max * 4) / 3))
    throw new Error('invalid encoding size');
  const bytes = decodeBase64Url(value);
  if (bytes.length < min || bytes.length > max) throw new Error('invalid encoding size');
  return bytes;
}
function exact(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((k) => !Object.hasOwn(value, k))
  )
    throw new Error('invalid envelope');
}
export function parseOwnerKeyEnvelope(value: unknown): OwnerKeyEnvelope {
  exact(value, [
    'format_version',
    'kind',
    'credential_id',
    'prf_input',
    'salt',
    'nonce',
    'wrapped_key',
  ]);
  if (value['format_version'] !== 2 || value['kind'] !== 'owner-key')
    throw new Error('unsupported owner-key format');
  const string = (key: string): string => {
    const v = value[key];
    if (typeof v !== 'string') throw new Error('invalid envelope');
    return v;
  };
  const envelope = {
    format_version: 2 as const,
    kind: 'owner-key' as const,
    credential_id: string('credential_id'),
    prf_input: string('prf_input'),
    salt: string('salt'),
    nonce: string('nonce'),
    wrapped_key: string('wrapped_key'),
  };
  decode(envelope.credential_id, 1, 512);
  decode(envelope.prf_input, KEY);
  decode(envelope.salt, KEY);
  decode(envelope.nonce, NONCE);
  decode(envelope.wrapped_key, KEY + TAG);
  return Object.freeze(envelope);
}
async function kek(
  output: Bytes,
  salt: Bytes,
  context: OwnerKeyContext,
  credential: Bytes,
  input: Bytes,
): Promise<CryptoKey> {
  if (output.length !== KEY) throw new Error('PRF output unavailable');
  const material = await crypto.subtle.importKey('raw', output, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: wrapContext('mikaki-vault-owner-kek', context, credential, input),
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}
async function wrap(
  raw: Bytes,
  context: OwnerKeyContext,
  credential: Bytes,
  input: Bytes,
  output: Bytes,
): Promise<OwnerKeyEnvelope> {
  context = ownerKeyContext(context);
  credential = credential.slice();
  input = input.slice();
  if (credential.length < 1 || credential.length > 512 || input.length !== KEY)
    throw new Error('invalid credential/input');
  const salt = random(KEY),
    nonce = random(NONCE);
  const key = await kek(output, salt, context, credential, input);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: wrapContext('mikaki-vault-owner-wrap', context, credential, input),
      },
      key,
      raw,
    ),
  );
  return Object.freeze({
    format_version: 2,
    kind: 'owner-key',
    credential_id: encodeBase64Url(credential),
    prf_input: encodeBase64Url(input),
    salt: encodeBase64Url(salt),
    nonce: encodeBase64Url(nonce),
    wrapped_key: encodeBase64Url(encrypted),
  });
}
async function unwrap(
  value: unknown,
  context: OwnerKeyContext,
  expected: Bytes,
  output: Bytes,
): Promise<Bytes> {
  context = ownerKeyContext(context);
  const envelope = parseOwnerKeyEnvelope(value);
  const credential = decode(envelope.credential_id, 1, 512),
    input = decode(envelope.prf_input, KEY);
  if (encodeBase64Url(expected) !== envelope.credential_id) throw new Error('wrong credential');
  const key = await kek(output, decode(envelope.salt, KEY), context, credential, input);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: decode(envelope.nonce, NONCE),
        additionalData: wrapContext('mikaki-vault-owner-wrap', context, credential, input),
      },
      key,
      decode(envelope.wrapped_key, KEY + TAG),
    ),
  );
}
async function importOwnerKey(raw: Bytes): Promise<CryptoKey> {
  if (raw.length !== KEY) throw new Error('invalid owner key');
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

// The caller supplies a verified credential's PRF output. All three owner-key
// operations consume (zero) that byte array, including on validation failure.
export async function createOwnerKey(
  context: OwnerKeyContext,
  credential: Bytes,
  input: Bytes,
  output: Bytes,
): Promise<{ envelope: OwnerKeyEnvelope; key: CryptoKey }> {
  const raw = random(KEY);
  try {
    const envelope = await wrap(raw, context, credential, input, output);
    return { envelope, key: await importOwnerKey(raw) };
  } finally {
    raw.fill(0);
    output.fill(0);
  }
}
export async function openOwnerKey(
  value: unknown,
  context: OwnerKeyContext,
  expected: Bytes,
  output: Bytes,
): Promise<CryptoKey> {
  let raw: Bytes | undefined;
  try {
    raw = await unwrap(value, context, expected, output);
    return await importOwnerKey(raw);
  } finally {
    raw?.fill(0);
    output.fill(0);
  }
}
export async function rewrapOwnerKey(
  value: unknown,
  context: OwnerKeyContext,
  source: Bytes,
  sourceOutput: Bytes,
  target: Bytes,
  targetInput: Bytes,
  targetOutput: Bytes,
): Promise<OwnerKeyEnvelope> {
  let raw: Bytes | undefined;
  try {
    context = ownerKeyContext(context);
    source = source.slice();
    target = target.slice();
    targetInput = targetInput.slice();
    if (encodeBase64Url(source) === encodeBase64Url(target))
      throw new Error('different credential required');
    raw = await unwrap(value, context, source, sourceOutput);
    return await wrap(raw, context, target, targetInput, targetOutput);
  } finally {
    raw?.fill(0);
    sourceOutput.fill(0);
    targetOutput.fill(0);
  }
}
function ownerHandle(key: CryptoKey): void {
  if (
    key.type !== 'secret' ||
    key.extractable ||
    key.algorithm.name !== 'AES-GCM' ||
    !('length' in key.algorithm) ||
    key.algorithm.length !== 256 ||
    !key.usages.includes('encrypt') ||
    !key.usages.includes('decrypt')
  )
    throw new Error('invalid owner handle');
}
export async function sealOwnerRecord(
  plaintext: Bytes,
  key: CryptoKey,
  context: OwnerKeyContext,
  item: OwnerRecordContext,
): Promise<OwnerRecord> {
  ownerHandle(key);
  if (plaintext.length > OWNER_RECORD_MAX_BYTES - 1 - NONCE - TAG)
    throw new Error('record too large');
  const content = recordAad('mikaki-vault-record-content', context, item);
  const keyAad = recordAad('mikaki-vault-record-key', context, item);
  const working = plaintext.slice();
  const raw = random(KEY),
    nonce = random(NONCE),
    wrapNonce = random(NONCE);
  try {
    const dataKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: content },
        dataKey,
        working,
      ),
    );
    const wrapped = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: wrapNonce, additionalData: keyAad },
        key,
        raw,
      ),
    );
    return Object.freeze({
      format_version: 2,
      ciphertext: encodeBase64Url(concat(new Uint8Array([2]), nonce, ciphertext)),
      key_envelope: encodeBase64Url(concat(new Uint8Array([2]), wrapNonce, wrapped)),
    });
  } finally {
    raw.fill(0);
    working.fill(0);
  }
}
export async function openOwnerRecord(
  value: unknown,
  key: CryptoKey,
  context: OwnerKeyContext,
  item: OwnerRecordContext,
): Promise<Bytes> {
  ownerHandle(key);
  context = ownerKeyContext(context);
  item = recordContext(item);
  exact(value, ['format_version', 'ciphertext', 'key_envelope']);
  if (value['format_version'] !== 2) throw new Error('unsupported record format');
  if (typeof value['ciphertext'] !== 'string' || typeof value['key_envelope'] !== 'string')
    throw new Error('invalid record');
  const body = decode(value['ciphertext'], 1 + NONCE + TAG, OWNER_RECORD_MAX_BYTES);
  const envelope = decode(value['key_envelope'], 1 + NONCE + KEY + TAG);
  if (body[0] !== 2 || envelope[0] !== 2) throw new Error('invalid record version');
  const raw = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: envelope.slice(1, 1 + NONCE),
        additionalData: recordAad('mikaki-vault-record-key', context, item),
      },
      key,
      envelope.slice(1 + NONCE),
    ),
  );
  try {
    if (raw.length !== KEY) throw new Error('invalid content key');
    const dataKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: body.slice(1, 1 + NONCE),
          additionalData: recordAad('mikaki-vault-record-content', context, item),
        },
        dataKey,
        body.slice(1 + NONCE),
      ),
    );
  } finally {
    raw.fill(0);
  }
}

// Parent-key rotation: verify the original body, then wrap its same content key
// under the next parent generation. A content-key/suite change needs resealing.
export async function rewrapOwnerRecord(
  value: OwnerRecord,
  sourceKey: CryptoKey,
  sourceContext: OwnerKeyContext,
  targetKey: CryptoKey,
  targetContext: OwnerKeyContext,
  item: OwnerRecordContext,
): Promise<OwnerRecord> {
  sourceContext = ownerKeyContext(sourceContext);
  targetContext = ownerKeyContext(targetContext);
  item = recordContext(item);
  if (
    sourceContext.origin !== targetContext.origin ||
    sourceContext.ownerId !== targetContext.ownerId ||
    sourceContext.vaultId !== targetContext.vaultId ||
    targetContext.keyGeneration !== sourceContext.keyGeneration + 1
  )
    throw new Error('invalid rotation context');
  ownerHandle(targetKey);
  const snapshot = Object.freeze({ ...value });
  const plaintext = await openOwnerRecord(snapshot, sourceKey, sourceContext, item);
  plaintext.fill(0);
  const envelope = decode(snapshot.key_envelope, 1 + NONCE + KEY + TAG);
  const raw = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: envelope.slice(1, 1 + NONCE),
        additionalData: recordAad('mikaki-vault-record-key', sourceContext, item),
      },
      sourceKey,
      envelope.slice(1 + NONCE),
    ),
  );
  try {
    if (raw.length !== KEY) throw new Error('invalid content key');
    const nonce = random(NONCE);
    const wrapped = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          additionalData: recordAad('mikaki-vault-record-key', targetContext, item),
        },
        targetKey,
        raw,
      ),
    );
    return Object.freeze({
      format_version: 2,
      ciphertext: snapshot.ciphertext,
      key_envelope: encodeBase64Url(concat(new Uint8Array([2]), nonce, wrapped)),
    });
  } finally {
    raw.fill(0);
  }
}

// This specific capability returns encrypted per-record material only. It never
// exposes a root, raw content key, or caller-controlled callback/transferable lease.
export async function sealOwnerRecordUserInfoRecipient(
  value: OwnerRecord,
  key: CryptoKey,
  context: OwnerKeyContext,
  selected: VaultRecordSource,
  selectedAuthority: VaultRecordAuthority,
  entry: RecordUserInfoRecipient,
): Promise<Bytes> {
  context = ownerKeyContext(context);
  const source = parseVaultRecordSource(selected);
  const authority = parseVaultRecordAuthority(selectedAuthority);
  const recipient = Object.freeze({ ...entry });
  const record = Object.freeze({ ...value });
  if (
    source.record_id !== 'name' ||
    source.kind !== 'name' ||
    source.owner_id !== context.ownerId ||
    source.origin !== context.origin ||
    source.vault_id !== context.vaultId ||
    authority.key_generation !== context.keyGeneration
  )
    throw new Error('Wrong UserInfo record binding');
  const item = {
    collectionId: source.collection_id,
    recordId: source.record_id,
    kind: source.kind,
    revision: source.revision,
  };
  let plaintext: Bytes | undefined;
  let raw: Bytes | undefined;
  try {
    if ((await vaultCiphertextDigest(record.ciphertext)) !== source.ciphertext_sha256)
      throw new Error('Selected ciphertext digest mismatch');
    // Authenticate the body and strict text before doing any recipient sealing.
    plaintext = await openOwnerRecord(record, key, context, item);
    const name = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext);
    if (!name.length || name.length > 256 || plaintext.length > 1024)
      throw new Error('Invalid saved name');
    const envelope = decode(record.key_envelope, 1 + NONCE + KEY + TAG);
    raw = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: envelope.slice(1, 1 + NONCE),
          additionalData: recordAad('mikaki-vault-record-key', context, item),
        },
        key,
        envelope.slice(1 + NONCE),
      ),
    );
    return await sealRecordUserInfoDataKey(raw, recipient, {
      source,
      authority,
      ciphertext: record.ciphertext,
    });
  } finally {
    plaintext?.fill(0);
    raw?.fill(0);
  }
}

export type PreparedApprovedOwnerRecord = Readonly<{
  proposal_id: string;
  request_hash: string;
  operation_id: string;
  candidate: string;
  candidate_sha256: string;
  proof: RecordAgentEnvelope;
}>;
// Operation-only proof of a freshly sealed note. No callback or raw content-key
// accessor is available to the owner UI, and existing source keys are never sent.
export async function sealApprovedOwnerRecord(
  value: ApprovedRecordNote,
  operationId: string,
  recipientValue: AgentRecipient,
  key: CryptoKey,
  ownerContext: OwnerKeyContext,
): Promise<PreparedApprovedOwnerRecord> {
  const proposal = parseApprovedRecordNote(value),
    context = ownerKeyContext(ownerContext);
  const recipient = Object.freeze({
    ...recipientValue,
    public_jwk: { ...recipientValue.public_jwk },
  });
  const target = proposal.target;
  if (
    !/^[A-Za-z0-9_-]{43}$/.test(operationId) ||
    target.origin !== context.origin ||
    target.owner_id !== context.ownerId ||
    target.vault_id !== context.vaultId ||
    proposal.authority.key_generation !== context.keyGeneration ||
    recipient.enabled === false
  )
    throw new Error('Wrong approved note binding');
  const item = {
    collectionId: target.collection_id,
    recordId: target.record_id,
    kind: target.kind,
    revision: target.revision + 1,
  };
  const bytes = new TextEncoder().encode(proposal.payload);
  let restored: Bytes | undefined, raw: Bytes | undefined;
  try {
    const sealed = await sealOwnerRecord(bytes, key, context, item);
    restored = await openOwnerRecord(sealed, key, context, item);
    if (restored.length !== bytes.length || restored.some((byte, index) => byte !== bytes[index]))
      throw new Error('Candidate verification failed');
    const candidate = JSON.stringify({
      format_version: 2,
      vault_id: context.vaultId,
      key_generation: context.keyGeneration,
      owner_key_revision: proposal.authority.owner_key_revision,
      kind: target.kind,
      revision: item.revision,
      ciphertext: sealed.ciphertext,
      key_envelope: sealed.key_envelope,
    });
    const candidateHash = encodeBase64Url(
      new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(candidate))),
    );
    const candidateSource = parseVaultRecordSource({
      storage_version: 2,
      origin: context.origin,
      owner_id: context.ownerId,
      vault_id: context.vaultId,
      collection_id: item.collectionId,
      record_id: item.recordId,
      kind: item.kind,
      revision: item.revision,
      ciphertext_sha256: await vaultCiphertextDigest(sealed.ciphertext),
    });
    const envelope = decode(sealed.key_envelope, 1 + NONCE + KEY + TAG);
    raw = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: envelope.slice(1, 1 + NONCE),
          additionalData: recordAad('mikaki-vault-record-key', context, item),
        },
        key,
        envelope.slice(1 + NONCE),
      ),
    );
    const proof = await sealApprovedRecordProof(raw, recipient, {
      owner: context.ownerId,
      grant_id: proposal.grant_id,
      key_id: recipient.key_id,
      resource: recipient.resource,
      expires_at: proposal.expires_at,
      proposal_id: proposal.proposal_id,
      request_hash: proposal.request_hash,
      operation_id: operationId,
      candidate_sha256: candidateHash,
      target,
      authority: proposal.authority,
      candidate_source: candidateSource,
    });
    return Object.freeze({
      proposal_id: proposal.proposal_id,
      request_hash: proposal.request_hash,
      operation_id: operationId,
      candidate,
      candidate_sha256: candidateHash,
      proof,
    });
  } finally {
    bytes.fill(0);
    restored?.fill(0);
    raw?.fill(0);
  }
}
