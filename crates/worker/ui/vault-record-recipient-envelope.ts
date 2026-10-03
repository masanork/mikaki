import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { decodeBase64Url } from './vault-crypto.ts';
import {
  parseVaultRecordSource,
  parseVaultRecordAuthority,
  vaultCiphertextDigest,
  type VaultRecordSource,
  type VaultRecordAuthority,
} from './vault-record-source.ts';
import {
  validateRecordUserInfoRecipient,
  type RecordUserInfoRecipient,
} from './recipient-directory-v2.ts';

// Candidate HPKE suite: ML-KEM-768, HKDF-SHA256, AES-256-GCM (PQ HPKE draft-04).
// This module only creates an additional recipient wrap; the owner envelope stays intact.
const VERSION = new Uint8Array([2]);
const SUITE = new Uint8Array([0, 0x41, 0, 1, 0, 2]);
const MAGIC = new TextEncoder().encode('MKVR');
const DOMAIN = new TextEncoder().encode('mikaki-vault-record-recipient-envelope-v2-draft04');
const SERVICE = new TextEncoder().encode('userinfo');
const PURPOSE = new TextEncoder().encode('oidc.userinfo.name');
const FRAME_BYTES = 1187;

export type RecordUserInfoWrapContext = Readonly<{
  source: VaultRecordSource;
  authority: VaultRecordAuthority;
  ciphertext: string;
}>;

function bytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(value);
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function u64(value: number): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('invalid envelope counter');
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, BigInt(value));
  return output;
}

function context(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  return concat(
    ...parts.flatMap((part) => {
      if (part.length > 65535) throw new Error('envelope context too long');
      const length = new Uint8Array(2);
      new DataView(length.buffer).setUint16(0, part.length);
      return [length, part];
    }),
  );
}

async function hmac(key: Uint8Array, value: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const importBytes = bytes(key);
  let imported: CryptoKey;
  try {
    imported = await crypto.subtle.importKey(
      'raw',
      importBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
  } finally {
    // WebCrypto copies the key on import; clear our temporary on either outcome.
    importBytes.fill(0);
  }
  return new Uint8Array(await crypto.subtle.sign('HMAC', imported, bytes(value)));
}

async function extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return hmac(salt.length === 0 ? new Uint8Array(32) : salt, ikm);
}

async function expand(
  prk: Uint8Array,
  info: Uint8Array,
  size: number,
): Promise<Uint8Array<ArrayBuffer>> {
  let previous: Uint8Array<ArrayBuffer> = new Uint8Array(0);
  const blocks: Uint8Array<ArrayBuffer>[] = [];
  let combined: Uint8Array<ArrayBuffer> | undefined;
  try {
    for (let counter = 1; blocks.length * 32 < size; counter++) {
      if (counter > 255) throw new Error('HPKE output too long');
      previous = await hmac(prk, concat(previous, info, new Uint8Array([counter])));
      blocks.push(previous);
    }
    combined = concat(...blocks);
    return combined.slice(0, size);
  } finally {
    combined?.fill(0);
    for (const block of blocks) block.fill(0);
  }
}

async function schedule(
  sharedSecret: Uint8Array,
  info: Uint8Array,
): Promise<{ key: Uint8Array<ArrayBuffer>; nonce: Uint8Array<ArrayBuffer> }> {
  const suiteId = concat(new TextEncoder().encode('HPKE'), SUITE);
  const hpkeVersion = new TextEncoder().encode('HPKE-v1');
  const empty = new Uint8Array(0);
  const labeledExtract = (salt: Uint8Array, label: string, ikm: Uint8Array) =>
    extract(salt, concat(hpkeVersion, suiteId, new TextEncoder().encode(label), ikm));
  const labeledExpand = (prk: Uint8Array, label: string, value: Uint8Array, size: number) => {
    const length = new Uint8Array(2);
    new DataView(length.buffer).setUint16(0, size);
    return expand(
      prk,
      concat(length, hpkeVersion, suiteId, new TextEncoder().encode(label), value),
      size,
    );
  };
  const scheduleContext = concat(
    new Uint8Array([0]),
    await labeledExtract(empty, 'psk_id_hash', empty),
    await labeledExtract(empty, 'info_hash', info),
  );
  const secret = await labeledExtract(sharedSecret, 'secret', empty);
  let key: Uint8Array<ArrayBuffer> | undefined;
  let nonce: Uint8Array<ArrayBuffer> | undefined;
  try {
    key = await labeledExpand(secret, 'key', scheduleContext, 32);
    nonce = await labeledExpand(secret, 'base_nonce', scheduleContext, 12);
    return { key, nonce };
  } catch (error) {
    key?.fill(0);
    nonce?.fill(0);
    throw error;
  } finally {
    secret.fill(0);
  }
}

export async function sealRecordUserInfoDataKey(
  dataKey: Uint8Array,
  directoryEntry: RecordUserInfoRecipient,
  binding: RecordUserInfoWrapContext,
): Promise<Uint8Array<ArrayBuffer>> {
  // Snapshot the caller-owned key as well as every binding before yielding.
  const keyBytes = bytes(dataKey);
  try {
    return await sealRecordDataKeySnapshot(keyBytes, directoryEntry, binding);
  } finally {
    keyBytes.fill(0);
  }
}

async function sealRecordDataKeySnapshot(
  dataKey: Uint8Array<ArrayBuffer>,
  directoryEntry: RecordUserInfoRecipient,
  binding: RecordUserInfoWrapContext,
): Promise<Uint8Array<ArrayBuffer>> {
  // Snapshot every binding before the first asynchronous boundary.
  const source = parseVaultRecordSource(binding.source);
  const authority = parseVaultRecordAuthority(binding.authority);
  const ciphertext = binding.ciphertext;
  const entry = { ...directoryEntry };
  if (dataKey.length !== 32 || source.record_id !== 'name' || source.kind !== 'name')
    throw new Error('UserInfo requires the exact saved name record');
  if (decodeBase64Url(ciphertext)[0] !== 2)
    throw new Error('UserInfo requires record-v2 ciphertext');
  if ((await vaultCiphertextDigest(ciphertext)) !== source.ciphertext_sha256)
    throw new Error('Selected ciphertext digest mismatch');
  const recipient = await validateRecordUserInfoRecipient(entry);
  const publicKey = decodeBase64Url(recipient.public_key);
  const keyId = decodeBase64Url(recipient.key_id);
  const generation = u64(recipient.generation);
  const info = context(DOMAIN, VERSION, SUITE, SERVICE, keyId, generation);
  const text = (value: string) => new TextEncoder().encode(value);
  const aad = context(
    text('2'),
    text(source.origin),
    text(source.owner_id),
    text(source.vault_id),
    text(source.collection_id),
    text(source.record_id),
    text(source.kind),
    u64(source.revision),
    decodeBase64Url(source.ciphertext_sha256),
    u64(authority.key_generation),
    u64(authority.owner_key_revision),
    SERVICE,
    PURPOSE,
  );
  const encapsulated = ml_kem768.encapsulate(publicKey);
  const sharedSecret = encapsulated.sharedSecret;
  let key: Uint8Array<ArrayBuffer>;
  let nonce: Uint8Array<ArrayBuffer>;
  try {
    ({ key, nonce } = await schedule(sharedSecret, info));
  } finally {
    sharedSecret.fill(0);
  }
  try {
    const aeadKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad },
        aeadKey,
        dataKey,
      ),
    );
    const frame = concat(
      MAGIC,
      VERSION,
      SUITE,
      keyId,
      generation,
      encapsulated.cipherText,
      ciphertext,
    );
    if (frame.length !== FRAME_BYTES) throw new Error('invalid recipient envelope length');
    return frame;
  } finally {
    key.fill(0);
    nonce.fill(0);
  }
}
