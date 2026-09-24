import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { decodeBase64Url } from './vault-crypto.js';
import { validateUserInfoRecipient, type UserInfoRecipient } from './recipient-directory.js';

// Candidate HPKE suite: ML-KEM-768, HKDF-SHA256, AES-256-GCM (PQ HPKE draft-04).
// This module only creates an additional recipient wrap; the owner envelope stays intact.
const VERSION = new Uint8Array([1]);
const SUITE = new Uint8Array([0, 0x41, 0, 1, 0, 2]);
const MAGIC = new TextEncoder().encode('MKVE');
const DOMAIN = new TextEncoder().encode('mikaki-vault-recipient-envelope-v1-draft04');
const SERVICE = new TextEncoder().encode('userinfo');
const PURPOSE = new TextEncoder().encode('oidc.userinfo.name');
const FRAME_BYTES = 1187;

export type UserInfoWrapContext = {
  origin: string;
  accountId: string;
  revision: number;
  ciphertext: Uint8Array;
};

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

async function sha256(value: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(value)));
}

async function hmac(key: Uint8Array, value: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const imported = await crypto.subtle.importKey(
    'raw',
    bytes(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
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
  for (let counter = 1; blocks.length * 32 < size; counter++) {
    if (counter > 255) throw new Error('HPKE output too long');
    previous = await hmac(prk, concat(previous, info, new Uint8Array([counter])));
    blocks.push(previous);
  }
  return concat(...blocks).slice(0, size);
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
  try {
    return {
      key: await labeledExpand(secret, 'key', scheduleContext, 32),
      nonce: await labeledExpand(secret, 'base_nonce', scheduleContext, 12),
    };
  } finally {
    secret.fill(0);
  }
}

export async function sealUserInfoDataKey(
  dataKey: Uint8Array,
  directoryEntry: UserInfoRecipient,
  binding: UserInfoWrapContext,
): Promise<Uint8Array<ArrayBuffer>> {
  if (dataKey.length !== 32 || binding.ciphertext.length === 0) {
    throw new Error('invalid Vault data key or ciphertext');
  }
  const url = new URL(binding.origin);
  if (url.origin !== binding.origin || url.protocol !== 'https:' || !binding.accountId) {
    throw new Error('invalid Vault binding');
  }
  const recipient = await validateUserInfoRecipient(directoryEntry);
  const publicKey = decodeBase64Url(recipient.public_key);
  const keyId = decodeBase64Url(recipient.key_id);
  const generation = u64(recipient.generation);
  const revision = u64(binding.revision);
  const info = context(DOMAIN, VERSION, SUITE, SERVICE, keyId, generation);
  const aad = context(
    new TextEncoder().encode(binding.origin),
    new TextEncoder().encode(binding.accountId),
    new TextEncoder().encode('name'),
    revision,
    SERVICE,
    PURPOSE,
    await sha256(binding.ciphertext),
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
        bytes(dataKey),
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
