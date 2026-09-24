// Key-directory validation for the future owner-approved UserInfo envelope flow.
// Call only before producing a recipient envelope; owner-only Vault use is independent.
export type UserInfoRecipient = {
  service_id: 'userinfo';
  algorithm: 'ML-KEM-768';
  envelope_suite: 'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1';
  key_id: string;
  public_key: string;
  generation: number;
  revision: number;
};

type Checkpoint = { generation: number; key_id: string; revision: number };

export const RECIPIENT_CHECKPOINT = 'mikaki:userinfo-recipient:v1';

function canonicalBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid recipient key encoding');
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/'));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (base64Url(bytes) !== value) throw new Error('noncanonical recipient key encoding');
  return bytes;
}

function base64Url(bytes: Uint8Array<ArrayBuffer>): string {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 8192) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 8192));
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function checkpoint(value: string | null): Checkpoint | null {
  if (value === null) return null;
  const parsed: unknown = JSON.parse(value);
  if (typeof parsed !== 'object' || parsed === null)
    throw new Error('invalid recipient checkpoint');
  const item = parsed as Partial<Checkpoint>;
  if (
    !Number.isSafeInteger(item.generation) ||
    typeof item.generation !== 'number' ||
    item.generation < 1 ||
    typeof item.key_id !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/.test(item.key_id) ||
    !Number.isSafeInteger(item.revision) ||
    typeof item.revision !== 'number' ||
    item.revision < 1
  ) {
    throw new Error('invalid recipient checkpoint');
  }
  return { generation: item.generation, key_id: item.key_id, revision: item.revision };
}

export async function validateUserInfoRecipient(value: unknown): Promise<UserInfoRecipient> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('invalid recipient directory');
  }
  const item = value as Partial<UserInfoRecipient>;
  if (
    item.service_id !== 'userinfo' ||
    item.algorithm !== 'ML-KEM-768' ||
    item.envelope_suite !== 'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1' ||
    typeof item.key_id !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/.test(item.key_id) ||
    typeof item.public_key !== 'string' ||
    !Number.isSafeInteger(item.generation) ||
    typeof item.generation !== 'number' ||
    item.generation < 1 ||
    !Number.isSafeInteger(item.revision) ||
    typeof item.revision !== 'number' ||
    item.revision < 1
  ) {
    throw new Error('invalid recipient directory');
  }
  const publicKey = canonicalBase64Url(item.public_key);
  if (publicKey.length !== 1184) throw new Error('invalid recipient key length');
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey));
  if (base64Url(digest) !== item.key_id) throw new Error('recipient key ID mismatch');
  return item as UserInfoRecipient;
}

export async function fetchVerifiedUserInfoRecipient(
  fetcher: typeof fetch,
  storage: Pick<Storage, 'getItem' | 'setItem'>,
): Promise<UserInfoRecipient> {
  const response = await fetcher('/vault/recipient-keys/userinfo', {
    cache: 'no-store',
    credentials: 'same-origin',
  });
  if (!response.ok) throw new Error('UserInfo recipient unavailable');
  const recipient = await validateUserInfoRecipient(await response.json());
  const prior = checkpoint(storage.getItem(RECIPIENT_CHECKPOINT));
  if (
    prior &&
    (recipient.generation < prior.generation ||
      (recipient.generation === prior.generation &&
        (recipient.key_id !== prior.key_id || recipient.revision < prior.revision)))
  ) {
    throw new Error('UserInfo recipient continuity failure');
  }
  storage.setItem(
    RECIPIENT_CHECKPOINT,
    JSON.stringify({
      generation: recipient.generation,
      key_id: recipient.key_id,
      revision: recipient.revision,
    }),
  );
  return recipient;
}
