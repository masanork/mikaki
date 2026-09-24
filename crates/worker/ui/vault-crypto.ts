// Version 1 owner-only attribute format. All secrets remain in the browser.
const VERSION = 1;
const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;
const MAX_CIPHERTEXT_BYTES = 24 * 1024;

export type SealedAttribute = {
  format_version: 1;
  ciphertext: string;
  owner_envelope: string;
};

export type OwnerEnvelope = {
  credentialId: Uint8Array<ArrayBuffer>;
  prfInput: Uint8Array<ArrayBuffer>;
};

function random(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

function concat(...parts: Uint8Array<ArrayBuffer>[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function encodedContext(parts: string[]): Uint8Array<ArrayBuffer> {
  const fields = parts.map((part) => new TextEncoder().encode(part));
  if (fields.some((field) => field.length > 65535)) throw new Error('context too long');
  const result = new Uint8Array(fields.reduce((size, field) => size + 2 + field.length, 0));
  const view = new DataView(result.buffer);
  let offset = 0;
  for (const field of fields) {
    view.setUint16(offset, field.length);
    offset += 2;
    result.set(field, offset);
    offset += field.length;
  }
  return result;
}

function contentAad(origin: string, attribute: string, revision: number): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(revision) || revision < 1) throw new Error('invalid revision');
  return encodedContext([
    'mikaki-vault-attribute-content',
    '1',
    origin,
    attribute,
    String(revision),
  ]);
}

function wrapAad(
  origin: string,
  attribute: string,
  revision: number,
  credentialId: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  return concat(
    encodedContext(['mikaki-vault-attribute-owner-wrap', '1', origin, attribute, String(revision)]),
    credentialId,
  );
}

export function encodeBase64Url(bytes: Uint8Array<ArrayBuffer>): string {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 8192) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 8192));
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

export function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('invalid base64url');
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/'));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) throw new Error('noncanonical base64url');
  return bytes;
}

export function newPrfInput(): Uint8Array<ArrayBuffer> {
  return random(KEY_BYTES);
}

export function parseOwnerEnvelope(encoded: string): OwnerEnvelope {
  const bytes = decodeBase64Url(encoded);
  if (
    bytes.length < 3 + KEY_BYTES * 2 + NONCE_BYTES + KEY_BYTES + TAG_BYTES ||
    bytes[0] !== VERSION
  ) {
    throw new Error('invalid owner envelope');
  }
  const idLength = new DataView(bytes.buffer).getUint16(1);
  if (
    idLength === 0 ||
    idLength > 512 ||
    bytes.length !== 3 + idLength + KEY_BYTES * 2 + NONCE_BYTES + KEY_BYTES + TAG_BYTES
  ) {
    throw new Error('invalid owner envelope');
  }
  return {
    credentialId: bytes.slice(3, 3 + idLength),
    prfInput: bytes.slice(3 + idLength, 3 + idLength + KEY_BYTES),
  };
}

async function wrappingKey(
  prfOutput: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  origin: string,
  attribute: string,
  credentialId: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> {
  if (prfOutput.length !== KEY_BYTES) throw new Error('PRF output unavailable');
  const input = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: concat(
        encodedContext(['mikaki-vault-attribute-kek', '1', origin, attribute]),
        credentialId,
      ),
    },
    input,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function sealAttribute(
  plaintext: Uint8Array<ArrayBuffer>,
  prfOutput: Uint8Array<ArrayBuffer>,
  credentialId: Uint8Array<ArrayBuffer>,
  prfInput: Uint8Array<ArrayBuffer>,
  origin: string,
  attribute: string,
  revision: number,
): Promise<SealedAttribute> {
  if (credentialId.length < 1 || credentialId.length > 512 || prfInput.length !== KEY_BYTES) {
    throw new Error('invalid credential or PRF input');
  }
  if (plaintext.length > MAX_CIPHERTEXT_BYTES - 1 - NONCE_BYTES - TAG_BYTES) {
    throw new Error('attribute too large');
  }
  const dek = random(KEY_BYTES);
  try {
    const dataNonce = random(NONCE_BYTES);
    const salt = random(KEY_BYTES);
    const wrapNonce = random(NONCE_BYTES);
    const dataKey = await crypto.subtle.importKey('raw', dek, 'AES-GCM', false, ['encrypt']);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: dataNonce, additionalData: contentAad(origin, attribute, revision) },
        dataKey,
        plaintext,
      ),
    );
    const kek = await wrappingKey(prfOutput, salt, origin, attribute, credentialId);
    const wrappedDek = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: wrapNonce,
          additionalData: wrapAad(origin, attribute, revision, credentialId),
        },
        kek,
        dek,
      ),
    );
    const idLength = new Uint8Array(2);
    new DataView(idLength.buffer).setUint16(0, credentialId.length);
    return {
      format_version: 1,
      ciphertext: encodeBase64Url(concat(new Uint8Array([VERSION]), dataNonce, ciphertext)),
      owner_envelope: encodeBase64Url(
        concat(
          new Uint8Array([VERSION]),
          idLength,
          credentialId,
          prfInput,
          salt,
          wrapNonce,
          wrappedDek,
        ),
      ),
    };
  } finally {
    dek.fill(0);
  }
}

export async function withOpenedAttribute<T>(
  sealed: SealedAttribute,
  prfOutput: Uint8Array<ArrayBuffer>,
  expectedCredentialId: Uint8Array<ArrayBuffer>,
  origin: string,
  attribute: string,
  revision: number,
  use: (plaintext: Uint8Array<ArrayBuffer>, dataKey: Uint8Array<ArrayBuffer>) => Promise<T>,
): Promise<T> {
  if (sealed.format_version !== 1) throw new Error('unsupported format');
  const body = decodeBase64Url(sealed.ciphertext);
  if (
    body.length < 1 + NONCE_BYTES + TAG_BYTES ||
    body.length > MAX_CIPHERTEXT_BYTES ||
    body[0] !== VERSION
  ) {
    throw new Error('invalid ciphertext');
  }
  const envelope = decodeBase64Url(sealed.owner_envelope);
  const { credentialId } = parseOwnerEnvelope(sealed.owner_envelope);
  if (encodeBase64Url(credentialId) !== encodeBase64Url(expectedCredentialId)) {
    throw new Error('wrong credential');
  }
  const saltStart = 3 + credentialId.length + KEY_BYTES;
  const salt = envelope.slice(saltStart, saltStart + KEY_BYTES);
  const wrapNonce = envelope.slice(saltStart + KEY_BYTES, saltStart + KEY_BYTES + NONCE_BYTES);
  const wrappedDek = envelope.slice(saltStart + KEY_BYTES + NONCE_BYTES);
  const kek = await wrappingKey(prfOutput, salt, origin, attribute, credentialId);
  const dek = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: wrapNonce,
        additionalData: wrapAad(origin, attribute, revision, credentialId),
      },
      kek,
      wrappedDek,
    ),
  );
  try {
    if (dek.length !== KEY_BYTES) throw new Error('invalid data key');
    const dataKey = await crypto.subtle.importKey('raw', dek, 'AES-GCM', false, ['decrypt']);
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: body.slice(1, 1 + NONCE_BYTES),
          additionalData: contentAad(origin, attribute, revision),
        },
        dataKey,
        body.slice(1 + NONCE_BYTES),
      ),
    );
    return await use(plaintext, dek);
  } finally {
    dek.fill(0);
  }
}

export async function openAttribute(
  sealed: SealedAttribute,
  prfOutput: Uint8Array<ArrayBuffer>,
  expectedCredentialId: Uint8Array<ArrayBuffer>,
  origin: string,
  attribute: string,
  revision: number,
): Promise<Uint8Array<ArrayBuffer>> {
  return withOpenedAttribute(
    sealed,
    prfOutput,
    expectedCredentialId,
    origin,
    attribute,
    revision,
    async (plaintext) => plaintext,
  );
}
