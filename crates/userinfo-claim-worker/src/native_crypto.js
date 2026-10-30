// @ts-check
// Workers Web Crypto boundary. Requires webcrypto_modern_algorithms.
// Snapshot Wasm views before yielding: another request may grow Wasm memory.
/** @param {Uint8Array} input */
export async function nativeSha256(input) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input.slice()));
}

/** @param {Uint8Array} seed */
export async function nativePublicKey(seed) {
  const snapshot = seed.slice();
  try {
    const privateKey = await crypto.subtle.importKey('raw-seed', snapshot, 'ML-KEM-768', false, [
      'decapsulateBits',
    ]);
    const publicKey = await crypto.subtle.getPublicKey(privateKey, ['encapsulateBits']);
    const raw = await crypto.subtle.exportKey('raw-public', publicKey);
    if (!(raw instanceof ArrayBuffer)) throw new Error('invalid native public key format');
    return new Uint8Array(raw);
  } finally {
    snapshot.fill(0);
  }
}

/** @param {...Uint8Array} parts */
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** @param {Uint8Array} key @param {Uint8Array} input */
async function hmac(key, input) {
  const imported = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', imported, input));
}

// Preserve the existing base-mode ML-KEM-768/HKDF-SHA256/AES-256-GCM
// draft-04 suite (0x0041, 0x0001, 0x0002). Native ML-KEM is the KEM;
// its output still passes through the HPKE labeled key schedule.
/** @param {Uint8Array} seed @param {Uint8Array} encapsulated
 * @param {Uint8Array} info @param {Uint8Array} aad @param {Uint8Array} ciphertext */
export async function nativeOpenHpke(seed, encapsulated, info, aad, ciphertext) {
  const seedBytes = seed.slice();
  const encBytes = encapsulated.slice();
  const infoBytes = info.slice();
  const aadBytes = aad.slice();
  const cipherBytes = ciphertext.slice();
  let shared, keyBytes, nonce;
  /** @type {Uint8Array | undefined} */
  let secret;
  try {
    const privateKey = await crypto.subtle.importKey('raw-seed', seedBytes, 'ML-KEM-768', false, [
      'decapsulateBits',
    ]);
    shared = new Uint8Array(
      await crypto.subtle.decapsulateBits('ML-KEM-768', privateKey, encBytes),
    );
    /** @param {string} value */
    const text = (value) => new TextEncoder().encode(value);
    const prefix = concat(text('HPKE-v1'), text('HPKE'), new Uint8Array([0, 0x41, 0, 1, 0, 2]));
    /** @param {string} name @param {Uint8Array} value */
    const label = (name, value) => concat(prefix, text(name), value);
    const empty = new Uint8Array(0);
    const pskHash = await hmac(new Uint8Array(32), label('psk_id_hash', empty));
    const infoHash = await hmac(new Uint8Array(32), label('info_hash', infoBytes));
    const scheduleContext = concat(new Uint8Array([0]), pskHash, infoHash);
    const prk = await hmac(shared, label('secret', empty));
    secret = prk;
    // Both outputs fit one HKDF-Expand block. Clear the full block, including
    // unused nonce bytes, after taking the required prefix.
    /** @param {string} name @param {number} length */
    const expand = async (name, length) => {
      const size = new Uint8Array([0, length]);
      const block = await hmac(
        prk,
        concat(size, label(name, scheduleContext), new Uint8Array([1])),
      );
      try {
        return block.slice(0, length);
      } finally {
        block.fill(0);
      }
    };
    keyBytes = await expand('key', 32);
    nonce = await expand('base_nonce', 12);
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aadBytes },
        key,
        cipherBytes,
      ),
    );
  } finally {
    seedBytes.fill(0);
    shared?.fill(0);
    secret?.fill(0);
    keyBytes?.fill(0);
    nonce?.fill(0);
  }
}

/** @param {Uint8Array} key @param {Uint8Array} nonce
 * @param {Uint8Array} aad @param {Uint8Array} ciphertext */
export async function nativeDecryptAes(key, nonce, aad, ciphertext) {
  const keyBytes = key.slice();
  const nonceBytes = nonce.slice();
  const aadBytes = aad.slice();
  const cipherBytes = ciphertext.slice();
  try {
    const imported = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonceBytes, additionalData: aadBytes },
        imported,
        cipherBytes,
      ),
    );
  } finally {
    keyBytes.fill(0);
  }
}
