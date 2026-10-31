/** Only ES256 primitives; strict protocol parsing and authority stay in Rust. */
function publicKeySnapshot(publicKeyView: Uint8Array) {
  const publicKey = new Uint8Array(publicKeyView);
  if (!(
    (publicKey.length === 33 && (publicKey[0] === 2 || publicKey[0] === 3)) ||
    (publicKey.length === 65 && publicKey[0] === 4)
  )) {
    throw new Error('invalid ES256 encoding');
  }
  return publicKey;
}

async function importPublicKey(publicKey: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const key = await crypto.subtle.importKey(
    'raw',
    publicKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
  if (
    key.extractable ||
    key.type !== 'public' ||
    key.usages.length !== 1 ||
    key.usages[0] !== 'verify'
  ) {
    throw new Error('invalid ES256 verification key');
  }
  return key;
}

/** Curve membership is checked by native raw-key import, without exporting the key. */
export async function nativeValidateEs256PublicKey(publicKeyView: Uint8Array): Promise<boolean> {
  await importPublicKey(publicKeySnapshot(publicKeyView));
  return true;
}

export async function nativeVerifyEs256(
  publicKeyView: Uint8Array,
  signatureView: Uint8Array,
  messageView: Uint8Array,
): Promise<boolean> {
  // Own all inputs before the first await. Wasm memory may grow or another
  // request may reuse a caller's buffers while importKey is suspended.
  const publicKey = publicKeySnapshot(publicKeyView);
  const signature = new Uint8Array(signatureView);
  const message = new Uint8Array(messageView);
  if (signature.length !== 64) throw new Error('invalid ES256 encoding');
  const key = await importPublicKey(publicKey);
  return (
    (await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, message)) ===
    true
  );
}
