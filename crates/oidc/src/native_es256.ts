/** Only the ES256 primitive; strict protocol parsing and authority stay in Rust. */
export async function nativeVerifyEs256(
  publicKeyView: Uint8Array,
  signatureView: Uint8Array,
  messageView: Uint8Array,
): Promise<boolean> {
  // Own all inputs before the first await. Wasm memory may grow or another
  // request may reuse a caller's buffers while importKey is suspended.
  const publicKey = new Uint8Array(publicKeyView);
  const signature = new Uint8Array(signatureView);
  const message = new Uint8Array(messageView);
  if (
    !(
      (publicKey.length === 33 && (publicKey[0] === 2 || publicKey[0] === 3)) ||
      (publicKey.length === 65 && publicKey[0] === 4)
    ) ||
    signature.length !== 64
  ) {
    throw new Error('invalid ES256 encoding');
  }
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
  return (
    (await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, message)) ===
    true
  );
}
