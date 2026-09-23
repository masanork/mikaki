const encoder = new TextEncoder();

function base64url(value) {
  const bytes = typeof value === 'string' ? encoder.encode(value) : new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export default {
  async fetch() {
    const { publicKey, privateKey } = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const header = base64url(JSON.stringify({ alg: 'ES256', kid: 'workerd-probe', typ: 'JWT' }));
    const payload = base64url(JSON.stringify({ sub: 'workerd-async-signer' }));
    const input = encoder.encode(`${header}.${payload}`);
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      input,
    );
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);
    return Response.json({ token: `${header}.${payload}.${base64url(signature)}`, jwk });
  },
};
