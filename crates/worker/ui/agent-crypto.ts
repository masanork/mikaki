// Selected plaintext is encrypted to a separate, explicitly approved service recipient.
import { encodeBase64Url, decodeBase64Url } from './vault-crypto.ts';

export type AgentDocument = { id: string; title: string; source: string; text: string };
export type AgentRecipient = {
  key_id: string;
  public_jwk: JsonWebKey;
  resource: string;
  enabled?: boolean;
};

export async function agentKeyId(jwk: JsonWebKey): Promise<string> {
  if (
    jwk.kty !== 'RSA' ||
    !jwk.n ||
    jwk.e !== 'AQAB' ||
    jwk.d ||
    jwk.p ||
    jwk.q ||
    decodeBase64Url(jwk.n).length < 256 ||
    decodeBase64Url(jwk.n).length > 512
  )
    throw new Error('Invalid agent recipient');
  const canonical = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
  return encodeBase64Url(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))),
  );
}
