// Selected plaintext is encrypted to a separate, explicitly approved service recipient.
import { encodeBase64Url, decodeBase64Url } from './vault-crypto.ts';

export type AgentBinding = {
  owner: string;
  grant_id: string;
  key_id: string;
  resource: string;
  expires_at: number;
  source_revision: number;
};
export type AgentEnvelope = { version: 1; wrapped_key: string; nonce: string; ciphertext: string };
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

function context(binding: AgentBinding, purpose: string): Uint8Array<ArrayBuffer> {
  if (
    !Number.isSafeInteger(binding.expires_at) ||
    !Number.isSafeInteger(binding.source_revision) ||
    binding.source_revision < 1
  )
    throw new Error('Invalid agent binding');
  return new Uint8Array(
    new TextEncoder().encode(
      JSON.stringify([
        purpose,
        1,
        binding.owner,
        binding.grant_id,
        binding.key_id,
        binding.resource,
        binding.expires_at,
        binding.source_revision,
      ]),
    ),
  );
}

export async function sealAgentSnapshot(
  documents: AgentDocument[],
  recipient: AgentRecipient,
  binding: AgentBinding,
): Promise<AgentEnvelope> {
  return sealAgentValue(documents, recipient, binding, 'mikaki-agent-snapshot');
}

export async function sealAgentValue(
  value: unknown,
  recipient: AgentRecipient,
  binding: AgentBinding,
  purpose: 'mikaki-agent-snapshot' | 'mikaki-approved-attribute-proof',
): Promise<AgentEnvelope> {
  if (
    (await agentKeyId(recipient.public_jwk)) !== recipient.key_id ||
    binding.key_id !== recipient.key_id ||
    binding.resource !== recipient.resource
  )
    throw new Error('Agent recipient mismatch');
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  if (plaintext.length > 24576) throw new Error('Agent snapshot too large');
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  try {
    const label = context(binding, purpose);
    const recipientKey = await crypto.subtle.importKey(
      'jwk',
      recipient.public_jwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt'],
    );
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: label },
        key,
        plaintext,
      ),
    );
    const wrapped = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'RSA-OAEP', label }, recipientKey, rawKey),
    );
    return {
      version: 1,
      wrapped_key: encodeBase64Url(wrapped),
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(ciphertext),
    };
  } finally {
    rawKey.fill(0);
    plaintext.fill(0);
  }
}

export async function openAgentSnapshot(
  envelope: AgentEnvelope,
  privateKey: CryptoKey,
  binding: AgentBinding,
): Promise<unknown> {
  return openAgentValue(envelope, privateKey, binding, 'mikaki-agent-snapshot');
}

export async function openAgentValue(
  envelope: AgentEnvelope,
  privateKey: CryptoKey,
  binding: AgentBinding,
  purpose: 'mikaki-agent-snapshot' | 'mikaki-approved-attribute-proof',
): Promise<unknown> {
  const label = context(binding, purpose);
  const rawKey = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'RSA-OAEP', label },
      privateKey,
      decodeBase64Url(envelope.wrapped_key),
    ),
  );
  try {
    if (rawKey.length !== 32) throw new Error('Invalid agent key');
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: decodeBase64Url(envelope.nonce), additionalData: label },
        key,
        decodeBase64Url(envelope.ciphertext),
      ),
    );
    try {
      if (plaintext.length > 24576) throw new Error('Agent snapshot too large');
      return JSON.parse(
        new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(plaintext),
      );
    } finally {
      plaintext.fill(0);
    }
  } finally {
    rawKey.fill(0);
  }
}
