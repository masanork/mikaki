import { z } from 'zod';
import { agentKeyId } from '../worker/ui/agent-crypto.js';
import { encodeBase64Url } from '../worker/ui/vault-crypto.js';

export const opaque = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const operation = z.enum(['list', 'search', 'read', 'propose', 'execute']);
export type Operation = z.infer<typeof operation>;
export const envelopeSchema = z.strictObject({
  version: z.literal(1),
  wrapped_key: z.string().regex(/^[A-Za-z0-9_-]{342,683}$/),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{16}$/),
  ciphertext: z.string().regex(/^[A-Za-z0-9_-]{22,32800}$/),
});
export const grantInput = z.strictObject({
  grant_id: opaque,
  delegate: z.string().regex(/^[A-Za-z0-9_-]{1,80}$/),
  provider: z.string().trim().min(1).max(160),
  resource: z.string().url().max(256),
  source_revision: z.number().int().positive(),
  recipient_key_id: opaque,
  operations: z
    .array(operation)
    .min(1)
    .max(5)
    .refine((items) => new Set(items).size === items.length),
  document_ids: z.tuple([z.literal('name')]),
  envelope: envelopeSchema,
  token_hash: opaque,
  expires_at: z.number().int().positive(),
});
export const documentsSchema = z
  .array(
    z.strictObject({
      id: z.literal('name'),
      title: z.string().min(1).max(160),
      source: z.string().min(1).max(160),
      text: z.string().min(1).max(256),
    }),
  )
  .length(1);
export type Grant = {
  grant_id: string;
  account_id: string;
  owner_epoch: number;
  credential_id: string;
  delegate: string;
  provider: string;
  resource: string;
  source_revision: number;
  recipient_key_id: string;
  operations: string;
  document_ids: string;
  encrypted_snapshot: string | null;
  token_hash: string;
  request_hash: string;
  created_at: number;
  expires_at: number;
  revoked: number;
  revision: number;
  access_token_hash?: string;
};
export type Owner = { account: string; secretHash: string };
export type Proposal = {
  proposal_id: string;
  grant_id: string;
  request_hash: string;
  document_id: string;
  title: string;
  text: string | null;
  expires_at: number;
  state: string;
  approved_revision: number | null;
  result_id: string | null;
  created_at: number;
};

export function randomId(): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}
export async function digest(value: string): Promise<string> {
  return encodeBase64Url(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))),
  );
}
export const now = () => Math.floor(Date.now() / 1000);

export async function recipient(env: Env) {
  const privateJwk: JsonWebKey = JSON.parse(env.AGENT_PRIVATE_JWK);
  if (!privateJwk.d) throw new Error('Recipient unavailable');
  const public_jwk: JsonWebKey = { kty: privateJwk.kty, n: privateJwk.n, e: privateJwk.e };
  const key_id = await agentKeyId(public_jwk);
  const registered = await env.DB.withSession('first-primary')
    .prepare('SELECT state FROM agent_recipient_key WHERE key_id=?')
    .bind(key_id)
    .first<{ state: string }>();
  if (!registered) throw new Error('Recipient unavailable');
  const resource = new URL(env.AGENT_RESOURCE);
  if (
    resource.protocol !== 'https:' ||
    resource.pathname !== '/mcp' ||
    resource.search ||
    resource.hash
  )
    throw new Error('Invalid resource');
  const key = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt'],
  );
  return {
    key,
    key_id,
    public_jwk,
    resource: resource.href,
    enabled: registered.state === 'active',
  };
}

export async function boundedJson(request: Request, limit = 49152): Promise<unknown> {
  if (!request.body) throw new Error('Missing body');
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel();
        throw new Error('Body too large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes));
}

export function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  });
}
