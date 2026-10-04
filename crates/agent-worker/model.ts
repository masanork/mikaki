import type { AgentRuntime } from './database.js';
import { z } from 'zod';
import { agentKeyId } from '../worker/ui/agent-crypto.js';
import { encodeBase64Url } from '../worker/ui/vault-crypto.js';
import { decodeOwnerNote } from '../worker/ui/vault-note.js';
import {
  parseVaultRecordSource,
  parseVaultRecordAuthority,
  type VaultRecordSource,
  type VaultRecordAuthority,
} from '../worker/ui/vault-record-source.js';

export const opaque = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const operation = z.enum(['list', 'search', 'read', 'propose', 'execute']);
export type Operation = z.infer<typeof operation>;
export const envelopeSchema = z.strictObject({
  version: z.literal(1),
  wrapped_key: z.string().regex(/^[A-Za-z0-9_-]{342,683}$/),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{16}$/),
  ciphertext: z.string().regex(/^[A-Za-z0-9_-]{22,32800}$/),
});
const grantFields = {
  grant_id: opaque,
  delegate: z.string().regex(/^[A-Za-z0-9_-]{1,80}$/),
  provider: z.string().trim().min(1).max(160),
  resource: z.string().url().max(256),
  recipient_key_id: opaque,
  operations: z
    .array(operation)
    .min(1)
    .max(5)
    .refine((items) => new Set(items).size === items.length),
  token_hash: opaque,
  expires_at: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
};
function parsed<T>(parse: (value: unknown) => T) {
  return z.unknown().transform((value, context): T => {
    try {
      return parse(value);
    } catch {
      context.addIssue({ code: 'custom', message: 'Invalid record source' });
      return z.NEVER;
    }
  });
}
export const recordSourceSchema = parsed(parseVaultRecordSource);
export const recordAuthoritySchema = parsed(parseVaultRecordAuthority);
export const recordEnvelopeSchema = envelopeSchema.extend({ version: z.literal(2) });
export const grantInput = z
  .strictObject({
    ...grantFields,
    storage_version: z.literal(2),
    source: recordSourceSchema,
    authority: recordAuthoritySchema,
    document_ids: z.tuple([z.enum(['name', 'owner_note'])]),
    envelope: recordEnvelopeSchema,
  })
  .refine((input) => input.document_ids[0] === input.source.record_id);
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
  storage_version: 1 | 2;
  source_origin: string | null;
  source_vault_id: string | null;
  source_collection_id: string | null;
  source_record_id: string | null;
  source_kind: string | null;
  source_ciphertext_sha256: string | null;
  source_key_generation: number | null;
  source_owner_key_revision: number | null;
  access_token_hash?: string;
};
// Metadata comes exclusively from the authenticated grant columns, never a label.
export function grantRecordSource(grant: Grant): VaultRecordSource {
  if (grant.storage_version !== 2) throw new Error('Record grant required');
  return parseVaultRecordSource({
    storage_version: 2,
    origin: grant.source_origin,
    owner_id: grant.account_id,
    vault_id: grant.source_vault_id,
    collection_id: grant.source_collection_id,
    record_id: grant.source_record_id,
    kind: grant.source_kind,
    revision: grant.source_revision,
    ciphertext_sha256: grant.source_ciphertext_sha256,
  });
}
export function grantRecordAuthority(grant: Grant): VaultRecordAuthority {
  return parseVaultRecordAuthority({
    key_generation: grant.source_key_generation,
    owner_key_revision: grant.source_owner_key_revision,
  });
}
export function recordDocuments(value: unknown, source: VaultRecordSource) {
  const documents = z
    .array(
      z.strictObject({
        id: z.enum(['name', 'owner_note']),
        title: z.string().min(1).max(160),
        source: z.string().min(1).max(160),
        text: z.string().min(1).max(16384),
      }),
    )
    .length(1)
    .parse(value);
  const document = documents[0];
  if (document.id !== source.record_id) throw new Error('Selected record mismatch');
  const bytes = new Uint8Array(new TextEncoder().encode(document.text));
  try {
    // Preserve every valid code point including a name's leading BOM; reject
    // lone UTF-16 surrogates rather than silently replacing them during UTF-8 encoding.
    if (new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) !== document.text)
      throw new Error('Invalid record Unicode');
    if (source.kind === 'name') {
      if (document.text.length > 256) throw new Error('Name too large');
    } else decodeOwnerNote(bytes);
    return documents;
  } finally {
    bytes.fill(0);
  }
}
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

export async function recipient(env: AgentRuntime) {
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
