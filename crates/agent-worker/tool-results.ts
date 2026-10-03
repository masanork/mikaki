import { z } from 'zod';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

const revision = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
const timestamp = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const opaque = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const vaultSourceInfo = z.strictObject({
  kind: z.literal('vault'),
  attribute: z.enum(['name', 'owner_note']),
  revision,
  provenance: z.literal('self-asserted'),
  confirmed_at: timestamp
    .nullable()
    .describe(
      'Unix seconds of the reported source-version check, not a content update or issuer verification.',
    ),
});
export type VaultSourceInfo = z.infer<typeof vaultSourceInfo>;
export const recordSource = z
  .strictObject({
    storage_version: z.literal(2),
    origin: z
      .string()
      .url()
      .refine((value) => {
        const url = new URL(value);
        return url.protocol === 'https:' && url.origin === value;
      }),
    owner_id: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
    vault_id: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
    collection_id: z.literal('personal'),
    record_id: z.enum(['name', 'owner_note']),
    kind: z.enum(['name', 'owner_note']),
    revision,
    ciphertext_sha256: z.string().regex(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/),
  })
  .refine((value) => value.record_id === value.kind);
export const recordAuthority = z.strictObject({
  key_generation: revision,
  owner_key_revision: revision,
});
export const recordSelection = z.strictObject({ source: recordSource, authority: recordAuthority });
export const vaultRecordSourceInfo = z.strictObject({
  kind: z.literal('vault-record'),
  source: recordSource,
  authority: recordAuthority,
  provenance: z.literal('self-asserted'),
  confirmed_at: timestamp
    .nullable()
    .describe(
      'Unix seconds of the last reported source check; not a live subscription or issuer proof.',
    ),
});
export type VaultRecordSourceInfo = z.infer<typeof vaultRecordSourceInfo>;
const unspecifiedSource = z.strictObject({
  kind: z.literal('unspecified'),
  attribute: z.null(),
  revision: z.null(),
  provenance: z.literal('unspecified'),
  confirmed_at: z.null(),
});
export const sourceInfo = z.discriminatedUnion('kind', [
  vaultSourceInfo,
  vaultRecordSourceInfo,
  unspecifiedSource,
]);
export const unknownSource = () =>
  unspecifiedSource.parse({
    kind: 'unspecified',
    attribute: null,
    revision: null,
    provenance: 'unspecified',
    confirmed_at: null,
  });
const document = z.strictObject({
  id: z.string().regex(/^[A-Za-z0-9_-]{1,80}$/),
  title: z.string().min(1).max(160),
  source: z
    .string()
    .min(1)
    .max(160)
    .describe(
      'Untrusted display label; never parse it as proof of provenance or a saved revision.',
    ),
  source_info: sourceInfo,
});
export const accessInfo = z.discriminatedUnion('mode', [
  z.strictObject({
    mode: z.literal('local-export'),
    checked_at: timestamp.describe('Unix seconds of the final access-grant check.'),
    grant_expires_at: timestamp.describe('Unix seconds of the access-grant deadline.'),
    source_check: z
      .literal('not-checked')
      .describe('No live Vault read is performed by the local adapter.'),
  }),
  z.strictObject({
    mode: z.literal('remote-snapshot'),
    checked_at: timestamp.describe('Unix seconds of the final live access/revision check.'),
    grant_expires_at: timestamp.describe('Unix seconds of the access-grant deadline.'),
    source_check: z
      .enum(['revision-matched', 'record-matched'])
      .describe(
        'The explicit saved source matched the grant during this call; this is not a live subscription.',
      ),
  }),
]);
const common = { result_version: z.literal(1), untrusted_content: z.literal(true) };
const page = z.strictObject({
  ...common,
  documents: z.array(document).max(100),
  next_offset: z.number().int().min(0).max(100).nullable(),
  access: accessInfo,
});
export const toolOutputs = {
  list: page,
  search: page,
  read: z.strictObject({
    ...common,
    ...document.shape,
    text: z.string().max(16384),
    access: accessInfo,
  }),
  propose: z.strictObject({
    ...common,
    proposal_id: opaque,
    request_hash: opaque,
    state: z.enum(['pending', 'approved', 'rejected', 'executed']),
  }),
  execute: z.strictObject({ ...common, draft_id: opaque, state: z.literal('executed') }),
  propose_attribute: z.strictObject({
    ...common,
    proposal_id: opaque,
    request_hash: opaque,
    state: z.enum(['pending', 'approved', 'rejected', 'invalid', 'committed']),
    attribute_id: z.literal('owner_note'),
    base_revision: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    expires_at: timestamp,
    destination: z.literal('owner-vault'),
  }),
};
export type ToolOperation = keyof typeof toolOutputs;

// Validate before either representation can disclose data. Error responses have no structured data.
export function toolResult(op: ToolOperation, data: unknown): CallToolResult {
  const structuredContent = toolOutputs[op].parse(data);
  return {
    structuredContent,
    content: [{ type: 'text', text: JSON.stringify(structuredContent) }],
  };
}
