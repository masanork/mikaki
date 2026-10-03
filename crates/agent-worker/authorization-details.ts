import { z } from 'zod';
import { operation, recordSourceSchema, recordAuthoritySchema } from './model.js';

const fields = {
  type: z.literal('mikaki_agent_snapshot'),
  locations: z.tuple([z.string().url().max(256)]),
  actions: z
    .array(operation)
    .min(1)
    .max(5)
    .refine((items) => new Set(items).size === items.length),
  purpose: z.string().trim().min(1).max(160),
};
const attributeDetail = z.strictObject({
  type: fields.type,
  locations: fields.locations,
  actions: fields.actions,
  document_id: z.literal('name'),
  source_revision: z.number().int().positive(),
  purpose: fields.purpose,
  storage_version: z.literal(1).optional(),
});
const recordDetail = z
  .strictObject({
    ...fields,
    storage_version: z.literal(2),
    document_id: z.enum(['name', 'owner_note']),
    source: recordSourceSchema,
    authority: recordAuthoritySchema,
  })
  .refine((value) => value.document_id === value.source.record_id);
const detail = z.union([attributeDetail, recordDetail]);
export type AgentAuthorizationDetail = z.infer<typeof detail>;

/** Mikaki's one-snapshot RFC 9396 profile; every requested operation remains
 * explicitly represented in OAuth scope for existing MCP clients. */
export function parseAuthorizationDetails(
  raw: string,
  resource: string,
  scopes: readonly string[],
): AgentAuthorizationDetail[] {
  if (raw.length > 2048) throw new Error('Authorization details too large');
  const [value] = z.tuple([detail]).parse(JSON.parse(raw));
  if (
    value.locations[0] !== resource ||
    value.actions.length !== scopes.length ||
    value.actions.some((action) => !scopes.includes(action))
  )
    throw new Error('Authorization details do not match resource and scope');
  return [value];
}

// The expression is a trusted SQL column supplied by callers, never client input.
// Scope-only compatibility is deliberately limited to historical v1 grants.
export function authorizationDetailsCondition(expression: string): string {
  const field = (path: string) => `json_extract(${expression},'$[0].${path}')`;
  const scopes = expression.replace(/authorization_details$/, 'scopes');
  const target = `json_array_length(${expression})=1 AND ${field('locations[0]')}=g.resource
    AND json_array_length(${expression},'$[0].locations')=1
    AND json_array_length(${expression},'$[0].actions')=json_array_length(${scopes})
    AND NOT EXISTS(SELECT 1 FROM json_each(${expression},'$[0].actions') action
      WHERE NOT EXISTS(SELECT 1 FROM json_each(${scopes}) scope WHERE scope.value=action.value))`;
  const selected = `json_array_length(g.document_ids)=1 AND json_extract(g.document_ids,'$[0]')`;
  return `((g.storage_version=1 AND (${expression} IS NULL OR (
    ${target} AND COALESCE(${field('storage_version')},1)=1 AND ${field('type')}='mikaki_agent_snapshot'
    AND ${field('source_revision')}=g.source_revision AND ${field('document_id')}='name'
    AND ${selected}='name'))) OR (g.storage_version=2 AND ${expression} IS NOT NULL
    AND ${target} AND ${field('storage_version')}=2 AND ${field('type')}='mikaki_agent_snapshot'
    AND ${field('document_id')}=g.source_record_id AND ${selected}=g.source_record_id
    AND ${field('source.storage_version')}=2 AND ${field('source.origin')}=g.source_origin
    AND ${field('source.owner_id')}=g.account_id AND ${field('source.vault_id')}=g.source_vault_id
    AND ${field('source.collection_id')}=g.source_collection_id
    AND ${field('source.record_id')}=g.source_record_id AND ${field('source.kind')}=g.source_kind
    AND ${field('source.revision')}=g.source_revision
    AND ${field('source.ciphertext_sha256')}=g.source_ciphertext_sha256
    AND ${field('authority.key_generation')}=g.source_key_generation
    AND ${field('authority.owner_key_revision')}=g.source_owner_key_revision))`;
}
