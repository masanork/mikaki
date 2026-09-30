import { z } from 'zod';
import { operation } from './model.js';

const detail = z.strictObject({
  type: z.literal('mikaki_agent_snapshot'),
  locations: z.tuple([z.string().url().max(256)]),
  actions: z
    .array(operation)
    .min(1)
    .max(5)
    .refine((items) => new Set(items).size === items.length),
  document_id: z.literal('name'),
  source_revision: z.number().int().positive(),
  purpose: z.string().trim().min(1).max(160),
});
export type AgentAuthorizationDetail = z.infer<typeof detail>;

/** Mikaki's one-snapshot RFC 9396 profile; every requested operation remains
 * explicitly represented in OAuth scope for existing MCP clients. */
export function parseAuthorizationDetails(
  raw: string,
  resource: string,
  scopes: readonly string[],
): AgentAuthorizationDetail[] {
  if (raw.length > 1024) throw new Error('Authorization details too large');
  const [value] = z.tuple([detail]).parse(JSON.parse(raw));
  if (
    value.locations[0] !== resource ||
    value.actions.length !== scopes.length ||
    value.actions.some((action) => !scopes.includes(action))
  )
    throw new Error('Authorization details do not match resource and scope');
  return [value];
}
