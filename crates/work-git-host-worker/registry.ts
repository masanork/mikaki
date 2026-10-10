/** Sealed data provisioning, not copy authority. Shared by Linux and Workers. */
import { z } from 'zod';
z.config({ jitless: true });
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const oid = z.string().regex(/^[a-f0-9]{40}$/);
const entry = z.strictObject({
  role: z.enum(['task', 'snapshot']),
  commit: oid,
  tree: oid,
  commits: z.number().int().min(1).max(4096),
  objects: z.number().int().min(1).max(65536),
  object_bytes: z.number().int().min(1).max(67108864),
  inventory_sha256: digest,
  pack_bytes: z.number().int().min(32).max(67108864),
  pack_sha256: digest,
});
export const gitRegistrySchema = z
  .strictObject({
    format_version: z.literal(1),
    disclosure_digest: digest,
    entries: z.tuple([entry, entry]),
  })
  .superRefine((r, c) => {
    if (
      r.entries[0].role !== 'task' ||
      r.entries[1].role !== 'snapshot' ||
      r.entries[1].commits !== 1
    )
      c.addIssue({ code: 'custom', message: 'invalid registry' });
  });
export type GitRegistry = z.infer<typeof gitRegistrySchema>;
