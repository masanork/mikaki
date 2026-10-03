import { z } from 'zod';
import { parseRecordNoteTarget } from '../worker/ui/vault-record-approval.ts';
const opaque = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const safeRevision = z
  .number()
  .int()
  .min(0)
  .max(Number.MAX_SAFE_INTEGER - 1);
export const noteTargetSchema = z
  .strictObject({
    storage_version: z.literal(2),
    origin: z.string().url(),
    owner_id: z.string(),
    vault_id: z.string(),
    collection_id: z.literal('personal'),
    record_id: z.literal('owner_note'),
    kind: z.literal('owner_note'),
    revision: safeRevision,
    ciphertext_sha256: opaque.nullable(),
    deleted: z.boolean(),
  })
  .refine((value) => {
    try {
      parseRecordNoteTarget(value);
      return true;
    } catch {
      return false;
    }
  });
