import { z } from 'zod';
import { checked, comparePaths, SourceError, type OwnedSource } from './work-source-view.ts';
const id = z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/),
  digest = z.string().regex(/^[a-f0-9]{64}$/),
  revision = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
const compositionSchema = z.strictObject({
  format_version: z.literal(1),
  checked_at: z.number().int().min(1),
  record: z.strictObject({
    request_digest: digest,
    preparation_id: id,
    preparation_digest: digest,
    disclosure_digest: digest,
    expires_at: revision,
  }),
});
export type PreparedSelection = z.infer<typeof compositionSchema>['record'];
export function preparationComposePort(transport: typeof fetch = (...args) => fetch(...args)) {
  return {
    async prepare(
      code: OwnedSource,
      contexts: { source: OwnedSource; paths: string[] }[],
      expires: number,
      signal?: AbortSignal,
    ): Promise<PreparedSelection> {
      if (code.role !== 'code' || !Number.isSafeInteger(expires) || expires <= Date.now() / 1000)
        throw new SourceError('invalid');
      const input = {
        format_version: 1,
        code: {
          source_id: code.source_id,
          source_revision: code.source_revision,
          access_revision: code.access_revision,
        },
        contexts: contexts.map(({ source, paths }) => ({
          format_version: 1,
          source_id: source.source_id,
          source_revision: source.source_revision,
          access_revision: source.access_revision,
          paths: [...paths].sort(comparePaths),
        })),
        expires_at: expires,
      };
      // Source IDs use ASCII native ordering, not locale ordering.
      input.contexts.sort((a, b) =>
        a.source_id < b.source_id ? -1 : a.source_id > b.source_id ? 1 : 0,
      );
      const body = JSON.stringify(input);
      const hash = [
        ...new Uint8Array(
          await crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode('mikaki.work-owner-compose-input.v1\0' + body),
          ),
        ),
      ]
        .map((v) => v.toString(16).padStart(2, '0'))
        .join('');
      try {
        if (signal?.aborted) throw new SourceError('unavailable');
        const record = compositionSchema.parse(
          await checked(
            await transport('/work/preparations', {
              method: 'POST',
              credentials: 'same-origin',
              cache: 'no-store',
              headers: { 'Content-Type': 'application/json' },
              body,
              ...(signal ? { signal } : {}),
            }),
            4096,
          ),
        ).record;
        if (record.request_digest !== hash || record.expires_at !== expires || signal?.aborted)
          throw new SourceError('stale');
        return record;
      } catch (e) {
        if (e instanceof SourceError) throw e;
        throw new SourceError('unavailable');
      }
    },
  };
}
