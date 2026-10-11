import { z } from 'zod';
import { checked } from './work-source-view.ts';
const id = z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  digest = z.string().regex(/^[a-f0-9]{64}$/);
const job = z.strictObject({
  preparation_id: id,
  review_digest: digest,
  state: z.enum(['queued', 'running', 'blocked', 'verified']),
  next_step: z.number().int().min(0).max(19),
  total_steps: z.literal(19),
  inflight: z.boolean(),
  updated_at: z.number().int().positive(),
});
const record = z.strictObject({
  review_digest: digest,
  can_start: z.boolean(),
  cleanup_pending: z.boolean(),
  preparation_state: z.enum(['reserved', 'dispatched', 'verified', 'cleanup_pending', 'cleaned']),
  job: job.nullable(),
});
const envelope = z
  .strictObject({
    format_version: z.literal(1),
    checked_at: z.number().int().positive(),
    record,
  })
  .refine(
    ({ record: r }) =>
      (!r.can_start || r.job === null) &&
      (!r.cleanup_pending || r.job?.state === 'blocked') &&
      (!r.job ||
        (r.job.review_digest === r.review_digest &&
          (r.job.state === 'verified') === (r.job.next_step === 19) &&
          (r.job.state !== 'verified' || !r.job.inflight))),
  );
export type CopyStatus = z.infer<typeof record>;
export function copyHttpPort(transport: typeof fetch = (...args) => fetch(...args)) {
  return {
    async read(preparation: string, signal: AbortSignal): Promise<CopyStatus> {
      signal.throwIfAborted();
      id.parse(preparation);
      const r = envelope.parse(
        await checked(
          await transport(`/work/preparations/${preparation}/copy`, {
            credentials: 'same-origin',
            cache: 'no-store',
            signal,
          }),
          4096,
        ),
      ).record;
      signal.throwIfAborted();
      if (r.job && r.job.preparation_id !== preparation) throw new Error('copy_identity');
      return r;
    },
    async start(preparation: string, review: string, signal: AbortSignal): Promise<CopyStatus> {
      signal.throwIfAborted();
      id.parse(preparation);
      digest.parse(review);
      const r = envelope.parse(
        await checked(
          await transport(`/work/preparations/${preparation}/copy`, {
            method: 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ format_version: 1, review_digest: review }),
            signal,
          }),
          4096,
        ),
      ).record;
      signal.throwIfAborted();
      if (r.review_digest !== review || !r.job || r.job.preparation_id !== preparation)
        throw new Error('copy_identity');
      return r;
    },
    async stop(preparation: string, review: string, signal: AbortSignal): Promise<CopyStatus> {
      signal.throwIfAborted();
      id.parse(preparation);
      digest.parse(review);
      const r = envelope.parse(
        await checked(
          await transport(`/work/preparations/${preparation}/copy`, {
            method: 'DELETE',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ format_version: 1, review_digest: review }),
            signal,
          }),
          4096,
        ),
      ).record;
      signal.throwIfAborted();
      if (r.review_digest !== review || !r.job || r.job.preparation_id !== preparation)
        throw new Error('copy_identity');
      return r;
    },
  };
}
