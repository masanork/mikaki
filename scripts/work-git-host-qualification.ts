/** Closed infrastructure-only targets and observations. No copy authority. */
import { z } from 'zod';
export const QUALIFICATION_NAME = 'mikaki-work-git-host-qualification';
const digest = z.string().regex(/^[a-f0-9]{64}$/);
export const qualificationTargetSchema = z
  .object({
    format_version: z.literal(1),
    account_id: z.string().regex(/^[a-f0-9]{32}$/),
    worker: z.literal(QUALIFICATION_NAME),
    bucket: z.literal(QUALIFICATION_NAME),
    namespace: z.literal('mikaki-dev'),
    authority: z.literal('mikaki-git-host-qualification-v1'),
    disclosure_digest: digest,
    registry_sha256: digest,
    source_commit: z.string().regex(/^[a-f0-9]{40}$/),
    source_clean: z.literal(true),
    host_sha256: digest,
    dockerfile_sha256: digest,
    worker_sha256: digest,
  })
  .strict();
export type QualificationTarget = z.infer<typeof qualificationTargetSchema>;
export const qualificationObservationSchema = z
  .object({
    kind: z.literal('git_host_infrastructure'),
    ready: z.literal(true),
    registry_sha256: digest,
    disclosure_digest: digest,
    image: z
      .string()
      .max(512)
      .regex(/^registry\.cloudflare\.com\/[a-f0-9]{32}\/[a-z0-9_.:/-]+@sha256:[a-f0-9]{64}$/),
    started: z.boolean(),
    ordinal: z.number().int().min(1).max(3),
    elapsed_ms: z.number().int().min(0).max(300000),
    internet_enabled: z.literal(false),
    git_dispatches: z.literal(0),
  })
  .strict();
export function qualificationImage(account: string, image: string) {
  if (
    !/^[a-f0-9]{32}$/.test(account) ||
    !new RegExp(`^registry\\.cloudflare\\.com/${account}/[a-z0-9_.:/-]+@sha256:[a-f0-9]{64}$`).test(
      image,
    )
  )
    throw new Error('qualification_image_denied');
  return image;
}
export function qualificationObservation(
  target: QualificationTarget,
  image: string,
  ordinal: number,
  started: boolean,
  value: unknown,
) {
  const observation = qualificationObservationSchema.parse(value);
  if (
    observation.registry_sha256 !== target.registry_sha256 ||
    observation.disclosure_digest !== target.disclosure_digest ||
    observation.image !== image ||
    observation.ordinal !== ordinal ||
    observation.started !== started
  )
    throw new Error('qualification_observation_denied');
  return observation;
}

export interface QualificationConnection {
  prepare(): Promise<unknown>;
  dispose(): Promise<void>;
}
// DO eviction may take 70–140s, followed by the configured 60s Container grace.
// This wait is a probe window, not proof of inactivity; started=true still gates step 3.
const COOLING_MS = 225000;
/** Release the authenticated RPC session before measuring inactivity. No retries. */
export async function runQualificationSequence(
  target: QualificationTarget,
  image: string,
  runtime: {
    connect(): Promise<QualificationConnection>;
    record(value: unknown): Promise<void>;
    cool(milliseconds: number): Promise<void>;
  },
) {
  let connection: QualificationConnection | undefined;
  const close = async () => {
    const current = connection;
    connection = undefined;
    await current?.dispose();
  };
  try {
    connection = await runtime.connect();
    for (const [ordinal, started] of [
      [1, true],
      [2, false],
      [3, true],
    ] as const) {
      if (ordinal === 3) {
        await close();
        await runtime.record({ event: 'disconnected', after_ordinal: 2 });
        await runtime.record({ event: 'cooling', wait_ms: COOLING_MS });
        await runtime.cool(COOLING_MS);
        connection = await runtime.connect();
      }
      await runtime.record({ event: 'intent', ordinal });
      let timer: ReturnType<typeof setTimeout> | undefined;
      let reply: unknown;
      try {
        reply = await Promise.race([
          connection!.prepare(),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error('qualification_timeout')), 300000);
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
      // Retain only the closed safe response before checking selected expectations.
      // A mismatching valid response is evidence, never a successful observation.
      const parsed = qualificationObservationSchema.safeParse(reply);
      if (!parsed.success) {
        await runtime.record({ event: 'response_refused', ordinal, reason: 'invalid_shape' });
        throw new Error('qualification_observation_denied');
      }
      await runtime.record({ event: 'response', expected_ordinal: ordinal, value: parsed.data });
      const value = qualificationObservation(target, image, ordinal, started, parsed.data);
      await runtime.record({ event: 'observed', ...value });
    }
  } finally {
    await close();
  }
}
