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
export const restartTargetSchema = z
  .object({
    format_version: z.literal(1),
    experiment: z.literal('inactive_restart_v1'),
    original: qualificationTargetSchema,
    image: qualificationObservationSchema.shape.image,
    namespace_id: z.string().regex(/^[a-f0-9]{32}$/),
    container_application_id: z.string().regex(/^[a-f0-9]{32}$/),
    previous_worker_version: z.string().uuid(),
    source_commit: z.string().regex(/^[a-f0-9]{40}$/),
    source_clean: z.literal(true),
    worker_sha256: digest,
  })
  .strict()
  .refine((t) => t.namespace_id === t.container_application_id);
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

export const restartObservationSchema = qualificationObservationSchema
  .omit({ kind: true, ordinal: true, started: true })
  .extend({
    kind: z.literal('git_host_infrastructure_restart'),
    experiment: z.literal('inactive_restart_v1'),
    prior_attempts: z.literal(3),
    started: z.literal(true),
  });
const failureSchema = z
  .object({
    kind: z.literal('git_host_infrastructure_failed'),
    slot: z.enum(['1', '2', '3', 'inactive_restart_v1']),
    reason: z.literal('not_ready'),
  })
  .strict();
export const qualificationStatusSchema = z
  .object({
    kind: z.literal('git_host_infrastructure_status'),
    registry_sha256: digest,
    disclosure_digest: digest,
    frame_present: z.boolean(),
    container_available: z.boolean(),
    container_running: z.boolean(),
    image: qualificationObservationSchema.shape.image.nullable(),
    attempts: z
      .array(
        z
          .object({
            ordinal: z.number().int().min(1).max(3),
            result: z.union([qualificationObservationSchema, failureSchema]).nullable(),
          })
          .strict(),
      )
      .max(3),
    restart: z
      .object({
        image: qualificationObservationSchema.shape.image,
        result: z.union([restartObservationSchema, failureSchema]).nullable(),
      })
      .strict()
      .nullable(),
    internet_enabled: z.literal(false),
    git_dispatches: z.literal(0),
  })
  .strict();
export function restartObservation(target: QualificationTarget, image: string, value: unknown) {
  const result = restartObservationSchema.parse(value);
  if (
    result.registry_sha256 !== target.registry_sha256 ||
    result.disclosure_digest !== target.disclosure_digest ||
    result.image !== image
  )
    throw new Error('qualification_observation_denied');
  return result;
}
export function qualificationStatus(target: QualificationTarget, image: string, value: unknown) {
  const status = qualificationStatusSchema.parse(value);
  if (
    status.registry_sha256 !== target.registry_sha256 ||
    status.disclosure_digest !== target.disclosure_digest ||
    status.image !== (status.container_available ? image : null) ||
    (!status.container_available && status.container_running) ||
    (!status.frame_present && (status.attempts.length || status.restart)) ||
    (status.restart && (status.restart.image !== image || status.attempts.length !== 3))
  )
    throw new Error('qualification_status_denied');
  for (const [index, attempt] of status.attempts.entries()) {
    if (attempt.ordinal !== index + 1) throw new Error('qualification_status_denied');
    if (attempt.result?.kind === 'git_host_infrastructure')
      qualificationObservation(
        target,
        image,
        attempt.ordinal,
        attempt.result.started,
        attempt.result,
      );
    else if (attempt.result && attempt.result.slot !== String(attempt.ordinal))
      throw new Error('qualification_status_denied');
  }
  if (status.restart?.result?.kind === 'git_host_infrastructure_restart')
    restartObservation(target, image, status.restart.result);
  else if (status.restart?.result && status.restart.result.slot !== 'inactive_restart_v1')
    throw new Error('qualification_status_denied');
  return status;
}
export interface RestartConnection {
  status(): Promise<unknown>;
  qualifyRestart(): Promise<unknown>;
}
/** Reconcile a retained result or charge the single separate stopped-state experiment. */
export async function runRestartQualification(
  target: QualificationTarget,
  image: string,
  connection: RestartConnection,
  record: (value: unknown) => Promise<void>,
) {
  const before = qualificationStatus(target, image, await connection.status());
  await record({ event: 'status_before', value: before });
  if (before.restart) {
    if (before.restart.result?.kind !== 'git_host_infrastructure_restart')
      throw new Error('qualification_restart_unobserved');
    return { reconciled: true, result: restartObservation(target, image, before.restart.result) };
  }
  if (
    !before.frame_present ||
    before.attempts.length !== 3 ||
    !before.container_available ||
    before.container_running
  )
    throw new Error('qualification_restart_denied');
  await record({ event: 'intent', experiment: 'inactive_restart_v1' });
  let timer: ReturnType<typeof setTimeout> | undefined;
  let reply: unknown;
  try {
    reply = await Promise.race([
      connection.qualifyRestart(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('qualification_timeout')), 300000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
  const parsed = restartObservationSchema.safeParse(reply);
  if (!parsed.success) {
    await record({ event: 'response_refused', reason: 'invalid_shape' });
    throw new Error('qualification_observation_denied');
  }
  await record({ event: 'response', value: parsed.data });
  const result = restartObservation(target, image, parsed.data);
  const after = qualificationStatus(target, image, await connection.status());
  await record({ event: 'status_after', value: after });
  if (
    JSON.stringify(after.attempts) !== JSON.stringify(before.attempts) ||
    JSON.stringify(after.restart?.result) !== JSON.stringify(result)
  )
    throw new Error('qualification_retention_denied');
  return { reconciled: false, result };
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
