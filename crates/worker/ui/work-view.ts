/** Owner presentation contract. These projections never issue authorization. */
import { z } from 'zod';

// Keep validation compatible with the OP/preview CSP: no dynamic Function/eval.
z.config({ jitless: true });

const id = z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const git = z.string().regex(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/);
const time = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const text = (max: number) =>
  z.string().refine((v) => v.trim().length > 0 && new TextEncoder().encode(v).length <= max);
export const workDraftSchema = z
  .object({
    goal: text(4096),
    acceptance: text(8192),
    contexts: z.array(z.enum(['style', 'design'])).max(2),
  })
  .strict();
export type WorkDraft = z.infer<typeof workDraftSchema>;

const file = z
  .object({ path: z.string(), content: z.string(), digest, size: z.number().int().nonnegative() })
  .strict();
const context = z
  .object({
    id: z.enum(['style', 'design']),
    scope: z.enum(['personal', 'project']),
    repository: z.string(),
    version: git,
    files: z.array(file),
  })
  .strict();
const destination = z
  .object({
    namespace: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/),
    name: z.string().regex(/^wk-[a-f0-9]{32}-(?:code|snapshot)$/),
    repository_id: id.nullable(),
  })
  .strict();
export const workPreparationSchema = z
  .object({
    id,
    digest,
    disclosure_digest: digest,
    destination_digest: digest.nullable(),
    task_repository: id,
    snapshot_repository: id,
    state: z.enum(['reserved', 'dispatched', 'verified', 'cleanup_pending', 'cleaned']),
    revision: z.number().int().min(1).max(5),
    expires_at: time,
    current_authority: z.boolean(),
    materialized: z.boolean(),
    task: destination,
    snapshot: destination,
  })
  .strict()
  .superRefine((p, ctx) => {
    const known = p.task.repository_id !== null && p.snapshot.repository_id !== null;
    if (
      (p.task.repository_id === null) !== (p.snapshot.repository_id === null) ||
      (p.destination_digest !== null) !== known ||
      (known && p.task.repository_id === p.snapshot.repository_id) ||
      (known && ['reserved', 'dispatched'].includes(p.state)) ||
      (p.state === 'verified' && !known) ||
      (p.materialized && !known) ||
      (p.current_authority && (p.state !== 'verified' || !p.materialized || !known))
    ) {
      ctx.addIssue({ code: 'custom', message: 'Invalid preparation projection' });
    }
  });
export type WorkPreparation = z.infer<typeof workPreparationSchema>;
export const workViewSchema = z
  .object({
    preview: z.literal(true),
    requestId: id,
    updatedAt: time,
    contexts: z.array(context),
    preparation: workPreparationSchema.nullable(),
    request: z
      .object({
        digest,
        revision: z.number().int().positive(),
        saved: z.boolean(),
        taskRepository: id,
        goal: z.string(),
        acceptance: z.string(),
        selected: z.array(z.enum(['style', 'design'])),
        source: z.string(),
        base: git,
        task: z.string(),
        target: z.string(),
        reference: z.string(),
        expectedHead: git,
        expiresAt: time,
        disclosure: digest,
        recipient: z.literal('launcher-client'),
        operator: z.literal('mikaki / Cloudflare'),
        history: z.literal('reachable-code-and-context-snapshot'),
        files: z.array(file),
        contextVersions: z.array(
          z.object({ id: z.enum(['style', 'design']), version: git }).strict(),
        ),
        stale: z.boolean(),
      })
      .strict()
      .nullable(),
    grant: z
      .object({
        id,
        revision: z.number().int().positive(),
        state: z.enum(['active', 'expired', 'revoked']),
        expiresAt: time,
      })
      .strict()
      .nullable(),
    run: z
      .object({
        id,
        execution: z.enum(['running', 'stop_requested', 'stopped', 'completed', 'unknown']),
        credential: z.enum(['active', 'revocation_pending', 'revoked', 'expired', 'unknown']),
        expiresAt: time,
        updatedAt: time,
      })
      .strict()
      .nullable(),
    candidate: z
      .object({
        digest,
        commit: git,
        tree: git,
        diff: z.string(),
        summary: z.string(),
        agentClaim: z.string(),
        checks: z.enum(['unverified', 'passed', 'failed']),
        source: z.string(),
      })
      .strict()
      .nullable(),
    target: z
      .object({
        repository: z.string(),
        reference: z.string(),
        head: git,
        revision: z.number().int().positive(),
        writable: z.boolean(),
      })
      .strict(),
    effect: z
      .object({
        id,
        state: z.enum([
          'prepared',
          'dispatched',
          'outcome_unknown',
          'applied',
          'rejected',
          'cancelled',
        ]),
        receipt: id.nullable(),
        candidate: digest,
        expectedHead: git,
      })
      .strict()
      .nullable(),
  })
  .strict()
  .superRefine((v, ctx) => {
    if (
      v.preparation &&
      (!v.request ||
        v.preparation.disclosure_digest !== v.request.disclosure ||
        v.preparation.task_repository !== v.request.taskRepository)
    ) {
      ctx.addIssue({ code: 'custom', message: 'Preparation does not match request' });
    }
  });
export type WorkView = z.infer<typeof workViewSchema>;
export const workPreviewScenarioSchema = z
  .object({
    action: z.enum([
      'reset',
      'complete',
      'cleanup',
      'source-changed',
      'target-changed',
      'untrusted-output',
      'preparation-pending',
      'preparation-cleanup',
    ]),
  })
  .strict();
export type WorkPreviewAction = z.infer<typeof workPreviewScenarioSchema>['action'];
export const workCommandSchema = z
  .discriminatedUnion('action', [
    z.object({ action: z.literal('review'), draft: workDraftSchema }).strict(),
    z.object({ action: z.literal('prepare'), digest }).strict(),
    z.object({ action: z.literal('delegate'), digest, destinations: digest }).strict(),
    z.object({ action: z.literal('stop'), grant: id }).strict(),
    z.object({ action: z.literal('adopt'), candidate: digest, head: git }).strict(),
    z.object({ action: z.literal('reconcile'), operation: id }).strict(),
  ])
  .readonly();
export type WorkCommand = z.infer<typeof workCommandSchema>;
export type WorkFailure = 'stale' | 'expired' | 'unavailable' | 'invalid';
export class WorkUiError extends Error {
  readonly reason: WorkFailure;
  constructor(reason: WorkFailure) {
    super(reason);
    this.reason = reason;
  }
}
export interface WorkPort {
  load(): Promise<WorkView>;
  send(command: WorkCommand): Promise<WorkView>;
}

/** Recompute exactly the native commitment to the displayed destinations. A
 * substituted ID/name must not retain the original digest/approval command. */
export async function checkWorkDestinations(view: WorkView): Promise<WorkView> {
  const p = view.preparation;
  if (!p?.destination_digest) return view;
  const values = [
    new TextEncoder().encode('mikaki.work-prepared-destination.v1'),
    Uint8Array.from(p.digest.match(/../g)!.map((v) => Number.parseInt(v, 16))),
    ...[
      p.task_repository,
      p.snapshot_repository,
      p.task.namespace,
      p.task.name,
      p.task.repository_id!,
      p.snapshot.namespace,
      p.snapshot.name,
      p.snapshot.repository_id!,
    ].map((v) => new TextEncoder().encode(v)),
  ];
  const bytes = new Uint8Array(values.reduce((n, v) => n + 8 + v.length, 0));
  const sizes = new DataView(bytes.buffer);
  let offset = 0;
  for (const value of values) {
    sizes.setBigUint64(offset, BigInt(value.length));
    offset += 8;
    bytes.set(value, offset);
    offset += value.length;
  }
  const actual = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes.buffer))]
    .map((v) => v.toString(16).padStart(2, '0'))
    .join('');
  if (actual !== p.destination_digest) throw new WorkUiError('unavailable');
  return view;
}
export function workHttpPort(path: string): WorkPort {
  const request = async (command?: WorkCommand): Promise<WorkView> => {
    let response: Response;
    try {
      response = await fetch(path, {
        credentials: 'same-origin',
        cache: 'no-store',
        ...(command
          ? {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(command),
            }
          : {}),
      });
    } catch {
      throw new WorkUiError('unavailable');
    }
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { error?: unknown } | null;
      const reason = body?.error;
      throw new WorkUiError(
        reason === 'stale' || reason === 'expired' || reason === 'invalid' ? reason : 'unavailable',
      );
    }
    try {
      return await checkWorkDestinations(workViewSchema.parse(await response.json()));
    } catch {
      throw new WorkUiError('unavailable');
    }
  };
  return { load: () => request(), send: (command) => request(workCommandSchema.parse(command)) };
}
