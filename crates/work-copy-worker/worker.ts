/** Fixed Workflow identity and transport only. Rust owns the durable copy job,
 * sequence, authority, effect selection and completion. No credentials here. */
import {
  WorkerEntrypoint,
  WorkflowEntrypoint,
  type WorkflowEvent,
  type WorkflowStep,
} from 'cloudflare:workers';
import { jsonBody } from '../work-effect-worker/worker';
import { closed, opaque } from '../work-effect-worker/protocol';
import { z } from 'zod';
type Params = { preparation_id: string };
const id = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const response = z.union([
  z.strictObject({ preparations: z.array(z.strictObject({ preparation_id: id })).max(20) }),
  z.strictObject({ preparation_id: id, cleanup_pending: z.boolean() }),
  z.strictObject({
    preparation_id: id,
    state: z.enum(['queued', 'running', 'blocked', 'verified']),
    next_step: z.number().int().min(0).max(19),
    total_steps: z.literal(19).optional(),
    inflight: z.boolean().optional(),
    updated_at: z.number().int().positive().optional(),
    review_digest: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
  }),
]);
async function op(env: CopyWorkflowEnv, input: Record<string, unknown>) {
  const r = await env.OP_COPY_STORE.fetch('https://private.invalid/copy-job', {
    method: 'POST',
    body: JSON.stringify(input),
  });
  if (r.status !== 200) throw new Error('copy_unavailable');
  const value = response.parse(await jsonBody(r));
  if (
    'preparation_id' in input &&
    (!('preparation_id' in value) || value.preparation_id !== input.preparation_id)
  )
    throw new Error('copy_identity');
  return value;
}
function input(value: unknown): Params {
  if (!closed(value, ['preparation_id']) || !opaque(value.preparation_id))
    throw new Error('copy_invalid');
  return { preparation_id: value.preparation_id };
}
async function start(env: CopyWorkflowEnv, p: Params) {
  const id = 'copy-' + p.preparation_id;
  try {
    const instance = await env.COPY_WORKFLOW.create({ id, params: p });
    if (instance.id !== id) throw new Error('copy_identity');
  } catch {
    const existing = await env.COPY_WORKFLOW.get(id);
    if (existing.id !== id) throw new Error('copy_identity');
    await existing.status();
  }
  return { preparation_id: p.preparation_id, workflow_id: id };
}
export class WorkCopyStarter extends WorkerEntrypoint<CopyWorkflowEnv> {
  async fetch(request: Request) {
    if (
      String(this.env.WORK_COPY_WORKFLOW_ENABLED) !== 'true' ||
      request.method !== 'POST' ||
      new URL(request.url).pathname !== '/start'
    )
      return new Response(null, { status: 404 });
    try {
      return Response.json(await start(this.env, input(await jsonBody(request))), {
        headers: { 'Cache-Control': 'no-store' },
      });
    } catch {
      return Response.json(
        { error: 'copy_unavailable_or_denied' },
        { status: 409, headers: { 'Cache-Control': 'no-store' } },
      );
    }
  }
}
export class WorkCopyWorkflow extends WorkflowEntrypoint<CopyWorkflowEnv, Params> {
  async run(event: WorkflowEvent<Params>, step: WorkflowStep) {
    const p = input(event.payload);
    if (String(this.env.WORK_COPY_WORKFLOW_ENABLED) !== 'true') throw new Error('copy_disabled');
    try {
      for (let ordinal = 0; ordinal < 19; ordinal++) {
        const result = await step.do(
          `native-copy-step-${ordinal}`,
          { retries: { limit: 0, delay: '1 second' }, timeout: '3 minutes' },
          () =>
            op(this.env, { action: 'advance', preparation_id: p.preparation_id, step: ordinal }),
        );
        if (!result || typeof result !== 'object' || !('state' in result))
          throw new Error('copy_reply');
        if (result.state !== 'running')
          return {
            preparation_id: p.preparation_id,
            state: result.state === 'verified' ? 'verified' : 'blocked',
          };
      }
      throw new Error('copy_incomplete');
    } catch {
      // This is safety-only. Retrying it cannot mint, create, copy or launch.
      await step.do(
        'retain-copy-stop',
        { retries: { limit: 2, delay: '5 seconds' }, timeout: '3 minutes' },
        () => op(this.env, { action: 'cancel', preparation_id: p.preparation_id }),
      );
      return { preparation_id: p.preparation_id, state: 'blocked' };
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
  async scheduled(_event: ScheduledController, env: CopyWorkflowEnv) {
    if (String(env.WORK_COPY_WORKFLOW_ENABLED) !== 'true') return;
    const pending = await op(env, { action: 'pending' });
    if (!('preparations' in pending)) throw new Error('copy_pending');
    for (const row of pending.preparations) await start(env, input(row));
  },
} satisfies ExportedHandler<CopyWorkflowEnv>;
