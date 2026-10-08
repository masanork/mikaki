/** One fixed Git use per custodied mint. No preparation/grant promotion. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { closed, opaque, gitPlan, gitResult } from './protocol';
import type { GitPlan, GitResult, MintRecord } from './protocol';
import { op, jsonBody } from './worker';
interface Env {
  WORK_GIT_GATE_ENABLED: string;
  OP_EFFECT_STORE: Fetcher;
  GIT_CHECKPOINT: {
    lookup(attempt: string): Promise<MintRecord | null>;
    claim(plan: GitPlan): Promise<{ started: boolean; record: MintRecord }>;
    finish(attempt: string, result: GitResult | null): Promise<MintRecord>;
  };
}
async function cleanup(env: Env, r: MintRecord) {
  if (!r.observation) return;
  try {
    await op(env, {
      action: 'mint-cleanup',
      attempt_id: r.plan.attempt_id,
      digest: r.plan.digest,
      ...r.observation,
    });
  } catch {
    /* independent intent retains liability */
  }
}
export class WorkGitGate extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    try {
      if (
        this.env.WORK_GIT_GATE_ENABLED !== 'true' ||
        request.method !== 'POST' ||
        new URL(request.url).pathname !== '/git'
      )
        throw new Error('git_denied');
      const input: unknown = await jsonBody(request);
      if (!closed(input, ['attempt_id']) || !opaque(input.attempt_id))
        throw new Error('git_invalid');
      const attempt = input.attempt_id;
      let r = await this.env.GIT_CHECKPOINT.lookup(attempt);
      if (r?.git) {
        if (r.state !== 'closed') {
          r = await this.env.GIT_CHECKPOINT.finish(attempt, null);
          await cleanup(this.env, r);
        }
        return Response.json(
          { attempt_id: attempt, state: r.git!.state, result: r.git!.result },
          { headers: { 'Cache-Control': 'no-store' } },
        );
      }
      const p = await op(this.env, { action: 'git-plan', attempt_id: attempt });
      gitPlan(p);
      const claim = await this.env.GIT_CHECKPOINT.claim(p);
      if (!claim.started)
        return Response.json({
          attempt_id: attempt,
          state: claim.record.git!.state,
          result: claim.record.git!.result,
        });
      let result: GitResult | null = null;
      try {
        const value = await op(this.env, { action: 'git-execute', attempt_id: attempt, plan: p });
        gitResult(value, p);
        result = value;
      } catch {
        /* a consumed permit can never replay */
      }
      r = await this.env.GIT_CHECKPOINT.finish(attempt, result);
      await cleanup(this.env, r);
      return Response.json(
        { attempt_id: attempt, state: r.git!.state, result: r.git!.result },
        { headers: { 'Cache-Control': 'no-store' } },
      );
    } catch {
      return Response.json(
        { error: 'git_unavailable_or_denied' },
        { status: 409, headers: { 'Cache-Control': 'no-store' } },
      );
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
