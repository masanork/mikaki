/** Private admission coordinator. No physical Artifacts, credential or egress. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { opaque } from './protocol';
import { boundedBody, copyManifest, fixedBody, gitPlan, sameMetadata } from './git-protocol';
import type { GitPlan, GitRecord } from './git-protocol';
import { jsonBody } from './worker';
interface Env {
  WORK_GIT_BROKER_ENABLED: string;
  OP_GIT_STORE: Fetcher;
  GIT_CHECKPOINT: {
    lookup(attempt: string): Promise<GitRecord | null>;
    claim(plan: GitPlan): Promise<{ started: boolean; record: GitRecord }>;
  };
}
export class WorkGitBroker extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/copy')
      return new Response(null, { status: 404 });
    try {
      const attempt = request.headers.get('X-Mikaki-Attempt-ID'),
        encoded = request.headers.get('X-Mikaki-Copy');
      if (
        this.env.WORK_GIT_BROKER_ENABLED !== 'true' ||
        !opaque(attempt) ||
        !encoded ||
        encoded.length > 2048 ||
        request.headers.has('Authorization')
      )
        throw new Error('git_denied');
      const manifest: unknown = JSON.parse(encoded);
      copyManifest(manifest);
      // A retained admission never produces another dispatch, including after restore.
      const prior = await this.env.GIT_CHECKPOINT.lookup(attempt);
      if (prior)
        return Response.json(
          { stage: 'outcome_unknown', attempt_id: attempt },
          { status: 409, headers: { 'Cache-Control': 'no-store' } },
        );
      const body = await boundedBody(request);
      const planResponse = await this.env.OP_GIT_STORE.fetch('https://private.invalid/git-effect', {
        method: 'POST',
        headers: {
          'X-Mikaki-Action': 'plan',
          'X-Mikaki-Attempt-ID': attempt,
          'X-Mikaki-Copy': encoded,
        },
        body,
      });
      if (planResponse.status !== 200) throw new Error('git_denied');
      const plan = await jsonBody(planResponse);
      gitPlan(plan);
      if (plan.mint.attempt_id !== attempt || !sameMetadata(plan.manifest, manifest))
        throw new Error('git_denied');
      await fixedBody(plan, body);
      const admission = await this.env.GIT_CHECKPOINT.claim(plan);
      if (!admission.started) throw new Error('git_unknown');
      return await this.env.OP_GIT_STORE.fetch('https://private.invalid/git-effect', {
        method: 'POST',
        headers: {
          'X-Mikaki-Action': 'execute',
          'X-Mikaki-Attempt-ID': attempt,
          'X-Mikaki-Copy': encoded,
        },
        body,
      });
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
