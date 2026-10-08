/** Identity-checked private bridge to a separately provisioned Git executor. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { gitPlan, gitResult } from './protocol';
import type { GitPlan, MintRecord } from './protocol';
import { scope, expiry, jsonBody } from './worker';
import { inventory } from './maintenance';
interface Env {
  WORK_GIT_TRANSPORT_ENABLED: string;
  WORK_ARTIFACTS_ACCOUNT: string;
  WORK_ARTIFACTS_NAMESPACE: string;
  WORK_AUTHORITY_ID: string;
  ARTIFACTS: Artifacts;
  MINT_LOOKUP: { lookup(attempt: string): Promise<MintRecord | null> };
  GIT_DISPATCH: { take(plan: GitPlan): Promise<{ taken: boolean }> };
  GIT_EXECUTOR: Fetcher;
}
export class WorkGitTransport extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    let repo: ArtifactsRepo | undefined;
    try {
      const auth = request.headers.get('Authorization');
      if (
        this.env.WORK_GIT_TRANSPORT_ENABLED !== 'true' ||
        request.method !== 'POST' ||
        request.url !== 'https://private.invalid/git-execute' ||
        !auth ||
        !/^Bearer [\x21-\x7e]{1,4096}$/.test(auth)
      )
        throw new Error('git_denied');
      const p: unknown = await jsonBody(request);
      gitPlan(p);
      const remote = scope(this.env, p);
      repo = await this.env.ARTIFACTS.get(p.name);
      const check = async (state: 'dispatching' | 'outcome_unknown') => {
        const r = await this.env.MINT_LOOKUP.lookup(p.attempt_id),
          info = await repo!.info();
        if (
          !r ||
          r.state !== 'custodied' ||
          r.cleanup_requested ||
          r.git?.state !== state ||
          JSON.stringify(r.git.plan) !== JSON.stringify(p) ||
          info.id !== p.repo_id ||
          info.name !== p.name ||
          info.remote !== remote ||
          info.defaultBranch !== p.branch ||
          info.description !== `mikaki initial ${p.initial_attempt_id}`
        )
          throw new Error('git_denied');
        const tokens = inventory(await repo!.listTokens()).tokens,
          t = tokens.find((t) => t.id === p.observation.token_id);
        if (
          !t ||
          t.state !== 'active' ||
          t.scope !== p.scope ||
          expiry(t.expiresAt) !== p.observation.expires_at ||
          tokens.filter((t) => t.state === 'active').length !== 1 ||
          p.observation.expires_at <= Math.floor(Date.now() / 1000) + 5
        )
          throw new Error('git_denied');
      };
      await check('dispatching');
      if (!(await this.env.GIT_DISPATCH.take(p)).taken) throw new Error('git_denied');
      await check('outcome_unknown');
      const response = await this.env.GIT_EXECUTOR.fetch('https://private.invalid/git-execute', {
        method: 'POST',
        headers: { Authorization: auth, 'Content-Type': 'application/json' },
        body: JSON.stringify(p),
        redirect: 'manual',
        signal: AbortSignal.timeout(60000),
      });
      if (response.status !== 200) {
        await response.body?.cancel();
        throw new Error('git_unknown');
      }
      const value: unknown = await jsonBody(response);
      gitResult(value, p);
      await check('outcome_unknown');
      return Response.json(value, { headers: { 'Cache-Control': 'no-store' } });
    } catch {
      return new Response(null, { status: 409, headers: { 'Cache-Control': 'no-store' } });
    } finally {
      repo?.[Symbol.dispose]();
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
