/** Fixed refusal-only egress. Never returns a bearer, response content or repo. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { mintPlan, opaque } from './protocol';
import type { MintRecord } from './protocol';
import { expiry, scope } from './worker';
import { inventory } from './maintenance';

interface Env {
  WORK_MINT_REFUSAL_TRANSPORT_ENABLED: string;
  WORK_ARTIFACTS_ACCOUNT: string;
  WORK_ARTIFACTS_NAMESPACE: string;
  WORK_AUTHORITY_ID: string;
  MINT_LOOKUP: { lookup(attempt: string): Promise<MintRecord | null> };
  ARTIFACTS: Artifacts;
}
export class WorkMintRefusalTransport extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    let repo: ArtifactsRepo | undefined;
    try {
      const attempt = request.headers.get('X-Mikaki-Attempt-ID');
      const authorization = request.headers.get('Authorization');
      if (
        this.env.WORK_MINT_REFUSAL_TRANSPORT_ENABLED !== 'true' ||
        request.method !== 'GET' ||
        !opaque(attempt) ||
        !authorization ||
        !/^Bearer [\x21-\x7e]{1,4096}$/.test(authorization) ||
        request.body !== null
      )
        throw new Error('refusal_denied');
      const r = await this.env.MINT_LOOKUP.lookup(attempt);
      if (
        !r ||
        r.state !== 'outcome_unknown' ||
        !r.cleanup_requested ||
        !r.cleanup ||
        !r.observation ||
        r.refusal
      )
        throw new Error('refusal_denied');
      mintPlan(r.plan);
      const p = r.plan,
        o = r.observation,
        remote = scope(this.env, p);
      if (p.attempt_id !== attempt || request.url !== `${remote}/info/refs?service=git-upload-pack`)
        throw new Error('refusal_denied');
      repo = await this.env.ARTIFACTS.get(p.name);
      const check = async () => {
        const latest = await this.env.MINT_LOOKUP.lookup(attempt),
          info = await repo!.info();
        if (
          !latest ||
          latest.state !== 'outcome_unknown' ||
          latest.refusal ||
          JSON.stringify(latest.plan) !== JSON.stringify(p) ||
          JSON.stringify(latest.cleanup) !== JSON.stringify(r.cleanup) ||
          JSON.stringify(latest.observation) !== JSON.stringify(o) ||
          info.id !== p.repo_id ||
          info.name !== p.name ||
          info.remote !== remote ||
          info.defaultBranch !== (p.role === 'task' ? 'work' : 'snapshot') ||
          info.description !== `mikaki initial ${p.initial_attempt_id}`
        )
          throw new Error('refusal_denied');
        const listed = inventory(await repo!.listTokens()),
          t = listed.tokens.find((t) => t.id === o.token_id);
        if (
          t
            ? t.state !== 'revoked' || t.scope !== o.scope || expiry(t.expiresAt) !== o.expires_at
            : !latest.revoke_acknowledged
        )
          throw new Error('refusal_denied');
      };
      await check();
      const response = await fetch(request.url, {
        headers: { Authorization: authorization },
        redirect: 'manual',
        signal: AbortSignal.timeout(5000),
      });
      await response.body?.cancel();
      if (response.status !== 403) throw new Error('refusal_unconfirmed');
      await check();
      return new Response(null, { status: 403, headers: { 'Cache-Control': 'no-store' } });
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
