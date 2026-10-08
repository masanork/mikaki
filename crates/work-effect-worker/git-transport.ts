/** Fixed private Git HTTP transport. Consumes independent admission before I/O. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { opaque } from './protocol';
import {
  advertisement,
  boundedBody,
  fixedBody,
  gitPlan,
  responsePayload,
  sameMetadata,
} from './git-protocol';
import type { GitRecord } from './git-protocol';
import type { MintRecord } from './protocol';
import { expiry, scope } from './worker';
import { inventory } from './maintenance';
interface Env {
  WORK_GIT_TRANSPORT_ENABLED: string;
  WORK_ARTIFACTS_ACCOUNT: string;
  WORK_ARTIFACTS_NAMESPACE: string;
  WORK_AUTHORITY_ID: string;
  GIT_TRANSMISSION: {
    take(attempt: string, digest: string): Promise<GitRecord>;
    current(attempt: string, digest: string): Promise<void>;
  };
  MINT_LOOKUP: { lookup(attempt: string): Promise<MintRecord | null> };
  GIT_LOOKUP: { lookup(attempt: string): Promise<GitRecord | null> };
  ARTIFACTS: Artifacts;
}
export class WorkGitTransport extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    let repo: ArtifactsRepo | undefined;
    try {
      const attempt = request.headers.get('X-Mikaki-Attempt-ID'),
        digest = request.headers.get('X-Mikaki-Git-Digest'),
        auth = request.headers.get('Authorization');
      if (
        this.env.WORK_GIT_TRANSPORT_ENABLED !== 'true' ||
        request.method !== 'POST' ||
        !opaque(attempt) ||
        !digest ||
        !auth ||
        !/^Bearer [\x21-\x7e]{16,4096}$/.test(auth)
      )
        throw new Error('git_denied');
      const retained = await this.env.GIT_LOOKUP.lookup(attempt);
      if (!retained || retained.consumed || retained.plan.digest !== digest)
        throw new Error('git_denied');
      const p = retained.plan;
      gitPlan(p);
      const remote = scope(this.env, p.mint),
        service = p.mint.purpose === 'upload' ? 'git-receive-pack' : 'git-upload-pack';
      if (request.url !== `${remote}/${service}`) throw new Error('git_denied');
      const body = await boundedBody(request);
      await fixedBody(p, body);
      // Permanent consumption gates every path through this private transport.
      await this.env.GIT_TRANSMISSION.take(attempt, digest);
      repo = await this.env.ARTIFACTS.get(p.mint.name);
      const check = async () => {
        await this.env.GIT_TRANSMISSION.current(attempt, digest);
        const r = await this.env.MINT_LOOKUP.lookup(attempt),
          info = await repo!.info();
        if (
          !r ||
          r.state !== 'custodied' ||
          r.cleanup_requested ||
          r.revoke_acknowledged ||
          !sameMetadata(r.plan, p.mint) ||
          !sameMetadata(r.observation, p.observation) ||
          info.id !== p.mint.repo_id ||
          info.name !== p.mint.name ||
          info.remote !== remote ||
          info.defaultBranch !== (p.mint.role === 'task' ? 'work' : 'snapshot') ||
          info.description !== `mikaki initial ${p.mint.initial_attempt_id}`
        )
          throw new Error('git_denied');
        const t = inventory(await repo!.listTokens()).tokens.find(
          (t) => t.id === p.observation.token_id,
        );
        if (
          !t ||
          t.state !== 'active' ||
          t.scope !== p.mint.scope ||
          expiry(t.expiresAt) !== p.observation.expires_at ||
          p.observation.expires_at <= Math.floor(Date.now() / 1000)
        )
          throw new Error('git_denied');
      };
      await check();
      const advertised = await fetch(`${remote}/info/refs?service=${service}`, {
        headers: { Authorization: auth },
        redirect: 'manual',
        signal: AbortSignal.timeout(5000),
      });
      if (
        advertised.status !== 200 ||
        advertised.headers.get('Content-Type') !== `application/x-${service}-advertisement`
      ) {
        await advertised.body?.cancel();
        throw new Error('git_denied');
      }
      advertisement(await boundedBody(advertised, 65536), p);
      await check();
      const result = await fetch(request.url, {
        method: 'POST',
        headers: { Authorization: auth, 'Content-Type': `application/x-${service}-request` },
        body,
        redirect: 'manual',
        signal: AbortSignal.timeout(15000),
      });
      if (
        result.status !== 200 ||
        result.headers.get('Content-Type') !== `application/x-${service}-result`
      ) {
        await result.body?.cancel();
        throw new Error('git_unknown');
      }
      const bytes = await responsePayload(await boundedBody(result), p);
      await check();
      return new Response(bytes, {
        headers: { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' },
      });
    } catch {
      return Response.json(
        { error: 'git_unavailable_or_unknown' },
        { status: 409, headers: { 'Cache-Control': 'no-store' } },
      );
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
