/** Strong refusal retention and Native closure. No bearer, mint or Git write. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { closed, integer, mintPlan, mintRefusal, opaque } from './protocol';
import type { MintRecord, MintRefusal } from './protocol';
import { jsonBody, scope } from './worker';
import { mintOp as op } from './mint-store';
interface Env {
  WORK_MINT_CLOSURE_ENABLED: string;
  WORK_ARTIFACTS_ACCOUNT: string;
  WORK_ARTIFACTS_NAMESPACE: string;
  WORK_AUTHORITY_ID: string;
  MINT_REFUSAL_CHECKPOINT: {
    lookup(attempt: string): Promise<MintRecord | null>;
    refused(attempt: string, digest: string, proof: MintRefusal): Promise<MintRecord>;
  };
  OP_MINT_STORE: Fetcher;
}
async function synchronize(env: Env, r: MintRecord) {
  if (r.state !== 'closed' || !r.refusal || !r.observation) throw new Error('closure_unconfirmed');
  let synced = false;
  try {
    const v = await op(env, {
      action: 'mint-close',
      attempt_id: r.plan.attempt_id,
      digest: r.plan.digest,
      ...r.observation,
      key_version: r.plan.key_version,
      receipt: r.refusal.receipt,
    });
    synced =
      closed(v, ['id', 'state', 'revision']) &&
      v.id === r.plan.attempt_id &&
      v.state === 'closed' &&
      integer(v.revision) &&
      v.revision >= 4 &&
      v.revision <= 6;
  } catch {
    /* Independent proof survives Native fencing/restoration. */
  }
  return {
    attempt_id: r.plan.attempt_id,
    repo_id: r.plan.repo_id,
    state: 'closed',
    cleanup: 'git_bearer_refused',
    op_synchronized: synced,
  };
}
export class WorkMintCloser extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/close-mint')
      return new Response(null, { status: 404 });
    try {
      if (this.env.WORK_MINT_CLOSURE_ENABLED !== 'true') throw new Error('closure_disabled');
      const input = await jsonBody(request);
      if (!closed(input, ['attempt_id']) || !opaque(input.attempt_id))
        throw new Error('closure_invalid');
      const r = await this.env.MINT_REFUSAL_CHECKPOINT.lookup(input.attempt_id);
      if (!r || !r.cleanup_requested || !r.cleanup || !r.observation || r.state === 'custodied')
        throw new Error('closure_denied');
      mintPlan(r.plan);
      scope(this.env, r.plan);
      if (r.plan.attempt_id !== input.attempt_id) throw new Error('closure_denied');
      if (r.state === 'closed')
        return Response.json(await synchronize(this.env, r), {
          headers: { 'Cache-Control': 'no-store' },
        });
      try {
        const proof = await op(this.env, {
          action: 'mint-refusal',
          attempt_id: r.plan.attempt_id,
          digest: r.plan.digest,
          ...r.observation,
          key_version: r.plan.key_version,
        });
        mintRefusal(proof);
        const saved = await this.env.MINT_REFUSAL_CHECKPOINT.refused(
          r.plan.attempt_id,
          r.plan.digest,
          proof,
        );
        return Response.json(await synchronize(this.env, saved), {
          headers: { 'Cache-Control': 'no-store' },
        });
      } catch {
        const latest = await this.env.MINT_REFUSAL_CHECKPOINT.lookup(r.plan.attempt_id);
        if (latest?.state === 'closed')
          return Response.json(await synchronize(this.env, latest), {
            headers: { 'Cache-Control': 'no-store' },
          });
        return Response.json(
          {
            attempt_id: r.plan.attempt_id,
            repo_id: r.plan.repo_id,
            state: 'outcome_unknown',
            cleanup: 'refusal_unconfirmed',
            op_synchronized: false,
          },
          { headers: { 'Cache-Control': 'no-store' } },
        );
      }
    } catch {
      return Response.json(
        { error: 'closure_unavailable_or_denied' },
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
