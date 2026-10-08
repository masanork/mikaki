/** Private one-shot upload/readback mint. Custody only; no Git or token release. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { closed, integer, opaque, resource, mintPlan } from './protocol';
import type { MintPlan, MintObservation, MintRecord } from './protocol';
import { expiry, jsonBody, op, scope } from './worker';

interface Ledger {
  lookup(attempt: string): Promise<MintRecord | null>;
  claim(plan: MintPlan): Promise<{ started: boolean; record: MintRecord }>;
  observe(attempt: string, digest: string, value: MintObservation): Promise<void>;
  custody(attempt: string, digest: string): Promise<MintRecord>;
  revoked(attempt: string, digest: string): Promise<void>;
}
interface Env {
  WORK_MINT_GATE_ENABLED: string;
  WORK_AUTHORITY_ID: string;
  WORK_ARTIFACTS_ACCOUNT: string;
  WORK_ARTIFACTS_NAMESPACE: string;
  OP_EFFECT_STORE: Fetcher;
  MINT_CHECKPOINT: Ledger;
  ARTIFACTS: Pick<Artifacts, 'get'>;
}
function output(r: MintRecord) {
  return {
    attempt_id: r.plan.attempt_id,
    state: r.state,
    repo_id: r.plan.repo_id,
    cleanup: r.revoke_acknowledged ? 'revoke_acknowledged' : 'unconfirmed',
  };
}
async function synchronized(env: Pick<Env, 'OP_EFFECT_STORE'>, r: MintRecord) {
  let synced = false;
  if (r.state === 'custodied' && r.observation) {
    try {
      const v = await op(env, {
        action: 'mint-status',
        attempt_id: r.plan.attempt_id,
        digest: r.plan.digest,
        ...r.observation,
        key_version: r.plan.key_version,
      });
      synced =
        closed(v, ['id', 'state', 'revision']) &&
        v.id === r.plan.attempt_id &&
        v.state === 'captured' &&
        integer(v.revision) &&
        v.revision >= 3 &&
        v.revision <= 5;
    } catch {
      /* Independent historical observation cannot recreate a lost secret. */
    }
  }
  return { ...output(r), op_synchronized: synced };
}
function identity(info: ArtifactsRepoInfo, p: MintPlan, remote: string) {
  if (
    info.id !== p.repo_id ||
    info.name !== p.name ||
    info.remote !== remote ||
    info.defaultBranch !== (p.role === 'task' ? 'work' : 'snapshot')
  )
    throw new Error('effect_result');
}
function inventory(v: ArtifactsTokenListResult) {
  if (
    !v ||
    !Array.isArray(v.tokens) ||
    !integer(v.total) ||
    v.total !== v.tokens.length ||
    v.total > 8 ||
    new Set(v.tokens.map((t) => t.id)).size !== v.total
  )
    throw new Error('effect_inventory');
  for (const t of v.tokens) {
    if (
      !resource(t.id) ||
      !['read', 'write'].includes(t.scope) ||
      !['active', 'expired', 'revoked'].includes(t.state)
    )
      throw new Error('effect_inventory');
    expiry(t.expiresAt);
  }
  return v.tokens;
}
export class WorkMintGate extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/mint')
      return new Response(null, { status: 404 });
    try {
      if (this.env.WORK_MINT_GATE_ENABLED !== 'true') throw new Error('effect_disabled');
      const input = await jsonBody(request);
      if (!closed(input, ['attempt_id']) || !opaque(input.attempt_id))
        throw new Error('effect_invalid');
      return Response.json(await this.#mint(input.attempt_id), {
        headers: { 'Cache-Control': 'no-store' },
      });
    } catch {
      return Response.json(
        { error: 'effect_unavailable_or_denied' },
        { status: 409, headers: { 'Cache-Control': 'no-store' } },
      );
    }
  }
  async #mint(attempt: string) {
    const env = this.env;
    const previous = await env.MINT_CHECKPOINT.lookup(attempt);
    if (previous) return synchronized(env, previous);
    const p = await op(env, { action: 'mint-plan', attempt_id: attempt });
    mintPlan(p);
    if (p.attempt_id !== attempt) throw new Error('effect_invalid');
    const remote = scope(env, p);
    const admitted = await env.MINT_CHECKPOINT.claim(p);
    if (!admitted.started) return synchronized(env, admitted.record);
    // The durable tombstone precedes every provider call. Even preflight loss
    // retains the slot; no retry, restart, expiry or primary restore re-mints.
    let returned: ArtifactsCreateTokenResult | undefined;
    let observed: MintObservation | undefined;
    let repo: ArtifactsRepo | undefined;
    try {
      repo = await env.ARTIFACTS.get(p.name);
      identity(await repo.info(), p, remote);
      const before = inventory(await repo.listTokens());
      if (before.some((t) => t.state === 'active')) throw new Error('effect_inventory');
      const ttl = Math.min(300, p.deadline - Math.ceil(Date.now() / 1000) - 5);
      if (ttl < 60) throw new Error('effect_deadline');
      returned = await repo.createToken(p.scope, ttl);
      if (
        !resource(returned.id) ||
        returned.scope !== p.scope ||
        typeof returned.plaintext !== 'string' ||
        !/^[\x21-\x7e]{1,4096}$/.test(returned.plaintext)
      )
        throw new Error('effect_result');
      const expires = expiry(returned.expiresAt);
      if (expires <= Math.floor(Date.now() / 1000) || expires > p.deadline)
        throw new Error('effect_deadline');
      identity(await repo.info(), p, remote);
      const after = inventory(await repo.listTokens());
      const t = after.find((t) => t.id === returned!.id);
      if (
        !t ||
        t.state !== 'active' ||
        t.scope !== p.scope ||
        expiry(t.expiresAt) !== expires ||
        after.length !== before.length + 1 ||
        before.some(
          (b) =>
            !after.some(
              (a) =>
                a.id === b.id &&
                a.state === b.state &&
                a.scope === b.scope &&
                a.expiresAt === b.expiresAt,
            ),
        ) ||
        after.some((a) => a.id !== t.id && !before.some((b) => b.id === a.id))
      )
        throw new Error('effect_inventory');
      observed = { repo_id: p.repo_id, token_id: t.id, scope: p.scope, expires_at: expires };
      await env.MINT_CHECKPOINT.observe(attempt, p.digest, observed);
      const captured = await op(env, {
        action: 'capture-mint',
        attempt_id: attempt,
        digest: p.digest,
        ...observed,
        key_version: p.key_version,
        key_fingerprint: p.key_fingerprint,
        plaintext: returned.plaintext,
      });
      if (
        !closed(captured, ['id', 'state', 'revision']) ||
        captured.id !== attempt ||
        captured.state !== 'captured' ||
        !integer(captured.revision) ||
        captured.revision < 3 ||
        captured.revision > 5
      )
        throw new Error('effect_custody');
      return synchronized(env, await env.MINT_CHECKPOINT.custody(attempt, p.digest));
    } catch {
      // A returned bearer is still revocable if result validation/custody fails.
      // Never print provider errors or put plaintext in the independent ledger.
      if (
        repo &&
        returned &&
        typeof returned.plaintext === 'string' &&
        /^[\x21-\x7e]{1,4096}$/.test(returned.plaintext)
      ) {
        let acknowledged = false;
        try {
          acknowledged = (await repo.revokeToken(returned.plaintext)) === true;
        } catch {
          /* retained uncertainty */
        }
        if (observed) {
          if (acknowledged) {
            try {
              await env.MINT_CHECKPOINT.revoked(attempt, p.digest);
            } catch {
              /* retained uncertainty */
            }
          }
          try {
            await op(env, {
              action: 'mint-cleanup',
              attempt_id: attempt,
              digest: p.digest,
              ...observed,
            });
          } catch {
            /* retained liability */
          }
        }
      }
      return {
        attempt_id: attempt,
        state: 'outcome_unknown',
        repo_id: p.repo_id,
        cleanup: 'unconfirmed',
      };
    } finally {
      if (returned) returned.plaintext = '';
      repo?.[Symbol.dispose]();
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
