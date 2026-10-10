/** Recovery only; no physical Artifacts, mint admission, plaintext or Git. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { closed, integer, mintPlan, mintObservation, opaque } from './protocol';
import type { MintPlan, MintRecord, MintCleanup } from './protocol';
import { expiry, jsonBody, scope } from './worker';
import { mintOp as op, synchronizeMintClosure } from './mint-store';
import { inventory } from './maintenance';
import type { MaintenanceAccess } from './maintenance';

interface Maintenance {
  lookup(attempt: string): Promise<MintRecord | null>;
  begin(attempt: string, digest: string): Promise<MintRecord>;
  cancel(attempt: string, digest: string): Promise<MintRecord>;
  revoked(attempt: string, digest: string): Promise<void>;
  record(attempt: string, digest: string, evidence: MintCleanup): Promise<MintRecord>;
}
interface Env {
  WORK_MINT_RECONCILE_ENABLED: string;
  WORK_ARTIFACTS_ACCOUNT: string;
  WORK_ARTIFACTS_NAMESPACE: string;
  WORK_AUTHORITY_ID: string;
  MINT_MAINTENANCE: Maintenance;
  MINT_ARTIFACTS_MAINTENANCE: MaintenanceAccess;
  OP_MINT_STORE: Fetcher;
}
async function evidence(
  p: MintPlan,
  r: MintRecord,
  method: MintCleanup['method'],
): Promise<MintCleanup> {
  const o = r.observation;
  if (!o) throw new Error('effect_unobserved');
  const data = new TextEncoder().encode(
    JSON.stringify([
      'mikaki-mint-cleanup-v1',
      p.digest,
      o.repo_id,
      o.token_id,
      o.scope,
      o.expires_at,
      method,
    ]),
  );
  const receipt = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', data)), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('');
  return { ...o, format_version: 1, method, receipt };
}
async function synchronized(env: Env, r: MintRecord) {
  const o = r.observation;
  let synced = false;
  if (!r.cleanup || !o) throw new Error('effect_unconfirmed');
  try {
    const v = await op(env, {
      action: 'mint-cleanup',
      attempt_id: r.plan.attempt_id,
      digest: r.plan.digest,
      ...o,
    });
    synced =
      closed(v, ['id', 'state', 'revision']) &&
      v.id === r.plan.attempt_id &&
      v.state === 'revocation_pending' &&
      integer(v.revision) &&
      v.revision >= 3 &&
      v.revision <= 5;
  } catch {
    /* Retain independent evidence even when Native is fenced or restored. */
  }
  return {
    attempt_id: r.plan.attempt_id,
    state: 'outcome_unknown',
    repo_id: r.plan.repo_id,
    cleanup: r.cleanup.method,
    op_synchronized: synced,
  };
}
export class WorkMintReconciler extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    const cancel = new URL(request.url).pathname === '/cancel-mint';
    if (
      request.method !== 'POST' ||
      (!cancel && new URL(request.url).pathname !== '/reconcile-mint')
    )
      return new Response(null, { status: 404 });
    try {
      if (this.env.WORK_MINT_RECONCILE_ENABLED !== 'true') throw new Error('effect_disabled');
      const input = await jsonBody(request);
      if (!closed(input, ['attempt_id']) || !opaque(input.attempt_id))
        throw new Error('effect_invalid');
      return Response.json(await this.#reconcile(input.attempt_id, cancel), {
        headers: { 'Cache-Control': 'no-store' },
      });
    } catch {
      return Response.json(
        { error: 'effect_unavailable_or_denied' },
        { status: 409, headers: { 'Cache-Control': 'no-store' } },
      );
    }
  }
  async #reconcile(attempt: string, cancel: boolean) {
    const env = this.env;
    let r = await env.MINT_MAINTENANCE.lookup(attempt);
    if (!r || (!cancel && r.state === 'custodied')) throw new Error('effect_not_recoverable');
    mintPlan(r.plan);
    const p = r.plan;
    scope(env, p);
    if (p.attempt_id !== attempt) throw new Error('effect_invalid');
    if (r.state === 'closed') return synchronizeMintClosure(env, r);
    if (r.cleanup) return synchronized(env, r);
    // Persist safety intent before any provider I/O. An in-flight mint can still
    // return, but cannot complete productive custody after this intent wins.
    r = cancel
      ? await env.MINT_MAINTENANCE.cancel(attempt, p.digest)
      : await env.MINT_MAINTENANCE.begin(attempt, p.digest);
    try {
      const repo = await env.MINT_ARTIFACTS_MAINTENANCE.open({ attempt_id: attempt });
      try {
        const listed = inventory(await repo.listTokens()),
          o = r.observation;
        if (!o)
          return {
            attempt_id: attempt,
            state: 'outcome_unknown',
            repo_id: p.repo_id,
            cleanup: 'token_unobserved',
            op_synchronized: false,
          };
        mintObservation(o);
        const t = listed.tokens.find((t) => t.id === o.token_id);
        let method: MintCleanup['method'];
        if (!t) {
          if (!r.revoke_acknowledged) throw new Error('effect_revocation_unknown');
          method = 'revoke_acknowledged';
        } else {
          if (t.scope !== o.scope || expiry(t.expiresAt) !== o.expires_at)
            throw new Error('effect_inventory');
          if (t.state === 'active') {
            if ((await repo.revokeToken(o.token_id)) !== true)
              throw new Error('effect_revocation_unknown');
            await env.MINT_MAINTENANCE.revoked(attempt, p.digest);
            r = { ...r, revoke_acknowledged: true };
            // Save the acknowledgement before another inventory lookup can fail.
            method = 'revoke_acknowledged';
          } else if (t.state === 'revoked') method = 'revoked_inventory';
          else throw new Error('effect_revocation_unknown');
          const after = inventory(await repo.listTokens()),
            a = after.tokens.find((t) => t.id === o.token_id);
          if (
            a &&
            (a.scope !== o.scope || expiry(a.expiresAt) !== o.expires_at || a.state !== 'revoked')
          )
            throw new Error('effect_inventory');
          if (!a && !r.revoke_acknowledged) throw new Error('effect_revocation_unknown');
        }
        await repo.info(); // Broker checks exact identity again before saving proof.
        return synchronized(
          env,
          await env.MINT_MAINTENANCE.record(attempt, p.digest, await evidence(p, r, method)),
        );
      } finally {
        repo[Symbol.dispose]();
      }
    } catch {
      return {
        attempt_id: attempt,
        state: 'outcome_unknown',
        repo_id: p.repo_id,
        cleanup: 'unconfirmed',
        op_synchronized: false,
      };
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
