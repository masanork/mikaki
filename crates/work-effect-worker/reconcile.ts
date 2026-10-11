/** Safety-only recovery of a previously admitted create; no productive methods. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { closed, initialPlan, integer, opaque, resource } from './protocol';
import type { EffectRecord, InitialPlan, RevocationInventory, TokenObservation } from './protocol';
import { expiry, jsonBody, scope, syncClosed } from './worker';
import type { MaintenanceAccess, MaintenanceInfo } from './maintenance';

interface Maintenance {
  lookup(attempt: string): Promise<EffectRecord | null>;
  observe(attempt: string, digest: string, repoId: string): Promise<void>;
  observeToken(attempt: string, digest: string, value: TokenObservation): Promise<EffectRecord>;
  recordRevocation(
    attempt: string,
    digest: string,
    value: RevocationInventory,
  ): Promise<EffectRecord>;
}
export interface Env {
  WORK_EFFECT_RECONCILE_ENABLED: string;
  WORK_AUTHORITY_ID: string;
  WORK_ARTIFACTS_ACCOUNT: string;
  WORK_ARTIFACTS_NAMESPACE: string;
  EFFECT_MAINTENANCE: Maintenance;
  OP_EFFECT_STORE: Fetcher;
  ARTIFACTS_MAINTENANCE: MaintenanceAccess;
}
function matches(info: MaintenanceInfo, p: InitialPlan, remote: string, id: string | null) {
  if (
    !resource(info.id) ||
    (id !== null && info.id !== id) ||
    info.name !== p.name ||
    info.defaultBranch !== (p.role === 'task' ? 'work' : 'snapshot') ||
    info.remote !== remote ||
    info.description !== `mikaki initial ${p.attempt_id}`
  )
    throw new Error('effect_result');
}
function soleToken(value: ArtifactsTokenListResult) {
  if (!value || !Array.isArray(value.tokens) || value.total !== 1 || value.tokens.length !== 1)
    throw new Error('effect_inventory');
  const t = value.tokens[0]!;
  if (!resource(t.id) || t.scope !== 'write' || !['active', 'revoked'].includes(t.state))
    throw new Error('effect_inventory');
  return { id: t.id, expires: expiry(t.expiresAt), state: t.state };
}
async function evidence(
  p: InitialPlan,
  repo: string,
  token: string,
  expires: number,
  method: RevocationInventory['method'],
): Promise<RevocationInventory> {
  const bytes = new TextEncoder().encode(
    JSON.stringify([
      'mikaki-initial-revocation-v1',
      p.digest,
      repo,
      token,
      'write',
      expires,
      method,
    ]),
  );
  const receipt = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('');
  return {
    format_version: 1,
    repo_id: repo,
    token_id: token,
    scope: 'write',
    expires_at: expires,
    receipt,
    method,
  };
}
export class WorkEffectReconciler extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/reconcile')
      return new Response(null, { status: 404 });
    try {
      if (this.env.WORK_EFFECT_RECONCILE_ENABLED !== 'true') throw new Error('effect_disabled');
      const input = await jsonBody(request);
      if (!closed(input, ['attempt_id']) || !opaque(input.attempt_id))
        throw new Error('effect_invalid');
      return Response.json(await this.#reconcile(input.attempt_id), {
        headers: { 'Cache-Control': 'no-store' },
      });
    } catch {
      return Response.json(
        { error: 'effect_unavailable_or_denied' },
        { status: 409, headers: { 'Cache-Control': 'no-store' } },
      );
    }
  }
  async #reconcile(attempt: string) {
    const env = this.env,
      record = await env.EFFECT_MAINTENANCE.lookup(attempt);
    if (!record) throw new Error('effect_not_admitted');
    initialPlan(record.plan);
    const p = record.plan,
      remote = scope(env, p);
    if (p.attempt_id !== attempt) throw new Error('effect_invalid');
    if (record.state === 'closed') return syncClosed(env, record);
    let repoId = record.repo_id;
    try {
      // Absence, an expired lease or a lost get never authorizes another create.
      const repo = await env.ARTIFACTS_MAINTENANCE.open({ attempt_id: attempt });
      try {
        const info = await repo.info();
        matches(info, p, remote, repoId);
        repoId = info.id;
        await env.EFFECT_MAINTENANCE.observe(attempt, p.digest, repoId);
        const inventory = await repo.listTokens();
        let proof = record.cleanup;
        let t: { id: string; expires: number; state: string };
        if (inventory.total === 0 && inventory.tokens.length === 0 && proof) {
          // Absence is usable ONLY with this token's already persisted positive
          // revocation evidence. A lost revoke reply + empty list remains unknown.
          t = { id: proof.token_id, expires: proof.expires_at, state: 'revoked' };
        } else {
          t = soleToken(inventory);
          const known = record.token_observation ?? record.cleanup;
          if (known && (known.token_id !== t.id || known.expires_at !== t.expires))
            throw new Error('effect_inventory');
          await env.EFFECT_MAINTENANCE.observeToken(attempt, p.digest, {
            repo_id: repoId,
            token_id: t.id,
            scope: 'write',
            expires_at: t.expires,
          });
          if (t.state === 'active') {
            if ((await repo.revokeToken(t.id)) !== true)
              throw new Error('effect_revocation_unknown');
            // A successful ID-specific acknowledgement is a control-plane fact;
            // save it BEFORE any later lookup can fail or drop revoked entries.
            const saved = await env.EFFECT_MAINTENANCE.recordRevocation(
              attempt,
              p.digest,
              await evidence(p, repoId, t.id, t.expires, 'revoke_acknowledged'),
            );
            proof = saved.cleanup;
          }
          const after = await repo.listTokens();
          if (!(after.total === 0 && after.tokens.length === 0 && proof)) {
            const a = soleToken(after);
            if (a.state !== 'revoked' || a.id !== t.id || a.expires !== t.expires)
              throw new Error('effect_inventory');
          }
        }
        matches(await repo.info(), p, remote, repoId);
        // Persist independently BEFORE attempting a possibly stale Native OP write.
        await env.EFFECT_MAINTENANCE.recordRevocation(
          attempt,
          p.digest,
          proof
            ? (({ observed_at, ...value }) => value)(proof)
            : await evidence(p, repoId, t.id, t.expires, 'revoked_inventory'),
        );
        let synchronized = false;
        try {
          const r = await env.OP_EFFECT_STORE.fetch('https://private.invalid/effect', {
            method: 'POST',
            body: JSON.stringify({
              action: 'capture-revocation',
              attempt_id: attempt,
              digest: p.digest,
              repo_id: repoId,
              token_id: t.id,
              expires_at: t.expires,
            }),
          });
          if (r.status === 200) {
            const v = await jsonBody(r);
            synchronized =
              closed(v, ['id', 'state', 'revision']) &&
              v.id === attempt &&
              v.state === 'revocation_pending' &&
              integer(v.revision) &&
              v.revision >= 1 &&
              v.revision <= 5;
          }
        } catch {
          /* The durable unknown record and safety evidence survive. */
        }
        return {
          attempt_id: attempt,
          state: 'outcome_unknown',
          repo_id: repoId,
          cleanup: 'initial_token_revoked',
          op_synchronized: synchronized,
        };
      } finally {
        repo[Symbol.dispose]();
      }
    } catch {
      // May have raced the original in-flight operation's stronger refusal proof.
      const latest = await env.EFFECT_MAINTENANCE.lookup(attempt);
      if (latest?.state === 'closed') return syncClosed(env, latest);
      return { attempt_id: attempt, state: 'outcome_unknown', repo_id: repoId };
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
