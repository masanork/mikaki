/** Private, one-shot initial repo create. No productive credential release. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { closed, initialPlan, integer, opaque, resource } from './protocol';
import type { InitialPlan, Closure, EffectRecord } from './protocol';

interface Ledger {
  lookup(attempt: string): Promise<EffectRecord | null>;
  claim(plan: InitialPlan): Promise<{ started: boolean; record: EffectRecord }>;
  observe(attempt: string, digest: string, repoId: string): Promise<void>;
  close(attempt: string, digest: string, value: Closure): Promise<EffectRecord>;
}
export interface Env {
  WORK_EFFECT_GATE_ENABLED: string;
  WORK_AUTHORITY_ID: string;
  WORK_ARTIFACTS_ACCOUNT: string;
  WORK_ARTIFACTS_NAMESPACE: string;
  OP_EFFECT_STORE: Fetcher;
  EFFECT_CHECKPOINT: Ledger;
  ARTIFACTS: Pick<Artifacts, 'create' | 'get'>;
}
export async function jsonBody(response: Request | Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('effect_invalid');
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 4096) {
        await reader.cancel();
        throw new Error('effect_invalid');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return JSON.parse(
    new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes),
  ) as unknown;
}
export async function op(env: Pick<Env, 'OP_EFFECT_STORE'>, input: Record<string, unknown>) {
  const response = await env.OP_EFFECT_STORE.fetch('https://private.invalid/effect', {
    method: 'POST',
    body: JSON.stringify(input),
  });
  if (response.status !== 200) throw new Error('effect_store_unavailable');
  return jsonBody(response);
}
export function scope(
  env: Pick<Env, 'WORK_ARTIFACTS_ACCOUNT' | 'WORK_ARTIFACTS_NAMESPACE' | 'WORK_AUTHORITY_ID'>,
  p: Pick<InitialPlan, 'namespace' | 'name' | 'checkpoint'>,
) {
  if (
    !/^[a-f0-9]{32}$/.test(env.WORK_ARTIFACTS_ACCOUNT) ||
    p.namespace !== env.WORK_ARTIFACTS_NAMESPACE ||
    p.checkpoint.authority !== env.WORK_AUTHORITY_ID
  )
    throw new Error('effect_scope');
  return `https://${env.WORK_ARTIFACTS_ACCOUNT}.artifacts.cloudflare.net/git/${p.namespace}/${p.name}.git`;
}
function tokenInfo(value: ArtifactsTokenListResult): ArtifactsTokenInfo {
  if (!value || !Array.isArray(value.tokens) || value.total !== 1 || value.tokens.length !== 1)
    throw new Error('effect_inventory');
  const t = value.tokens[0]!;
  if (!resource(t.id) || t.scope !== 'write' || t.state !== 'active')
    throw new Error('effect_inventory');
  expiry(t.expiresAt);
  return t;
}
export function expiry(value: string) {
  if (typeof value !== 'string' || value.length > 40 || !/^\d{4}-\d\d-\d\dT/.test(value))
    throw new Error('effect_inventory');
  // Preserve fractional ISO timestamps without ever declaring expiry early.
  const n = Math.ceil(Date.parse(value) / 1000);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('effect_inventory');
  return n;
}
async function receipt(plan: InitialPlan, repo: string, token: string, expires: number) {
  const bytes = new TextEncoder().encode(
    JSON.stringify(['mikaki-initial-refusal-v1', plan.digest, repo, token, expires, 403]),
  );
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('');
}
export async function syncClosed(env: Pick<Env, 'OP_EFFECT_STORE'>, record: EffectRecord) {
  const c = record.closure;
  if (!c) throw new Error('effect_invalid');
  let synchronized = false;
  try {
    const value = await op(env, {
      action: 'capture-closed',
      attempt_id: record.plan.attempt_id,
      ...c,
    });
    synchronized =
      closed(value, ['id', 'state', 'revision']) &&
      value.id === record.plan.attempt_id &&
      value.state === 'closed' &&
      integer(value.revision) &&
      value.revision >= 1 &&
      value.revision <= 5;
  } catch {
    /* Independent cleanup evidence survives stale/unavailable OP. */
  }
  return {
    attempt_id: record.plan.attempt_id,
    state: 'closed',
    repo_id: c.repo_id,
    op_synchronized: synchronized,
  };
}
export class WorkEffectGate extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/initial')
      return new Response(null, { status: 404 });
    try {
      if (this.env.WORK_EFFECT_GATE_ENABLED !== 'true') throw new Error('effect_disabled');
      const input = await jsonBody(request);
      if (!closed(input, ['attempt_id']) || !opaque(input.attempt_id))
        throw new Error('effect_invalid');
      return Response.json(await this.#executeInitial(input.attempt_id), {
        headers: { 'Cache-Control': 'no-store' },
      });
    } catch {
      return Response.json(
        { error: 'effect_unavailable_or_denied' },
        { status: 409, headers: { 'Cache-Control': 'no-store' } },
      );
    }
  }
  async #executeInitial(attempt: string) {
    const env = this.env;
    const previous = await env.EFFECT_CHECKPOINT.lookup(attempt);
    if (previous) {
      if (previous.state === 'closed') return syncClosed(env, previous);
      return { attempt_id: attempt, state: 'outcome_unknown', repo_id: previous.repo_id };
    }
    const plan = await op(env, { action: 'initial-plan', attempt_id: attempt });
    initialPlan(plan);
    if (plan.attempt_id !== attempt) throw new Error('effect_invalid');
    const remote = scope(env, plan),
      branch = plan.role === 'task' ? 'work' : 'snapshot';
    const claim = await env.EFFECT_CHECKPOINT.claim(plan);
    if (!claim.started) {
      if (claim.record.state === 'closed') return syncClosed(env, claim.record);
      return { attempt_id: attempt, state: 'outcome_unknown', repo_id: claim.record.repo_id };
    }
    // Durable admission is the linearization point. A crash/lost reply NEVER
    // authorizes another create; revocation may race an already admitted call.
    let repoId: string | null = null;
    try {
      const created = await env.ARTIFACTS.create(plan.name, {
        setDefaultBranch: branch,
        description: `mikaki initial ${attempt}`,
      });
      const creationMatches =
        resource(created.id) &&
        created.name === plan.name &&
        created.defaultBranch === branch &&
        created.remote === remote;
      if (creationMatches) repoId = created.id;
      if (typeof created.token !== 'string' || !/^[\x21-\x7e]{1,4096}$/.test(created.token))
        throw new Error('effect_result');
      const repo = await env.ARTIFACTS.get(plan.name);
      try {
        let token: ArtifactsTokenInfo | undefined;
        try {
          if (!creationMatches) throw new Error('effect_result');
          const info = await repo.info();
          if (
            info.id !== created.id ||
            info.name !== plan.name ||
            info.defaultBranch !== branch ||
            info.remote !== remote
          )
            throw new Error('effect_result');
          repoId = created.id;
          await env.EFFECT_CHECKPOINT.observe(attempt, plan.digest, repoId);
          token = tokenInfo(await repo.listTokens());
        } finally {
          // Revoke the returned plaintext even when metadata validation fails.
          // This secret never enters D1, DO storage, receipts, logs or outputs.
          await repo.revokeToken(created.token);
        }
        if (!token) throw new Error('effect_inventory');
        const after = await repo.listTokens();
        if (
          !after ||
          !Array.isArray(after.tokens) ||
          !Number.isSafeInteger(after.total) ||
          after.total !== after.tokens.length ||
          after.total > 8 ||
          new Set(after.tokens.map((t) => t.id)).size !== after.total ||
          after.tokens.some(
            (t) =>
              !resource(t.id) ||
              !['read', 'write'].includes(t.scope) ||
              !['active', 'expired', 'revoked'].includes(t.state) ||
              t.state === 'active',
          ) ||
          after.tokens.some(
            (t) => t.id !== token.id || t.scope !== token.scope || t.expiresAt !== token.expiresAt,
          )
        )
          throw new Error('effect_inventory');
        // Revoke success and metadata alone never certify bearer refusal. Probe
        // the exact configured Git endpoint, send the secret only in a header,
        // refuse redirects, and cancel all response content before any output.
        const refused = await fetch(`${remote}/info/refs?service=git-upload-pack`, {
          headers: { Authorization: `Bearer ${created.token}` },
          redirect: 'manual',
          signal: AbortSignal.timeout(5000),
        });
        await refused.body?.cancel();
        if (refused.status !== 403) throw new Error('effect_refusal_unknown');
        const finalInfo = await repo.info();
        if (
          finalInfo.id !== created.id ||
          finalInfo.name !== plan.name ||
          finalInfo.defaultBranch !== branch ||
          finalInfo.remote !== remote
        )
          throw new Error('effect_result');
        const expires = expiry(token.expiresAt);
        const c: Closure = {
          repo_id: created.id,
          token_id: token.id,
          expires_at: expires,
          receipt: await receipt(plan, created.id, token.id, expires),
        };
        const record = await env.EFFECT_CHECKPOINT.close(attempt, plan.digest, c);
        return syncClosed(env, record);
      } finally {
        repo[Symbol.dispose]();
      }
    } catch {
      // Preserve a validated creation ID even if the disposable get reply was
      // lost. This safety-only write neither repeats I/O nor releases a token.
      if (repoId !== null) {
        try {
          await env.EFFECT_CHECKPOINT.observe(attempt, plan.digest, repoId);
        } catch {
          /* Keep the durable unknown claim. */
        }
      }
      // Cleanup is an obligation, not permission to repeat the productive call.
      return { attempt_id: attempt, state: 'outcome_unknown', repo_id: repoId };
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
