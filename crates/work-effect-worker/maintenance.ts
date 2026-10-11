/** Physical Artifacts owner. Returns only fixed-repository safety capabilities. */
import { RpcTarget, WorkerEntrypoint } from 'cloudflare:workers';
import { closed, initialPlan, opaque, resource } from './protocol';
import type { EffectRecord, InitialPlan } from './protocol';
import { expiry, scope } from './worker';

export type MaintenanceInfo = Pick<
  ArtifactsRepoInfo,
  'id' | 'name' | 'description' | 'defaultBranch' | 'remote'
>;
export interface MaintenanceRepository extends Disposable {
  info(): Promise<MaintenanceInfo>;
  listTokens(): Promise<ArtifactsTokenListResult>;
  revokeToken(id: string): Promise<boolean>;
}
export interface MaintenanceAccess {
  open(input: { attempt_id: string }): Promise<MaintenanceRepository>;
}
interface Lookup {
  lookup(attempt: string): Promise<EffectRecord | null>;
}
export interface Env {
  WORK_ARTIFACTS_MAINTENANCE_ENABLED: string;
  WORK_ARTIFACTS_ACCOUNT: string;
  WORK_ARTIFACTS_NAMESPACE: string;
  WORK_AUTHORITY_ID: string;
  EFFECT_LOOKUP: Lookup;
  ARTIFACTS: Artifacts;
}
function checkInfo(
  info: ArtifactsRepoInfo,
  p: InitialPlan,
  remote: string,
  id: string | null,
): MaintenanceInfo {
  if (
    !resource(info.id) ||
    (id !== null && info.id !== id) ||
    info.name !== p.name ||
    info.defaultBranch !== (p.role === 'task' ? 'work' : 'snapshot') ||
    info.remote !== remote ||
    info.description !== `mikaki initial ${p.attempt_id}`
  )
    throw new Error('maintenance_denied');
  // Never forward the provider object or a nested provider RPC capability.
  return {
    id: info.id,
    name: p.name,
    description: info.description,
    defaultBranch: info.defaultBranch,
    remote,
  };
}
function inventory(v: ArtifactsTokenListResult): ArtifactsTokenListResult {
  if (
    !v ||
    !Array.isArray(v.tokens) ||
    !Number.isSafeInteger(v.total) ||
    v.total < 0 ||
    v.total > 8 ||
    v.total !== v.tokens.length ||
    new Set(v.tokens.map((t) => t.id)).size !== v.total
  )
    throw new Error('maintenance_denied');
  return {
    total: v.total,
    tokens: v.tokens.map((t) => {
      if (
        !resource(t.id) ||
        !['read', 'write'].includes(t.scope) ||
        !['active', 'revoked', 'expired'].includes(t.state)
      )
        throw new Error('maintenance_denied');
      expiry(t.createdAt);
      expiry(t.expiresAt);
      return {
        id: t.id,
        scope: t.scope,
        state: t.state,
        createdAt: t.createdAt,
        expiresAt: t.expiresAt,
      };
    }),
  };
}
class RepositorySafety extends RpcTarget implements MaintenanceRepository {
  #repo: ArtifactsRepo;
  #lookup: Lookup;
  #plan: InitialPlan;
  #remote: string;
  #id: string;
  #disposed = false;
  constructor(repo: ArtifactsRepo, lookup: Lookup, plan: InitialPlan, remote: string, id: string) {
    super();
    this.#repo = repo;
    this.#lookup = lookup;
    this.#plan = plan;
    this.#remote = remote;
    this.#id = id;
  }
  async #current() {
    if (this.#disposed) throw new Error('maintenance_denied');
    const r = await this.#lookup.lookup(this.#plan.attempt_id);
    if (
      !r ||
      r.state !== 'outcome_unknown' ||
      JSON.stringify(r.plan) !== JSON.stringify(this.#plan) ||
      (r.repo_id !== null && r.repo_id !== this.#id)
    )
      throw new Error('maintenance_denied');
    return r;
  }
  async #identity() {
    const record = await this.#current();
    const info = checkInfo(await this.#repo.info(), this.#plan, this.#remote, this.#id);
    return { record, info };
  }
  async info() {
    return (await this.#identity()).info;
  }
  async listTokens() {
    await this.#identity();
    return inventory(await this.#repo.listTokens());
  }
  async revokeToken(input: unknown) {
    if (!resource(input)) throw new Error('maintenance_denied');
    const { record } = await this.#identity(),
      observed = record.token_observation;
    // The caller can neither revoke plaintext nor choose an unrelated token.
    if (
      !observed ||
      record.repo_id !== this.#id ||
      observed.repo_id !== this.#id ||
      observed.token_id !== input ||
      observed.scope !== 'write'
    )
      throw new Error('maintenance_denied');
    const listed = inventory(await this.#repo.listTokens()),
      t = listed.tokens[0];
    if (
      listed.total !== 1 ||
      !t ||
      t.id !== input ||
      t.scope !== 'write' ||
      t.state !== 'active' ||
      expiry(t.expiresAt) !== observed.expires_at
    )
      throw new Error('maintenance_denied');
    await this.#identity();
    return this.#repo.revokeToken(input);
  }
  [Symbol.dispose]() {
    if (!this.#disposed) {
      this.#disposed = true;
      this.#repo[Symbol.dispose]();
    }
  }
}
export class WorkArtifactsMaintenance extends WorkerEntrypoint<Env> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  async open(input: unknown) {
    if (
      this.env.WORK_ARTIFACTS_MAINTENANCE_ENABLED !== 'true' ||
      !closed(input, ['attempt_id']) ||
      !opaque(input.attempt_id)
    )
      throw new Error('maintenance_denied');
    const r = await this.env.EFFECT_LOOKUP.lookup(input.attempt_id);
    if (!r || r.state !== 'outcome_unknown') throw new Error('maintenance_denied');
    initialPlan(r.plan);
    if (r.plan.attempt_id !== input.attempt_id || !(r.repo_id === null || resource(r.repo_id)))
      throw new Error('maintenance_denied');
    const remote = scope(this.env, r.plan),
      repo = await this.env.ARTIFACTS.get(r.plan.name);
    try {
      const info = checkInfo(await repo.info(), r.plan, remote, r.repo_id);
      return new RepositorySafety(repo, this.env.EFFECT_LOOKUP, r.plan, remote, info.id);
    } catch {
      repo[Symbol.dispose]();
      throw new Error('maintenance_denied');
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
