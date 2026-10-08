/** Physical Artifacts owner; fixed known-ID cleanup, without mint/Git/release. */
import { RpcTarget, WorkerEntrypoint } from 'cloudflare:workers';
import { closed, mintPlan, opaque, resource } from './protocol';
import type { MintPlan, MintRecord } from './protocol';
import { expiry, scope } from './worker';
import { inventory } from './maintenance';
import type { MaintenanceInfo, MaintenanceRepository } from './maintenance';

interface Lookup {
  lookup(attempt: string): Promise<MintRecord | null>;
}
interface Env {
  WORK_MINT_MAINTENANCE_ENABLED: string;
  WORK_ARTIFACTS_ACCOUNT: string;
  WORK_ARTIFACTS_NAMESPACE: string;
  WORK_AUTHORITY_ID: string;
  MINT_LOOKUP: Lookup;
  ARTIFACTS: Artifacts;
}
function identity(info: ArtifactsRepoInfo, p: MintPlan, remote: string): MaintenanceInfo {
  if (
    info.id !== p.repo_id ||
    info.name !== p.name ||
    info.defaultBranch !== (p.role === 'task' ? 'work' : 'snapshot') ||
    info.remote !== remote ||
    info.description !== `mikaki initial ${p.initial_attempt_id}`
  )
    throw new Error('maintenance_denied');
  return {
    id: info.id,
    name: info.name,
    defaultBranch: info.defaultBranch,
    remote,
    description: info.description,
  };
}
class MintSafety extends RpcTarget implements MaintenanceRepository {
  #repo: ArtifactsRepo;
  #lookup: Lookup;
  #plan: MintPlan;
  #remote: string;
  #disposed = false;
  constructor(repo: ArtifactsRepo, lookup: Lookup, p: MintPlan, remote: string) {
    super();
    this.#repo = repo;
    this.#lookup = lookup;
    this.#plan = p;
    this.#remote = remote;
  }
  async #current() {
    if (this.#disposed) throw new Error('maintenance_denied');
    const r = await this.#lookup.lookup(this.#plan.attempt_id);
    if (
      !r ||
      r.state !== 'outcome_unknown' ||
      r.cleanup ||
      JSON.stringify(r.plan) !== JSON.stringify(this.#plan)
    )
      throw new Error('maintenance_denied');
    return r;
  }
  async #identity() {
    const r = await this.#current();
    const info = identity(await this.#repo.info(), this.#plan, this.#remote);
    await this.#current();
    return { r, info };
  }
  async info() {
    return (await this.#identity()).info;
  }
  async listTokens() {
    await this.#identity();
    const result = inventory(await this.#repo.listTokens());
    await this.#identity();
    return result;
  }
  async revokeToken(input: unknown) {
    if (!resource(input)) throw new Error('maintenance_denied');
    const { r } = await this.#identity(),
      o = r.observation;
    if (
      !r.cleanup_requested ||
      !o ||
      input !== o.token_id ||
      o.repo_id !== this.#plan.repo_id ||
      o.scope !== this.#plan.scope
    )
      throw new Error('maintenance_denied');
    const listed = inventory(await this.#repo.listTokens()),
      t = listed.tokens.find((t) => t.id === input);
    if (!t || t.scope !== o.scope || t.state !== 'active' || expiry(t.expiresAt) !== o.expires_at)
      throw new Error('maintenance_denied');
    const current = await this.#identity();
    if (!current.r.cleanup_requested || current.r.observation?.token_id !== input)
      throw new Error('maintenance_denied');
    return this.#repo.revokeToken(input);
  }
  [Symbol.dispose]() {
    if (!this.#disposed) {
      this.#disposed = true;
      this.#repo[Symbol.dispose]();
    }
  }
}
export class WorkMintArtifactsMaintenance extends WorkerEntrypoint<Env> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  async open(input: unknown) {
    if (
      this.env.WORK_MINT_MAINTENANCE_ENABLED !== 'true' ||
      !closed(input, ['attempt_id']) ||
      !opaque(input.attempt_id)
    )
      throw new Error('maintenance_denied');
    const r = await this.env.MINT_LOOKUP.lookup(input.attempt_id);
    if (!r || r.state !== 'outcome_unknown' || r.cleanup) throw new Error('maintenance_denied');
    mintPlan(r.plan);
    if (r.plan.attempt_id !== input.attempt_id) throw new Error('maintenance_denied');
    const remote = scope(this.env, r.plan),
      repo = await this.env.ARTIFACTS.get(r.plan.name);
    try {
      identity(await repo.info(), r.plan, remote);
      return new MintSafety(repo, this.env.MINT_LOOKUP, r.plan, remote);
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
