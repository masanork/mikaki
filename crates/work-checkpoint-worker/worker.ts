/** Private write-ahead checkpoint. No D1, credential, Git or public capability. */
import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';
import {
  initialPlan,
  closure,
  opaque,
  hex,
  resource,
  revocationInventory,
  tokenObservation,
  mintPlan,
  mintObservation,
  mintCleanup,
  mintRefusal,
  gitPlan,
  gitResult,
} from '../work-effect-worker/protocol';
import type { InitialPlan, Closure, EffectRecord } from '../work-effect-worker/protocol';
import type { MintPlan, MintRecord, GitPlan, GitResult } from '../work-effect-worker/protocol';

export type Checkpoint = { authority: string; epoch: string; sequence: number; tip: string };
export type Permit = { operation: string; previous: Checkpoint; next: Checkpoint };
type State = {
  checkpoint: Checkpoint;
  pending: Permit | null;
  last: Permit | null;
  release_floor: number;
  frozen: boolean;
};
export interface Env {
  CHECKPOINTS: DurableObjectNamespace<WorkCheckpoint>;
  WORK_AUTHORITY_ID: string;
}
const id = (v: unknown): v is string => typeof v === 'string' && /^[a-zA-Z0-9_.:-]{1,128}$/.test(v);
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const integer = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
const closed = (v: unknown, keys: string[]): v is Record<string, unknown> =>
  typeof v === 'object' &&
  v !== null &&
  !Array.isArray(v) &&
  Object.keys(v).sort().join(',') === keys.sort().join(',');
function checkpoint(v: unknown): asserts v is Checkpoint {
  if (
    !closed(v, ['authority', 'epoch', 'sequence', 'tip']) ||
    !id(v.authority) ||
    !digest(v.epoch) ||
    !integer(v.sequence) ||
    !digest(v.tip)
  )
    throw new Error('checkpoint_invalid');
}
function permit(v: unknown): asserts v is Permit {
  if (!closed(v, ['operation', 'previous', 'next']) || !id(v.operation))
    throw new Error('checkpoint_invalid');
  checkpoint(v.previous);
  checkpoint(v.next);
  if (
    v.next.authority !== v.previous.authority ||
    v.next.epoch !== v.previous.epoch ||
    v.next.sequence !== v.previous.sequence + 1 ||
    v.next.tip === v.previous.tip
  )
    throw new Error('checkpoint_invalid');
}
const equal = (a: Checkpoint, b: Checkpoint) =>
  a.authority === b.authority &&
  a.epoch === b.epoch &&
  a.sequence === b.sequence &&
  a.tip === b.tip;
const same = (a: Permit, b: Permit) =>
  a.operation === b.operation && equal(a.previous, b.previous) && equal(a.next, b.next);
const random = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('');

export class WorkCheckpoint extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Synchronous SQLite setup only; never hold an input gate across service I/O.
    this.ctx.storage.sql.exec(
      'CREATE TABLE IF NOT EXISTS checkpoint_state(id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)',
    );
    this.ctx.storage.sql.exec(
      'CREATE TABLE IF NOT EXISTS effect_ledger(attempt_id TEXT PRIMARY KEY, body TEXT NOT NULL)',
    );
    this.ctx.storage.sql.exec(
      'CREATE TABLE IF NOT EXISTS mint_ledger(attempt_id TEXT PRIMARY KEY, slot TEXT UNIQUE NOT NULL, body TEXT NOT NULL)',
    );
  }
  private state(): State {
    const rows = this.ctx.storage.sql
      .exec<{ body: string }>('SELECT body FROM checkpoint_state WHERE id=1')
      .toArray();
    if (rows.length !== 1) throw new Error('checkpoint_uninitialized');
    return JSON.parse(rows[0]!.body) as State;
  }
  private save(state: State) {
    this.ctx.storage.sql.exec(
      'INSERT OR REPLACE INTO checkpoint_state VALUES(1,?)',
      JSON.stringify(state),
    );
  }
  private current(release: unknown): State {
    const s = this.state();
    if (!integer(release) || release < s.release_floor || s.frozen)
      throw new Error('checkpoint_blocked');
    return s;
  }
  async bootstrap(initial: unknown, releaseFloor: unknown) {
    checkpoint(initial);
    if (
      initial.authority !== this.env.WORK_AUTHORITY_ID ||
      initial.sequence !== 0 ||
      !integer(releaseFloor) ||
      releaseFloor < 1
    )
      throw new Error('checkpoint_invalid');
    this.ctx.storage.transactionSync(() => {
      if (this.ctx.storage.sql.exec('SELECT id FROM checkpoint_state').toArray().length)
        throw new Error('checkpoint_already_initialized');
      this.save({
        checkpoint: initial,
        pending: null,
        last: null,
        release_floor: releaseFloor,
        frozen: false,
      });
    });
    await this.ctx.storage.sync();
    return initial;
  }
  async status(release: unknown) {
    const s = this.current(release);
    await this.ctx.storage.sync();
    return s;
  }
  async begin(expected: unknown, operation: unknown, release: unknown) {
    checkpoint(expected);
    if (!id(operation)) throw new Error('checkpoint_invalid');
    const result = this.ctx.storage.transactionSync(() => {
      const s = this.current(release);
      if (s.pending) {
        if (s.pending.operation === operation && equal(s.pending.previous, expected))
          return s.pending;
        throw new Error('checkpoint_pending');
      }
      if (
        !equal(s.checkpoint, expected) ||
        expected.authority !== this.env.WORK_AUTHORITY_ID ||
        expected.sequence === Number.MAX_SAFE_INTEGER
      )
        throw new Error('checkpoint_mismatch');
      const p: Permit = {
        operation,
        previous: expected,
        next: { ...expected, sequence: expected.sequence + 1, tip: random() },
      };
      s.pending = p;
      this.save(s);
      return p;
    });
    await this.ctx.storage.sync();
    return result;
  }
  async commit(plan: unknown, observed: unknown, release: unknown) {
    permit(plan);
    checkpoint(observed);
    const result = this.ctx.storage.transactionSync(() => {
      const s = this.current(release);
      if (!equal(observed, plan.next)) throw new Error('checkpoint_mismatch');
      if (!s.pending) {
        if (s.last && same(s.last, plan) && equal(s.checkpoint, plan.next)) return s.checkpoint;
        throw new Error('checkpoint_mismatch');
      }
      if (!same(s.pending, plan)) throw new Error('checkpoint_mismatch');
      s.checkpoint = plan.next;
      s.last = plan;
      s.pending = null;
      this.save(s);
      return s.checkpoint;
    });
    await this.ctx.storage.sync();
    return result;
  }
  async raiseFloor(value: unknown) {
    if (!integer(value) || value < 1) throw new Error('checkpoint_invalid');
    this.ctx.storage.transactionSync(() => {
      const s = this.state();
      if (value < s.release_floor) throw new Error('checkpoint_downgrade');
      s.release_floor = value;
      this.save(s);
    });
    await this.ctx.storage.sync();
  }
  async freeze() {
    this.ctx.storage.transactionSync(() => {
      const s = this.state();
      s.frozen = true;
      this.save(s);
    });
    await this.ctx.storage.sync();
  }
  private effect(attempt: unknown): EffectRecord | null {
    if (!opaque(attempt)) throw new Error('effect_invalid');
    const rows = this.ctx.storage.sql
      .exec<{ body: string }>('SELECT body FROM effect_ledger WHERE attempt_id=?', attempt)
      .toArray();
    return rows.length ? (JSON.parse(rows[0]!.body) as EffectRecord) : null;
  }
  private saveEffect(record: EffectRecord) {
    this.ctx.storage.sql.exec(
      'INSERT OR REPLACE INTO effect_ledger VALUES(?,?)',
      record.plan.attempt_id,
      JSON.stringify(record),
    );
  }
  async lookupEffect(attempt: unknown) {
    const record = this.effect(attempt);
    await this.ctx.storage.sync();
    return record;
  }
  #mint(attempt: unknown): MintRecord | null {
    if (!opaque(attempt)) throw new Error('effect_invalid');
    const rows = this.ctx.storage.sql
      .exec<{ body: string }>('SELECT body FROM mint_ledger WHERE attempt_id=?', attempt)
      .toArray();
    return rows.length ? (JSON.parse(rows[0]!.body) as MintRecord) : null;
  }
  #saveMint(r: MintRecord) {
    this.ctx.storage.sql.exec(
      'INSERT OR REPLACE INTO mint_ledger VALUES(?,?,?)',
      r.plan.attempt_id,
      JSON.stringify([r.plan.namespace, r.plan.name, r.plan.purpose]),
      JSON.stringify(r),
    );
  }
  async lookupMint(attempt: unknown) {
    const r = this.#mint(attempt);
    await this.ctx.storage.sync();
    return r;
  }
  /** Read-only, bounded projection. Closed records are retained and immutable;
   * no permit, framing, maintenance, secret or physical repository is returned. */
  async preparationEvidence(input: unknown) {
    if (
      !closed(input, ['attempts']) ||
      !Array.isArray(input.attempts) ||
      input.attempts.length !== 6
    )
      throw new Error('preparation_invalid');
    const seen = new Set<string>();
    const initial: { plan: InitialPlan; closure: Closure }[] = [];
    const mint: {
      plan: MintPlan;
      observation: NonNullable<MintRecord['observation']>;
      refusal: Omit<NonNullable<MintRecord['refusal']>, 'observed_at'>;
      git: { plan: GitPlan; result: GitResult };
    }[] = [];
    // All reads run synchronously in this turn before the durability wait.
    for (const a of input.attempts) {
      if (!closed(a, ['attempt_id', 'purpose']) || !opaque(a.attempt_id) || seen.has(a.attempt_id))
        throw new Error('preparation_invalid');
      seen.add(a.attempt_id);
      if (a.purpose === 'initial') {
        const r = this.effect(a.attempt_id);
        if (!r || r.state !== 'closed' || !r.closure) throw new Error('preparation_incomplete');
        initialPlan(r.plan);
        closure(r.closure);
        initial.push({ plan: r.plan, closure: r.closure });
      } else {
        const r = this.#mint(a.attempt_id);
        if (
          !r ||
          r.plan.purpose !== a.purpose ||
          r.state !== 'closed' ||
          !r.refusal ||
          !r.observation ||
          r.git?.state !== 'completed' ||
          !r.git.result
        )
          throw new Error('preparation_incomplete');
        mintPlan(r.plan);
        mintObservation(r.observation);
        const { observed_at: _at, ...refusal } = r.refusal;
        mintRefusal(refusal);
        gitPlan(r.git.plan);
        gitResult(r.git.result, r.git.plan);
        mint.push({
          plan: r.plan,
          observation: r.observation,
          refusal,
          git: { plan: r.git.plan, result: r.git.result },
        });
      }
    }
    if (initial.length !== 2 || mint.length !== 4) throw new Error('preparation_incomplete');
    await this.ctx.storage.sync();
    return { format_version: 1, initial, mint };
  }
  async claimGit(input: unknown) {
    gitPlan(input);
    const result = this.ctx.storage.transactionSync(() => {
      const s = this.current(1),
        r = this.#mint(input.attempt_id);
      if (
        s.pending ||
        !equal(s.checkpoint, input.checkpoint) ||
        !r ||
        r.state !== 'custodied' ||
        r.cleanup_requested ||
        !r.observation ||
        input.observation.expires_at <= Math.floor(Date.now() / 1000) + 5 ||
        input.deadline <= Math.floor(Date.now() / 1000) + 5
      )
        throw new Error('git_blocked');
      const { checkpoint: _a, ...a } = r.plan;
      const {
        checkpoint: _b,
        preparation_digest: _p,
        disclosure_digest: _d,
        commit: _c,
        tree: _t,
        branch: _r,
        observation: _o,
        ...b
      } = input;
      if (
        !sameJson(a, { ...b, effect: 'token.mint' }) ||
        !sameJson(r.observation, input.observation)
      )
        throw new Error('git_conflict');
      if (r.git) {
        if (!sameJson(r.git.plan, input)) throw new Error('git_conflict');
        return { started: false, record: r };
      }
      if (input.purpose === 'readback') {
        const rows = this.ctx.storage.sql
          .exec<{ body: string }>(
            'SELECT body FROM mint_ledger WHERE slot=?',
            JSON.stringify([input.namespace, input.name, 'upload']),
          )
          .toArray();
        const upload = rows.length ? (JSON.parse(rows[0]!.body) as MintRecord) : null;
        if (
          !upload ||
          upload.state !== 'closed' ||
          !upload.refusal ||
          upload.git?.state !== 'completed' ||
          !upload.git.result ||
          upload.plan.repo_id !== input.repo_id ||
          upload.git.plan.preparation_digest !== input.preparation_digest ||
          upload.git.plan.disclosure_digest !== input.disclosure_digest ||
          upload.git.plan.commit !== input.commit ||
          upload.git.plan.tree !== input.tree ||
          upload.git.plan.branch !== input.branch
        )
          throw new Error('git_upload_not_closed');
      }
      r.git = { plan: input, state: 'admitted', result: null };
      this.#saveMint(r);
      return { started: true, record: r };
    });
    await this.ctx.storage.sync();
    return result;
  }
  async takeGit(input: unknown, transport = false) {
    gitPlan(input);
    this.ctx.storage.transactionSync(() => {
      const s = this.current(1),
        r = this.#mint(input.attempt_id);
      if (
        s.pending ||
        !equal(s.checkpoint, input.checkpoint) ||
        !r ||
        r.state !== 'custodied' ||
        r.cleanup_requested ||
        !r.git ||
        !sameJson(r.git.plan, input) ||
        r.git.state !== (transport ? 'dispatching' : 'admitted') ||
        input.observation.expires_at <= Math.floor(Date.now() / 1000) + 5
      )
        throw new Error('git_blocked');
      r.git.state = transport ? 'outcome_unknown' : 'dispatching';
      this.#saveMint(r);
    });
    await this.ctx.storage.sync();
    return { taken: true };
  }
  async finishGit(attempt: unknown, input: unknown) {
    const result = this.ctx.storage.transactionSync(() => {
      const r = this.#mint(attempt);
      if (!r || !r.git || r.state === 'closed') throw new Error('git_conflict');
      if (input !== null) {
        gitResult(input, r.git.plan);
        if (r.git.state !== 'outcome_unknown' && r.git.state !== 'completed')
          throw new Error('git_conflict');
        if (r.git.result && !sameJson(r.git.result, input)) throw new Error('git_conflict');
        r.git.result = input;
        r.git.state = 'completed';
      }
      r.cleanup_requested = true;
      r.state = 'outcome_unknown';
      this.#saveMint(r);
      return r;
    });
    await this.ctx.storage.sync();
    return result;
  }
  async claimMint(input: unknown, release: unknown) {
    mintPlan(input);
    const result = this.ctx.storage.transactionSync(() => {
      const s = this.current(release);
      if (
        s.pending ||
        !equal(s.checkpoint, input.checkpoint) ||
        input.checkpoint.authority !== this.env.WORK_AUTHORITY_ID ||
        input.deadline <= Math.floor(Date.now() / 1000) + 65
      )
        throw new Error('effect_blocked');
      const initial = this.effect(input.initial_attempt_id);
      if (
        !initial ||
        initial.state !== 'closed' ||
        initial.closure?.repo_id !== input.repo_id ||
        initial.plan.namespace !== input.namespace ||
        initial.plan.name !== input.name ||
        initial.plan.role !== input.role ||
        initial.plan.deadline !== input.deadline
      )
        throw new Error('effect_initial_not_closed');
      const previous = this.#mint(input.attempt_id);
      if (previous) {
        // Checkpoint may advance between retries; immutable intent and custody
        // key cannot change. A retry receives no second external permit.
        const { checkpoint: _a, ...a } = previous.plan,
          { checkpoint: _b, ...b } = input;
        if (JSON.stringify(Object.entries(a).sort()) !== JSON.stringify(Object.entries(b).sort()))
          throw new Error('effect_conflict');
        return { started: false, record: previous };
      }
      const n = this.ctx.storage.sql
        .exec<{ n: number }>(
          'SELECT (SELECT count(*) FROM effect_ledger)+(SELECT count(*) FROM mint_ledger) AS n',
        )
        .one().n;
      if (n >= 256) throw new Error('effect_capacity');
      const r: MintRecord = {
        plan: input,
        state: 'outcome_unknown',
        observation: null,
        revoke_acknowledged: false,
      };
      // The unique permanent slot prevents new attempt IDs after primary restore.
      this.ctx.storage.sql.exec(
        'INSERT INTO mint_ledger VALUES(?,?,?)',
        input.attempt_id,
        JSON.stringify([input.namespace, input.name, input.purpose]),
        JSON.stringify(r),
      );
      return { started: true, record: r };
    });
    await this.ctx.storage.sync();
    return result;
  }
  async observeMint(attempt: unknown, digest: unknown, input: unknown) {
    mintObservation(input);
    this.ctx.storage.transactionSync(() => {
      const r = this.#mint(attempt);
      if (
        !r ||
        r.plan.digest !== digest ||
        r.plan.repo_id !== input.repo_id ||
        r.plan.scope !== input.scope ||
        input.expires_at > r.plan.deadline ||
        (r.observation &&
          (r.observation.token_id !== input.token_id ||
            r.observation.scope !== input.scope ||
            r.observation.expires_at !== input.expires_at))
      )
        throw new Error('effect_conflict');
      r.observation = input;
      this.#saveMint(r);
    });
    await this.ctx.storage.sync();
  }
  async custodyMint(attempt: unknown, digest: unknown) {
    const result = this.ctx.storage.transactionSync(() => {
      const r = this.#mint(attempt);
      if (
        !r ||
        r.plan.digest !== digest ||
        r.state === 'closed' ||
        !r.observation ||
        r.revoke_acknowledged ||
        r.cleanup_requested
      )
        throw new Error('effect_conflict');
      // Custody is a result observation, never copy verification or release.
      r.state = 'custodied';
      this.#saveMint(r);
      return r;
    });
    await this.ctx.storage.sync();
    return result;
  }
  async revokeMint(attempt: unknown, digest: unknown, safety = false) {
    this.ctx.storage.transactionSync(() => {
      const r = this.#mint(attempt);
      if (
        !r ||
        r.plan.digest !== digest ||
        r.state === 'closed' ||
        !r.observation ||
        (safety && (!r.cleanup_requested || r.state !== 'outcome_unknown'))
      )
        throw new Error('effect_conflict');
      r.revoke_acknowledged = true;
      r.cleanup_requested = true;
      r.state = 'outcome_unknown';
      this.#saveMint(r);
    });
    await this.ctx.storage.sync();
  }
  async beginMintCleanup(attempt: unknown, digest: unknown, productive = false) {
    const result = this.ctx.storage.transactionSync(() => {
      const r = this.#mint(attempt);
      if (
        !r ||
        r.plan.digest !== digest ||
        r.state === 'closed' ||
        (!productive && r.state !== 'outcome_unknown')
      )
        throw new Error('effect_conflict');
      r.cleanup_requested = true;
      r.state = 'outcome_unknown';
      this.#saveMint(r);
      return r;
    });
    await this.ctx.storage.sync();
    return result;
  }
  async recordMintCleanup(attempt: unknown, digest: unknown, input: unknown) {
    mintCleanup(input);
    const result = this.ctx.storage.transactionSync(() => {
      const r = this.#mint(attempt),
        o = r?.observation;
      if (
        !r ||
        !o ||
        r.plan.digest !== digest ||
        r.state !== 'outcome_unknown' ||
        !r.cleanup_requested ||
        o.repo_id !== input.repo_id ||
        o.token_id !== input.token_id ||
        o.scope !== input.scope ||
        o.expires_at !== input.expires_at ||
        (input.method === 'revoke_acknowledged' && !r.revoke_acknowledged) ||
        (r.cleanup && (r.cleanup.receipt !== input.receipt || r.cleanup.method !== input.method))
      )
        throw new Error('effect_conflict');
      if (!r.cleanup) r.cleanup = { ...input, observed_at: Math.floor(Date.now() / 1000) };
      this.#saveMint(r);
      return r;
    });
    await this.ctx.storage.sync();
    return result;
  }
  async closeMintRefused(attempt: unknown, digest: unknown, input: unknown) {
    mintRefusal(input);
    const result = this.ctx.storage.transactionSync(() => {
      const r = this.#mint(attempt),
        o = r?.observation;
      if (
        !r ||
        !o ||
        !r.cleanup ||
        !r.cleanup_requested ||
        r.plan.digest !== digest ||
        r.state === 'custodied' ||
        input.key_version !== r.plan.key_version ||
        input.repo_id !== o.repo_id ||
        input.token_id !== o.token_id ||
        input.scope !== o.scope ||
        input.expires_at !== o.expires_at ||
        (r.refusal && r.refusal.receipt !== input.receipt)
      )
        throw new Error('effect_conflict');
      if (!r.refusal) r.refusal = { ...input, observed_at: Math.floor(Date.now() / 1000) };
      r.state = 'closed';
      this.#saveMint(r);
      return r;
    });
    await this.ctx.storage.sync();
    return result;
  }
  async claimEffect(input: unknown, release: unknown) {
    initialPlan(input);
    const result = this.ctx.storage.transactionSync(() => {
      const s = this.current(release);
      if (
        s.pending ||
        !equal(s.checkpoint, input.checkpoint) ||
        input.checkpoint.authority !== this.env.WORK_AUTHORITY_ID ||
        input.deadline <= Math.floor(Date.now() / 1000)
      )
        throw new Error('effect_blocked');
      const previous = this.effect(input.attempt_id);
      if (previous) {
        if (
          previous.plan.digest !== input.digest ||
          previous.plan.namespace !== input.namespace ||
          previous.plan.name !== input.name ||
          previous.plan.role !== input.role ||
          previous.plan.deadline !== input.deadline
        )
          throw new Error('effect_conflict');
        return { started: false, record: previous };
      }
      // Retained tombstones never expire or get reclaimed. Capacity fails closed.
      const n = this.ctx.storage.sql
        .exec<{ n: number }>(
          'SELECT (SELECT count(*) FROM effect_ledger)+(SELECT count(*) FROM mint_ledger) AS n',
        )
        .one().n;
      if (n >= 256) throw new Error('effect_capacity');
      const record: EffectRecord = {
        plan: input,
        state: 'outcome_unknown',
        repo_id: null,
        closure: null,
      };
      this.saveEffect(record);
      return { started: true, record };
    });
    await this.ctx.storage.sync();
    return result;
  }
  async observeEffect(attempt: unknown, digest: unknown, repoId: unknown) {
    if (!hex(digest) || !resource(repoId)) throw new Error('effect_invalid');
    this.ctx.storage.transactionSync(() => {
      const r = this.effect(attempt);
      if (!r || r.plan.digest !== digest || (r.repo_id !== null && r.repo_id !== repoId))
        throw new Error('effect_conflict');
      r.repo_id = repoId;
      this.saveEffect(r);
    });
    await this.ctx.storage.sync();
  }
  async closeEffect(attempt: unknown, digest: unknown, input: unknown) {
    closure(input);
    if (!hex(digest)) throw new Error('effect_invalid');
    const result = this.ctx.storage.transactionSync(() => {
      const r = this.effect(attempt);
      if (
        !r ||
        r.plan.digest !== digest ||
        r.repo_id !== input.repo_id ||
        (r.closure !== null &&
          (r.closure.token_id !== input.token_id ||
            r.closure.expires_at !== input.expires_at ||
            r.closure.receipt !== input.receipt))
      )
        throw new Error('effect_conflict');
      r.closure = input;
      r.state = 'closed';
      this.saveEffect(r);
      return r;
    });
    // Recording already admitted cleanup remains possible after freeze/floor raise.
    await this.ctx.storage.sync();
    return result;
  }
  async observeEffectToken(attempt: unknown, digest: unknown, input: unknown) {
    tokenObservation(input);
    if (!hex(digest)) throw new Error('effect_invalid');
    const result = this.ctx.storage.transactionSync(() => {
      const r = this.effect(attempt);
      if (
        !r ||
        r.state !== 'outcome_unknown' ||
        r.plan.digest !== digest ||
        r.repo_id !== input.repo_id ||
        (r.token_observation &&
          (r.token_observation.token_id !== input.token_id ||
            r.token_observation.expires_at !== input.expires_at))
      )
        throw new Error('effect_conflict');
      if (!r.token_observation)
        r.token_observation = { ...input, observed_at: Math.floor(Date.now() / 1000) };
      this.saveEffect(r);
      return r;
    });
    await this.ctx.storage.sync();
    return result;
  }
  async recordRevocationInventory(attempt: unknown, digest: unknown, input: unknown) {
    revocationInventory(input);
    if (!hex(digest)) throw new Error('effect_invalid');
    const result = this.ctx.storage.transactionSync(() => {
      const r = this.effect(attempt);
      if (
        !r ||
        r.state !== 'outcome_unknown' ||
        r.plan.digest !== digest ||
        r.repo_id !== input.repo_id ||
        !r.token_observation ||
        r.token_observation.token_id !== input.token_id ||
        r.token_observation.expires_at !== input.expires_at ||
        (r.cleanup &&
          (r.cleanup.token_id !== input.token_id ||
            r.cleanup.expires_at !== input.expires_at ||
            r.cleanup.receipt !== input.receipt ||
            r.cleanup.method !== input.method))
      )
        throw new Error('effect_conflict');
      // Evidence never clears the dispatch tombstone or certifies bearer refusal.
      if (!r.cleanup) r.cleanup = { ...input, observed_at: Math.floor(Date.now() / 1000) };
      this.saveEffect(r);
      return r;
    });
    await this.ctx.storage.sync();
    return result;
  }
}

function object(env: Env) {
  if (!id(env.WORK_AUTHORITY_ID)) throw new Error('checkpoint_invalid');
  return env.CHECKPOINTS.getByName(env.WORK_AUTHORITY_ID);
}
function sameJson(a: unknown, b: unknown): boolean {
  const normalize = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(normalize)
      : v && typeof v === 'object'
        ? Object.fromEntries(
            Object.entries(v)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([k, x]) => [k, normalize(x)]),
          )
        : v;
  return JSON.stringify(normalize(a)) === JSON.stringify(normalize(b));
}
/** Independently owned read-only evidence capability for Native composition. */
export class WorkPreparationEvidence extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/preparation-evidence')
      return new Response(null, { status: 404 });
    try {
      return Response.json(
        await object(this.env).preparationEvidence(JSON.parse(await boundedGitBody(request))),
        { headers: { 'Cache-Control': 'no-store' } },
      );
    } catch {
      return Response.json(
        { error: 'preparation_evidence_unavailable' },
        { status: 409, headers: { 'Cache-Control': 'no-store' } },
      );
    }
  }
}
/** Opaque Git orchestration: no mint, OP framing, credentials or physical repo. */
export class WorkGitCheckpoint extends WorkerEntrypoint<Env> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  lookup(attempt: unknown) {
    return object(this.env).lookupMint(attempt);
  }
  claim(plan: GitPlan) {
    return object(this.env).claimGit(plan);
  }
  finish(attempt: unknown, result: GitResult | null) {
    return object(this.env).finishGit(attempt, result);
  }
}
/** Native can consume one admission; it cannot create or finish one. */
export class WorkGitExecutionCheckpoint extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    try {
      if (request.method !== 'POST' || new URL(request.url).pathname !== '/git-permit')
        return new Response(null, { status: 404 });
      const bytes = await boundedGitBody(request);
      return Response.json(await object(this.env).takeGit(JSON.parse(bytes)));
    } catch {
      return new Response(null, { status: 409 });
    }
  }
}
/** Physical transport consumes once, independently of Native response loss. */
export class WorkGitDispatch extends WorkerEntrypoint<Env> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  take(plan: GitPlan) {
    return object(this.env).takeGit(plan, true);
  }
}
async function boundedGitBody(request: Request) {
  const reader = request.body?.getReader();
  if (!reader) throw new Error('git_invalid');
  let size = 0;
  const parts: Uint8Array[] = [];
  for (;;) {
    const r = await reader.read();
    if (r.done) break;
    size += r.value.byteLength;
    if (size > 8192) {
      await reader.cancel();
      throw new Error('git_invalid');
    }
    parts.push(r.value);
  }
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
    Uint8Array.from(parts.flatMap((p) => Array.from(p))),
  );
}
// Rust service-binding bridge. Fixed purpose/path and bounded closed messages.
// This named entrypoint is never the public default handler.
export class WorkCheckpointService extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/checkpoint')
      return new Response(null, { status: 404 });
    const reader = request.body?.getReader();
    if (!reader) return new Response(null, { status: 400 });
    let bytes = 0;
    const chunks: Uint8Array[] = [];
    try {
      for (;;) {
        const r = await reader.read();
        if (r.done) break;
        bytes += r.value.byteLength;
        if (bytes > 4096) {
          await reader.cancel();
          return new Response(null, { status: 413 });
        }
        chunks.push(r.value);
      }
      const input: unknown = JSON.parse(
        new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
          Uint8Array.from(chunks.flatMap((c) => Array.from(c))),
        ),
      );
      const stub = object(this.env);
      let result: unknown;
      if (closed(input, ['action', 'release']) && input.action === 'status')
        result = await stub.status(input.release);
      else if (
        closed(input, ['action', 'release', 'expected', 'operation']) &&
        input.action === 'begin'
      )
        result = await stub.begin(input.expected, input.operation, input.release);
      else if (
        closed(input, ['action', 'release', 'permit', 'observed']) &&
        input.action === 'commit'
      )
        result = await stub.commit(input.permit, input.observed, input.release);
      else return new Response(null, { status: 400 });
      return Response.json(result);
    } catch {
      return Response.json({ error: 'checkpoint_unavailable' }, { status: 409 });
    }
  }
}
/** Separately owned operator capability. No reset/unfreeze/rebase method. */
export class WorkCheckpointAdmin extends WorkerEntrypoint<Env> {
  bootstrap(initial: unknown, floor: unknown) {
    return object(this.env).bootstrap(initial, floor);
  }
  raiseFloor(floor: unknown) {
    return object(this.env).raiseFloor(floor);
  }
  freeze() {
    return object(this.env).freeze();
  }
}
/** Separate binding: the gate cannot bootstrap, commit, unfreeze or reset history. */
export class WorkEffectCheckpoint extends WorkerEntrypoint<Env> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  lookup(attempt: unknown) {
    return object(this.env).lookupEffect(attempt);
  }
  claim(plan: unknown) {
    return object(this.env).claimEffect(plan, 1);
  }
  observe(attempt: unknown, digest: unknown, repoId: unknown) {
    return object(this.env).observeEffect(attempt, digest, repoId);
  }
  close(attempt: unknown, digest: unknown, value: unknown) {
    return object(this.env).closeEffect(attempt, digest, value);
  }
}
/** Broker's read-only admission view: no mutation or namespace capability. */
export class WorkEffectLookup extends WorkerEntrypoint<Env> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  lookup(attempt: unknown) {
    return object(this.env).lookupEffect(attempt);
  }
}
/** Mint gate cannot admit creates, mutate OP frames or reset retained slots. */
export class WorkMintCheckpoint extends WorkerEntrypoint<Env> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  lookup(attempt: unknown) {
    return object(this.env).lookupMint(attempt);
  }
  claim(plan: MintPlan) {
    return object(this.env).claimMint(plan, 1);
  }
  observe(attempt: unknown, digest: unknown, value: unknown) {
    return object(this.env).observeMint(attempt, digest, value);
  }
  custody(attempt: unknown, digest: unknown) {
    return object(this.env).custodyMint(attempt, digest);
  }
  abandon(attempt: unknown, digest: unknown) {
    return object(this.env).beginMintCleanup(attempt, digest, true);
  }
  revoked(attempt: unknown, digest: unknown) {
    return object(this.env).revokeMint(attempt, digest);
  }
}
/** Physical broker's read-only view. No observation, dispatch or mutation. */
export class WorkMintLookup extends WorkerEntrypoint<Env> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  lookup(attempt: unknown) {
    return object(this.env).lookupMint(attempt);
  }
}
/** Retain verified refusal only; no mint, plaintext, cleanup intent or OP framing. */
export class WorkMintRefusalCheckpoint extends WorkerEntrypoint<Env> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  lookup(attempt: unknown) {
    return object(this.env).lookupMint(attempt);
  }
  refused(attempt: unknown, digest: unknown, value: unknown) {
    return object(this.env).closeMintRefused(attempt, digest, value);
  }
}
/** Safety only: cannot claim, observe unknown IDs, custody, close or reset. */
export class WorkMintMaintenance extends WorkerEntrypoint<Env> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  lookup(attempt: unknown) {
    return object(this.env).lookupMint(attempt);
  }
  begin(attempt: unknown, digest: unknown) {
    return object(this.env).beginMintCleanup(attempt, digest);
  }
  revoked(attempt: unknown, digest: unknown) {
    return object(this.env).revokeMint(attempt, digest, true);
  }
  record(attempt: unknown, digest: unknown, value: unknown) {
    return object(this.env).recordMintCleanup(attempt, digest, value);
  }
}
/** Safety-only capability: no claim, close, frame, floor, bootstrap or reset. */
export class WorkEffectMaintenance extends WorkerEntrypoint<Env> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  lookup(attempt: unknown) {
    return object(this.env).lookupEffect(attempt);
  }
  observe(attempt: unknown, digest: unknown, repo: unknown) {
    return object(this.env).observeEffect(attempt, digest, repo);
  }
  recordRevocation(attempt: unknown, digest: unknown, input: unknown) {
    return object(this.env).recordRevocationInventory(attempt, digest, input);
  }
  observeToken(attempt: unknown, digest: unknown, input: unknown) {
    return object(this.env).observeEffectToken(attempt, digest, input);
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
