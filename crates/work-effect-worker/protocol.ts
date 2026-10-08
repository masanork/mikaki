/** Closed metadata shared by the gate and its independent one-shot ledger. */
export type Checkpoint = { authority: string; epoch: string; sequence: number; tip: string };
export type InitialPlan = {
  format_version: 1;
  effect: 'repo.create';
  attempt_id: string;
  digest: string;
  namespace: string;
  name: string;
  role: 'task' | 'snapshot';
  deadline: number;
  checkpoint: Checkpoint;
};
export type MintPlan = Omit<InitialPlan, 'effect'> & {
  effect: 'token.mint';
  purpose: 'upload' | 'readback';
  scope: 'read' | 'write';
  repo_id: string;
  initial_attempt_id: string;
  expires_at: number;
  key_version: number;
  key_fingerprint: string;
};
/** No plaintext, ciphertext or credential release capability in this ledger. */
export type MintObservation = {
  repo_id: string;
  token_id: string;
  scope: 'read' | 'write';
  expires_at: number;
};
export type MintRecord = {
  plan: MintPlan;
  state: 'outcome_unknown' | 'custodied' | 'closed';
  observation: MintObservation | null;
  revoke_acknowledged: boolean;
  cleanup_requested: boolean;
  receipt: string | null;
  cleanup?: MintCleanup & { observed_at: number };
  refusal?: MintRefusal & { observed_at: number };
  git?: GitRecord;
};
export type GitPlan = Omit<MintPlan, 'effect' | 'expires_at'> & {
  effect: 'git.upload' | 'git.readback';
  preparation_digest: string;
  disclosure_digest: string;
  commit: string;
  tree: string;
  branch: 'work' | 'snapshot';
  observation: MintObservation;
};
export type GitResult = {
  method: 'git_push_accepted' | 'git_readback_verified';
  commit: string;
  tree: string;
  branch: 'work' | 'snapshot';
  commits: number;
  objects: number;
  object_bytes: number;
  inventory_sha256: string;
  receipt: string;
};
export type GitRecord = {
  plan: GitPlan;
  state: 'admitted' | 'dispatching' | 'outcome_unknown' | 'completed';
  result: GitResult | null;
};
/** Specific control-plane evidence, not bearer refusal or copy verification. */
export type MintCleanup = MintObservation & {
  format_version: 1;
  method: 'revoked_inventory' | 'revoke_acknowledged';
  receipt: string;
};
/** Native-decrypted bearer refused at the fixed Git endpoint. No copy authority. */
export type MintRefusal = MintObservation & {
  format_version: 1;
  method: 'git_bearer_refused';
  status: 403;
  key_version: number;
  receipt: string;
};
export type Closure = {
  repo_id: string;
  token_id: string;
  expires_at: number | null;
  receipt: string;
};
export type EffectRecord = {
  plan: InitialPlan;
  state: 'outcome_unknown' | 'closed';
  repo_id: string | null;
  closure: Closure | null;
  cleanup?: RevocationInventory & { observed_at: number };
  token_observation?: TokenObservation & { observed_at: number };
};
/** Control-plane revocation evidence; never claims a Git bearer refusal. */
export type RevocationInventory = {
  format_version: 1;
  repo_id: string;
  token_id: string;
  scope: 'write';
  expires_at: number;
  receipt: string;
  method: 'revoked_inventory' | 'revoke_acknowledged';
};
export type TokenObservation = Pick<
  RevocationInventory,
  'repo_id' | 'token_id' | 'scope' | 'expires_at'
>;
export const closed = (v: unknown, keys: string[]): v is Record<string, unknown> =>
  typeof v === 'object' &&
  v !== null &&
  !Array.isArray(v) &&
  Object.keys(v).sort().join(',') === [...keys].sort().join(',');
export const hex = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
export const opaque = (v: unknown): v is string =>
  typeof v === 'string' && /^[A-Za-z0-9_-]{43}$/.test(v);
export const resource = (v: unknown): v is string =>
  typeof v === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(v);
export const integer = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
export function initialPlan(v: unknown): asserts v is InitialPlan {
  if (
    !closed(v, [
      'format_version',
      'effect',
      'attempt_id',
      'digest',
      'namespace',
      'name',
      'role',
      'deadline',
      'checkpoint',
    ]) ||
    v.format_version !== 1 ||
    v.effect !== 'repo.create' ||
    !opaque(v.attempt_id) ||
    !hex(v.digest) ||
    typeof v.namespace !== 'string' ||
    !/^[a-z0-9-]{1,63}$/.test(v.namespace) ||
    typeof v.name !== 'string' ||
    !/^wk-[a-f0-9]{32}-(code|snapshot)$/.test(v.name) ||
    !['task', 'snapshot'].includes(String(v.role)) ||
    !v.name.endsWith(v.role === 'task' ? '-code' : '-snapshot') ||
    !integer(v.deadline) ||
    !closed(v.checkpoint, ['authority', 'epoch', 'sequence', 'tip']) ||
    !resource(v.checkpoint.authority) ||
    !hex(v.checkpoint.epoch) ||
    !hex(v.checkpoint.tip) ||
    !integer(v.checkpoint.sequence)
  )
    throw new Error('effect_invalid');
}
export function closure(v: unknown): asserts v is Closure {
  if (
    !closed(v, ['repo_id', 'token_id', 'expires_at', 'receipt']) ||
    !resource(v.repo_id) ||
    !resource(v.token_id) ||
    !(v.expires_at === null || integer(v.expires_at)) ||
    !hex(v.receipt)
  )
    throw new Error('effect_invalid');
}
export function mintPlan(v: unknown): asserts v is MintPlan {
  const extra = [
    'purpose',
    'scope',
    'repo_id',
    'initial_attempt_id',
    'expires_at',
    'key_version',
    'key_fingerprint',
  ];
  if (
    !closed(v, [
      'format_version',
      'effect',
      'attempt_id',
      'digest',
      'namespace',
      'name',
      'role',
      'deadline',
      'checkpoint',
      ...extra,
    ]) ||
    v.effect !== 'token.mint' ||
    !['upload', 'readback'].includes(String(v.purpose)) ||
    v.scope !== (v.purpose === 'upload' ? 'write' : 'read') ||
    !resource(v.repo_id) ||
    !opaque(v.initial_attempt_id) ||
    v.initial_attempt_id === v.attempt_id ||
    !integer(v.deadline) ||
    !integer(v.expires_at) ||
    v.expires_at > v.deadline ||
    !integer(v.key_version) ||
    v.key_version < 1 ||
    !hex(v.key_fingerprint)
  )
    throw new Error('effect_invalid');
  const base = Object.fromEntries(Object.entries(v).filter(([k]) => !extra.includes(k)));
  initialPlan({ ...base, effect: 'repo.create' });
}
export function mintObservation(v: unknown): asserts v is MintObservation {
  if (
    !closed(v, ['repo_id', 'token_id', 'scope', 'expires_at']) ||
    !resource(v.repo_id) ||
    !resource(v.token_id) ||
    !['read', 'write'].includes(String(v.scope)) ||
    !integer(v.expires_at) ||
    v.expires_at < 1
  )
    throw new Error('effect_invalid');
}
export function gitPlan(v: unknown): asserts v is GitPlan {
  if (
    !closed(v, [
      'format_version',
      'effect',
      'attempt_id',
      'digest',
      'namespace',
      'name',
      'role',
      'deadline',
      'checkpoint',
      'purpose',
      'scope',
      'repo_id',
      'initial_attempt_id',
      'key_version',
      'key_fingerprint',
      'preparation_digest',
      'disclosure_digest',
      'commit',
      'tree',
      'branch',
      'observation',
    ]) ||
    v.effect !== (v.purpose === 'upload' ? 'git.upload' : 'git.readback') ||
    !hex(v.preparation_digest) ||
    !hex(v.disclosure_digest) ||
    typeof v.commit !== 'string' ||
    !/^[a-f0-9]{40}$/.test(v.commit) ||
    typeof v.tree !== 'string' ||
    !/^[a-f0-9]{40}$/.test(v.tree) ||
    v.branch !== (v.role === 'task' ? 'work' : 'snapshot')
  )
    throw new Error('git_invalid');
  const {
    preparation_digest: _p,
    disclosure_digest: _d,
    commit: _c,
    tree: _t,
    branch: _b,
    observation: _o,
    ...base
  } = v;
  mintObservation(v.observation);
  mintPlan({ ...base, effect: 'token.mint', expires_at: v.observation.expires_at });
  if (
    v.observation.repo_id !== v.repo_id ||
    v.observation.scope !== v.scope ||
    v.observation.expires_at > Number(v.deadline)
  )
    throw new Error('git_invalid');
}
export function gitResult(v: unknown, p: GitPlan): asserts v is GitResult {
  if (
    !closed(v, [
      'method',
      'commit',
      'tree',
      'branch',
      'commits',
      'objects',
      'object_bytes',
      'inventory_sha256',
      'receipt',
    ]) ||
    v.method !== (p.purpose === 'upload' ? 'git_push_accepted' : 'git_readback_verified') ||
    v.commit !== p.commit ||
    v.tree !== p.tree ||
    v.branch !== p.branch ||
    !integer(v.commits) ||
    v.commits < 1 ||
    v.commits > 4096 ||
    (p.role === 'snapshot' && v.commits !== 1) ||
    !integer(v.objects) ||
    v.objects < v.commits ||
    v.objects > 65536 ||
    !integer(v.object_bytes) ||
    v.object_bytes > 67108864 ||
    !hex(v.inventory_sha256) ||
    !hex(v.receipt)
  )
    throw new Error('git_invalid');
}
export function mintCleanup(v: unknown): asserts v is MintCleanup {
  if (
    !closed(v, [
      'repo_id',
      'token_id',
      'scope',
      'expires_at',
      'format_version',
      'method',
      'receipt',
    ]) ||
    v.format_version !== 1 ||
    !hex(v.receipt) ||
    !['revoked_inventory', 'revoke_acknowledged'].includes(String(v.method))
  )
    throw new Error('effect_invalid');
  mintObservation({
    repo_id: v.repo_id,
    token_id: v.token_id,
    scope: v.scope,
    expires_at: v.expires_at,
  });
}
export function mintRefusal(v: unknown): asserts v is MintRefusal {
  if (
    !closed(v, [
      'repo_id',
      'token_id',
      'scope',
      'expires_at',
      'format_version',
      'method',
      'status',
      'key_version',
      'receipt',
    ]) ||
    v.format_version !== 1 ||
    v.method !== 'git_bearer_refused' ||
    v.status !== 403 ||
    !integer(v.key_version) ||
    v.key_version < 1 ||
    !hex(v.receipt)
  )
    throw new Error('effect_invalid');
  mintObservation({
    repo_id: v.repo_id,
    token_id: v.token_id,
    scope: v.scope,
    expires_at: v.expires_at,
  });
}
export function revocationInventory(v: unknown): asserts v is RevocationInventory {
  if (
    !closed(v, [
      'format_version',
      'repo_id',
      'token_id',
      'scope',
      'expires_at',
      'receipt',
      'method',
    ]) ||
    v.format_version !== 1 ||
    !resource(v.repo_id) ||
    !resource(v.token_id) ||
    v.scope !== 'write' ||
    !integer(v.expires_at) ||
    !hex(v.receipt) ||
    !['revoked_inventory', 'revoke_acknowledged'].includes(String(v.method))
  )
    throw new Error('effect_invalid');
}
export function tokenObservation(v: unknown): asserts v is TokenObservation {
  if (
    !closed(v, ['repo_id', 'token_id', 'scope', 'expires_at']) ||
    !resource(v.repo_id) ||
    !resource(v.token_id) ||
    v.scope !== 'write' ||
    !integer(v.expires_at)
  )
    throw new Error('effect_invalid');
}
