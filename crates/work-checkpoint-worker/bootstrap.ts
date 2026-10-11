/** Closed initial-enrollment record. Resource claims require separate operator inventory. */
export type InitialCheckpoint = {
  authority: string;
  epoch: string;
  sequence: 0;
  tip: string;
};
export type BootstrapPlan = {
  format_version: 1;
  packet_sha256: string;
  allocation_sha256: string;
  ownership_review_sha256: string;
  quiescence_review_sha256: string;
  account_id: string;
  database_id: string;
  checkpoint_namespace_id: string;
  checkpoint_object_id: string;
  checkpoint_version_id: string;
  initial: InitialCheckpoint;
  release_floor: 1;
};
export type BootstrapInspection = {
  authority: string;
  object_id: string;
  enrollment: BootstrapPlan | null;
  state: {
    checkpoint: { authority: string; epoch: string; sequence: number; tip: string };
    pending: unknown;
    last: unknown;
    release_floor: number;
    frozen: boolean;
  } | null;
  ledger_entries: number;
};
export const bootstrapHex = (v: unknown): v is string =>
  typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const hex32 = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
export const bootstrapUuid = (v: unknown): v is string =>
  typeof v === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v);
export function bootstrapClosed(v: unknown, keys: string[]): v is Record<string, unknown> {
  return (
    v !== null &&
    typeof v === 'object' &&
    !Array.isArray(v) &&
    Object.keys(v).sort().join(',') === [...keys].sort().join(',')
  );
}
export function validateBootstrapPlan(v: unknown): asserts v is BootstrapPlan {
  if (
    !bootstrapClosed(v, [
      'format_version',
      'packet_sha256',
      'allocation_sha256',
      'ownership_review_sha256',
      'quiescence_review_sha256',
      'account_id',
      'database_id',
      'checkpoint_namespace_id',
      'checkpoint_object_id',
      'checkpoint_version_id',
      'initial',
      'release_floor',
    ]) ||
    v.format_version !== 1 ||
    !bootstrapHex(v.packet_sha256) ||
    !bootstrapHex(v.allocation_sha256) ||
    !bootstrapHex(v.ownership_review_sha256) ||
    !bootstrapHex(v.quiescence_review_sha256) ||
    !hex32(v.account_id) ||
    !bootstrapUuid(v.database_id) ||
    !hex32(v.checkpoint_namespace_id) ||
    !bootstrapHex(v.checkpoint_object_id) ||
    !bootstrapUuid(v.checkpoint_version_id) ||
    v.release_floor !== 1 ||
    !bootstrapClosed(v.initial, ['authority', 'epoch', 'sequence', 'tip']) ||
    typeof v.initial.authority !== 'string' ||
    !/^[a-zA-Z0-9_.:-]{1,128}$/.test(v.initial.authority) ||
    !bootstrapHex(v.initial.epoch) ||
    !bootstrapHex(v.initial.tip) ||
    v.initial.sequence !== 0
  )
    throw new Error('authority_bootstrap_plan_invalid');
}
