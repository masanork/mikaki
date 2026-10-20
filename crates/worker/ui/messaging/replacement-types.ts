import {
  invitation,
  rejoinChain,
  encode,
  decode,
  type InvitationProgress,
  type InvitationOffer,
  type RecoveryInfo,
} from './delivery-types.ts';
export type ReplacementInfo = {
  previous: InvitationOffer;
  next: InvitationOffer;
  operation_id: string;
  phase:
    | 'prepared'
    | 'consented'
    | 'active'
    | 'cancelling'
    | 'cancelled'
    | 'recovery_required'
    | 'recovering'
    | 'abandoned';
  cancellation?: { operation_id: string; outcome: 'pending' | 'cancelled' | 'admitted' };
  predecessor_confirmed?: true;
  restart_from?: string;
  abandoned: { id: string; kind: string; digest: string }[];
};
export type ReplacementStopInfo = {
  previous: InvitationOffer;
  next: InvitationOffer;
  operation_id: string;
  phase: 'stopping' | 'stopped' | 'retired';
  /** This endpoint already activated this exact target; keep its prior fence. */
  native_origin?: true;
  /** Exact ordinary close intent bridged by this stop; its receipt is retained. */
  recovery_id?: string;
  /** Ordered ordinary close UUIDs, including the root, when descendants exist. */
  recovery_chain?: string[];
  abandoned: { id: string; kind: string; digest: string }[];
};
type RecoveryLink = Omit<RecoveryInfo, 'abandoned' | 'inbox_ids'>;
type ReplacementLink = Omit<ReplacementInfo, 'abandoned'>;
type StopLink = Omit<ReplacementStopInfo, 'abandoned'>;
/** Every deferred target must have its own confirmed close. No active native
 * group, pending proposal, missing link or cancellation can be skipped. */
export function replacementStopRecoveries<T extends RecoveryLink>(
  stop: Pick<StopLink, 'previous' | 'next' | 'recovery_id' | 'recovery_chain'>,
  recoveries: T[],
  replacements: ReplacementLink[],
): T[] {
  if (!stop.recovery_id) return [];
  const ids = stop.recovery_chain ?? [stop.recovery_id];
  if (
    !Array.isArray(ids) ||
    ids.length < (stop.recovery_chain ? 2 : 1) ||
    ids.length > 9 ||
    ids[0] !== stop.recovery_id ||
    new Set(ids).size !== ids.length
  )
    return [];
  const leaf = recoveries.find((r) => r.operation_id === ids.at(-1));
  if (!leaf) return [];
  let chain: T[];
  try {
    chain = rejoinChain(recoveries, leaf.offer.channel.id);
  } catch {
    return [];
  }
  const root = chain[0];
  if (
    chain.length !== ids.length ||
    root.replacement_id !== stop.next.channel.id ||
    JSON.stringify(root.offer) !== JSON.stringify(stop.next) ||
    !replacements.some(
      (r) =>
        r.phase === 'abandoned' &&
        JSON.stringify(r.previous) === JSON.stringify(stop.previous) &&
        JSON.stringify(r.next) === JSON.stringify(stop.next),
    ) ||
    new Set(chain.map((r) => r.offer.channel.id)).size !== chain.length ||
    new Set(chain.map((r) => r.offer.channel.group)).size !== chain.length ||
    chain.some(
      (r, i) =>
        r.operation_id !== ids[i] ||
        r.reason !== 'cancel_invitation' ||
        r.phase !== 'closed' ||
        (i > 0 && r.replacement_id !== undefined) ||
        JSON.stringify(r.offer.channel.a) !== JSON.stringify(stop.next.channel.a) ||
        JSON.stringify(r.offer.channel.b) !== JSON.stringify(stop.next.channel.b) ||
        r.offer.channel.id === stop.previous.channel.id ||
        r.offer.channel.group === stop.previous.channel.group ||
        (i === chain.length - 1 && (r.next !== null || r.successor_failed)) ||
        (r.cancellations ?? []).some(
          (c) =>
            c.outcome !== 'cancelled' &&
            !(
              c.outcome === 'admitted' &&
              chain[i + 1] &&
              JSON.stringify(c.next) === JSON.stringify(chain[i + 1].offer)
            ),
        ),
    )
  )
    return [];
  return chain;
}
/** Snapshot the exact complete chain. This never closes or cancels a target. */
export function replacementRecoveryLink(
  previous: InvitationOffer,
  next: InvitationOffer,
  recoveries: RecoveryLink[],
  replacements: ReplacementLink[],
): Pick<ReplacementStopInfo, 'recovery_id' | 'recovery_chain'> | undefined {
  const leaf = recoveries.at(-1);
  if (!leaf) return undefined;
  let chain: RecoveryLink[];
  try {
    chain = rejoinChain(recoveries, leaf.offer.channel.id);
  } catch {
    return undefined;
  }
  const link = {
    recovery_id: chain[0].operation_id,
    ...(chain.length > 1 ? { recovery_chain: chain.map((r) => r.operation_id) } : {}),
  };
  return replacementStopRecoveries({ previous, next, ...link }, recoveries, replacements).length
    ? link
    : undefined;
}
/** A retained ordinary close stops freezing only after its exact linked native
 * retirement has committed. An unrelated stop cannot shadow that recovery. */
export function recoveryReplaced(
  recovery: RecoveryLink,
  replacements: ReplacementLink[],
  stops: StopLink[],
  recoveries: RecoveryLink[],
): boolean {
  return (
    replacements.some(
      (r) =>
        ['active', 'recovering', 'abandoned'].includes(r.phase) &&
        r.previous.channel.id === recovery.offer.channel.id,
    ) ||
    stops.some(
      (s) =>
        s.phase === 'retired' &&
        replacementStopRecoveries(s, recoveries, replacements).some(
          (r) =>
            r.operation_id === recovery.operation_id &&
            JSON.stringify(r.offer) === JSON.stringify(recovery.offer),
        ),
    )
  );
}
export type ReplacementProgress =
  InvitationProgress | { phase: 'cancelled'; sent: number; processed: number };
export function replacement(oldValue: InvitationOffer, nextValue: InvitationOffer) {
  const previous = invitation(oldValue),
    next = invitation(nextValue);
  const before = [previous.channel.a, previous.channel.b],
    after = [next.channel.a, next.channel.b];
  const same = (a: (typeof before)[0], b: (typeof before)[0]) =>
    a.scope === b.scope && a.fingerprint === b.fingerprint;
  const stable = before.filter((a) => after.some((b) => same(a, b)));
  if (
    previous.channel.id === next.channel.id ||
    previous.channel.group === next.channel.group ||
    stable.length !== 1
  )
    throw new Error('invalid_channel_replacement');
  const retired = before.find((a) => !same(a, stable[0]))!,
    current = after.find((a) => !same(a, stable[0]))!;
  if (retired.scope === current.scope || retired.fingerprint === current.fingerprint)
    throw new Error('invalid_channel_replacement');
  return { previous, next, stable: stable[0], retired, current };
}

const PREFIX = 'mikaki-replace-v1:';
export function replacementCode(previous: InvitationOffer, next: InvitationOffer): string {
  const checked = replacement(previous, next);
  return (
    PREFIX +
    encode(
      new TextEncoder().encode(JSON.stringify({ previous: checked.previous, next: checked.next })),
    )
  );
}
export function parseReplacementCode(code: string) {
  try {
    if (!code.startsWith(PREFIX) || code.length > 8192) throw new Error();
    const value = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(decode(code.slice(PREFIX.length))),
    ) as Record<string, InvitationOffer>;
    if (
      !value ||
      Object.keys(value).length !== 2 ||
      !Object.hasOwn(value, 'next') ||
      !Object.hasOwn(value, 'previous')
    )
      throw new Error('invalid_replacement_code');
    return replacement(value.previous, value.next);
  } catch {
    throw new Error('invalid_replacement_code');
  }
}
