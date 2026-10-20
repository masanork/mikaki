/** Same-instance, mutually approved transport for an already established group. */
export type DeliveryChannel = {
  id: string;
  group: string;
  a: { scope: string; fingerprint: string };
  b: { scope: string; fingerprint: string };
};
export type DeliveryEnvelope = {
  message_id: string;
  channel_id: string;
  sender_scope: string;
  recipient_scope: string;
  kind: 'application' | 'commit' | 'key_package' | 'invite_commit' | 'welcome';
  digest: string;
  expires_at: number;
  wire: string;
};
export type InvitationOffer = { channel: DeliveryChannel; inviter_scope: string };
export type CloseReason = 'cancel_invitation' | 'epoch_conflict' | 'leave';
export type RecoveryInfo = {
  offer: InvitationOffer;
  operation_id: string;
  reason: CloseReason;
  phase: 'closing' | 'closed' | 'rejoined';
  next: InvitationOffer | null;
  abandoned: { id: string; kind: string; digest: string }[];
  inbox_ids: string[];
  replacement_id?: string;
  deferred_from?: string;
  successor_failed?: true;
  cancellations?: {
    next: InvitationOffer;
    operation_id: string;
    outcome: 'pending' | 'cancelled' | 'admitted';
  }[];
};
/** Ordered, bounded pending retirements. Links always point to the immediately
 * previous recovery; a failed successor is never silently substituted. */
export function rejoinChain<
  T extends Pick<RecoveryInfo, 'offer' | 'phase' | 'next' | 'deferred_from' | 'successor_failed'>,
>(entries: T[], id: string): T[] {
  if (entries.length > 9) throw new Error('invalid_recovery_state');
  let index = entries.findIndex((r) => r.offer.channel.id === id);
  if (index < 0) throw new Error('invalid_recovery_state');
  const result = [entries[index]];
  while (entries[index].deferred_from !== undefined) {
    const child = entries[index],
      parent = entries[index - 1];
    if (
      !parent ||
      parent.offer.channel.id !== child.deferred_from ||
      !parent.successor_failed ||
      !parent.next ||
      JSON.stringify(parent.next) !== JSON.stringify(child.offer) ||
      !['closed', 'rejoined'].includes(parent.phase) ||
      (parent.phase === 'rejoined') !== (child.phase === 'rejoined')
    )
      throw new Error('invalid_recovery_state');
    result.unshift(parent);
    index--;
  }
  return result;
}
export type InvitationProgress = {
  phase:
    | 'waiting_peer'
    | 'proposal_cancelled'
    | 'waiting_key_package'
    | 'waiting_welcome'
    | 'waiting_activation'
    | 'active'
    | 'pending'
    | 'recovery_required';
  sent: number;
  processed: number;
};
export function invitation(value: InvitationOffer): InvitationOffer {
  exact(value, ['channel', 'inviter_scope']);
  const route = channel(value.channel);
  if (![route.a.scope, route.b.scope].includes(value.inviter_scope))
    throw new Error('invalid_inviter');
  return { channel: route, inviter_scope: value.inviter_scope };
}
export type DeliveryReceipt = Omit<DeliveryEnvelope, 'wire'> & {
  sequence: number;
  envelope_hash: string;
};
export function exact(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((k) => !Object.hasOwn(value, k))
  )
    throw new Error('invalid_delivery_response');
}
export function channel(value: DeliveryChannel): DeliveryChannel {
  exact(value, ['id', 'group', 'a', 'b']);
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  if (typeof value.id !== 'string' || !uuid.test(value.id)) throw new Error('invalid_channel');
  for (const endpoint of [value.a, value.b]) {
    exact(endpoint, ['scope', 'fingerprint']);
    for (const text of [endpoint.scope, endpoint.fingerprint]) decode(text, 32);
  }
  decode(value.group, 16);
  if (value.a.scope >= value.b.scope) throw new Error('invalid_channel');
  return {
    id: value.id,
    group: value.group,
    a: { scope: value.a.scope, fingerprint: value.a.fingerprint },
    b: { scope: value.b.scope, fingerprint: value.b.fingerprint },
  };
}
export function encode(bytes: Uint8Array): string {
  let result = '';
  for (let i = 0; i < bytes.length; i += 16384)
    result += String.fromCharCode(...bytes.subarray(i, i + 16384));
  return btoa(result).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
export function decode(value: string, size?: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > 87382)
    throw new Error('invalid_delivery_encoding');
  const bytes = Uint8Array.from(
    atob(
      value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4),
    ),
    (c) => c.charCodeAt(0),
  );
  if (
    bytes.length > 65536 ||
    (size !== undefined && bytes.length !== size) ||
    encode(bytes) !== value
  )
    throw new Error('invalid_delivery_encoding');
  return bytes;
}
export async function envelopeHash(e: Omit<DeliveryEnvelope, 'wire'>): Promise<string> {
  return encode(
    new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(
          JSON.stringify([
            'mikaki-mail-envelope-v1',
            e.message_id,
            e.channel_id,
            e.sender_scope,
            e.recipient_scope,
            e.kind,
            e.digest,
            e.expires_at,
          ]),
        ),
      ),
    ),
  );
}
export async function receipt(
  value: unknown,
  expected: DeliveryEnvelope,
): Promise<DeliveryReceipt> {
  exact(value, ['status', 'receipt']);
  if (value.status !== 'stored') throw new Error('invalid_delivery_receipt');
  const r = value.receipt;
  exact(r, [
    'sequence',
    'message_id',
    'channel_id',
    'sender_scope',
    'recipient_scope',
    'kind',
    'digest',
    'expires_at',
    'envelope_hash',
  ]);
  for (const key of [
    'message_id',
    'channel_id',
    'sender_scope',
    'recipient_scope',
    'kind',
    'digest',
    'expires_at',
  ] as const)
    if (r[key] !== expected[key]) throw new Error('delivery_receipt_mismatch');
  if (
    !Number.isSafeInteger(r.sequence) ||
    (r.sequence as number) < 1 ||
    r.envelope_hash !== (await envelopeHash(expected))
  )
    throw new Error('delivery_receipt_mismatch');
  return r as DeliveryReceipt;
}

/** Authenticate transport metadata before the journal performs MLS admission. */
export async function incoming(
  value: unknown,
  route: DeliveryChannel,
  scope: string,
  kinds: DeliveryEnvelope['kind'][],
  now: number,
): Promise<{ message: DeliveryEnvelope; wire: number[] }> {
  exact(value, [
    'sequence',
    'message_id',
    'channel_id',
    'sender_scope',
    'recipient_scope',
    'kind',
    'digest',
    'expires_at',
    'envelope_hash',
    'wire',
  ]);
  const own = route.a.scope === scope ? route.a : route.b.scope === scope ? route.b : null;
  const peer = own === route.a ? route.b : route.a;
  if (
    !own ||
    value.channel_id !== route.id ||
    value.sender_scope !== peer.scope ||
    value.recipient_scope !== scope ||
    typeof value.message_id !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      value.message_id,
    ) ||
    !kinds.includes(value.kind as DeliveryEnvelope['kind']) ||
    !Number.isSafeInteger(value.expires_at) ||
    (value.expires_at as number) <= now
  )
    throw new Error('invalid_incoming_delivery');
  const bytes = decode(value.wire as string);
  if (encode(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))) !== value.digest)
    throw new Error('delivery_digest_mismatch');
  const { wire: _, ...r } = value;
  await receipt({ status: 'stored', receipt: r }, value as DeliveryEnvelope);
  return { message: value as DeliveryEnvelope, wire: Array.from(bytes) };
}
