/** Encrypted, witnessed device journal. Only committed records can release wire
 * messages or received events. Requires an independent authenticated witness and
 * an unlocked nonextractable device-state key; supplies neither service itself. */
import {
  channel as checkedChannel,
  invitation as checkedInvitation,
  decode,
  rejoinChain,
  type DeliveryChannel,
  type DeliveryEnvelope,
  type InvitationOffer,
  type CloseReason,
  type RecoveryInfo,
} from './delivery-types.js';
import {
  contact as checkedContact,
  verifiedDevice,
  type PeerTrust,
  type PeerReview,
  type VerifiedDevice,
} from './peer-review.js';
import {
  replacement,
  replacementStopRecoveries,
  replacementRecoveryLink,
  recoveryReplaced,
  type ReplacementInfo,
  type ReplacementStopInfo,
} from './replacement-types.js';

export type DeviceIdentity = {
  issuer: string;
  account_id: string;
  device_id: string;
  generation: number;
};
export type DeviceScope = {
  device: DeviceIdentity;
  storage_id: string;
  key_id: string;
  fingerprint: string;
};
export type Head = { revision: number; hash: string | null };
/** Must be linearizable and authenticated outside this browser database. A CAS
 * retry returns the candidate while it is current; a conflict returns the actual
 * newer head, never an old historical acknowledgment presented as current. */
export interface HeadWitness {
  read(scope: string): Promise<Head>;
  compareAndSet(scope: string, expected: Head, next: Head): Promise<Head>;
}
export interface DeviceEngine {
  identity_json(): string;
  fingerprint(): string;
  inspect_peer(token: string, now: bigint): string;
  peer_trust(now: bigint): string;
  review_peer(token: string, now: bigint): string;
  replace_group(previous: Uint8Array, next: Uint8Array, keys: string, now: bigint): void;
  check_replacement_origin(previous: Uint8Array, now: bigint): void;
  check_activated_replacement_origin(
    previous: Uint8Array,
    failed: Uint8Array,
    own: string,
    peer: string,
    now: bigint,
  ): string;
  restart_activated_replacement(
    previous: Uint8Array,
    failed: Uint8Array,
    next: Uint8Array,
    keys: string,
    now: bigint,
  ): void;
  check_group_predecessor(
    token: string,
    fingerprint: string,
    previous: Uint8Array,
    next: Uint8Array,
    now: bigint,
  ): void;
  cancel_group_predecessor(previous: Uint8Array, next: Uint8Array, now: bigint): void;
  outgoing_context(now: bigint, requirePeer: boolean): string;
  check_delivery(group: Uint8Array, own: string, peer: string, now: bigint): void;
  check_bootstrap(group: Uint8Array, own: string, peer: string, now: bigint): string;
  restart_group(
    previous: Uint8Array,
    next: Uint8Array,
    own: string,
    peer: string,
    now: bigint,
  ): void;
  checkpoint(): Uint8Array;
  free(): void;
  key_package(now: bigint): Uint8Array;
  create_group(group: Uint8Array, now: bigint): void;
  invite(keyPackage: Uint8Array, now: bigint): string;
  join(welcome: Uint8Array, group: Uint8Array, now: bigint): void;
  send(text: string, now: bigint): Uint8Array;
  receive(message: Uint8Array, now: bigint): string;
  update(now: bigint): Uint8Array;
  remove_peer(now: bigint): Uint8Array;
  merge_pending(now: bigint): void;
  bind_self(token: string, now: bigint): void;
  refresh_self(token: string, now: bigint): string;
  confirm_peer(token: string, fingerprint: string, now: bigint): void;
  observe_binding(token: string, now: bigint): string;
  accept_key_change(token: string, previous: string, replacement: string, now: bigint): void;
}
export interface DeviceModule {
  BoundMlsClient: { restore(bytes: Uint8Array, authorities: string): DeviceEngine };
}
export type Command =
  | { kind: 'key_package' }
  | { kind: 'create_group'; group: number[] }
  | { kind: 'invite'; key_package: number[] }
  | { kind: 'join'; welcome: number[]; group: number[] }
  | { kind: 'send'; text: string }
  | { kind: 'send_chat'; text: string; route: string }
  | { kind: 'receive'; message_id: string; wire: number[] }
  | { kind: 'receive_delivery'; message_id: string; wire: number[]; route: string }
  | { kind: 'update' }
  | { kind: 'remove_peer' }
  | { kind: 'merge_pending'; commit_id: string }
  | { kind: 'acknowledge'; message_id: string; digest: string }
  | { kind: 'accept_delivery'; message_id: string; digest: string; channel_id: string }
  | { kind: 'prepare_invitation'; offer: string }
  | {
      kind: 'invite_from_delivery' | 'join_from_delivery';
      offer: string;
      message_id: string;
      wire: number[];
    }
  | { kind: 'complete_invitation' | 'mark_invitation_failed'; offer: string }
  | { kind: 'mark_replacement_failed'; previous: string; next: string }
  | { kind: 'begin_replacement_recovery'; previous: string; next: string; close_id: string }
  | { kind: 'begin_close'; offer: string; close_id: string; reason: CloseReason }
  | { kind: 'complete_close'; offer: string; close_id: string }
  | {
      kind: 'prepare_rejoin' | 'activate_rejoin';
      offer: string;
      next: string;
    }
  | { kind: 'mark_rejoin_failed'; offer: string; next: string }
  | { kind: 'begin_rejoin_recovery'; offer: string; next: string; close_id: string }
  | { kind: 'begin_cancel_rejoin'; offer: string; next: string; cancel_id: string }
  | {
      kind: 'finish_cancel_rejoin';
      offer: string;
      next: string;
      cancel_id: string;
      outcome: 'cancelled' | 'admitted';
    }
  | { kind: 'bind_self'; token: string }
  | { kind: 'refresh_self'; token: string }
  | { kind: 'confirm_peer'; token: string; fingerprint: string }
  | { kind: 'observe_binding'; token: string }
  | { kind: 'accept_key_change'; token: string; previous: string; replacement: string }
  | { kind: 'stage_peer'; contact: string }
  | { kind: 'approve_peer'; review_id: string; fingerprint: string; previous: string }
  | { kind: 'prepare_replacement'; previous: string; next: string; approval_id: string }
  | { kind: 'attest_replacement_predecessor'; previous: string; next: string; token: string }
  | {
      kind: 'begin_stop_replacement' | 'complete_stop_replacement';
      previous: string;
      next: string;
      stop_id: string;
    }
  | {
      kind: 'consent_replacement' | 'activate_replacement' | 'observe_replacement_cancelled';
      previous: string;
      next: string;
    }
  | { kind: 'begin_cancel_replacement'; previous: string; next: string; cancel_id: string }
  | {
      kind: 'finish_cancel_replacement';
      previous: string;
      next: string;
      cancel_id: string;
      outcome: 'cancelled' | 'admitted';
    };

export type Receipt = {
  operation_id: string;
  ok: boolean;
  message_ids: string[];
  event_id?: string;
  observation?: string;
  error?: string;
};
type WireKind = 'key_package' | 'commit' | 'welcome' | 'application';
type Queued = {
  id: string;
  kind: WireKind;
  wire: string;
  digest: string;
  context: string;
  require_peer: boolean;
  depends_on: string | null;
  delivery?: Pick<
    DeliveryEnvelope,
    'channel_id' | 'sender_scope' | 'recipient_scope' | 'expires_at'
  >;
};
export type InboxEvent = { id: string; event: unknown; channel_id?: string; position?: number };
type SentText = { id: string; channel_id: string; text: string; position: number };
/** Public, Vault-scoped UI data. Never includes wire bytes or private checkpoints. */
export type ChatSnapshot = {
  own: { scope: string; fingerprint: string };
  trust: PeerTrust;
  peer_review: PeerReview | null;
  replacements: ReplacementInfo[];
  replacement_stops: ReplacementStopInfo[];
  invitation: { offer: InvitationOffer; phase: InvitationState['phase'] } | null;
  recoveries: RecoveryInfo[];
  received: InboxEvent[];
  sent: (SentText & { status: 'queued' | 'accepted' | 'isolated' })[];
};
type Recovery = Omit<RecoveryInfo, 'abandoned'> & { quarantined: Queued[] };
type ReplacementState = Omit<ReplacementInfo, 'abandoned'> & { quarantined: Queued[] };
type ReplacementStopState = Omit<ReplacementStopInfo, 'abandoned'> & { quarantined: Queued[] };
type InvitationState = InvitationOffer & {
  phase: 'prepared' | 'invited' | 'joined' | 'active' | 'recovery_required';
  key_package_id: string | null;
  commit_id: string | null;
  welcome_id: string | null;
};
type State = {
  version: 1;
  last_time: number;
  checkpoint: string;
  outbox: Queued[];
  inbox: InboxEvent[];
  received: { id: string; digest: string; event_id: string | null }[];
  delivered: { id: string; digest: string; channel_id?: string }[];
  operations: { id: string; intent: string; receipt: Receipt }[];
  pending_commit: { id: string; accepted: boolean } | null;
  invitation?: InvitationState | null;
  recoveries?: Recovery[];
  sent_texts?: SentText[];
  chat_sequence?: number;
  peer_review?: PeerReview;
  replacements?: ReplacementState[];
  replacement_stops?: ReplacementStopState[];
};
type Sealed = {
  version: 1;
  revision: number;
  previous: Head;
  transaction_id: string;
  iv: string;
  ciphertext: string;
  hash: string;
};
type RecordValue = { version: 1; head: Sealed | null; pending: Sealed | null };
export type Phase = 'before_prepare' | 'after_prepare' | 'after_witness' | 'after_publish';
type Options = { onPhase?: (phase: Phase) => void | Promise<void> };
const DATABASE = 'mikaki-mls-device-v1';
const STORE = 'devices';
const GENESIS: Head = { revision: 0, hash: null };
const MAX_STATE = 8 * 1024 * 1024;
const MAX_QUEUE = 64,
  MAX_EVENTS = 128,
  MAX_OPERATIONS = 512;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[A-Za-z0-9_-]{43}$/;
const encoder = new TextEncoder();
function fail(code: string): never {
  throw new Error(code);
}
function equal(a: Head, b: Head): boolean {
  return a.revision === b.revision && a.hash === b.hash;
}
function head(value: Sealed | null): Head {
  return value ? { revision: value.revision, hash: value.hash } : { ...GENESIS };
}
function uuid(value: string): void {
  if (!UUID.test(value)) fail('invalid_identifier');
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_record');
  return value as Record<string, unknown>;
}
function exact(value: unknown, keys: string[]): void {
  const fields = Object.keys(object(value));
  if (fields.length !== keys.length || fields.some((field) => !keys.includes(field)))
    fail('invalid_record');
}
function base64(bytes: Uint8Array): string {
  let text = '';
  for (let i = 0; i < bytes.length; i += 16384)
    text += String.fromCharCode(...bytes.subarray(i, i + 16384));
  return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
function bytes(text: string, limit = MAX_STATE): Uint8Array<ArrayBuffer> {
  if (
    typeof text !== 'string' ||
    text.length > Math.ceil((limit * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(text)
  )
    fail('invalid_encoding');
  let decoded: string;
  try {
    decoded = atob(
      text.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (text.length % 4)) % 4),
    );
  } catch {
    fail('invalid_encoding');
  }
  const value = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  if (value.length > limit || base64(value) !== text) fail('invalid_encoding');
  return value;
}
async function hash(value: Uint8Array<ArrayBuffer>): Promise<string> {
  return base64(new Uint8Array(await crypto.subtle.digest('SHA-256', value)));
}
function safeError(error: unknown): string {
  const code = typeof error === 'string' ? error : error instanceof Error ? error.message : '';
  return /^[a-z_]{1,64}$/.test(code) ? code : 'operation_failed';
}
function witnessHead(value: Head): Head {
  exact(value, ['revision', 'hash']);
  if (
    !Number.isSafeInteger(value.revision) ||
    value.revision < 0 ||
    (value.revision === 0
      ? value.hash !== null
      : typeof value.hash !== 'string' || !HASH.test(value.hash))
  )
    fail('invalid_witness_head');
  return { revision: value.revision, hash: value.hash };
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onerror = () => reject(new Error('storage_unavailable'));
    request.onblocked = () => reject(new Error('storage_blocked'));
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => db.close();
      resolve(db);
    };
  });
}
async function readRecord(key: string): Promise<RecordValue> {
  const db = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const request = tx.objectStore(STORE).get(key);
      tx.onabort = () => reject(new Error('storage_read_failed'));
      tx.oncomplete = () => {
        const record = request.result ?? { version: 1, head: null, pending: null };
        try {
          exact(record, ['version', 'head', 'pending']);
          if (record.version !== 1) fail('unsupported_storage_version');
          resolve(record);
        } catch (error) {
          reject(error);
        }
      };
    });
  } finally {
    db.close();
  }
}
/** Crypto/network work happens outside IDB transactions. The callback and all
 * scheduled writes are synchronous within the request's transaction task. */
async function writeRecord(
  key: string,
  change: (record: RecordValue) => RecordValue,
): Promise<void> {
  const db = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      let failure: unknown;
      const tx = db.transaction(STORE, 'readwrite', { durability: 'strict' });
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(failure ?? new Error('storage_commit_failed'));
      const store = tx.objectStore(STORE),
        request = store.get(key);
      request.onsuccess = () => {
        try {
          store.put(change(request.result ?? { version: 1, head: null, pending: null }), key);
        } catch (error) {
          failure = error;
          tx.abort();
        }
      };
    });
  } finally {
    db.close();
  }
}

function intent(command: Command): string {
  const fields: Record<Command['kind'], string[]> = {
    key_package: [],
    create_group: ['group'],
    invite: ['key_package'],
    join: ['welcome', 'group'],
    send: ['text'],
    send_chat: ['text', 'route'],
    receive: ['message_id', 'wire'],
    receive_delivery: ['message_id', 'wire', 'route'],
    update: [],
    remove_peer: [],
    merge_pending: ['commit_id'],
    acknowledge: ['message_id', 'digest'],
    accept_delivery: ['message_id', 'digest', 'channel_id'],
    prepare_invitation: ['offer'],
    invite_from_delivery: ['offer', 'message_id', 'wire'],
    join_from_delivery: ['offer', 'message_id', 'wire'],
    complete_invitation: ['offer'],
    mark_invitation_failed: ['offer'],
    mark_replacement_failed: ['previous', 'next'],
    begin_replacement_recovery: ['previous', 'next', 'close_id'],
    begin_close: ['offer', 'close_id', 'reason'],
    complete_close: ['offer', 'close_id'],
    mark_rejoin_failed: ['offer', 'next'],
    begin_rejoin_recovery: ['offer', 'next', 'close_id'],
    begin_cancel_rejoin: ['offer', 'next', 'cancel_id'],
    finish_cancel_rejoin: ['offer', 'next', 'cancel_id', 'outcome'],
    prepare_rejoin: ['offer', 'next'],
    activate_rejoin: ['offer', 'next'],
    bind_self: ['token'],
    refresh_self: ['token'],
    confirm_peer: ['token', 'fingerprint'],
    observe_binding: ['token'],
    accept_key_change: ['token', 'previous', 'replacement'],
    stage_peer: ['contact'],
    approve_peer: ['review_id', 'fingerprint', 'previous'],
    prepare_replacement: ['previous', 'next', 'approval_id'],
    attest_replacement_predecessor: ['previous', 'next', 'token'],
    begin_stop_replacement: ['previous', 'next', 'stop_id'],
    complete_stop_replacement: ['previous', 'next', 'stop_id'],
    consent_replacement: ['previous', 'next'],
    activate_replacement: ['previous', 'next'],
    observe_replacement_cancelled: ['previous', 'next'],
    begin_cancel_replacement: ['previous', 'next', 'cancel_id'],
    finish_cancel_replacement: ['previous', 'next', 'cancel_id', 'outcome'],
  };
  const selected = fields[command.kind];
  if (!selected) fail('invalid_command');
  exact(command, ['kind', ...selected]);
  const value = object(command);
  const canonical: Record<string, unknown> = { kind: command.kind };
  for (const field of selected) {
    const input = value[field];
    if (['wire', 'key_package', 'welcome', 'group'].includes(field)) {
      if (
        !Array.isArray(input) ||
        input.length < 1 ||
        input.length > (field === 'group' ? 16 : 65536) ||
        (field === 'group' && input.length !== 16) ||
        input.some((b) => !Number.isInteger(b) || b < 0 || b > 255)
      )
        fail('invalid_command_bytes');
      canonical[field] = input.slice();
    } else {
      if (typeof input !== 'string' || !input || input.length > (field === 'text' ? 4096 : 8192))
        fail('invalid_command_string');
      if (field.endsWith('_id')) uuid(input);
      canonical[field] = input;
    }
  }
  return JSON.stringify(canonical);
}

/** Canonical journal AAD scope, shared with the Vault custody boundary. */
export function deviceScopeContext(scope: DeviceScope, origin = location.origin): string {
  exact(scope, ['device', 'storage_id', 'key_id', 'fingerprint']);
  exact(scope.device, ['issuer', 'account_id', 'device_id', 'generation']);
  uuid(scope.storage_id);
  uuid(scope.key_id);
  uuid(scope.device.account_id);
  uuid(scope.device.device_id);
  if (
    !HASH.test(scope.fingerprint) ||
    !Number.isSafeInteger(scope.device.generation) ||
    scope.device.generation < 1 ||
    typeof scope.device.issuer !== 'string' ||
    scope.device.issuer.length > 256
  )
    fail('invalid_scope');
  return JSON.stringify([
    'mikaki-mls-device-state-v1',
    origin,
    scope.device.issuer,
    scope.device.account_id,
    scope.device.device_id,
    scope.device.generation,
    scope.storage_id,
    scope.key_id,
    scope.fingerprint,
  ]);
}

/** Per-operation fresh restore under an exclusive Web Lock. No engine/candidate
 * or checkpoint is exposed by this adapter, even when persistence fails. */
export class PersistentMlsDevice {
  readonly #context: string;
  readonly #scope: DeviceScope;
  readonly #module: DeviceModule;
  readonly #authorities: string;
  readonly #witness: HeadWitness;
  readonly #options: Options;
  readonly #abort = new AbortController();
  #key: CryptoKey | undefined;
  #scopeId: string | undefined;

  constructor(
    scope: DeviceScope,
    key: CryptoKey,
    module: DeviceModule,
    authorities: string,
    witness: HeadWitness,
    options: Options = {},
  ) {
    const context = deviceScopeContext(scope);
    if (
      key.type !== 'secret' ||
      key.extractable ||
      key.algorithm.name !== 'AES-GCM' ||
      (key.algorithm as AesKeyAlgorithm).length !== 256 ||
      !key.usages.includes('encrypt') ||
      !key.usages.includes('decrypt')
    )
      fail('invalid_storage_key');
    this.#scope = structuredClone(scope);
    // Always construct canonical field order; caller JSON ordering is irrelevant.
    this.#context = context;
    this.#key = key;
    this.#module = module;
    this.#authorities = authorities;
    this.#witness = witness;
    this.#options = options;
  }

  close(): void {
    this.#key = undefined;
    this.#abort.abort();
  }
  #active(): void {
    if (!this.#key || this.#abort.signal.aborted) fail('device_locked');
  }
  async #phase(phase: Phase): Promise<void> {
    await this.#options.onPhase?.(phase);
    this.#active();
  }
  async #locked<T>(operation: (id: string) => Promise<T>): Promise<T> {
    this.#active();
    if (!navigator.locks) fail('web_locks_required');
    this.#scopeId ??= await hash(encoder.encode(this.#context));
    this.#active();
    return navigator.locks.request(
      `mikaki-mls:${this.#scopeId}`,
      { mode: 'exclusive', signal: this.#abort.signal },
      async () => {
        this.#active();
        const value = await operation(this.#scopeId!);
        this.#active();
        return value;
      },
    );
  }
  #aad(
    value: Pick<Sealed, 'version' | 'revision' | 'previous' | 'transaction_id'>,
  ): Uint8Array<ArrayBuffer> {
    return encoder.encode(
      JSON.stringify([
        this.#context,
        value.version,
        value.revision,
        value.previous.revision,
        value.previous.hash,
        value.transaction_id,
      ]),
    );
  }
  async #digest(value: Sealed): Promise<string> {
    const aad = this.#aad(value),
      iv = bytes(value.iv, 12),
      ciphertext = bytes(value.ciphertext, MAX_STATE + 16);
    if (iv.length !== 12 || ciphertext.length < 16) fail('invalid_encrypted_record');
    const joined = new Uint8Array(aad.length + iv.length + ciphertext.length);
    joined.set(aad);
    joined.set(iv, aad.length);
    joined.set(ciphertext, aad.length + iv.length);
    return hash(joined);
  }
  async #open(value: Sealed): Promise<State> {
    exact(value, ['version', 'revision', 'previous', 'transaction_id', 'iv', 'ciphertext', 'hash']);
    const previous = witnessHead(value.previous);
    if (
      value.version !== 1 ||
      !Number.isSafeInteger(value.revision) ||
      value.revision !== previous.revision + 1 ||
      !HASH.test(value.hash)
    )
      fail('invalid_encrypted_record');
    uuid(value.transaction_id);
    if ((await this.#digest(value)) !== value.hash) fail('ciphertext_digest_mismatch');
    this.#active();
    let plaintext: Uint8Array<ArrayBuffer>;
    try {
      plaintext = new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: bytes(value.iv, 12),
            additionalData: this.#aad(value),
            tagLength: 128,
          },
          this.#key!,
          bytes(value.ciphertext, MAX_STATE + 16),
        ),
      );
    } catch {
      fail('state_authentication_failed');
    }
    try {
      this.#active();
      const state = JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(plaintext),
      ) as State;
      exact(state, [
        'version',
        'last_time',
        'checkpoint',
        'outbox',
        'inbox',
        'received',
        'delivered',
        'operations',
        'pending_commit',
        ...(Object.hasOwn(state, 'invitation') ? ['invitation'] : []),
        ...(Object.hasOwn(state, 'recoveries') ? ['recoveries'] : []),
        ...(Object.hasOwn(state, 'sent_texts') ? ['sent_texts'] : []),
        ...(Object.hasOwn(state, 'chat_sequence') ? ['chat_sequence'] : []),
        ...(Object.hasOwn(state, 'peer_review') ? ['peer_review'] : []),
        ...(Object.hasOwn(state, 'replacements') ? ['replacements'] : []),
        ...(Object.hasOwn(state, 'replacement_stops') ? ['replacement_stops'] : []),
      ]);
      if (
        state.version !== 1 ||
        !Number.isSafeInteger(state.last_time) ||
        state.last_time < 0 ||
        !Array.isArray(state.outbox) ||
        !Array.isArray(state.inbox) ||
        !Array.isArray(state.received) ||
        !Array.isArray(state.delivered) ||
        !Array.isArray(state.operations) ||
        state.outbox.length > MAX_QUEUE ||
        state.inbox.length > MAX_EVENTS ||
        state.received.length > MAX_OPERATIONS ||
        state.delivered.length > MAX_OPERATIONS ||
        state.operations.length > MAX_OPERATIONS
      )
        fail('invalid_device_state');
      if (state.invitation) {
        const current = state.invitation;
        exact(current, [
          'channel',
          'inviter_scope',
          'phase',
          'key_package_id',
          'commit_id',
          'welcome_id',
        ]);
        checkedInvitation({ channel: current.channel, inviter_scope: current.inviter_scope });
        if (
          !['prepared', 'invited', 'joined', 'active', 'recovery_required'].includes(current.phase)
        )
          fail('invalid_invitation_state');
        for (const id of [current.key_package_id, current.commit_id, current.welcome_id])
          if (id !== null) uuid(id);
      }
      if (state.peer_review !== undefined) {
        const r = state.peer_review;
        exact(r, ['id', 'contact', 'verified', 'observation']);
        uuid(r.id);
        checkedContact(r.contact);
        verifiedDevice(r.verified);
        if (
          !['unconfirmed', 'current', 'key_changed', 'revoked', 'registry_conflict'].includes(
            r.observation,
          )
        )
          fail('invalid_peer_review');
      }
      if (state.replacements !== undefined) {
        if (!Array.isArray(state.replacements) || state.replacements.length > 8)
          fail('invalid_replacement_state');
        const ids = new Set<string>();
        for (const [index, entry] of state.replacements.entries()) {
          exact(entry, [
            'previous',
            'next',
            'operation_id',
            'phase',
            'quarantined',
            ...(Object.hasOwn(entry, 'cancellation') ? ['cancellation'] : []),
            ...(Object.hasOwn(entry, 'predecessor_confirmed') ? ['predecessor_confirmed'] : []),
            ...(Object.hasOwn(entry, 'restart_from') ? ['restart_from'] : []),
          ]);
          if (Object.hasOwn(entry, 'predecessor_confirmed') && entry.predecessor_confirmed !== true)
            fail('invalid_replacement_state');
          if (Object.hasOwn(entry, 'cancellation')) {
            const cancellation = entry.cancellation;
            if (!cancellation) fail('invalid_replacement_state');
            exact(cancellation, ['operation_id', 'outcome']);
            uuid(cancellation.operation_id);
            if (
              !['pending', 'cancelled', 'admitted'].includes(cancellation.outcome) ||
              (cancellation.outcome === 'pending' && entry.phase !== 'cancelling') ||
              (cancellation.outcome === 'cancelled' && entry.phase !== 'cancelled')
            )
              fail('invalid_replacement_state');
          }
          if (entry.phase === 'cancelling' && entry.cancellation?.outcome !== 'pending')
            fail('invalid_replacement_state');
          const route = replacement(entry.previous, entry.next);
          if (Object.hasOwn(entry, 'restart_from')) {
            uuid(entry.restart_from!);
            const stop = state.replacement_stops?.find(
              (s) => s.next.channel.id === entry.restart_from,
            );
            if (
              !stop ||
              JSON.stringify(stop.previous) !== JSON.stringify(entry.previous) ||
              (entry.phase === 'active'
                ? stop.phase !== 'retired'
                : !['stopped', 'retired'].includes(stop.phase))
            )
              fail('invalid_replacement_state');
          }
          if (entry.predecessor_confirmed && route.current.scope !== this.#scopeId)
            fail('invalid_replacement_state');
          uuid(entry.operation_id);
          if (
            ids.has(entry.next.channel.id) ||
            ![
              'prepared',
              'consented',
              'active',
              'cancelling',
              'cancelled',
              'recovery_required',
              'recovering',
              'abandoned',
            ].includes(entry.phase) ||
            !Array.isArray(entry.quarantined) ||
            entry.quarantined.length > MAX_QUEUE ||
            (index < state.replacements.length - 1 &&
              !['active', 'cancelled', 'abandoned'].includes(entry.phase)) ||
            (!['active', 'cancelled', 'abandoned'].includes(entry.phase) &&
              entry.quarantined.length)
          )
            fail('invalid_replacement_state');
          ids.add(entry.next.channel.id);
        }
      }
      if (state.replacement_stops !== undefined) {
        if (!Array.isArray(state.replacement_stops) || state.replacement_stops.length > 8)
          fail('invalid_replacement_state');
        const ids = new Set<string>(),
          groups = new Set<string>();
        let pending: string | undefined;
        for (const [i, stop] of state.replacement_stops.entries()) {
          exact(stop, [
            'previous',
            'next',
            'operation_id',
            'phase',
            'quarantined',
            ...(Object.hasOwn(stop, 'native_origin') ? ['native_origin'] : []),
            ...(Object.hasOwn(stop, 'recovery_id') ? ['recovery_id'] : []),
            ...(Object.hasOwn(stop, 'recovery_chain') ? ['recovery_chain'] : []),
          ]);
          replacement(stop.previous, stop.next);
          uuid(stop.operation_id);
          if (Object.hasOwn(stop, 'native_origin')) {
            if (
              stop.native_origin !== true ||
              replacement(stop.previous, stop.next).stable.scope !== this.#scopeId ||
              stop.recovery_id ||
              stop.recovery_chain ||
              !state.replacements?.some(
                (r) =>
                  r.phase === 'active' &&
                  JSON.stringify(r.previous) === JSON.stringify(stop.previous) &&
                  JSON.stringify(r.next) === JSON.stringify(stop.next),
              ) ||
              (stop.phase !== 'retired' &&
                (!state.invitation ||
                  JSON.stringify({
                    channel: state.invitation.channel,
                    inviter_scope: state.invitation.inviter_scope,
                  }) !== JSON.stringify(stop.next) ||
                  state.replacement_stops.slice(0, i).some((s) => s.phase !== 'retired')))
            )
              fail('invalid_replacement_state');
          }
          if (Object.hasOwn(stop, 'recovery_chain')) {
            if (
              !stop.recovery_id ||
              !Array.isArray(stop.recovery_chain) ||
              stop.recovery_chain.length < 2 ||
              stop.recovery_chain.length > 9
            )
              fail('invalid_replacement_state');
            for (const id of stop.recovery_chain) uuid(id);
          }
          if (Object.hasOwn(stop, 'recovery_id')) {
            uuid(stop.recovery_id!);
            if (
              !replacementStopRecoveries(stop, state.recoveries ?? [], state.replacements ?? [])
                .length
            )
              fail('invalid_replacement_state');
          }
          if (
            (stop.recovery_id || stop.native_origin) &&
            stop.phase === 'retired' &&
            !state.replacements?.some((r) => {
              const last = state.replacement_stops!.findIndex(
                (s) => s.next.channel.id === r.restart_from,
              );
              return (
                last >= i &&
                r.phase === 'active' &&
                JSON.stringify(r.previous) === JSON.stringify(stop.previous) &&
                state
                  .replacement_stops!.slice(i, last + 1)
                  .every(
                    (s) =>
                      s.phase === 'retired' &&
                      JSON.stringify(s.previous) === JSON.stringify(stop.previous),
                  )
              );
            })
          )
            fail('invalid_replacement_state');
          if (
            !['stopping', 'stopped', 'retired'].includes(stop.phase) ||
            ids.has(stop.next.channel.id) ||
            groups.has(stop.next.channel.group) ||
            !Array.isArray(stop.quarantined) ||
            stop.quarantined.length > MAX_QUEUE ||
            (stop.phase === 'stopping' && i !== state.replacement_stops.length - 1)
          )
            fail('invalid_replacement_state');
          if (stop.phase !== 'retired') {
            if (pending && pending !== JSON.stringify(stop.previous))
              fail('invalid_replacement_state');
            pending = JSON.stringify(stop.previous);
          } else if (pending) fail('invalid_replacement_state');
          for (const offer of this.#stopOffers(state, stop)) {
            if (ids.has(offer.channel.id) || groups.has(offer.channel.group))
              fail('invalid_replacement_state');
            ids.add(offer.channel.id);
            groups.add(offer.channel.group);
          }
        }
      }
      if (state.sent_texts !== undefined) {
        if (!Array.isArray(state.sent_texts) || state.sent_texts.length > MAX_EVENTS)
          fail('invalid_chat_history');
        const ids = new Set<string>();
        for (const message of state.sent_texts) {
          exact(message, ['id', 'channel_id', 'text', 'position']);
          uuid(message.id);
          uuid(message.channel_id);
          if (
            ids.has(message.id) ||
            typeof message.text !== 'string' ||
            !message.text ||
            encoder.encode(message.text).length > 4096 ||
            !Number.isSafeInteger(message.position) ||
            message.position < 1 ||
            message.position > (state.chat_sequence ?? 0)
          )
            fail('invalid_chat_history');
          ids.add(message.id);
        }
      }
      if (
        state.chat_sequence !== undefined &&
        (!Number.isSafeInteger(state.chat_sequence) ||
          state.chat_sequence < 0 ||
          state.chat_sequence > MAX_EVENTS * 2)
      )
        fail('invalid_chat_history');
      if (state.recoveries !== undefined) {
        if (!Array.isArray(state.recoveries) || state.recoveries.length > 9)
          fail('invalid_recovery_state');
        const ids = new Set<string>(),
          groups = new Set<string>();
        for (const [index, entry] of state.recoveries.entries()) {
          exact(entry, [
            'offer',
            'operation_id',
            'reason',
            'phase',
            'next',
            'quarantined',
            'inbox_ids',
            ...(Object.hasOwn(entry, 'replacement_id') ? ['replacement_id'] : []),
            ...(Object.hasOwn(entry, 'deferred_from') ? ['deferred_from'] : []),
            ...(Object.hasOwn(entry, 'successor_failed') ? ['successor_failed'] : []),
            ...(Object.hasOwn(entry, 'cancellations') ? ['cancellations'] : []),
          ]);
          if (
            entry.replacement_id !== undefined &&
            !state.replacements?.some(
              (r) =>
                r.next.channel.id === entry.replacement_id &&
                JSON.stringify(r.next) === JSON.stringify(entry.offer) &&
                ['recovering', 'abandoned', 'active'].includes(r.phase),
            )
          )
            fail('invalid_recovery_state');
          if (Object.hasOwn(entry, 'successor_failed') && entry.successor_failed !== true)
            fail('invalid_recovery_state');
          if (entry.successor_failed && !entry.next) fail('invalid_recovery_state');
          rejoinChain(state.recoveries, entry.offer.channel.id);
          const offer = checkedInvitation(entry.offer);
          uuid(entry.operation_id);
          if (
            ids.has(offer.channel.id) ||
            groups.has(offer.channel.group) ||
            !['cancel_invitation', 'epoch_conflict', 'leave'].includes(entry.reason) ||
            !['closing', 'closed', 'rejoined'].includes(entry.phase) ||
            !Array.isArray(entry.quarantined) ||
            entry.quarantined.length > MAX_QUEUE ||
            !Array.isArray(entry.inbox_ids) ||
            entry.inbox_ids.length > MAX_EVENTS ||
            (index < state.recoveries.length - 1 &&
              entry.phase !== 'rejoined' &&
              state.recoveries[index + 1]?.deferred_from !== entry.offer.channel.id &&
              !recoveryReplaced(
                entry,
                state.replacements ?? [],
                state.replacement_stops ?? [],
                state.recoveries,
              )) ||
            (entry.phase !== 'rejoined' && entry.quarantined.length)
          )
            fail('invalid_recovery_state');
          if (entry.next) this.#successor(offer, checkedInvitation(entry.next));
          if (entry.phase === 'rejoined' && !entry.next) fail('invalid_recovery_state');
          if (entry.cancellations !== undefined) {
            if (!Array.isArray(entry.cancellations) || !entry.cancellations.length)
              fail('invalid_recovery_state');
            const proposals = new Set<string>(),
              operations = new Set<string>();
            for (const [i, attempt] of entry.cancellations.entries()) {
              exact(attempt, ['next', 'operation_id', 'outcome']);
              const next = checkedInvitation(attempt.next);
              this.#successor(offer, next);
              uuid(attempt.operation_id);
              if (
                proposals.has(next.channel.id) ||
                proposals.has(next.channel.group) ||
                operations.has(attempt.operation_id) ||
                !['pending', 'cancelled', 'admitted'].includes(attempt.outcome) ||
                (attempt.outcome !== 'cancelled' &&
                  (i !== entry.cancellations.length - 1 ||
                    JSON.stringify(entry.next) !== JSON.stringify(next))) ||
                (attempt.outcome === 'pending' && entry.phase !== 'closed') ||
                (attempt.outcome === 'cancelled' &&
                  entry.next &&
                  (entry.next.channel.id === next.channel.id ||
                    entry.next.channel.group === next.channel.group))
              )
                fail('invalid_recovery_state');
              proposals.add(next.channel.id);
              proposals.add(next.channel.group);
              operations.add(attempt.operation_id);
            }
          }
          for (const id of entry.inbox_ids) uuid(id);
          ids.add(offer.channel.id);
          groups.add(offer.channel.group);
        }
        const cancellations = state.recoveries.flatMap((r) => r.cancellations ?? []);
        if (
          cancellations.length > 32 ||
          new Set(cancellations.map((c) => c.operation_id)).size !== cancellations.length
        )
          fail('invalid_recovery_state');
        const vetoedIds = new Set<string>(),
          vetoedGroups = new Set<string>();
        for (const { next, outcome } of cancellations) {
          if (outcome !== 'cancelled') continue;
          const known = [
            ...state.recoveries.flatMap((r) => [r.offer, ...(r.next ? [r.next] : [])]),
            ...(state.replacements ?? []).flatMap((r) => [r.previous, r.next]),
          ];
          if (
            vetoedIds.has(next.channel.id) ||
            vetoedGroups.has(next.channel.group) ||
            known.some(
              (o) => o.channel.id === next.channel.id || o.channel.group === next.channel.group,
            )
          )
            fail('invalid_recovery_state');
          vetoedIds.add(next.channel.id);
          vetoedGroups.add(next.channel.group);
        }
      }
      return state;
    } finally {
      plaintext.fill(0);
    }
  }
  async #seal(state: State, previous: Head): Promise<Sealed> {
    if (previous.revision >= Number.MAX_SAFE_INTEGER) fail('revision_exhausted');
    const plaintext = encoder.encode(JSON.stringify(state));
    if (plaintext.length > MAX_STATE) {
      plaintext.fill(0);
      fail('device_state_full');
    }
    const value: Sealed = {
      version: 1,
      revision: previous.revision + 1,
      previous: { ...previous },
      transaction_id: crypto.randomUUID(),
      iv: base64(crypto.getRandomValues(new Uint8Array(12))),
      ciphertext: '',
      hash: '',
    };
    try {
      this.#active();
      value.ciphertext = base64(
        new Uint8Array(
          await crypto.subtle.encrypt(
            {
              name: 'AES-GCM',
              iv: bytes(value.iv, 12),
              additionalData: this.#aad(value),
              tagLength: 128,
            },
            this.#key!,
            plaintext,
          ),
        ),
      );
      this.#active();
      value.hash = await this.#digest(value);
      return value;
    } finally {
      plaintext.fill(0);
    }
  }
  #restore(state: State): DeviceEngine {
    const checkpoint = bytes(state.checkpoint, 2 * 1024 * 1024);
    let engine: DeviceEngine | undefined;
    try {
      engine = this.#module.BoundMlsClient.restore(checkpoint, this.#authorities);
      const actual = JSON.parse(engine.identity_json()) as DeviceIdentity;
      if (
        actual.issuer !== this.#scope.device.issuer ||
        actual.account_id !== this.#scope.device.account_id ||
        actual.device_id !== this.#scope.device.device_id ||
        actual.generation !== this.#scope.device.generation ||
        engine.fingerprint() !== this.#scope.fingerprint
      )
        fail('checkpoint_scope_mismatch');
      return engine;
    } catch (error) {
      engine?.free();
      throw error;
    } finally {
      checkpoint.fill(0);
    }
  }
  async #synchronize(id: string): Promise<{ state: State; head: Sealed } | null> {
    const record = await readRecord(id);
    const witnessed = witnessHead(await this.#witness.read(id));
    this.#active();
    if (!record.pending) {
      if (!equal(head(record.head), witnessed)) fail('rollback_or_state_loss');
      return record.head ? { state: await this.#open(record.head), head: record.head } : null;
    }
    const candidate = record.pending;
    if (!equal(candidate.previous, head(record.head))) fail('invalid_pending_base');
    const state = await this.#open(candidate);
    // Verify the restored private state/context before advancing any witness.
    this.#restore(state).free();
    if (!equal(witnessed, head(candidate))) {
      if (!equal(witnessed, head(record.head))) fail('witness_conflict');
      const committed = witnessHead(
        await this.#witness.compareAndSet(id, head(record.head), head(candidate)),
      );
      this.#active();
      if (!equal(committed, head(candidate))) fail('witness_conflict');
    }
    await this.#phase('after_witness');
    await writeRecord(id, (current) => {
      if (
        !equal(head(current.head), head(record.head)) ||
        !equal(head(current.pending), head(candidate))
      )
        fail('local_head_conflict');
      return { version: 1, head: candidate, pending: null };
    });
    await this.#phase('after_publish');
    return { state, head: candidate };
  }
  async #persist(id: string, state: State, previous: Sealed | null): Promise<void> {
    const candidate = await this.#seal(state, head(previous));
    await this.#phase('before_prepare');
    await writeRecord(id, (current) => {
      if (current.version !== 1 || current.pending || !equal(head(current.head), head(previous)))
        fail('local_head_conflict');
      return { version: 1, head: current.head, pending: candidate };
    });
    await this.#phase('after_prepare');
    await this.#synchronize(id);
  }

  async bootstrap(checkpoint: Uint8Array): Promise<void> {
    const copy = new Uint8Array(checkpoint);
    try {
      await this.#locked(async (id) => {
        if (await this.#synchronize(id)) fail('device_already_initialized');
        const state: State = {
          version: 1,
          last_time: 0,
          checkpoint: base64(copy),
          outbox: [],
          inbox: [],
          received: [],
          delivered: [],
          operations: [],
          pending_commit: null,
          invitation: null,
          recoveries: [],
        };
        this.#restore(state).free();
        await this.#persist(id, state, null);
      });
    } finally {
      copy.fill(0);
    }
  }

  async request(operationId: string, command: Command, now: number): Promise<Receipt> {
    uuid(operationId);
    if (!Number.isSafeInteger(now) || now < 0) fail('invalid_time');
    const canonical = intent(command);
    // Snapshot intent before the first await; caller mutations cannot alter it.
    const selected = JSON.parse(canonical) as Command;
    const requestHash = await hash(encoder.encode(canonical));
    return this.#locked(async (id) => {
      const saved = await this.#synchronize(id);
      if (!saved) fail('device_not_initialized');
      let state = structuredClone(saved.state);
      const previous = state.operations.find((entry) => entry.id === operationId);
      if (previous) {
        if (previous.intent !== requestHash) fail('operation_id_conflict');
        return structuredClone(previous.receipt);
      }
      if (state.operations.length >= MAX_OPERATIONS) fail('operation_ledger_full');
      if (now < state.last_time) fail('clock_rollback');
      let engine = this.#restore(state);
      let receipt: Receipt;
      try {
        receipt = await this.#apply(engine, state, operationId, selected, now);
      } catch (error) {
        // A command is all-or-nothing, including queue admission and protocol
        // mutation. Its failure receipt/clock are durable, not a partial send.
        engine.free();
        state = structuredClone(saved.state);
        engine = this.#restore(state);
        receipt = {
          operation_id: operationId,
          ok: false,
          message_ids: [],
          error: safeError(error),
        };
      }
      try {
        state.last_time = now;
        const checkpoint = engine.checkpoint();
        try {
          state.checkpoint = base64(checkpoint);
        } finally {
          checkpoint.fill(0);
        }
        state.operations.push({ id: operationId, intent: requestHash, receipt });
        await this.#persist(id, state, saved.head);
        return structuredClone(receipt);
      } finally {
        engine.free();
      }
    });
  }

  async #apply(
    engine: DeviceEngine,
    state: State,
    id: string,
    command: Command,
    now: number,
  ): Promise<Receipt> {
    const receipt: Receipt = { operation_id: id, ok: true, message_ids: [] };
    const time = BigInt(now);
    if (
      state.replacement_stops?.some((s) => s.phase !== 'retired') &&
      ![
        'begin_stop_replacement',
        'complete_stop_replacement',
        'stage_peer',
        'approve_peer',
        'refresh_self',
        'observe_binding',
        'prepare_replacement',
        'attest_replacement_predecessor',
        'consent_replacement',
        'activate_replacement',
        'begin_cancel_replacement',
        'finish_cancel_replacement',
        'observe_replacement_cancelled',
      ].includes(command.kind)
    )
      fail('conversation_frozen');
    const recovery = state.recoveries?.at(-1);
    const frozen =
      recovery &&
      !recoveryReplaced(
        recovery,
        state.replacements ?? [],
        state.replacement_stops ?? [],
        state.recoveries ?? [],
      )
        ? recovery.phase
        : undefined;
    if (
      frozen &&
      frozen !== 'rejoined' &&
      ![
        'mark_invitation_failed',
        'mark_replacement_failed',
        'begin_replacement_recovery',
        'begin_stop_replacement',
        'complete_stop_replacement',
        'begin_close',
        'complete_close',
        'mark_rejoin_failed',
        'begin_rejoin_recovery',
        'begin_cancel_rejoin',
        'finish_cancel_rejoin',
        'prepare_rejoin',
        'activate_rejoin',
        'refresh_self',
        'observe_binding',
        'stage_peer',
        'approve_peer',
        'prepare_replacement',
        'attest_replacement_predecessor',
        'consent_replacement',
        'activate_replacement',
        'begin_cancel_replacement',
        'finish_cancel_replacement',
        'observe_replacement_cancelled',
      ].includes(command.kind)
    )
      fail('conversation_frozen');
    if (
      state.replacements?.at(-1)?.phase !== undefined &&
      !['active', 'abandoned'].includes(state.replacements.at(-1)!.phase) &&
      ![
        'mark_replacement_failed',
        'begin_replacement_recovery',
        'begin_stop_replacement',
        'complete_stop_replacement',
        'begin_close',
        'complete_close',
        'prepare_replacement',
        'attest_replacement_predecessor',
        'consent_replacement',
        'activate_replacement',
        'begin_cancel_replacement',
        'finish_cancel_replacement',
        'observe_replacement_cancelled',
        'refresh_self',
        'observe_binding',
        'stage_peer',
        'approve_peer',
      ].includes(command.kind)
    )
      fail('conversation_frozen');
    if (
      state.invitation?.phase === 'recovery_required' &&
      !this.#stoppedOrigin(state) &&
      ![
        'begin_stop_replacement',
        'complete_stop_replacement',
        'mark_invitation_failed',
        'begin_close',
        'attest_replacement_predecessor',
        'complete_close',
        'mark_rejoin_failed',
        'begin_rejoin_recovery',
        'begin_cancel_rejoin',
        'finish_cancel_rejoin',
        'prepare_rejoin',
        'activate_rejoin',
        'refresh_self',
        'observe_binding',
        'stage_peer',
        'approve_peer',
      ].includes(command.kind)
    )
      fail('conversation_frozen');
    const add = async (
      kind: WireKind,
      wire: Uint8Array,
      requirePeer: boolean,
      dependsOn: string | null = null,
    ) => {
      if (state.outbox.length >= MAX_QUEUE) fail('outbox_full');
      const context = engine.outgoing_context(time, requirePeer);
      const message: Queued = {
        id: crypto.randomUUID(),
        kind,
        wire: base64(wire),
        digest: await hash(new Uint8Array(wire)),
        context,
        require_peer: requirePeer,
        depends_on: dependsOn,
      };
      state.outbox.push(message);
      receipt.message_ids.push(message.id);
      return message.id;
    };
    switch (command.kind) {
      case 'begin_stop_replacement':
      case 'complete_stop_replacement': {
        const { previous, next } = replacement(
          JSON.parse(command.previous),
          JSON.parse(command.next),
        );
        let stop = state.replacement_stops?.find((s) => s.next.channel.id === next.channel.id);
        if (stop) {
          if (
            JSON.stringify(stop.previous) !== JSON.stringify(previous) ||
            JSON.stringify(stop.next) !== JSON.stringify(next) ||
            stop.operation_id !== command.stop_id
          )
            fail('replacement_stop_conflict');
          if (stop.phase !== 'stopping') break;
        } else {
          if (command.kind !== 'begin_stop_replacement') fail('replacement_stop_unconfirmed');
          const activated = state.replacements?.find(
            (r) =>
              r.phase === 'active' &&
              JSON.stringify(r.previous) === JSON.stringify(previous) &&
              JSON.stringify(r.next) === JSON.stringify(next),
          );
          const inherited = state.replacement_stops?.find(
            (s) =>
              s.phase !== 'retired' &&
              s.native_origin &&
              JSON.stringify(s.previous) === JSON.stringify(previous),
          );
          if (activated && replacement(previous, next).stable.scope !== this.#scopeId)
            fail('replacement_origin_advanced');
          const origin = inherited ?? (activated ? { previous, next } : undefined);
          if (origin) {
            const own = [origin.next.channel.a, origin.next.channel.b].find(
              (e) => e.scope === this.#scopeId,
            );
            if (!own) fail('replacement_origin_advanced');
            const peer =
              own === origin.next.channel.a ? origin.next.channel.b : origin.next.channel.a;
            engine.check_activated_replacement_origin(
              decode(previous.channel.group, 16),
              decode(origin.next.channel.group, 16),
              own.fingerprint,
              peer.fingerprint,
              time,
            );
          } else engine.check_replacement_origin(decode(previous.channel.group, 16), time);
          if ((state.replacement_stops?.length ?? 0) >= 8) fail('recovery_ledger_full');
          const pending = state.replacement_stops?.filter((s) => s.phase !== 'retired') ?? [];
          const stoppedOffers =
            state.replacement_stops?.flatMap((s) => this.#stopOffers(state, s)) ?? [];
          if (
            pending.some(
              (s) =>
                s.phase !== 'stopped' || JSON.stringify(s.previous) !== JSON.stringify(previous),
            ) ||
            stoppedOffers.some(
              (o) => o.channel.id === next.channel.id || o.channel.group === next.channel.group,
            ) ||
            state.replacement_stops?.some(
              (s) =>
                s.previous.channel.id === next.channel.id ||
                s.previous.channel.group === next.channel.group,
            )
          )
            fail('replacement_stop_conflict');
          const latest = state.replacements?.at(-1);
          if (
            latest &&
            !['active', 'cancelled', 'abandoned'].includes(latest.phase) &&
            (JSON.stringify(latest.previous) !== JSON.stringify(previous) ||
              JSON.stringify(latest.next) !== JSON.stringify(next))
          )
            fail('replacement_intent_conflict');
          if (
            state.replacements?.some(
              (r) =>
                r.next.channel.id === next.channel.id &&
                (JSON.stringify(r.previous) !== JSON.stringify(previous) ||
                  JSON.stringify(r.next) !== JSON.stringify(next) ||
                  ['cancelled', 'cancelling', 'recovering'].includes(r.phase) ||
                  (r.phase === 'active' && !activated)),
            )
          )
            fail('replacement_intent_conflict');
          const recovery = state.recoveries?.at(-1);
          const bridge = replacementRecoveryLink(
            previous,
            next,
            state.recoveries ?? [],
            state.replacements ?? [],
          );
          // Further admitted targets may share an earlier linked stop while
          // managed metadata still names that closed root. Keep the exact root.
          const retainedOrigin = this.#stoppedOrigin(state, previous);
          if (activated && !state.invitation) fail('replacement_origin_advanced');
          if (state.invitation && !retainedOrigin) {
            this.#invitation(state, activated ? next : bridge ? recovery!.offer : previous);
            if (!activated && state.invitation.phase !== (bridge ? 'recovery_required' : 'active'))
              fail('replacement_origin_advanced');
          } else if (!state.invitation && (bridge || state.outbox.length || state.pending_commit))
            fail('replacement_requires_empty_device');
          if (
            recovery &&
            recovery.phase !== 'rejoined' &&
            !bridge &&
            !retainedOrigin &&
            (JSON.stringify(recovery.offer) !== JSON.stringify(previous) ||
              recovery.phase !== 'closed' ||
              recovery.next)
          )
            fail('rejoin_intent_conflict');
          stop = {
            previous,
            next,
            operation_id: command.stop_id,
            phase: 'stopping',
            quarantined: state.outbox,
            ...bridge,
            ...(activated ? { native_origin: true as const } : {}),
          };
          state.outbox = [];
          state.pending_commit = null;
          (state.replacement_stops ??= []).push(stop);
        }
        if (command.kind === 'complete_stop_replacement') {
          stop.phase = 'stopped';
          const old = state.replacements?.find((r) => r.next.channel.id === next.channel.id);
          if (old && !stop.native_origin) old.phase = 'abandoned';
        }
        break;
      }
      case 'attest_replacement_predecessor': {
        const { previous, next, retired, current } = replacement(
          JSON.parse(command.previous),
          JSON.parse(command.next),
        );
        const entry = state.replacements?.find((r) => r.next.channel.id === next.channel.id);
        if (state.replacement_stops?.some((s) => s.next.channel.id === next.channel.id))
          fail('conversation_frozen');
        if (
          !entry ||
          JSON.stringify(entry.previous) !== JSON.stringify(previous) ||
          JSON.stringify(entry.next) !== JSON.stringify(next) ||
          !['prepared', 'consented'].includes(entry.phase) ||
          current.scope !== this.#scopeId
        )
          fail('replacement_intent_conflict');
        if (entry.predecessor_confirmed) break;
        engine.check_group_predecessor(
          command.token,
          retired.fingerprint,
          decode(previous.channel.group, 16),
          decode(this.#stoppedGroups(state, entry)[0]?.channel.group ?? next.channel.group, 16),
          time,
        );
        entry.predecessor_confirmed = true;
        break;
      }
      case 'prepare_replacement':
      case 'consent_replacement':
      case 'activate_replacement':
      case 'begin_cancel_replacement':
      case 'finish_cancel_replacement':
      case 'observe_replacement_cancelled': {
        const { previous, next, stable, retired, current } = replacement(
          JSON.parse(command.previous),
          JSON.parse(command.next),
        );
        let entry = state.replacements?.find((r) => r.next.channel.id === next.channel.id);
        if (state.replacement_stops?.some((s) => s.next.channel.id === next.channel.id))
          fail('conversation_frozen');
        if (
          entry &&
          (JSON.stringify(entry.previous) !== JSON.stringify(previous) ||
            JSON.stringify(entry.next) !== JSON.stringify(next))
        )
          fail('replacement_intent_conflict');
        if (entry?.phase === 'active') {
          if (['begin_cancel_replacement', 'finish_cancel_replacement'].includes(command.kind))
            fail('replacement_already_active');
          break;
        }
        if (entry && ['recovering', 'abandoned', 'recovery_required'].includes(entry.phase))
          fail('conversation_frozen');
        if (entry?.phase === 'cancelled') {
          if (command.kind === 'observe_replacement_cancelled') break;
          if (
            (command.kind === 'begin_cancel_replacement' ||
              command.kind === 'finish_cancel_replacement') &&
            entry.cancellation?.operation_id === command.cancel_id
          )
            break;
          fail('replacement_cancelled');
        }
        if (
          entry?.phase === 'cancelling' &&
          !['begin_cancel_replacement', 'finish_cancel_replacement'].includes(command.kind)
        )
          fail('replacement_cancellation_pending');
        if (!entry) {
          if (command.kind !== 'prepare_replacement') fail('replacement_not_prepared');
          const latest = state.replacements?.at(-1);
          const stops = state.replacement_stops?.filter((s) => s.phase !== 'retired') ?? [];
          if (
            stops.some(
              (s) =>
                s.phase !== 'stopped' || JSON.stringify(s.previous) !== JSON.stringify(previous),
            )
          )
            fail('replacement_stop_unconfirmed');
          if (
            latest &&
            latest.phase !== 'active' &&
            !(
              (latest.phase === 'abandoned' &&
                stops.some((s) => s.next.channel.id === latest.next.channel.id)) ||
              (latest.phase === 'cancelled' &&
                JSON.stringify(latest.previous) === JSON.stringify(previous))
            )
          )
            fail('replacement_intent_conflict');
          if (
            state.replacements?.some(
              (r) =>
                r.next.channel.id === next.channel.id ||
                r.next.channel.group === next.channel.group,
            )
          )
            fail('replacement_cancelled');
          if (
            (state.replacements?.length ?? 0) >= 8 ||
            this.#retirementCount(state, [previous.channel.group]) > 8
          )
            fail('recovery_ledger_full');
          if (
            state.recoveries?.some(
              (r) =>
                r.offer.channel.group === next.channel.group ||
                r.offer.channel.id === next.channel.id ||
                r.cancellations?.some(
                  (c) =>
                    c.outcome === 'cancelled' &&
                    (c.next.channel.id === next.channel.id ||
                      c.next.channel.group === next.channel.group),
                ),
            ) ||
            state.replacements?.some(
              (r) =>
                r.previous.channel.group === next.channel.group ||
                r.previous.channel.id === next.channel.id,
            ) ||
            state.replacement_stops?.some(
              (s) =>
                s.next.channel.id === next.channel.id ||
                s.next.channel.group === next.channel.group,
            )
          )
            fail('retired_or_unexpected_group');
          if (state.recoveries?.some((r) => r.offer.channel.id === previous.channel.id && r.next))
            fail('rejoin_intent_conflict');
          if (state.invitation) {
            if (!this.#stoppedOrigin(state, previous)) {
              this.#invitation(state, previous);
              if (state.invitation.phase !== 'active') fail('chat_not_active');
            }
          } else if (state.outbox.length || state.pending_commit)
            fail('replacement_requires_empty_device');
          const own =
            next.channel.a.scope === this.#scopeId
              ? next.channel.a
              : next.channel.b.scope === this.#scopeId
                ? next.channel.b
                : null;
          if (!own || own.fingerprint !== this.#scope.fingerprint) fail('delivery_scope_mismatch');
          const peer = own === next.channel.a ? next.channel.b : next.channel.a;
          if (
            engine.outgoing_context(time, true) !==
            JSON.stringify([own.fingerprint, peer.fingerprint])
          )
            fail('delivery_context_mismatch');
          if (!state.invitation && !stops.length)
            engine.check_bootstrap(
              decode(next.channel.group, 16),
              own.fingerprint,
              peer.fingerprint,
              time,
            );
          entry = {
            previous,
            next,
            operation_id: command.approval_id,
            phase: 'prepared',
            quarantined: [],
            ...(stops.length ? { restart_from: stops.at(-1)!.next.channel.id } : {}),
          };
          (state.replacements ??= []).push(entry);
        }
        if (command.kind === 'begin_cancel_replacement') {
          if (entry.cancellation && entry.cancellation.operation_id !== command.cancel_id)
            fail('replacement_intent_conflict');
          entry.cancellation = { operation_id: command.cancel_id, outcome: 'pending' };
          entry.phase = 'cancelling';
          break;
        }
        if (
          command.kind === 'finish_cancel_replacement' ||
          command.kind === 'observe_replacement_cancelled'
        ) {
          if (command.kind === 'finish_cancel_replacement') {
            if (
              entry.phase !== 'cancelling' ||
              entry.cancellation?.operation_id !== command.cancel_id ||
              !['cancelled', 'admitted'].includes(command.outcome)
            )
              fail('replacement_cancellation_pending');
            entry.cancellation.outcome = command.outcome;
            if (command.outcome === 'admitted') {
              entry.phase = 'consented';
              break;
            }
          }
          if (entry.predecessor_confirmed)
            engine.cancel_group_predecessor(
              decode(previous.channel.group, 16),
              decode(this.#stoppedGroups(state, entry)[0]?.channel.group ?? next.channel.group, 16),
              time,
            );
          entry.phase = 'cancelled';
          entry.quarantined = state.outbox;
          state.outbox = [];
          state.pending_commit = null;
          break;
        }
        if (command.kind === 'consent_replacement') {
          entry.phase = 'consented';
          break;
        }
        if (command.kind !== 'activate_replacement') break;
        if (entry.phase !== 'consented') fail('replacement_unconfirmed');
        const own = next.channel.a.scope === this.#scopeId ? next.channel.a : next.channel.b;
        const peer = own === next.channel.a ? next.channel.b : next.channel.a;
        const unchanged = own.scope === stable.scope;
        const stops = this.#stoppedGroups(state, entry);
        if (!unchanged && own.scope !== current.scope) fail('delivery_scope_mismatch');
        const activated = state.replacement_stops?.find(
          (s) => s.phase !== 'retired' && s.native_origin,
        );
        if (activated) {
          if (JSON.stringify(activated.next) !== JSON.stringify(stops[0]))
            fail('replacement_stop_unconfirmed');
          const oldOwn = [activated.next.channel.a, activated.next.channel.b].find(
            (e) => e.scope === this.#scopeId,
          );
          if (!oldOwn) fail('delivery_scope_mismatch');
          const oldPeer =
            oldOwn === activated.next.channel.a
              ? activated.next.channel.b
              : activated.next.channel.a;
          engine.restart_activated_replacement(
            decode(previous.channel.group, 16),
            decode(activated.next.channel.group, 16),
            decode(stops[1]?.channel.group ?? next.channel.group, 16),
            JSON.stringify({
              old_own: oldOwn.fingerprint,
              old_peer: oldPeer.fingerprint,
              own: own.fingerprint,
              peer: peer.fingerprint,
            }),
            time,
          );
        } else
          engine.replace_group(
            decode(previous.channel.group, 16),
            decode(stops[0]?.channel.group ?? next.channel.group, 16),
            JSON.stringify({
              old_own: unchanged ? stable.fingerprint : retired.fingerprint,
              old_peer: unchanged ? retired.fingerprint : stable.fingerprint,
              own: own.fingerprint,
              peer: peer.fingerprint,
            }),
            time,
          );
        for (const [i, offer] of stops.entries()) {
          if (activated && i === 0) continue;
          engine.restart_group(
            decode(offer.channel.group, 16),
            decode(stops[i + 1]?.channel.group ?? next.channel.group, 16),
            own.fingerprint,
            peer.fingerprint,
            time,
          );
        }
        for (const stop of state.replacement_stops ?? []) stop.phase = 'retired';
        entry.quarantined = state.outbox;
        entry.phase = 'active';
        state.outbox = [];
        state.pending_commit = null;
        state.invitation = {
          ...next,
          phase: 'prepared',
          key_package_id: null,
          commit_id: null,
          welcome_id: null,
        };
        if (next.inviter_scope !== this.#scopeId)
          state.invitation.key_package_id = await add(
            'key_package',
            engine.key_package(time),
            true,
          );
        break;
      }
      case 'stage_peer': {
        const contact = checkedContact(JSON.parse(command.contact));
        const verified = verifiedDevice(
          JSON.parse(engine.inspect_peer(contact.binding, time)) as VerifiedDevice,
        );
        const observation = engine.review_peer(contact.binding, time);
        if (
          !['unconfirmed', 'current', 'key_changed', 'revoked', 'registry_conflict'].includes(
            observation,
          )
        )
          fail('invalid_peer_observation');
        state.peer_review = {
          id: crypto.randomUUID(),
          contact,
          verified,
          observation: observation as PeerReview['observation'],
        };
        receipt.observation = observation;
        break;
      }
      case 'approve_peer': {
        const review = state.peer_review;
        if (!review || review.id !== command.review_id) fail('peer_review_changed');
        if (review.observation === 'registry_conflict') fail('registry_conflict');
        engine.inspect_peer(review.contact.binding, time);
        const trust = JSON.parse(engine.peer_trust(time)) as PeerTrust;
        if (!trust.peer) {
          if (command.previous !== 'unconfirmed') fail('peer_review_changed');
          engine.confirm_peer(review.contact.binding, command.fingerprint, time);
        } else {
          engine.accept_key_change(
            review.contact.binding,
            command.previous,
            command.fingerprint,
            time,
          );
        }
        break;
      }
      case 'mark_invitation_failed': {
        const offer = checkedInvitation(JSON.parse(command.offer));
        this.#invitation(state, offer).phase = 'recovery_required';
        break;
      }
      case 'mark_replacement_failed':
      case 'begin_replacement_recovery': {
        const { previous, next } = replacement(
          JSON.parse(command.previous),
          JSON.parse(command.next),
        );
        const entry = state.replacements?.find((r) => r.next.channel.id === next.channel.id);
        if (
          !entry ||
          JSON.stringify(entry.previous) !== JSON.stringify(previous) ||
          JSON.stringify(entry.next) !== JSON.stringify(next)
        )
          fail('replacement_not_prepared');
        if (['active', 'cancelled', 'cancelling'].includes(entry.phase))
          fail('replacement_intent_conflict');
        if (['recovering', 'abandoned'].includes(entry.phase)) break;
        if (command.kind === 'mark_replacement_failed') {
          entry.phase = 'recovery_required';
          break;
        }
        if ((state.recoveries?.length ?? 0) >= 9) fail('recovery_ledger_full');
        if (state.recoveries?.some((r) => r.offer.channel.id === next.channel.id))
          fail('channel_close_conflict');
        entry.phase = 'recovering';
        // Keep the old engine intact. The failed admission is metadata only;
        // both native retirements happen atomically after fresh bilateral consent.
        state.invitation = {
          ...next,
          phase: 'recovery_required',
          key_package_id: null,
          commit_id: null,
          welcome_id: null,
        };
        (state.recoveries ??= []).push({
          offer: next,
          operation_id: command.close_id,
          reason: 'cancel_invitation',
          phase: 'closing',
          next: null,
          quarantined: [],
          inbox_ids: [],
          replacement_id: next.channel.id,
        });
        break;
      }
      case 'begin_cancel_rejoin':
      case 'finish_cancel_rejoin': {
        const offer = checkedInvitation(JSON.parse(command.offer)),
          next = checkedInvitation(JSON.parse(command.next)),
          entry = this.#recovery(state, offer);
        this.#successor(offer, next);
        let attempt = entry.cancellations?.find((c) => c.next.channel.id === next.channel.id);
        if (
          attempt &&
          (JSON.stringify(attempt.next) !== JSON.stringify(next) ||
            attempt.operation_id !== command.cancel_id)
        )
          fail('rejoin_cancellation_conflict');
        if (attempt && attempt.outcome !== 'pending') {
          if (command.kind === 'finish_cancel_rejoin' && command.outcome !== attempt.outcome)
            fail('rejoin_cancellation_conflict');
          break;
        }
        if (this.#recoveryStop(state, entry)) fail('conversation_frozen');
        if (
          entry.phase !== 'closed' ||
          state.recoveries?.at(-1) !== entry ||
          JSON.stringify(entry.next) !== JSON.stringify(next)
        )
          fail('rejoin_not_prepared');
        if (command.kind === 'begin_cancel_rejoin') {
          if (attempt) break;
          if ((state.recoveries?.flatMap((r) => r.cancellations ?? []).length ?? 0) >= 32)
            fail('rejoin_cancellation_ledger_full');
          attempt = { next, operation_id: command.cancel_id, outcome: 'pending' };
          (entry.cancellations ??= []).push(attempt);
          break;
        }
        if (!attempt || !['cancelled', 'admitted'].includes(command.outcome))
          fail('rejoin_cancellation_conflict');
        attempt.outcome = command.outcome;
        if (command.outcome === 'cancelled') {
          entry.next = null;
          delete entry.successor_failed;
        }
        break;
      }
      case 'mark_rejoin_failed':
      case 'begin_rejoin_recovery': {
        const offer = checkedInvitation(JSON.parse(command.offer)),
          next = checkedInvitation(JSON.parse(command.next));
        const parent = this.#recovery(state, offer);
        if (this.#recoveryStop(state, parent)) fail('conversation_frozen');
        if (parent.cancellations?.at(-1)?.outcome === 'pending')
          fail('rejoin_cancellation_pending');
        if (
          parent.phase !== 'closed' ||
          !parent.next ||
          JSON.stringify(parent.next) !== JSON.stringify(next)
        )
          fail('rejoin_not_prepared');
        this.#successor(offer, next);
        const existing = state.recoveries?.find((r) => r.offer.channel.id === next.channel.id);
        if (existing) {
          if (
            existing.deferred_from !== offer.channel.id ||
            JSON.stringify(existing.offer) !== JSON.stringify(next)
          )
            fail('rejoin_intent_conflict');
          break;
        }
        if (state.recoveries?.at(-1) !== parent) fail('rejoin_intent_conflict');
        parent.successor_failed = true;
        if (command.kind === 'mark_rejoin_failed') break;
        if ((state.recoveries?.length ?? 0) >= 9) fail('recovery_ledger_full');
        (state.recoveries ??= []).push({
          offer: next,
          operation_id: command.close_id,
          reason: 'cancel_invitation',
          phase: 'closing',
          next: null,
          quarantined: [],
          inbox_ids: [],
          deferred_from: offer.channel.id,
        });
        state.invitation = {
          ...next,
          phase: 'recovery_required',
          key_package_id: null,
          commit_id: null,
          welcome_id: null,
        };
        break;
      }
      case 'begin_close': {
        const offer = checkedInvitation(JSON.parse(command.offer) as InvitationOffer);
        if (!['cancel_invitation', 'epoch_conflict', 'leave'].includes(command.reason))
          fail('invalid_close_reason');
        const previous = state.recoveries?.find((r) => r.offer.channel.id === offer.channel.id);
        if (previous) {
          if (
            JSON.stringify(previous.offer) !== JSON.stringify(offer) ||
            previous.reason !== command.reason
          )
            fail('channel_close_conflict');
          break;
        }
        this.#invitation(state, offer);
        if ((state.recoveries?.length ?? 0) >= 9) fail('recovery_ledger_full');
        const known = new Set(state.recoveries?.flatMap((r) => r.inbox_ids));
        (state.recoveries ??= []).push({
          offer,
          operation_id: command.close_id,
          reason: command.reason,
          phase: 'closing',
          next: null,
          quarantined: [],
          inbox_ids: state.inbox
            .filter((e) => !known.has(e.id) && (!e.channel_id || e.channel_id === offer.channel.id))
            .map((e) => e.id),
        });
        break;
      }
      case 'complete_close': {
        const offer = checkedInvitation(JSON.parse(command.offer) as InvitationOffer),
          entry = this.#recovery(state, offer);
        if (entry.operation_id !== command.close_id) fail('channel_close_conflict');
        if (entry.phase === 'closing') entry.phase = 'closed';
        if (entry.replacement_id) {
          const replaced = state.replacements?.find(
            (r) => r.next.channel.id === entry.replacement_id,
          );
          if (!replaced) fail('invalid_recovery_state');
          if (replaced.phase === 'recovering') replaced.phase = 'abandoned';
        }
        break;
      }
      case 'prepare_rejoin':
      case 'activate_rejoin': {
        const offer = checkedInvitation(JSON.parse(command.offer) as InvitationOffer),
          next = checkedInvitation(JSON.parse(command.next) as InvitationOffer);
        const entry = this.#recovery(state, offer);
        if (this.#recoveryStop(state, entry)) fail('conversation_frozen');
        if (entry.phase === 'closing') fail('channel_close_unconfirmed');
        if (entry.cancellations?.at(-1)?.outcome === 'pending') fail('rejoin_cancellation_pending');
        const chain = rejoinChain(state.recoveries ?? [], offer.channel.id),
          root = chain[0];
        const deferred = root.replacement_id
          ? state.replacements?.find((r) => r.next.channel.id === root.replacement_id)
          : undefined;
        if (
          entry.phase !== 'rejoined' &&
          this.#retirementCount(state, [
            ...chain.map((r) => r.offer.channel.group),
            ...(deferred?.phase === 'abandoned' ? [deferred.previous.channel.group] : []),
          ]) > 8
        )
          fail('recovery_ledger_full');
        this.#successor(offer, next);
        if (
          state.recoveries?.some(
            (r) =>
              r.offer.channel.group === next.channel.group ||
              r.offer.channel.id === next.channel.id ||
              r.cancellations?.some(
                (c) =>
                  c.outcome === 'cancelled' &&
                  (c.next.channel.id === next.channel.id ||
                    c.next.channel.group === next.channel.group),
              ),
          ) ||
          state.replacements?.some(
            (r) =>
              r.previous.channel.group === next.channel.group ||
              r.previous.channel.id === next.channel.id ||
              (r.phase === 'cancelled' &&
                (r.next.channel.group === next.channel.group ||
                  r.next.channel.id === next.channel.id)),
          )
        )
          fail('retired_or_unexpected_group');
        if (entry.next && JSON.stringify(entry.next) !== JSON.stringify(next))
          fail('rejoin_intent_conflict');
        if (entry.phase === 'rejoined') break;
        if (entry.successor_failed) fail('rejoin_recovery_required');
        if (command.kind === 'prepare_rejoin') {
          entry.next = next;
          break;
        }
        if (!entry.next) fail('rejoin_not_prepared');
        const route = next.channel,
          own =
            route.a.scope === this.#scopeId
              ? route.a
              : route.b.scope === this.#scopeId
                ? route.b
                : null;
        if (!own) fail('delivery_scope_mismatch');
        const peer = own === route.a ? route.b : route.a;
        if (deferred) {
          if (deferred.phase !== 'abandoned') fail('replacement_intent_conflict');
          const { stable, retired } = replacement(deferred.previous, deferred.next);
          const unchanged = own.scope === stable.scope;
          engine.replace_group(
            decode(deferred.previous.channel.group, 16),
            decode(root.offer.channel.group, 16),
            JSON.stringify({
              old_own: unchanged ? stable.fingerprint : retired.fingerprint,
              old_peer: unchanged ? retired.fingerprint : stable.fingerprint,
              own: own.fingerprint,
              peer: peer.fingerprint,
            }),
            time,
          );
          deferred.phase = 'active';
        }
        for (const step of chain) {
          if (step.phase !== 'closed' || !step.next) fail('invalid_recovery_state');
          engine.restart_group(
            decode(step.offer.channel.group, 16),
            decode(step.next.channel.group, 16),
            own.fingerprint,
            peer.fingerprint,
            time,
          );
        }
        for (const step of chain) {
          step.quarantined = step === root ? state.outbox : [];
          step.phase = 'rejoined';
        }
        state.outbox = [];
        state.pending_commit = null;
        state.invitation = {
          ...next,
          phase: 'prepared',
          key_package_id: null,
          commit_id: null,
          welcome_id: null,
        };
        if (next.inviter_scope !== this.#scopeId)
          state.invitation.key_package_id = await add(
            'key_package',
            engine.key_package(time),
            true,
          );
        break;
      }
      case 'prepare_invitation': {
        const offer = checkedInvitation(JSON.parse(command.offer) as InvitationOffer);
        if (state.invitation) {
          // Resume the same public consent without generating/releasing wire.
          // Fresh leases are required separately before packet publication.
          this.#invitation(state, offer);
          break;
        }
        const status = this.#bootstrapContext(engine, offer, now);
        if (status !== 'unjoined' || state.pending_commit || state.outbox.length)
          fail('invitation_requires_empty_group');
        state.invitation = {
          ...offer,
          phase: 'prepared',
          key_package_id: null,
          commit_id: null,
          welcome_id: null,
        };
        if (offer.inviter_scope !== this.#scopeId)
          state.invitation.key_package_id = await add(
            'key_package',
            engine.key_package(time),
            true,
          );
        break;
      }
      case 'invite_from_delivery':
      case 'join_from_delivery': {
        const offer = checkedInvitation(JSON.parse(command.offer) as InvitationOffer);
        const invitation = this.#invitation(state, offer);
        this.#bootstrapContext(engine, offer, now);
        const wire = Uint8Array.from(command.wire),
          digest = await hash(wire);
        const previous = state.received.find((r) => r.id === command.message_id);
        if (previous) {
          if (previous.digest !== digest) fail('message_id_conflict');
          break;
        }
        if (state.received.length >= MAX_OPERATIONS) fail('inbox_full');
        if (invitation.phase !== 'prepared') fail('invitation_phase_conflict');
        if (command.kind === 'invite_from_delivery') {
          if (offer.inviter_scope !== this.#scopeId || state.pending_commit)
            fail('invitation_role_mismatch');
          engine.create_group(decode(offer.channel.group, 16), time);
          const result = JSON.parse(engine.invite(wire, time)) as {
            commit: number[];
            welcome: number[];
          };
          const commit = await add('commit', Uint8Array.from(result.commit), true);
          invitation.commit_id = commit;
          invitation.welcome_id = await add(
            'welcome',
            Uint8Array.from(result.welcome),
            true,
            commit,
          );
          invitation.key_package_id = command.message_id;
          invitation.phase = 'invited';
          state.pending_commit = { id: commit, accepted: false };
        } else {
          if (
            offer.inviter_scope === this.#scopeId ||
            !state.delivered.some(
              (r) => r.id === invitation.key_package_id && r.channel_id === offer.channel.id,
            )
          )
            fail('invitation_key_package_not_accepted');
          engine.join(wire, decode(offer.channel.group, 16), time);
          invitation.phase = 'joined';
          invitation.welcome_id = command.message_id;
        }
        state.received.push({ id: command.message_id, digest, event_id: null });
        break;
      }
      case 'complete_invitation': {
        const offer = checkedInvitation(JSON.parse(command.offer) as InvitationOffer);
        const invitation = this.#invitation(state, offer);
        this.#deliveryContext(engine, offer.channel, now);
        if (
          state.pending_commit ||
          state.outbox.some((r) =>
            [invitation.key_package_id, invitation.commit_id, invitation.welcome_id].includes(r.id),
          )
        )
          fail('invitation_delivery_pending');
        invitation.phase = 'active';
        break;
      }
      case 'create_group':
        engine.create_group(Uint8Array.from(command.group), time);
        break;
      case 'key_package':
        await add('key_package', engine.key_package(time), false);
        break;
      case 'send':
        await add('application', engine.send(command.text, time), true);
        break;
      case 'send_chat': {
        const route = checkedChannel(JSON.parse(command.route) as DeliveryChannel);
        const current = state.invitation;
        if (
          !current ||
          current.phase !== 'active' ||
          JSON.stringify(current.channel) !== JSON.stringify(route)
        )
          fail('chat_not_active');
        this.#deliveryContext(engine, route, now);
        if ((state.sent_texts?.length ?? 0) >= MAX_EVENTS) fail('chat_history_full');
        const messageId = await add('application', engine.send(command.text, time), true);
        (state.sent_texts ??= []).push({
          id: messageId,
          channel_id: route.id,
          text: command.text,
          position: (state.chat_sequence = (state.chat_sequence ?? 0) + 1),
        });
        break;
      }
      case 'invite': {
        if (state.pending_commit) fail('commit_pending');
        const invitation = JSON.parse(
          engine.invite(Uint8Array.from(command.key_package), time),
        ) as { commit: number[]; welcome: number[] };
        const commit = await add('commit', Uint8Array.from(invitation.commit), true);
        await add('welcome', Uint8Array.from(invitation.welcome), true, commit);
        state.pending_commit = { id: commit, accepted: false };
        break;
      }
      case 'update':
      case 'remove_peer': {
        if (state.pending_commit) fail('commit_pending');
        const removal = command.kind === 'remove_peer';
        const wire = removal ? engine.remove_peer(time) : engine.update(time);
        const commit = await add('commit', wire, !removal);
        state.pending_commit = { id: commit, accepted: false };
        break;
      }
      case 'join':
        engine.join(Uint8Array.from(command.welcome), Uint8Array.from(command.group), time);
        break;
      case 'merge_pending': {
        if (state.pending_commit?.id !== command.commit_id || !state.pending_commit.accepted)
          fail('commit_not_accepted');
        engine.merge_pending(time);
        for (const entry of state.outbox)
          if (entry.depends_on === command.commit_id) entry.depends_on = null;
        state.pending_commit = null;
        break;
      }
      case 'accept_delivery':
      case 'acknowledge': {
        const entry = state.outbox.find((entry) => entry.id === command.message_id);
        const accepted = state.delivered.find((entry) => entry.id === command.message_id);
        if (!entry && !accepted) fail('message_missing');
        if ((entry ?? accepted)!.digest !== command.digest) fail('receipt_digest_mismatch');
        if (command.kind === 'accept_delivery') {
          if ((entry?.delivery?.channel_id ?? accepted?.channel_id) !== command.channel_id)
            fail('delivery_channel_mismatch');
          if (entry && engine.outgoing_context(time, entry.require_peer) !== entry.context)
            fail('outgoing_key_changed');
        }
        if (entry) {
          if (entry.depends_on) fail('message_not_released');
          if (state.delivered.length >= MAX_OPERATIONS) fail('delivery_ledger_full');
          state.delivered.push({
            id: entry.id,
            digest: entry.digest,
            ...(command.kind === 'accept_delivery' ? { channel_id: command.channel_id } : {}),
          });
          state.outbox = state.outbox.filter((item) => item.id !== entry.id);
          if (state.pending_commit?.id === entry.id) state.pending_commit.accepted = true;
        }
        // Receipt and local commit merge are one witnessed transaction. A crash
        // cannot remove the outbox entry while stranding an unmerged commit.
        if (command.kind === 'accept_delivery' && state.pending_commit?.id === command.message_id) {
          engine.merge_pending(time);
          for (const queued of state.outbox)
            if (queued.depends_on === command.message_id) queued.depends_on = null;
          state.pending_commit = null;
        }
        break;
      }
      case 'receive_delivery':
      case 'receive': {
        if (command.kind === 'receive_delivery')
          this.#deliveryContext(
            engine,
            checkedChannel(JSON.parse(command.route) as DeliveryChannel),
            now,
          );
        const wire = Uint8Array.from(command.wire),
          digest = await hash(wire);
        const previous = state.received.find((entry) => entry.id === command.message_id);
        if (previous) {
          if (previous.digest !== digest) fail('message_id_conflict');
          if (previous.event_id) receipt.event_id = previous.event_id;
          break;
        }
        if (state.received.length >= MAX_OPERATIONS || state.inbox.length >= MAX_EVENTS)
          fail('inbox_full');
        let event: { kind: string };
        try {
          event = JSON.parse(engine.receive(wire, time)) as { kind: string };
        } catch (error) {
          if (command.kind === 'receive_delivery' && safeError(error) === 'operation_failed')
            fail('mls_receive_rejected');
          throw error;
        }
        const eventId = event.kind === 'application' ? command.message_id : null;
        if (eventId) {
          state.inbox.push({
            id: eventId,
            event,
            ...(command.kind === 'receive_delivery'
              ? { channel_id: (JSON.parse(command.route) as DeliveryChannel).id }
              : {}),
            position: (state.chat_sequence = (state.chat_sequence ?? 0) + 1),
          });
          receipt.event_id = eventId;
        }
        state.received.push({ id: command.message_id, digest, event_id: eventId });
        break;
      }
      case 'bind_self':
        engine.bind_self(command.token, time);
        break;
      case 'refresh_self':
        receipt.observation = engine.refresh_self(command.token, time);
        break;
      case 'confirm_peer':
        engine.confirm_peer(command.token, command.fingerprint, time);
        break;
      case 'observe_binding':
        receipt.observation = engine.observe_binding(command.token, time);
        break;
      case 'accept_key_change':
        engine.accept_key_change(command.token, command.previous, command.replacement, time);
        break;
    }
    return receipt;
  }

  #recovery(state: State, offer: InvitationOffer): Recovery {
    const entry = state.recoveries?.find((r) => r.offer.channel.id === offer.channel.id);
    if (!entry || JSON.stringify(entry.offer) !== JSON.stringify(offer))
      fail('recovery_not_prepared');
    return entry;
  }
  #successor(previous: InvitationOffer, next: InvitationOffer): void {
    if (
      previous.channel.id === next.channel.id ||
      previous.channel.group === next.channel.group ||
      JSON.stringify(previous.channel.a) !== JSON.stringify(next.channel.a) ||
      JSON.stringify(previous.channel.b) !== JSON.stringify(next.channel.b)
    )
      fail('invalid_channel_successor');
  }
  #stopOffers(state: State, stop: ReplacementStopState): InvitationOffer[] {
    if (!stop.recovery_id) return [stop.next];
    const chain = replacementStopRecoveries(stop, state.recoveries ?? [], state.replacements ?? []);
    if (!chain.length) fail('invalid_replacement_state');
    return chain.map((r) => r.offer);
  }
  #retirementCount(state: State, extra: string[]): number {
    // Activated stops share their anchor with the original active replacement.
    // Count the fenced group IDs once, including all reserved stop targets.
    return new Set([
      ...(state.replacements
        ?.filter((r) => r.phase === 'active')
        .map((r) => r.previous.channel.group) ?? []),
      ...(state.recoveries
        ?.filter((r) => r.phase === 'rejoined')
        .map((r) => r.offer.channel.group) ?? []),
      ...(state.replacement_stops?.flatMap((s) =>
        this.#stopOffers(state, s).map((o) => o.channel.group),
      ) ?? []),
      ...extra,
    ]).size;
  }
  #recoveryStop(state: State, entry: Recovery): ReplacementStopState | undefined {
    return state.replacement_stops?.find((s) =>
      replacementStopRecoveries(s, state.recoveries ?? [], state.replacements ?? []).some(
        (r) =>
          r.operation_id === entry.operation_id &&
          JSON.stringify(r.offer) === JSON.stringify(entry.offer),
      ),
    );
  }
  #recoveryQueued(state: State, entry: Recovery): Queued[] {
    const stop = this.#recoveryStop(state, entry);
    if (stop) return stop.recovery_id === entry.operation_id ? stop.quarantined : [];
    return entry.phase === 'rejoined' ? entry.quarantined : state.outbox;
  }
  #stoppedGroups(state: State, entry: ReplacementState): InvitationOffer[] {
    if (!entry.restart_from) return [];
    const stops = state.replacement_stops?.filter((s) => s.phase !== 'retired') ?? [];
    if (
      !stops.length ||
      stops.at(-1)!.next.channel.id !== entry.restart_from ||
      stops.some(
        (s) =>
          s.phase !== 'stopped' || JSON.stringify(s.previous) !== JSON.stringify(entry.previous),
      )
    )
      fail('replacement_stop_unconfirmed');
    return stops.flatMap((s) => this.#stopOffers(state, s));
  }
  #stoppedOrigin(state: State, previous?: InvitationOffer): boolean {
    const invitation = state.invitation;
    if (!invitation) return false;
    return !!state.replacement_stops?.some((stop) => {
      if (
        stop.phase === 'retired' ||
        (previous && JSON.stringify(stop.previous) !== JSON.stringify(previous))
      )
        return false;
      if (
        stop.native_origin &&
        JSON.stringify(stop.next) ===
          JSON.stringify({ channel: invitation.channel, inviter_scope: invitation.inviter_scope })
      )
        return true;
      if (invitation.phase !== 'recovery_required') return false;
      const recovery = replacementStopRecoveries(
        stop,
        state.recoveries ?? [],
        state.replacements ?? [],
      ).at(-1);
      return (
        !!recovery &&
        JSON.stringify(recovery.offer) ===
          JSON.stringify({ channel: invitation.channel, inviter_scope: invitation.inviter_scope })
      );
    });
  }
  #unfrozen(state: State): void {
    if (state.replacement_stops?.some((s) => s.phase !== 'retired')) fail('conversation_frozen');
    if (state.invitation?.phase === 'recovery_required') fail('conversation_frozen');
    const latest = state.recoveries?.at(-1);
    if (
      latest &&
      latest.phase !== 'rejoined' &&
      !recoveryReplaced(
        latest,
        state.replacements ?? [],
        state.replacement_stops ?? [],
        state.recoveries ?? [],
      )
    )
      fail('conversation_frozen');
    if (
      state.replacements?.at(-1) &&
      !['active', 'abandoned'].includes(state.replacements.at(-1)!.phase)
    )
      fail('conversation_frozen');
  }
  async recoveryStatus(value: InvitationOffer): Promise<RecoveryInfo> {
    const offer = checkedInvitation(value);
    return this.#locked(async (id) => {
      const saved = await this.#synchronize(id);
      if (!saved) fail('device_not_initialized');
      const entry = this.#recovery(saved.state, offer);
      const queued = this.#recoveryQueued(saved.state, entry);
      return {
        offer: structuredClone(entry.offer),
        operation_id: entry.operation_id,
        reason: entry.reason,
        phase: entry.phase,
        next: structuredClone(entry.next),
        inbox_ids: [...entry.inbox_ids],
        ...(entry.replacement_id ? { replacement_id: entry.replacement_id } : {}),
        ...(entry.deferred_from ? { deferred_from: entry.deferred_from } : {}),
        ...(entry.successor_failed ? { successor_failed: true as const } : {}),
        ...(entry.cancellations ? { cancellations: structuredClone(entry.cancellations) } : {}),
        abandoned: queued.map(({ id, kind, digest }) => ({ id, kind, digest })),
      };
    });
  }
  #invitation(state: State, offer: InvitationOffer): InvitationState {
    const current = state.invitation;
    if (!current) fail('invitation_not_prepared');
    if (
      JSON.stringify({ channel: current.channel, inviter_scope: current.inviter_scope }) !==
      JSON.stringify(offer)
    )
      fail('invitation_conflict');
    return current;
  }
  #bootstrapContext(engine: DeviceEngine, offer: InvitationOffer, now: number): string {
    const route = offer.channel;
    const own =
      route.a.scope === this.#scopeId ? route.a : route.b.scope === this.#scopeId ? route.b : null;
    if (!own) fail('delivery_scope_mismatch');
    const peer = own === route.a ? route.b : route.a;
    return engine.check_bootstrap(
      decode(route.group, 16),
      own.fingerprint,
      peer.fingerprint,
      BigInt(now),
    );
  }
  async invitationStatus(value: InvitationOffer): Promise<InvitationState['phase']> {
    const offer = checkedInvitation(value);
    return this.#locked(async (id) => {
      const saved = await this.#synchronize(id);
      if (!saved) fail('device_not_initialized');
      return this.#invitation(saved.state, offer).phase;
    });
  }
  /** Release only the fixed packets of this local invitation, preserving each
   * exact envelope and the Commit-before-Welcome dependency across crashes. */
  async invitationOutbox(value: InvitationOffer, now: number): Promise<DeliveryEnvelope[]> {
    const offer = checkedInvitation(value);
    if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER - 86400)
      fail('invalid_time');
    return this.#locked(async (id) => {
      const saved = await this.#synchronize(id);
      if (!saved) fail('device_not_initialized');
      this.#unfrozen(saved.state);
      if (now < saved.state.last_time) fail('clock_rollback');
      const intent = this.#invitation(saved.state, offer),
        route = offer.channel;
      const engine = this.#restore(saved.state);
      try {
        this.#bootstrapContext(engine, offer, now);
        const own = route.a.scope === id ? route.a : route.b,
          peer = own === route.a ? route.b : route.a;
        const result: DeliveryEnvelope[] = [];
        let changed = now > saved.state.last_time;
        for (const entry of saved.state.outbox) {
          const kind =
            entry.id === intent.commit_id
              ? 'invite_commit'
              : entry.id === intent.welcome_id
                ? 'welcome'
                : entry.id === intent.key_package_id
                  ? 'key_package'
                  : null;
          if (!kind || entry.depends_on) continue;
          if (engine.outgoing_context(BigInt(now), true) !== entry.context)
            fail('outgoing_key_changed');
          if ((await hash(bytes(entry.wire, 65536))) !== entry.digest)
            fail('message_digest_mismatch');
          if (entry.delivery) {
            if (
              entry.delivery.channel_id !== route.id ||
              entry.delivery.sender_scope !== own.scope ||
              entry.delivery.recipient_scope !== peer.scope
            )
              fail('delivery_channel_mismatch');
          } else {
            entry.delivery = {
              channel_id: route.id,
              sender_scope: own.scope,
              recipient_scope: peer.scope,
              expires_at: now + 86400,
            };
            changed = true;
          }
          result.push({
            ...entry.delivery,
            message_id: entry.id,
            kind,
            digest: entry.digest,
            wire: entry.wire,
          });
        }
        if (changed) {
          saved.state.last_time = now;
          await this.#persist(id, saved.state, saved.head);
        }
        return result;
      } finally {
        engine.free();
      }
    });
  }

  #deliveryContext(engine: DeviceEngine, route: DeliveryChannel, now: number) {
    const own =
      route.a.scope === this.#scopeId ? route.a : route.b.scope === this.#scopeId ? route.b : null;
    if (!own) fail('delivery_scope_mismatch');
    const peer = own === route.a ? route.b : route.a;
    engine.check_delivery(decode(route.group, 16), own.fingerprint, peer.fingerprint, BigInt(now));
    return { own, peer };
  }

  /** Fix routing/expiry in the encrypted journal before any HTTP publication. */
  async deliveryOutbox(channel: DeliveryChannel, now: number): Promise<DeliveryEnvelope[]> {
    const route = checkedChannel(channel);
    if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER - 86400)
      fail('invalid_time');
    return this.#locked(async (id) => {
      const saved = await this.#synchronize(id);
      if (!saved) fail('device_not_initialized');
      this.#unfrozen(saved.state);
      if (now < saved.state.last_time) fail('clock_rollback');
      const engine = this.#restore(saved.state);
      try {
        const { own, peer } = this.#deliveryContext(engine, route, now);
        const envelopes: DeliveryEnvelope[] = [];
        let changed = now > saved.state.last_time;
        for (const entry of saved.state.outbox) {
          if (entry.depends_on || !['commit', 'application'].includes(entry.kind))
            fail('delivery_bootstrap_required');
          if (engine.outgoing_context(BigInt(now), entry.require_peer) !== entry.context)
            fail('outgoing_key_changed');
          const wire = bytes(entry.wire, 65536);
          if ((await hash(wire)) !== entry.digest) fail('message_digest_mismatch');
          if (entry.delivery) {
            if (
              entry.delivery.channel_id !== route.id ||
              entry.delivery.sender_scope !== own.scope ||
              entry.delivery.recipient_scope !== peer.scope
            )
              fail('delivery_channel_mismatch');
          } else {
            entry.delivery = {
              channel_id: route.id,
              sender_scope: own.scope,
              recipient_scope: peer.scope,
              expires_at: now + 86400,
            };
            changed = true;
          }
          envelopes.push({
            ...entry.delivery,
            message_id: entry.id,
            kind: entry.kind as 'application' | 'commit',
            digest: entry.digest,
            wire: entry.wire,
          });
        }
        if (changed) {
          saved.state.last_time = now;
          await this.#persist(id, saved.state, saved.head);
        }
        return envelopes;
      } finally {
        engine.free();
      }
    });
  }

  async outbox(now: number): Promise<{
    ready: { id: string; kind: WireKind; wire: number[]; digest: string }[];
    blocked: { id: string; error: string }[];
    waiting: string[];
  }> {
    if (!Number.isSafeInteger(now) || now < 0) fail('invalid_time');
    return this.#locked(async (id) => {
      const saved = await this.#synchronize(id);
      if (!saved) fail('device_not_initialized');
      this.#unfrozen(saved.state);
      if (now < saved.state.last_time) fail('clock_rollback');
      if (now > saved.state.last_time) {
        saved.state.last_time = now;
        await this.#persist(id, saved.state, saved.head);
      }
      const engine = this.#restore(saved.state);
      const ready: { id: string; kind: WireKind; wire: number[]; digest: string }[] = [],
        blocked: { id: string; error: string }[] = [],
        waiting: string[] = [];
      try {
        for (const entry of saved.state.outbox) {
          if (entry.depends_on) {
            waiting.push(entry.id);
            continue;
          }
          try {
            if (engine.outgoing_context(BigInt(now), entry.require_peer) !== entry.context)
              fail('outgoing_key_changed');
            const wire = bytes(entry.wire, 65536);
            if ((await hash(wire)) !== entry.digest) fail('message_digest_mismatch');
            ready.push({
              id: entry.id,
              kind: entry.kind,
              wire: Array.from(wire),
              digest: entry.digest,
            });
          } catch (error) {
            blocked.push({ id: entry.id, error: safeError(error) });
          }
        }
        return { ready, blocked, waiting };
      } finally {
        engine.free();
      }
    });
  }

  async inbox(): Promise<InboxEvent[]> {
    return this.#locked(async (id) => {
      const saved = await this.#synchronize(id);
      if (!saved) fail('device_not_initialized');
      return structuredClone(saved.state.inbox);
    });
  }

  async chatSnapshot(): Promise<ChatSnapshot> {
    return this.#locked(async (id) => {
      const saved = await this.#synchronize(id);
      if (!saved) fail('device_not_initialized');
      const state = saved.state;
      const engine = this.#restore(state);
      let trust: PeerTrust;
      try {
        trust = JSON.parse(engine.peer_trust(BigInt(Math.floor(Date.now() / 1000)))) as PeerTrust;
      } finally {
        engine.free();
      }
      return {
        own: { scope: this.#scopeId!, fingerprint: this.#scope.fingerprint },
        trust,
        peer_review: structuredClone(state.peer_review ?? null),
        replacement_stops: (state.replacement_stops ?? []).map(({ quarantined, ...entry }) => ({
          ...structuredClone(entry),
          abandoned: quarantined.map(({ id, kind, digest }) => ({ id, kind, digest })),
        })),
        replacements: (state.replacements ?? []).map(({ quarantined, ...entry }) => ({
          ...structuredClone(entry),
          abandoned: (
            state.replacement_stops?.find(
              (s) => !s.native_origin && s.next.channel.id === entry.next.channel.id,
            )?.quarantined ??
            (['active', 'cancelled'].includes(entry.phase) ? quarantined : state.outbox)
          ).map(({ id, kind, digest }) => ({ id, kind, digest })),
        })),
        invitation: state.invitation
          ? {
              offer: structuredClone({
                channel: state.invitation.channel,
                inviter_scope: state.invitation.inviter_scope,
              }),
              phase: state.invitation.phase,
            }
          : null,
        recoveries: (state.recoveries ?? []).map((entry) => ({
          offer: structuredClone(entry.offer),
          operation_id: entry.operation_id,
          reason: entry.reason,
          phase: entry.phase,
          next: structuredClone(entry.next),
          inbox_ids: [...entry.inbox_ids],
          ...(entry.replacement_id ? { replacement_id: entry.replacement_id } : {}),
          ...(entry.deferred_from ? { deferred_from: entry.deferred_from } : {}),
          ...(entry.successor_failed ? { successor_failed: true as const } : {}),
          ...(entry.cancellations ? { cancellations: structuredClone(entry.cancellations) } : {}),
          abandoned: this.#recoveryQueued(state, entry).map(({ id, kind, digest }) => ({
            id,
            kind,
            digest,
          })),
        })),
        received: structuredClone(state.inbox),
        sent: (state.sent_texts ?? []).map((message) => ({
          ...message,
          status:
            state.recoveries?.some((r) => r.offer.channel.id === message.channel_id) ||
            state.replacements?.some((r) => r.previous.channel.id === message.channel_id) ||
            state.replacement_stops?.some(
              (r) =>
                r.previous.channel.id === message.channel_id ||
                this.#stopOffers(state, r).some((o) => o.channel.id === message.channel_id),
            )
              ? state.delivered.some((d) => d.id === message.id)
                ? 'accepted'
                : 'isolated'
              : state.delivered.some((d) => d.id === message.id)
                ? 'accepted'
                : 'queued',
        })),
      };
    });
  }
}
