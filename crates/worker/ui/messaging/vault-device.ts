/** Vault-wrapped local device custody and crash-resumable first enrollment.
 * No raw owner key, PRF output, device checkpoint or state key is public here. */
import type { OwnerVaultController } from '../vault-owner-controller.ts';
import type { OwnerKeyContext, OwnerRecord } from '../vault-owner-crypto.ts';
import { decodeBase64Url, encodeBase64Url } from '../vault-crypto.ts';
import {
  deviceScopeContext,
  PersistentMlsDevice,
  type Command,
  type DeviceEngine,
  type DeviceModule,
  type DeviceScope,
} from './device-store.js';
import { AuthenticatedHeadWitness } from './http-witness.js';
import { contact as checkedContact, verifiedDevice, type PeerContact } from './peer-review.js';
import type { VerifiedDevice } from './peer-review.js';
import {
  replacement,
  type ReplacementInfo,
  type ReplacementProgress,
} from './replacement-types.js';
import {
  channel as checkedChannel,
  invitation as checkedInvitation,
  incoming,
  exact as deliveryExact,
  decode as deliveryBytes,
  encode as deliveryBase64,
  envelopeHash,
  receipt as deliveryReceipt,
  type DeliveryChannel,
  type DeliveryEnvelope,
  type InvitationOffer,
  type InvitationProgress,
  type CloseReason,
  type RecoveryInfo,
} from './delivery-types.js';

type Bytes = Uint8Array<ArrayBuffer>;
type EnrollmentEngine = Omit<DeviceEngine, 'checkpoint'> & {
  checkpoint(): Bytes;
  public_key(): Bytes;
  registration_proof(nonce: string, now: bigint): string;
  check_enrollment_predecessor(
    token: string,
    fingerprint: string,
    revision: bigint,
    now: bigint,
  ): void;
  enrollment_binding_state(token: string, now: bigint): string;
};
export type EnrollmentModule = Omit<DeviceModule, 'BoundMlsClient'> & {
  BoundMlsClient: {
    new (identity: string, authorities: string): EnrollmentEngine;
    restore(checkpoint: Uint8Array, authorities: string): EnrollmentEngine;
  };
};
export type EnrollmentPhase =
  | 'after_custody_prepare'
  | 'after_challenge_prepare'
  | 'after_binding_prepare'
  | 'after_journal_bootstrap'
  | 'after_activation';
type Options = { onPhase?: (phase: EnrollmentPhase) => void | Promise<void> };
type Challenge = {
  enrollment_id: string;
  device: DeviceScope['device'];
  scope: DeviceScope;
  nonce: string;
  expires_at: number;
};
type Initial = {
  phase: 'enrolling' | 'bound';
  checkpoint: string;
  operation_id: string;
  body: string;
  session_tag: string;
  challenge: Challenge | null;
  proof_body: string | null;
};
type State = Initial | { phase: 'active' };
type Sealed = { revision: number; iv: string; ciphertext: string };
type Stored = {
  version: 1;
  owner: OwnerKeyContext;
  scope: DeviceScope;
  public_key: string;
  custody: OwnerRecord;
  state: Sealed;
};
const DATABASE = 'mikaki-mls-custody-v1',
  STORE = 'devices',
  MAX_STATE = 4 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const encoder = new TextEncoder();
function fail(code: string): never {
  throw new Error(code);
}
function exact(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((k) => !Object.hasOwn(value, k))
  )
    fail('invalid_device_custody');
}
function decode(value: string, max: number, min = 1): Bytes {
  if (typeof value !== 'string' || value.length > Math.ceil((max * 4) / 3))
    fail('invalid_device_encoding');
  const raw = decodeBase64Url(value);
  if (raw.length < min || raw.length > max || encodeBase64Url(raw) !== value)
    fail('invalid_device_encoding');
  return raw;
}
async function hash(value: string): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
}
const context = (scope: DeviceScope) => deviceScopeContext(scope);
function item(scope: DeviceScope) {
  return {
    collectionId: 'messaging-device-keys',
    recordId: scope.key_id,
    kind: 'mls-device-custody-v1',
    revision: 1,
  };
}
function ownerContext(c: OwnerKeyContext): string {
  return JSON.stringify([c.origin, c.ownerId, c.vaultId, c.keyGeneration]);
}
async function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DATABASE, 1);
    let abandoned = false;
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onerror = () => reject(new Error('custody_storage_unavailable'));
    r.onblocked = () => {
      abandoned = true;
      reject(new Error('custody_storage_blocked'));
    };
    r.onsuccess = () => {
      if (abandoned) {
        r.result.close();
        return;
      }
      r.result.onversionchange = () => r.result.close();
      resolve(r.result);
    };
  });
}
async function read(key: string): Promise<Stored | null> {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly'),
        r = tx.objectStore(STORE).get(key);
      tx.oncomplete = () => resolve(r.result ?? null);
      tx.onabort = () => reject(new Error('custody_read_failed'));
    });
  } finally {
    db.close();
  }
}
async function write(key: string, previous: Stored | null, next: Stored): Promise<void> {
  const db = await database();
  try {
    await new Promise<void>((resolve, reject) => {
      let failure: Error | undefined;
      const tx = db.transaction(STORE, 'readwrite', { durability: 'strict' }),
        store = tx.objectStore(STORE),
        r = store.get(key);
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(failure ?? new Error('custody_commit_failed'));
      r.onsuccess = () => {
        try {
          if (JSON.stringify(r.result ?? null) !== JSON.stringify(previous))
            fail('custody_conflict');
          store.put(next, key);
        } catch (error) {
          failure =
            error instanceof Error ? error : new Error('custody_change_failed', { cause: error });
          tx.abort();
        }
      };
    });
  } finally {
    db.close();
  }
}
function validate(value: Stored, owner: OwnerKeyContext, deviceId: string): void {
  exact(value, ['version', 'owner', 'scope', 'public_key', 'custody', 'state']);
  exact(value.owner, ['origin', 'ownerId', 'vaultId', 'keyGeneration']);
  exact(value.state, ['revision', 'iv', 'ciphertext']);
  if (
    value.version !== 1 ||
    ownerContext(value.owner) !== ownerContext(owner) ||
    value.scope.device.device_id !== deviceId ||
    value.scope.device.issuer !== location.origin ||
    !Number.isSafeInteger(value.state.revision) ||
    value.state.revision < 1
  )
    fail('custody_scope_mismatch');
  context(value.scope);
  decode(value.public_key, 32, 32);
}
function aad(record: Stored, revision: number): Bytes {
  return encoder.encode(
    JSON.stringify([
      'mikaki-mls-enrollment-v1',
      ownerContext(record.owner),
      context(record.scope),
      record.public_key,
      revision,
    ]),
  );
}
async function seal(record: Stored, key: CryptoKey, state: State): Promise<Stored> {
  const revision = record.state.revision + 1;
  if (!Number.isSafeInteger(revision)) fail('custody_revision_exhausted');
  const plaintext = encoder.encode(JSON.stringify(state)),
    iv = crypto.getRandomValues(new Uint8Array(12));
  try {
    if (plaintext.length > MAX_STATE) fail('custody_state_full');
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad(record, revision), tagLength: 128 },
        key,
        plaintext,
      ),
    );
    return {
      ...record,
      state: { revision, iv: encodeBase64Url(iv), ciphertext: encodeBase64Url(ciphertext) },
    };
  } finally {
    plaintext.fill(0);
  }
}
async function open(record: Stored, key: CryptoKey): Promise<State> {
  let plaintext: Bytes;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: decode(record.state.iv, 12, 12),
          additionalData: aad(record, record.state.revision),
          tagLength: 128,
        },
        key,
        decode(record.state.ciphertext, MAX_STATE + 16, 16),
      ),
    );
  } catch {
    fail('custody_authentication_failed');
  }
  try {
    const state = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)) as State;
    if (state.phase === 'active') {
      exact(state, ['phase']);
      return state;
    }
    exact(state, [
      'phase',
      'checkpoint',
      'operation_id',
      'body',
      'session_tag',
      'challenge',
      'proof_body',
    ]);
    if (
      (state.phase !== 'enrolling' && state.phase !== 'bound') ||
      !UUID.test(state.operation_id) ||
      typeof state.body !== 'string' ||
      state.body.length > 1024 ||
      typeof state.session_tag !== 'string' ||
      (state.proof_body !== null &&
        (typeof state.proof_body !== 'string' || state.proof_body.length > 9216))
    )
      fail('invalid_enrollment_state');
    const checkpoint = decode(state.checkpoint, 2 * 1024 * 1024);
    checkpoint.fill(0);
    return state;
  } finally {
    plaintext.fill(0);
  }
}
class ServiceError extends Error {
  readonly status: number;
  constructor(code: string, status: number) {
    super(code);
    this.status = status;
  }
}

/** One unlocked lease; close invalidates all retained child handles. Reopen with
 * a fresh owner lease. create() is explicit and never a missing-state fallback. */
export class VaultMlsDevice {
  readonly #owner: OwnerVaultController;
  readonly #module: EnrollmentModule;
  readonly #authorities: string;
  readonly #deviceId: string;
  readonly #token: number;
  readonly #abort = new AbortController();
  readonly #options: Options;
  #unsubscribe: (() => void) | undefined;
  #journal: PersistentMlsDevice | undefined;
  #key: CryptoKey | undefined;
  #record: Stored | undefined;
  #id: string | undefined;
  readonly #closeListeners = new Set<() => void>();
  constructor(
    owner: OwnerVaultController,
    module: EnrollmentModule,
    authorities: string,
    deviceId: string,
    options: Options = {},
  ) {
    if (
      !UUID.test(deviceId) ||
      owner.origin !== location.origin ||
      new URL(owner.origin).protocol !== 'https:'
    )
      fail('invalid_device_owner');
    owner.lease();
    this.#token = owner.checkpoint();
    this.#owner = owner;
    this.#module = module;
    this.#authorities = authorities;
    this.#deviceId = deviceId;
    this.#options = options;
    this.#unsubscribe = owner.onLeaseInvalidated(this.close);
    owner.scope.signal.addEventListener('abort', this.close, { once: true });
    document.addEventListener('visibilitychange', this.#visibility);
    window.addEventListener('pagehide', this.close);
  }
  readonly #visibility = () => {
    if (document.visibilityState !== 'visible') this.close();
  };
  readonly close = (): void => {
    if (this.#abort.signal.aborted) return;
    this.#abort.abort();
    this.#journal?.close();
    this.#journal = undefined;
    this.#key = undefined;
    this.#unsubscribe?.();
    this.#unsubscribe = undefined;
    this.#owner.scope.signal.removeEventListener('abort', this.close);
    document.removeEventListener('visibilitychange', this.#visibility);
    window.removeEventListener('pagehide', this.close);
    for (const listener of this.#closeListeners) {
      try {
        listener();
      } catch {
        // A view must not prevent invalidation of another retained child.
      }
    }
    this.#closeListeners.clear();
  };
  onClose(listener: () => void): () => void {
    this.#assert();
    this.#closeListeners.add(listener);
    return () => this.#closeListeners.delete(listener);
  }
  #assert(): void {
    if (this.#abort.signal.aborted) fail('device_locked');
    this.#owner.assertCurrent(this.#token);
    this.#owner.lease();
  }
  async #authority(): Promise<void> {
    await this.#owner.scope.ensure();
    this.#assert();
    await this.#owner.verifyAuthority();
    this.#assert();
  }
  async #phase(phase: EnrollmentPhase): Promise<void> {
    await this.#options.onPhase?.(phase);
    this.#assert();
  }
  async #locked<T>(run: (id: string) => Promise<T>): Promise<T> {
    if (this.#abort.signal.aborted) fail('device_locked');
    if (!navigator.locks) fail('web_locks_required');
    if (!this.#id) {
      await this.#owner.scope.ensure();
      this.#assert();
      const owner = this.#owner.lease().stored.context;
      this.#id = encodeBase64Url(
        await hash(
          JSON.stringify([
            'mikaki-mls-custody-slot-v1',
            owner.origin,
            owner.ownerId,
            this.#deviceId,
          ]),
        ),
      );
    }
    return navigator.locks.request(
      `mikaki-mls-custody:${this.#id}`,
      { mode: 'exclusive', signal: this.#abort.signal },
      async () => {
        await this.#authority();
        const result = await run(this.#id!);
        await this.#authority();
        return result;
      },
    );
  }
  async #call(
    path: string,
    body?: string,
    operationId?: string,
    maxResponse = 16384,
  ): Promise<unknown> {
    this.#assert();
    const response = await this.#owner.scope.request(path, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'same-origin',
      redirect: 'error',
      cache: 'no-store',
      signal: this.#abort.signal,
      headers: {
        Accept: 'application/json',
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(operationId ? { 'X-Operation-ID': operationId } : {}),
      },
      ...(body === undefined ? {} : { body }),
    });
    this.#assert();
    if (
      !response.body ||
      !response.headers.get('Cache-Control')?.includes('no-store') ||
      !response.headers.get('Content-Type')?.startsWith('application/json')
    )
      fail('invalid_device_service_response');
    const reader = response.body.getReader();
    const chunks: Bytes[] = [];
    let count = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        count += value.length;
        if (count > maxResponse) {
          await reader.cancel();
          fail('device_service_response_too_large');
        }
        chunks.push(value);
      }
      const raw = new Uint8Array(count);
      let offset = 0;
      for (const chunk of chunks) {
        raw.set(chunk, offset);
        offset += chunk.length;
      }
      const result: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
      this.#assert();
      if (response.status !== 200) {
        const code =
          result &&
          typeof result === 'object' &&
          'error' in result &&
          typeof result.error === 'string' &&
          /^[a-z_]{1,64}$/.test(result.error)
            ? result.error
            : 'device_service_unavailable';
        throw new ServiceError(code, response.status);
      }
      return result;
    } finally {
      reader.releaseLock();
    }
  }
  async #binding(): Promise<string | null> {
    try {
      const value = await this.#call(`/messaging/devices/${this.#deviceId}/binding`);
      exact(value, ['binding']);
      if (typeof value.binding !== 'string' || value.binding.length > 8192)
        fail('invalid_device_binding');
      return value.binding;
    } catch (error) {
      if (
        error instanceof ServiceError &&
        error.status === 404 &&
        error.message === 'device_missing'
      )
        return null;
      throw error;
    }
  }
  async #unwrap(record: Stored): Promise<CryptoKey> {
    validate(record, this.#owner.lease().stored.context, this.#deviceId);
    const raw = await this.#owner.lease().session.open(record.custody, item(record.scope));
    try {
      this.#assert();
      const expected = await hash(context(record.scope));
      if (raw.length !== 65 || raw[0] !== 1 || expected.some((b, i) => raw[i + 1] !== b))
        fail('custody_scope_mismatch');
      const key = await crypto.subtle.importKey('raw', raw.subarray(33), 'AES-GCM', false, [
        'encrypt',
        'decrypt',
      ]);
      this.#assert();
      return key;
    } finally {
      raw.fill(0);
    }
  }
  #restore(record: Stored, state: Initial): EnrollmentEngine {
    const raw = decode(state.checkpoint, 2 * 1024 * 1024);
    let engine: EnrollmentEngine | undefined;
    try {
      engine = this.#module.BoundMlsClient.restore(raw, this.#authorities);
      if (
        engine.fingerprint() !== record.scope.fingerprint ||
        encodeBase64Url(engine.public_key()) !== record.public_key
      )
        fail('custody_checkpoint_mismatch');
      const identity = JSON.parse(engine.identity_json()) as DeviceScope['device'];
      if (context({ ...record.scope, device: identity }) !== context(record.scope))
        fail('custody_checkpoint_mismatch');
      return engine;
    } catch (error) {
      engine?.free();
      throw error;
    } finally {
      raw.fill(0);
    }
  }
  async #save(id: string, record: Stored, state: State): Promise<Stored> {
    this.#assert();
    const next = await seal(record, this.#key!, state);
    this.#assert();
    await write(id, record, next);
    this.#assert();
    return next;
  }
  /** Explicit first-device creation. Existing server or local identity forbids it. */
  async create(): Promise<void> {
    return this.#create();
  }
  /** Explicit fresh-profile replacement. Existing local custody is preserved;
   * this does not rotate in place or transfer old private state/history. */
  async createReplacement(previous: VerifiedDevice): Promise<void> {
    return this.#create(verifiedDevice(previous));
  }
  async #create(previous?: VerifiedDevice): Promise<void> {
    try {
      await this.#locked(async (id) => {
        if (await read(id)) fail('device_already_initialized');
        const oldBinding = await this.#binding();
        if (oldBinding && !previous) fail('device_already_registered');
        if (previous && !oldBinding) fail('registered_device_missing');
        const account = await this.#call('/messaging/account', '{}');
        exact(account, ['issuer', 'account_id']);
        if (
          account.issuer !== location.origin ||
          typeof account.account_id !== 'string' ||
          !UUID.test(account.account_id)
        )
          fail('invalid_messaging_account');
        const identity = {
          issuer: account.issuer,
          account_id: account.account_id,
          device_id: this.#deviceId,
          generation: previous ? previous.device.generation + 1 : 1,
        };
        if (
          previous &&
          (previous.device.issuer !== identity.issuer ||
            previous.device.account_id !== identity.account_id ||
            previous.device.device_id !== identity.device_id)
        )
          fail('enrollment_predecessor_mismatch');
        const engine = new this.#module.BoundMlsClient(JSON.stringify(identity), this.#authorities);
        try {
          if (previous)
            engine.check_enrollment_predecessor(
              oldBinding!,
              previous.fingerprint,
              BigInt(previous.revision),
              BigInt(Math.floor(Date.now() / 1000)),
            );
          const scope: DeviceScope = {
            device: identity,
            storage_id: crypto.randomUUID(),
            key_id: crypto.randomUUID(),
            fingerprint: engine.fingerprint(),
          };
          const key = crypto.getRandomValues(new Uint8Array(32)),
            frame = new Uint8Array(65);
          let custody: OwnerRecord;
          try {
            frame[0] = 1;
            frame.set(await hash(context(scope)), 1);
            frame.set(key, 33);
            this.#key = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, [
              'encrypt',
              'decrypt',
            ]);
            custody = await this.#owner.lease().session.seal(frame, item(scope));
            this.#assert();
          } finally {
            key.fill(0);
            frame.fill(0);
          }
          const raw = engine.checkpoint();
          let checkpoint: string;
          try {
            checkpoint = encodeBase64Url(raw);
          } finally {
            raw.fill(0);
          }
          const publicKey = encodeBase64Url(engine.public_key());
          const state: Initial = {
            phase: 'enrolling',
            checkpoint,
            operation_id: crypto.randomUUID(),
            body: JSON.stringify({
              device_id: this.#deviceId,
              public_key: publicKey,
              storage_id: scope.storage_id,
              key_id: scope.key_id,
              expected_revision: previous?.revision ?? 0,
            }),
            session_tag: this.#owner.scope.identity!.session_tag,
            challenge: null,
            proof_body: null,
          };
          const initial: Stored = {
            version: 1,
            owner: structuredClone(this.#owner.lease().stored.context),
            scope,
            public_key: publicKey,
            custody,
            state: { revision: 0, iv: '', ciphertext: '' },
          };
          const prepared = await seal(initial, this.#key, state);
          this.#assert();
          await write(id, null, prepared);
          await this.#phase('after_custody_prepare');
          this.#record = await this.#finish(id, prepared, state);
        } finally {
          engine.free();
        }
      });
    } catch (error) {
      this.close();
      throw error;
    }
  }
  /** No creation fallback. Lost local state, wrong Vault or inactive scope stops. */
  async open(): Promise<void> {
    try {
      await this.#locked(async (id) => {
        const record = await read(id);
        if (!record) fail('device_custody_missing');
        this.#key = await this.#unwrap(record);
        const state = await open(record, this.#key);
        this.#assert();
        this.#record = await this.#finish(id, record, state);
      });
    } catch (error) {
      this.close();
      throw error;
    }
  }
  async #registeredBinding(record: Stored, state: State): Promise<string | null> {
    const binding = await this.#binding();
    if (!binding || state.phase !== 'enrolling' || record.scope.device.generation === 1)
      return binding;
    const engine = this.#restore(record, state);
    try {
      return engine.enrollment_binding_state(binding, BigInt(Math.floor(Date.now() / 1000))) ===
        'previous'
        ? null
        : binding;
    } finally {
      engine.free();
    }
  }
  async #finish(id: string, record: Stored, state: State, renewed = false): Promise<Stored> {
    let binding = await this.#registeredBinding(record, state);
    if (state.phase !== 'active') {
      const engine = this.#restore(record, state);
      try {
        if (!binding) {
          // Only the pre-MLS signing-key phase can renew an expired/session-bound
          // ticket, retaining the same key, generation, storage IDs and scope.
          if (
            state.session_tag !== this.#owner.scope.identity!.session_tag ||
            (state.challenge && state.challenge.expires_at <= Math.floor(Date.now() / 1000))
          ) {
            state = {
              ...state,
              phase: 'enrolling',
              operation_id: crypto.randomUUID(),
              session_tag: this.#owner.scope.identity!.session_tag,
              challenge: null,
              proof_body: null,
            };
            record = await this.#save(id, record, state);
          }
          if (!state.proof_body) {
            let value: unknown;
            try {
              value = await this.#call('/messaging/enrollments', state.body, state.operation_id);
            } catch (error) {
              if (!(error instanceof ServiceError) || error.status !== 410) throw error;
              if (await this.#registeredBinding(record, state))
                fail('enrollment_reconciliation_required');
              state = {
                ...state,
                operation_id: crypto.randomUUID(),
                challenge: null,
                proof_body: null,
              };
              record = await this.#save(id, record, state);
              value = await this.#call('/messaging/enrollments', state.body, state.operation_id);
            }
            exact(value, ['enrollment_id', 'device', 'nonce', 'expires_at', 'scope']);
            const challenge = value as unknown as Challenge;
            if (
              !UUID.test(challenge.enrollment_id) ||
              context(challenge.scope) !== context(record.scope) ||
              context({ ...record.scope, device: challenge.device }) !== context(record.scope) ||
              !Number.isSafeInteger(challenge.expires_at) ||
              challenge.expires_at <= Math.floor(Date.now() / 1000)
            )
              fail('enrollment_scope_mismatch');
            const proof = engine.registration_proof(
              challenge.nonce,
              BigInt(Math.floor(Date.now() / 1000)),
            );
            state = { ...state, challenge, proof_body: JSON.stringify({ proof }) };
            record = await this.#save(id, record, state);
            await this.#phase('after_challenge_prepare');
          }
          let result: unknown;
          try {
            result = await this.#call(
              `/messaging/enrollments/${state.challenge!.enrollment_id}/complete`,
              state.proof_body!,
            );
          } catch (error) {
            if (!(error instanceof ServiceError) || error.status !== 410 || renewed) throw error;
            // A server-expired ticket cannot authorize a later old commit.
            // Reconcile before renewing, preserving the same pre-MLS key/scope.
            if (await this.#registeredBinding(record, state))
              fail('enrollment_reconciliation_required');
            state = {
              ...state,
              operation_id: crypto.randomUUID(),
              challenge: null,
              proof_body: null,
            };
            record = await this.#save(id, record, state);
            return await this.#finish(id, record, state, true);
          }
          exact(result, ['binding']);
          if (typeof result.binding !== 'string') fail('invalid_device_binding');
          binding = result.binding;
        }
        if (state.phase === 'bound') {
          if (engine.refresh_self(binding, BigInt(Math.floor(Date.now() / 1000))) !== 'current')
            fail('own_binding_not_current');
        } else engine.bind_self(binding, BigInt(Math.floor(Date.now() / 1000)));
        engine.outgoing_context(BigInt(Math.floor(Date.now() / 1000)), false);
        const raw = engine.checkpoint();
        try {
          state = { ...state, phase: 'bound', checkpoint: encodeBase64Url(raw) };
        } finally {
          raw.fill(0);
        }
        record = await this.#save(id, record, state);
        await this.#phase('after_binding_prepare');
        this.#journal = this.#makeJournal(record);
        try {
          await this.#journal.inbox();
        } catch (error) {
          if (!(error instanceof Error) || error.message !== 'device_not_initialized') throw error;
          const raw = decode(state.checkpoint, 2 * 1024 * 1024);
          try {
            await this.#journal.bootstrap(raw);
          } finally {
            raw.fill(0);
          }
        }
        await this.#phase('after_journal_bootstrap');
        record = await this.#save(id, record, { phase: 'active' });
        await this.#phase('after_activation');
      } finally {
        engine.free();
      }
    } else {
      if (!binding) fail('registered_device_missing');
      this.#journal = this.#makeJournal(record);
      const receipt = await this.#journal.request(
        crypto.randomUUID(),
        { kind: 'refresh_self', token: binding },
        Math.floor(Date.now() / 1000),
      );
      if (!receipt.ok) fail(receipt.error ?? 'binding_refresh_failed');
      if (receipt.observation !== 'current') fail('own_binding_not_current');
    }
    this.#assert();
    return record;
  }
  #makeJournal(record: Stored): PersistentMlsDevice {
    return new PersistentMlsDevice(
      record.scope,
      this.#key!,
      this.#module,
      this.#authorities,
      new AuthenticatedHeadWitness(
        location.origin,
        AbortSignal.any([this.#abort.signal, this.#owner.scope.signal]),
        this.#owner.scope.request,
      ),
    );
  }
  #ready(): PersistentMlsDevice {
    this.#assert();
    if (!this.#record || !this.#journal) fail('device_not_open');
    return this.#journal;
  }
  async request(operationId: string, command: Command) {
    const selected = structuredClone(command);
    return this.#locked(async () => {
      const result = await this.#ready().request(
        operationId,
        selected,
        Math.floor(Date.now() / 1000),
      );
      this.#assert();
      return result;
    });
  }
  async outbox() {
    return this.#locked(async () => this.#ready().outbox(Math.floor(Date.now() / 1000)));
  }
  async inbox() {
    return this.#locked(async () => this.#ready().inbox());
  }
  async chatSnapshot() {
    return this.#locked(() => this.#ready().chatSnapshot());
  }
  async ownContact(): Promise<PeerContact> {
    return this.#locked(async () => {
      const binding = await this.#binding();
      if (!binding) fail('registered_device_missing');
      const receipt = await this.#ready().request(
        crypto.randomUUID(),
        { kind: 'refresh_self', token: binding },
        Math.floor(Date.now() / 1000),
      );
      if (!receipt.ok || receipt.observation !== 'current') fail(receipt.error ?? 'device_revoked');
      return { scope: encodeBase64Url(await hash(context(this.#record!.scope))), binding };
    });
  }
  async stagePeer(value: PeerContact): Promise<void> {
    const contact = checkedContact(value);
    return this.#locked(() =>
      this.#commit(this.#ready(), { kind: 'stage_peer', contact: JSON.stringify(contact) }),
    );
  }
  approvePeerReview(
    operationId: string,
    reviewId: string,
    previous: string,
    independentFingerprint: string,
  ) {
    return this.request(operationId, {
      kind: 'approve_peer',
      review_id: reviewId,
      previous,
      fingerprint: independentFingerprint,
    });
  }
  /** Idempotent send intent and local text history share the MLS transaction. */
  async sendText(operationId: string, value: DeliveryChannel, text: string) {
    const route = checkedChannel(value);
    return this.request(operationId, { kind: 'send_chat', route: JSON.stringify(route), text });
  }

  async #commit(journal: PersistentMlsDevice, command: Command): Promise<void> {
    const result = await journal.request(
      crypto.randomUUID(),
      command,
      Math.floor(Date.now() / 1000),
    );
    this.#assert();
    if (!result.ok) fail(result.error ?? 'device_state_failed');
  }
  async recoveryStatus(value: InvitationOffer): Promise<RecoveryInfo> {
    const offer = checkedInvitation(value);
    return this.#locked(() => this.#ready().recoveryStatus(offer));
  }
  /** Freeze first, then obtain an exact durable termination receipt. Private
   * group state is retained until a separately approved successor is ready. */
  async closeConversation(value: InvitationOffer, reason: CloseReason): Promise<RecoveryInfo> {
    const offer = checkedInvitation(value);
    return this.#locked(() => this.#closeConversation(offer, reason));
  }
  async #closeConversation(offer: InvitationOffer, reason: CloseReason): Promise<RecoveryInfo> {
    const journal = this.#ready();
    await this.#commit(journal, {
      kind: 'begin_close',
      offer: JSON.stringify(offer),
      reason,
      close_id: crypto.randomUUID(),
    });
    const entry = await journal.recoveryStatus(offer);
    if (entry.phase === 'rejoined') return entry;
    const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
    const path = `/messaging/channels/${offer.channel.id}/close`,
      body = JSON.stringify({
        offer,
        scope,
        operation_id: entry.operation_id,
        reason: entry.reason,
      });
    let result: unknown;
    try {
      result = await this.#call(path, body);
    } catch (error) {
      if (
        !(error instanceof ServiceError) ||
        error.status !== 403 ||
        error.message !== 'channel_unavailable'
      )
        throw error;
      const snapshot = await journal.chatSnapshot();
      if (
        snapshot.replacements.some((r) => r.next.channel.id === offer.channel.id) ||
        snapshot.recoveries.some((r) => r.next?.channel.id === offer.channel.id)
      )
        throw error;
      // Local explicit admission may have been saved before its first HTTP
      // request reached the service. Reconcile only that original consent,
      // without unfreezing or releasing any admission wire, then terminate it.
      this.#invitationResponse(
        await this.#call(
          `/messaging/channels/${offer.channel.id}/invitation`,
          JSON.stringify(offer),
        ),
        offer,
        false,
      );
      result = await this.#call(path, body);
    }
    deliveryExact(result, ['status', 'offer', 'scope', 'operation_id', 'reason']);
    if (
      result.status !== 'closed' ||
      result.scope !== scope ||
      result.operation_id !== entry.operation_id ||
      result.reason !== entry.reason ||
      JSON.stringify(checkedInvitation(result.offer as InvitationOffer)) !== JSON.stringify(offer)
    )
      fail('channel_close_receipt_mismatch');
    await this.#commit(journal, {
      kind: 'complete_close',
      offer: JSON.stringify(offer),
      close_id: entry.operation_id,
    });
    return journal.recoveryStatus(offer);
  }
  async #rejoinStatus(previous: InvitationOffer, next: InvitationOffer) {
    const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
    const result = await this.#call(
      `/messaging/channels/${next.channel.id}/rejoin/status`,
      JSON.stringify({ previous, next, scope }),
    );
    deliveryExact(result, [
      'predecessor_id',
      'channel',
      'inviter_scope',
      'scope',
      'state',
      'complete',
      'expired',
    ]);
    if (
      result.predecessor_id !== previous.channel.id ||
      result.scope !== scope ||
      JSON.stringify(
        checkedInvitation({
          channel: result.channel as DeliveryChannel,
          inviter_scope: result.inviter_scope as string,
        }),
      ) !== JSON.stringify(next) ||
      !['unpublished', 'waiting', 'admitted', 'closed', 'cancelled'].includes(
        result.state as string,
      ) ||
      typeof result.complete !== 'boolean' ||
      typeof result.expired !== 'boolean' ||
      (result.complete && result.expired) ||
      (result.complete && !['admitted', 'closed'].includes(result.state as string))
    )
      fail('rejoin_status_mismatch');
    return { state: result.state as string, expired: result.expired };
  }
  async cancelRejoin(
    oldValue: InvitationOffer,
    newValue: InvitationOffer,
  ): Promise<'cancelled' | 'admitted'> {
    const previous = checkedInvitation(oldValue),
      next = checkedInvitation(newValue);
    return this.#locked(async () => {
      const journal = this.#ready(),
        entry = await journal.recoveryStatus(previous);
      const saved = entry.cancellations?.find((c) => c.next.channel.id === next.channel.id);
      if (saved && JSON.stringify(saved.next) !== JSON.stringify(next))
        fail('rejoin_cancellation_conflict');
      if (saved && saved.outcome !== 'pending') return saved.outcome;
      const cancel_id = saved?.operation_id ?? crypto.randomUUID();
      if (!saved)
        await this.#commit(journal, {
          kind: 'begin_cancel_rejoin',
          offer: JSON.stringify(previous),
          next: JSON.stringify(next),
          cancel_id,
        });
      const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
      const result = await this.#call(
        `/messaging/channels/${next.channel.id}/rejoin/cancel`,
        JSON.stringify({ previous, next, scope, operation_id: cancel_id }),
      );
      deliveryExact(result, [
        'predecessor_id',
        'channel',
        'inviter_scope',
        'scope',
        'operation_id',
        'outcome',
      ]);
      if (
        result.predecessor_id !== previous.channel.id ||
        result.scope !== scope ||
        result.operation_id !== cancel_id ||
        JSON.stringify(
          checkedInvitation({
            channel: result.channel as DeliveryChannel,
            inviter_scope: result.inviter_scope as string,
          }),
        ) !== JSON.stringify(next) ||
        !['cancelled', 'admitted'].includes(result.outcome as string)
      )
        fail('rejoin_cancellation_receipt_mismatch');
      const outcome = result.outcome as 'cancelled' | 'admitted';
      await this.#commit(journal, {
        kind: 'finish_cancel_rejoin',
        offer: JSON.stringify(previous),
        next: JSON.stringify(next),
        cancel_id,
        outcome,
      });
      return outcome;
    });
  }
  async recoverRejoin(oldValue: InvitationOffer, newValue: InvitationOffer): Promise<RecoveryInfo> {
    const previous = checkedInvitation(oldValue),
      next = checkedInvitation(newValue);
    return this.#locked(async () => {
      const journal = this.#ready(),
        parent = await journal.recoveryStatus(previous);
      if (!parent.next || JSON.stringify(parent.next) !== JSON.stringify(next))
        fail('rejoin_not_prepared');
      if (parent.phase === 'rejoined') return this.#closeConversation(next, 'cancel_invitation');
      const existing = (await journal.chatSnapshot()).recoveries.find(
        (r) => r.offer.channel.id === next.channel.id,
      );
      if (existing) {
        if (
          existing.deferred_from !== previous.channel.id ||
          JSON.stringify(existing.offer) !== JSON.stringify(next)
        )
          fail('rejoin_intent_conflict');
      } else {
        const status = await this.#rejoinStatus(previous, next);
        if (status.state === 'unpublished') fail('rejoin_unconfirmed');
        if (status.state === 'cancelled') fail('rejoin_cancelled');
        await this.#commit(journal, {
          kind: 'begin_rejoin_recovery',
          offer: JSON.stringify(previous),
          next: JSON.stringify(next),
          close_id: crypto.randomUUID(),
        });
      }
      return this.#closeConversation(next, 'cancel_invitation');
    });
  }
  async #resumeRejoin(
    previous: InvitationOffer,
    next: InvitationOffer,
  ): Promise<'ready' | 'waiting_peer' | 'recovery_required' | 'proposal_cancelled'> {
    const journal = this.#ready(),
      entry = await journal.recoveryStatus(previous);
    if (
      entry.phase === 'closing' ||
      !entry.next ||
      JSON.stringify(entry.next) !== JSON.stringify(next)
    )
      fail('rejoin_not_prepared');
    if (entry.cancellations?.at(-1)?.outcome === 'pending') fail('rejoin_cancellation_pending');
    if (entry.successor_failed) return 'recovery_required';
    const failed = async (): Promise<'recovery_required'> => {
      await this.#commit(
        journal,
        entry.phase === 'rejoined'
          ? { kind: 'mark_invitation_failed', offer: JSON.stringify(next) }
          : {
              kind: 'mark_rejoin_failed',
              offer: JSON.stringify(previous),
              next: JSON.stringify(next),
            },
      );
      return 'recovery_required';
    };
    const status = await this.#rejoinStatus(previous, next);
    if (status.state === 'cancelled') return 'proposal_cancelled';
    if (status.state === 'closed' || status.expired) return failed();
    if (entry.phase === 'rejoined') {
      if (status.state !== 'admitted') fail('rejoin_status_mismatch');
      const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
      await this.#refreshBindings(journal, next.channel, scope);
      return 'ready';
    }
    let result: unknown;
    try {
      result = await this.#call(
        `/messaging/channels/${next.channel.id}/rejoin`,
        JSON.stringify({ previous, next }),
      );
    } catch (error) {
      if (error instanceof ServiceError && error.status === 409) {
        const latest = await this.#rejoinStatus(previous, next);
        if (latest.state === 'cancelled') return 'proposal_cancelled';
        if (latest.state === 'closed' || latest.expired) return failed();
      }
      throw error;
    }
    deliveryExact(result, ['predecessor_id', 'channel', 'inviter_scope', 'ready', 'complete']);
    if (result.predecessor_id !== previous.channel.id) fail('channel_successor_mismatch');
    const { predecessor_id: _, ...response } = result;
    const remote = this.#invitationResponse(response, next, false);
    if (!remote.ready) return 'waiting_peer';
    const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
    if (await this.#admissionUnavailable(next, scope)) return failed();
    await this.#refreshBindings(journal, next.channel, scope);
    await this.#commit(journal, {
      kind: 'activate_rejoin',
      offer: JSON.stringify(previous),
      next: JSON.stringify(next),
    });
    return 'ready';
  }
  async approveRejoin(oldValue: InvitationOffer, newValue: InvitationOffer): Promise<boolean> {
    const previous = checkedInvitation(oldValue),
      next = checkedInvitation(newValue);
    return this.#locked(async () => {
      await this.#commit(this.#ready(), {
        kind: 'prepare_rejoin',
        offer: JSON.stringify(previous),
        next: JSON.stringify(next),
      });
      return (await this.#resumeRejoin(previous, next)) === 'ready';
    });
  }
  async syncRejoin(
    oldValue: InvitationOffer,
    newValue: InvitationOffer,
  ): Promise<InvitationProgress> {
    const previous = checkedInvitation(oldValue),
      next = checkedInvitation(newValue);
    return this.#locked(async () => {
      const entry = await this.#ready().recoveryStatus(previous);
      if (
        entry.phase === 'rejoined' &&
        !entry.successor_failed &&
        entry.next &&
        JSON.stringify(entry.next) === JSON.stringify(next)
      ) {
        // The witnessed transition already applied. Current invitation authority
        // governs its packets; never reissue consent or reapply that transition.
        return this.#syncInvitation(next);
      }
      const phase = await this.#resumeRejoin(previous, next);
      if (phase !== 'ready') return { phase, sent: 0, processed: 0 };
      return this.#syncInvitation(next);
    });
  }

  /** Persist a distinct stop intent before any write. Old and new generations
   * reconcile their own receipt; this never grants consent or releases wire. */
  async stopReplacement(oldValue: InvitationOffer, failedValue: InvitationOffer): Promise<void> {
    const { previous, next } = replacement(oldValue, failedValue);
    return this.#locked(async () => {
      const journal = this.#ready();
      let entry = (await journal.chatSnapshot()).replacement_stops.find(
        (s) => s.next.channel.id === next.channel.id,
      );
      if (
        entry &&
        (JSON.stringify(entry.previous) !== JSON.stringify(previous) ||
          JSON.stringify(entry.next) !== JSON.stringify(next))
      )
        fail('replacement_stop_conflict');
      if (entry && entry.phase !== 'stopping') return;
      const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
      const operation = entry?.operation_id ?? crypto.randomUUID();
      const body = JSON.stringify({ previous, next, scope, operation_id: operation });
      const path = `/messaging/channels/${next.channel.id}/replace/stop`;
      const verify = (result: unknown, states: string[]) => {
        deliveryExact(result, [
          'predecessor_id',
          'channel',
          'inviter_scope',
          'scope',
          'operation_id',
          'state',
        ]);
        if (
          result.predecessor_id !== previous.channel.id ||
          result.scope !== scope ||
          result.operation_id !== operation ||
          typeof result.state !== 'string' ||
          !states.includes(result.state) ||
          JSON.stringify(
            checkedInvitation({
              channel: result.channel as DeliveryChannel,
              inviter_scope: result.inviter_scope as string,
            }),
          ) !== JSON.stringify(next)
        )
          fail('replacement_stop_receipt_mismatch');
      };
      if (!entry) {
        verify(await this.#call(`${path}/status`, body), ['admitted', 'closed']);
        await this.#commit(journal, {
          kind: 'begin_stop_replacement',
          previous: JSON.stringify(previous),
          next: JSON.stringify(next),
          stop_id: operation,
        });
        entry = (await journal.chatSnapshot()).replacement_stops.find(
          (s) => s.next.channel.id === next.channel.id,
        );
        if (!entry || entry.operation_id !== operation) fail('replacement_stop_conflict');
      }
      verify(await this.#call(path, body), ['closed']);
      await this.#commit(journal, {
        kind: 'complete_stop_replacement',
        previous: JSON.stringify(previous),
        next: JSON.stringify(next),
        stop_id: operation,
      });
    });
  }
  async approveReplacement(
    oldValue: InvitationOffer,
    newValue: InvitationOffer,
  ): Promise<ReplacementProgress> {
    const { previous, next } = replacement(oldValue, newValue);
    return this.#locked(async () => {
      await this.#commit(this.#ready(), {
        kind: 'prepare_replacement',
        previous: JSON.stringify(previous),
        next: JSON.stringify(next),
        approval_id: crypto.randomUUID(),
      });
      return this.#syncReplacement(previous, next);
    });
  }
  async syncReplacement(
    oldValue: InvitationOffer,
    newValue: InvitationOffer,
  ): Promise<ReplacementProgress> {
    const { previous, next } = replacement(oldValue, newValue);
    return this.#locked(() => this.#syncReplacement(previous, next));
  }
  async recoverReplacement(
    oldValue: InvitationOffer,
    newValue: InvitationOffer,
  ): Promise<RecoveryInfo> {
    const { previous, next } = replacement(oldValue, newValue);
    return this.#locked(async () => {
      const journal = this.#ready();
      const entry = (await journal.chatSnapshot()).replacements.find(
        (r) => r.next.channel.id === next.channel.id,
      );
      if (
        !entry ||
        JSON.stringify(entry.previous) !== JSON.stringify(previous) ||
        JSON.stringify(entry.next) !== JSON.stringify(next)
      )
        fail('replacement_not_prepared');
      if (entry.phase !== 'active' && !['recovering', 'abandoned'].includes(entry.phase)) {
        const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
        if (!['admitted', 'closed'].includes(await this.#replacementStatus(entry, scope)))
          fail('replacement_unconfirmed');
        await this.#commit(journal, {
          kind: 'begin_replacement_recovery',
          previous: JSON.stringify(previous),
          next: JSON.stringify(next),
          close_id: crypto.randomUUID(),
        });
      }
      return this.#closeConversation(next, 'cancel_invitation');
    });
  }
  async #syncReplacement(
    previous: InvitationOffer,
    next: InvitationOffer,
  ): Promise<ReplacementProgress> {
    const journal = this.#ready();
    const snapshot = await journal.chatSnapshot();
    const entry = snapshot.replacements.find((r) => r.next.channel.id === next.channel.id);
    if (
      !entry ||
      JSON.stringify(entry.previous) !== JSON.stringify(previous) ||
      JSON.stringify(entry.next) !== JSON.stringify(next)
    )
      fail('replacement_not_prepared');
    if (snapshot.replacement_stops.some((s) => s.next.channel.id === next.channel.id))
      return { phase: 'recovery_required', sent: 0, processed: 0 };
    if (['recovery_required', 'recovering', 'abandoned'].includes(entry.phase))
      return { phase: 'recovery_required', sent: 0, processed: 0 };
    if (entry.phase === 'cancelled') return { phase: 'cancelled', sent: 0, processed: 0 };
    if (entry.phase === 'cancelling') {
      if ((await this.#cancelReplacement(previous, next)) === 'cancelled')
        return { phase: 'cancelled', sent: 0, processed: 0 };
      return this.#syncReplacement(previous, next);
    }
    if (entry.phase === 'active') return this.#syncInvitation(next);
    const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
    const status = await this.#replacementStatus(entry, scope);
    const failed = async (): Promise<ReplacementProgress> => {
      await this.#commit(journal, {
        kind: 'mark_replacement_failed',
        previous: JSON.stringify(previous),
        next: JSON.stringify(next),
      });
      return { phase: 'recovery_required', sent: 0, processed: 0 };
    };
    if (status === 'closed') return failed();
    if (status === 'cancelled') {
      await this.#commit(journal, {
        kind: 'observe_replacement_cancelled',
        previous: JSON.stringify(previous),
        next: JSON.stringify(next),
      });
      return { phase: 'cancelled', sent: 0, processed: 0 };
    }
    if (replacement(previous, next).current.scope === scope && !entry.predecessor_confirmed) {
      const result = await this.#call(
        `/messaging/channels/${next.channel.id}/replace/predecessor`,
        JSON.stringify({ previous, next, scope, operation_id: entry.operation_id }),
      );
      deliveryExact(result, [
        'predecessor_id',
        'channel',
        'inviter_scope',
        'scope',
        'operation_id',
        'binding',
      ]);
      if (
        result.predecessor_id !== previous.channel.id ||
        result.scope !== scope ||
        result.operation_id !== entry.operation_id ||
        typeof result.binding !== 'string' ||
        result.binding.length > 8192 ||
        JSON.stringify(
          checkedInvitation({
            channel: result.channel as DeliveryChannel,
            inviter_scope: result.inviter_scope as string,
          }),
        ) !== JSON.stringify(next)
      )
        fail('replacement_receipt_mismatch');
      await this.#commit(journal, {
        kind: 'attest_replacement_predecessor',
        previous: JSON.stringify(previous),
        next: JSON.stringify(next),
        token: result.binding,
      });
    }
    let result: unknown;
    try {
      result = await this.#call(
        `/messaging/channels/${next.channel.id}/replace`,
        JSON.stringify({ previous, next, scope, operation_id: entry.operation_id }),
      );
    } catch (error) {
      if (error instanceof ServiceError && error.status === 409) {
        const latest = await this.#replacementStatus(entry, scope);
        if (latest === 'closed') return failed();
        if (latest === 'cancelled') {
          await this.#commit(journal, {
            kind: 'observe_replacement_cancelled',
            previous: JSON.stringify(previous),
            next: JSON.stringify(next),
          });
          return { phase: 'cancelled', sent: 0, processed: 0 };
        }
      }
      throw error;
    }
    deliveryExact(result, [
      'predecessor_id',
      'channel',
      'inviter_scope',
      'ready',
      'complete',
      'scope',
      'operation_id',
    ]);
    if (
      result.predecessor_id !== previous.channel.id ||
      result.scope !== scope ||
      result.operation_id !== entry.operation_id
    )
      fail('replacement_receipt_mismatch');
    const { predecessor_id: _, scope: _scope, operation_id: _operation, ...response } = result;
    const remote = this.#invitationResponse(response, next, false);
    if (entry.phase !== 'consented')
      await this.#commit(journal, {
        kind: 'consent_replacement',
        previous: JSON.stringify(previous),
        next: JSON.stringify(next),
      });
    if (!remote.ready) return { phase: 'waiting_peer', sent: 0, processed: 0 };
    if (await this.#admissionUnavailable(next, scope)) return failed();
    await this.#refreshBindings(journal, next.channel, scope);
    await this.#commit(journal, {
      kind: 'activate_replacement',
      previous: JSON.stringify(previous),
      next: JSON.stringify(next),
    });
    return this.#syncInvitation(next);
  }

  async #replacementStatus(entry: ReplacementInfo, scope: string): Promise<string> {
    const result = await this.#call(
      `/messaging/channels/${entry.next.channel.id}/replace/status`,
      JSON.stringify({
        previous: entry.previous,
        next: entry.next,
        scope,
        operation_id: entry.operation_id,
      }),
    );
    deliveryExact(result, [
      'predecessor_id',
      'channel',
      'inviter_scope',
      'scope',
      'operation_id',
      'state',
    ]);
    if (
      result.predecessor_id !== entry.previous.channel.id ||
      result.scope !== scope ||
      result.operation_id !== entry.operation_id ||
      JSON.stringify(
        checkedInvitation({
          channel: result.channel as DeliveryChannel,
          inviter_scope: result.inviter_scope as string,
        }),
      ) !== JSON.stringify(entry.next) ||
      !['unpublished', 'waiting', 'cancelled', 'admitted', 'closed'].includes(
        result.state as string,
      )
    )
      fail('replacement_receipt_mismatch');
    return result.state as string;
  }
  async cancelReplacement(
    oldValue: InvitationOffer,
    newValue: InvitationOffer,
  ): Promise<'cancelled' | 'admitted'> {
    const { previous, next } = replacement(oldValue, newValue);
    return this.#locked(() => this.#cancelReplacement(previous, next));
  }
  async #cancelReplacement(
    previous: InvitationOffer,
    next: InvitationOffer,
  ): Promise<'cancelled' | 'admitted'> {
    const journal = this.#ready();
    const entry = (await journal.chatSnapshot()).replacements.find(
      (r) => r.next.channel.id === next.channel.id,
    );
    if (
      !entry ||
      JSON.stringify(entry.previous) !== JSON.stringify(previous) ||
      JSON.stringify(entry.next) !== JSON.stringify(next)
    )
      fail('replacement_not_prepared');
    if (entry.phase === 'active') fail('replacement_already_active');
    if (entry.phase === 'cancelled') return 'cancelled';
    const cancel_id = entry.cancellation?.operation_id ?? crypto.randomUUID();
    if (entry.phase !== 'cancelling')
      await this.#commit(journal, {
        kind: 'begin_cancel_replacement',
        previous: JSON.stringify(previous),
        next: JSON.stringify(next),
        cancel_id,
      });
    const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
    const result = await this.#call(
      `/messaging/channels/${next.channel.id}/replace/cancel`,
      JSON.stringify({
        previous,
        next,
        scope,
        approval_id: entry.operation_id,
        operation_id: cancel_id,
      }),
    );
    deliveryExact(result, [
      'predecessor_id',
      'channel',
      'inviter_scope',
      'scope',
      'approval_id',
      'operation_id',
      'outcome',
    ]);
    if (
      result.predecessor_id !== previous.channel.id ||
      result.scope !== scope ||
      result.approval_id !== entry.operation_id ||
      result.operation_id !== cancel_id ||
      JSON.stringify(
        checkedInvitation({
          channel: result.channel as DeliveryChannel,
          inviter_scope: result.inviter_scope as string,
        }),
      ) !== JSON.stringify(next) ||
      !['cancelled', 'admitted'].includes(result.outcome as string)
    )
      fail('replacement_receipt_mismatch');
    const outcome = result.outcome as 'cancelled' | 'admitted';
    await this.#commit(journal, {
      kind: 'finish_cancel_replacement',
      previous: JSON.stringify(previous),
      next: JSON.stringify(next),
      cancel_id,
      outcome,
    });
    return outcome;
  }

  async #refreshBindings(
    journal: PersistentMlsDevice,
    route: DeliveryChannel,
    scope: string,
  ): Promise<void> {
    const bindings = await this.#call(`/messaging/channels/${route.id}/bindings/${scope}`);
    deliveryExact(bindings, ['own', 'peer']);
    if (typeof bindings.own !== 'string' || typeof bindings.peer !== 'string')
      fail('invalid_delivery_bindings');
    for (const command of [
      { kind: 'refresh_self', token: bindings.own },
      { kind: 'observe_binding', token: bindings.peer },
    ] as const) {
      const result = await journal.request(
        crypto.randomUUID(),
        command,
        Math.floor(Date.now() / 1000),
      );
      this.#assert();
      if (!result.ok || result.observation !== 'current')
        fail(result.error ?? 'delivery_key_review_required');
    }
  }
  #invitationResponse(value: unknown, offer: InvitationOffer, packet: boolean) {
    deliveryExact(value, [
      'channel',
      'inviter_scope',
      'ready',
      'complete',
      ...(packet ? ['packet'] : []),
    ]);
    if (
      JSON.stringify(
        checkedInvitation({
          channel: value.channel as DeliveryChannel,
          inviter_scope: value.inviter_scope as string,
        }),
      ) !== JSON.stringify(offer) ||
      typeof value.ready !== 'boolean' ||
      typeof value.complete !== 'boolean' ||
      (value.complete && !value.ready)
    )
      fail('invitation_response_mismatch');
    return { ready: value.ready, complete: value.complete, packet: value.packet };
  }
  async approveInvitation(value: InvitationOffer): Promise<boolean> {
    const offer = checkedInvitation(value);
    return this.#locked(async () => {
      const journal = this.#ready();
      const result = await journal.request(
        crypto.randomUUID(),
        { kind: 'prepare_invitation', offer: JSON.stringify(offer) },
        Math.floor(Date.now() / 1000),
      );
      this.#assert();
      if (!result.ok) fail(result.error ?? 'invitation_prepare_failed');
      return this.#invitationResponse(
        await this.#call(
          `/messaging/channels/${offer.channel.id}/invitation`,
          JSON.stringify(offer),
        ),
        offer,
        false,
      ).ready;
    });
  }
  /** A caller-approved, bounded admission workflow. All private preparation,
   * packet receipts and MLS transitions live in the witnessed journal. */
  async syncInvitation(value: InvitationOffer): Promise<InvitationProgress> {
    const offer = checkedInvitation(value);
    return this.#locked(() => this.#syncInvitation(offer));
  }
  async #admissionUnavailable(offer: InvitationOffer, scope: string): Promise<boolean> {
    const result = await this.#call(
      `/messaging/channels/${offer.channel.id}/invitation/status`,
      JSON.stringify({ offer, scope }),
    );
    deliveryExact(result, ['channel', 'inviter_scope', 'ready', 'complete', 'blocked', 'expired']);
    this.#invitationResponse(
      {
        channel: result.channel,
        inviter_scope: result.inviter_scope,
        ready: result.ready,
        complete: result.complete,
      },
      offer,
      false,
    );
    if (typeof result.blocked !== 'boolean' || typeof result.expired !== 'boolean')
      fail('invalid_invitation_status');
    return result.blocked || result.expired;
  }
  async #syncInvitation(offer: InvitationOffer): Promise<InvitationProgress> {
    const journal = this.#ready();
    if ((await journal.invitationStatus(offer)) === 'recovery_required')
      return { phase: 'recovery_required', sent: 0, processed: 0 };
    const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
    const failed = async (): Promise<InvitationProgress> => {
      await this.#commit(journal, { kind: 'mark_invitation_failed', offer: JSON.stringify(offer) });
      return { phase: 'recovery_required', sent: 0, processed: 0 };
    };
    if (await this.#admissionUnavailable(offer, scope)) return failed();
    try {
      return await this.#advanceInvitation(offer);
    } catch (error) {
      if (
        error instanceof ServiceError &&
        [403, 409, 410].includes(error.status) &&
        (await this.#admissionUnavailable(offer, scope))
      )
        return failed();
      if (error instanceof Error && error.message === 'invitation_expired_recovery_required')
        return failed();
      throw error;
    }
  }
  async #advanceInvitation(offer: InvitationOffer): Promise<InvitationProgress> {
    const route = offer.channel;
    const journal = this.#ready(),
      local = await journal.invitationStatus(offer);
    const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
    const base = `/messaging/channels/${route.id}/invitation`,
      now = () => Math.floor(Date.now() / 1000);
    const snapshot = async () =>
      this.#invitationResponse(
        await this.#call(`${base}/${scope}`, undefined, undefined, 96 * 1024),
        offer,
        true,
      );
    let remote = await snapshot(),
      sent = 0,
      processed = 0;
    if (!remote.ready) return { phase: 'waiting_peer', sent, processed };
    if (remote.complete && local === 'active') return { phase: 'active', sent, processed };
    await this.#refreshBindings(journal, route, scope);
    const required = async (command: Command) => {
      const result = await journal.request(crypto.randomUUID(), command, now());
      this.#assert();
      if (!result.ok) fail(result.error ?? 'invitation_state_failed');
    };
    for (let step = 0; step < 8; step++) {
      if (step) remote = await snapshot();
      const inviter = scope === offer.inviter_scope;
      // A received KeyPackage is acknowledged before publishing the Commit.
      // A joiner's own KeyPackage receipt precedes Welcome processing.
      const outgoing = await journal.invitationOutbox(offer, now());
      if (outgoing.length && (!inviter || remote.packet === null)) {
        const e = outgoing[0];
        if (e.expires_at <= now()) fail('invitation_expired_recovery_required');
        await deliveryReceipt(await this.#call(`${base}/packets`, JSON.stringify(e)), e);
        await required({
          kind: 'accept_delivery',
          message_id: e.message_id,
          digest: e.digest,
          channel_id: route.id,
        });
        sent++;
        continue;
      }
      if (remote.packet !== null) {
        const { message, wire } = await incoming(
          remote.packet,
          route,
          scope,
          [inviter ? 'key_package' : 'welcome'],
          now(),
        );
        await required({
          kind: inviter ? 'invite_from_delivery' : 'join_from_delivery',
          offer: JSON.stringify(offer),
          message_id: message.message_id,
          wire,
        });
        const consumed = await this.#call(
          `${base}/packets/${message.message_id}/consume`,
          JSON.stringify({
            recipient_scope: scope,
            digest: message.digest,
            envelope_hash: await envelopeHash(message),
          }),
        );
        deliveryExact(consumed, ['status', 'complete']);
        if (consumed.status !== 'consumed' || typeof consumed.complete !== 'boolean')
          fail('invalid_consume_receipt');
        processed++;
        continue;
      }
      if (remote.complete) {
        await required({ kind: 'complete_invitation', offer: JSON.stringify(offer) });
        return { phase: 'active', sent, processed };
      }
      const phase = await journal.invitationStatus(offer);
      return {
        phase: inviter
          ? phase === 'prepared'
            ? 'waiting_key_package'
            : 'waiting_activation'
          : 'waiting_welcome',
        sent,
        processed,
      };
    }
    return { phase: 'pending', sent, processed };
  }

  /** Consent follows existing independent fingerprint review and MLS join. */
  async approveDelivery(channel: DeliveryChannel): Promise<boolean> {
    const route = checkedChannel(channel);
    return this.#locked(async () => {
      await this.#ready().deliveryOutbox(route, Math.floor(Date.now() / 1000));
      const result = await this.#call(`/messaging/channels/${route.id}`, JSON.stringify(route));
      deliveryExact(result, ['channel', 'ready']);
      if (
        JSON.stringify(checkedChannel(result.channel as DeliveryChannel)) !==
          JSON.stringify(route) ||
        typeof result.ready !== 'boolean'
      )
        fail('delivery_channel_mismatch');
      return result.ready;
    });
  }

  /** Bounded foreground catch-up. Server acceptance is not a read receipt.
   * No inbox cursor moves until MLS state and its event are witnessed locally. */
  async syncDelivery(
    channel: DeliveryChannel,
    limit = 16,
  ): Promise<{ sent: number; received: number }> {
    const route = checkedChannel(channel);
    if (!Number.isInteger(limit) || limit < 1 || limit > 32) fail('invalid_sync_limit');
    return this.#locked(async () => {
      const journal = this.#ready();
      const scope = encodeBase64Url(await hash(context(this.#record!.scope)));
      const own = route.a.scope === scope ? route.a : route.b.scope === scope ? route.b : null;
      if (!own) fail('delivery_scope_mismatch');
      const peer = own === route.a ? route.b : route.a;
      const now = () => Math.floor(Date.now() / 1000);
      const required = async (command: Command) => {
        const result = await journal.request(crypto.randomUUID(), command, now());
        this.#assert();
        if (!result.ok) fail(result.error ?? 'delivery_state_failed');
      };
      let sent = 0,
        received = 0;
      await this.#refreshBindings(journal, route, scope);
      const outgoing = await journal.deliveryOutbox(route, now());
      for (const envelope of outgoing.slice(0, limit)) {
        const result = await this.#call(
          `/messaging/channels/${route.id}/messages`,
          JSON.stringify(envelope),
        );
        await deliveryReceipt(result, envelope);
        await required({
          kind: 'accept_delivery',
          message_id: envelope.message_id,
          digest: envelope.digest,
          channel_id: route.id,
        });
        sent++;
      }
      for (let i = 0; i < limit; i++) {
        const result = await this.#call(
          `/messaging/channels/${route.id}/inbox/${scope}`,
          undefined,
          undefined,
          96 * 1024,
        );
        deliveryExact(result, ['message']);
        if (result.message === null) break;
        const message = result.message;
        deliveryExact(message, [
          'sequence',
          'channel_id',
          'message_id',
          'sender_scope',
          'recipient_scope',
          'kind',
          'digest',
          'expires_at',
          'envelope_hash',
          'wire',
        ]);
        if (
          message.channel_id !== route.id ||
          message.sender_scope !== peer.scope ||
          message.recipient_scope !== scope ||
          typeof message.message_id !== 'string' ||
          !UUID.test(message.message_id) ||
          !['application', 'commit'].includes(message.kind as string) ||
          !Number.isSafeInteger(message.expires_at) ||
          (message.expires_at as number) <= now()
        )
          fail('invalid_incoming_delivery');
        const wire = deliveryBytes(message.wire as string);
        if (
          deliveryBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', wire))) !==
          message.digest
        )
          fail('delivery_digest_mismatch');
        const { wire: _, ...receipt } = message;
        await deliveryReceipt({ status: 'stored', receipt }, message as DeliveryEnvelope);
        await required({
          kind: 'receive_delivery',
          message_id: message.message_id,
          wire: Array.from(wire),
          route: JSON.stringify(route),
        });
        const consumed = await this.#call(
          `/messaging/channels/${route.id}/messages/${message.message_id}/consume`,
          JSON.stringify({
            recipient_scope: scope,
            digest: message.digest,
            envelope_hash: await envelopeHash(message as DeliveryEnvelope),
          }),
        );
        deliveryExact(consumed, ['status']);
        if (consumed.status !== 'consumed') fail('invalid_consume_receipt');
        received++;
      }
      return { sent, received };
    });
  }
}
