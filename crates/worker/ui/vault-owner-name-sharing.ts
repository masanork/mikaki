// Owner-approved record-v2 name sharing. Plaintext stays in this module's
// memory and is never included in an operation body.
import {
  fetchVerifiedRecordUserInfoRecipient,
  type RecordUserInfoRecipient,
} from './recipient-directory-v2.ts';
import { encodeBase64Url } from './vault-crypto.ts';
import { OwnerRecordStore, OWNER_NAME, type OwnerRecordHead } from './vault-owner-record-store.ts';
import type { OwnerVaultController } from './vault-owner-controller.ts';
import type { OwnerRecord } from './vault-owner-crypto.ts';
import {
  parseVaultRecordAuthority,
  parseVaultRecordSource,
  vaultCiphertextDigest,
  type VaultRecordAuthority,
  type VaultRecordSource,
} from './vault-record-source.ts';

export type OwnerNameSystemGrant = Readonly<{
  storage_version: 2;
  owner_id: string;
  vault_id: string;
  origin: string;
  collection_id: 'personal';
  record_id: 'name';
  kind: 'name';
  record_revision: number;
  ciphertext_sha256: string;
  key_generation: number;
  owner_key_revision: number;
  version: number;
  status: 'active' | 'revoked';
  expires_at: number;
  authority_current: boolean;
  recipient_key_id: string;
  recipient_generation: number;
  directory_revision: number;
  policy_revision: number;
}>;

export type OwnerNameReleaseClient = Readonly<{
  client_id: string;
  sector_identifier: string;
  client_revision: number;
  connection_grant_version: number;
  release_version: number | null;
  release_status: 'active' | 'revoked' | null;
  expires_at: number | null;
  source_storage_version: number | null;
  source_origin: string | null;
  source_vault_id: string | null;
  source_collection_id: string | null;
  source_record_id: string | null;
  source_kind: string | null;
  attribute_revision: number | null;
  source_ciphertext_sha256: string | null;
  source_key_generation: number | null;
  source_owner_key_revision: number | null;
  system_grant_version: number | null;
  authority_current: boolean;
  current: boolean;
  eligible: boolean;
}>;

export type OwnerNameSharingSnapshot = Readonly<{
  name: string;
  source: VaultRecordSource;
  authority: VaultRecordAuthority;
  record: OwnerRecord;
  recipient: RecordUserInfoRecipient | null;
  sharing: Readonly<{
    enabled: boolean;
    policy_revision: number;
    grant_ttl_seconds: number;
    grant: OwnerNameSystemGrant | null;
    authorityCurrent: boolean;
  }>;
  releases: Readonly<{
    enabled: boolean;
    policy_revision: number;
    ttl_seconds: number;
    clients: readonly OwnerNameReleaseClient[];
  }>;
}>;

export type OwnerNameOperationAction = 'share' | 'revoke-share' | 'release' | 'revoke-release';
export type PreparedOwnerNameOperation = Readonly<{
  action: OwnerNameOperationAction;
  clientId: string | null;
  operationId: string;
}>;

export class OwnerNameSharingError extends Error {
  readonly code: string;
  readonly definitelyRejected: boolean;
  constructor(code: string, definitelyRejected = false) {
    super(code);
    this.name = 'OwnerNameSharingError';
    this.code = code;
    this.definitelyRejected = definitelyRejected;
  }
}

type ObjectValue = Record<string, unknown>;
type InternalOperation = Readonly<{
  method: 'POST' | 'DELETE';
  path: string;
  ifMatch: number;
  body: string;
}>;

const SHARE_PATH = '/vault/records/personal/name/sharing';
const RELEASE_PATH = '/vault/records/personal/name/releases';

function object(value: unknown, code = 'invalid_status'): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new OwnerNameSharingError(code);
  return value as ObjectValue;
}
function exact(value: ObjectValue, keys: readonly string[], code = 'invalid_status'): void {
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key)))
    throw new OwnerNameSharingError(code);
}
function safeInt(value: unknown, min = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min)
    throw new OwnerNameSharingError('invalid_status');
  return value;
}
function flag(value: unknown): boolean {
  if (value !== 0 && value !== 1) throw new OwnerNameSharingError('invalid_status');
  return value === 1;
}
function strictBoolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new OwnerNameSharingError('invalid_status');
  return value;
}
function text(value: unknown, max = 256): string {
  if (typeof value !== 'string' || !value.length || value.length > max)
    throw new OwnerNameSharingError('invalid_status');
  return value;
}
function nullableText(value: unknown, max = 256): string | null {
  return value === null ? null : text(value, max);
}
function nullableInt(value: unknown, min = 0): number | null {
  return value === null ? null : safeInt(value, min);
}
function same(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}
function nameFrom(plaintext: Uint8Array<ArrayBuffer>): string {
  try {
    const value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext);
    if (!value.trim() || value.length > 256) throw new OwnerNameSharingError('name_unavailable');
    return value;
  } catch (error) {
    if (error instanceof OwnerNameSharingError) throw error;
    throw new OwnerNameSharingError('name_unavailable');
  } finally {
    plaintext.fill(0);
  }
}

function parseSystemGrant(value: unknown): OwnerNameSystemGrant | null {
  if (value === null) return null;
  const item = object(value);
  exact(item, [
    'storage_version',
    'owner_id',
    'vault_id',
    'origin',
    'collection_id',
    'record_id',
    'kind',
    'record_revision',
    'ciphertext_sha256',
    'key_generation',
    'owner_key_revision',
    'version',
    'status',
    'expires_at',
    'authority_current',
    'recipient_key_id',
    'recipient_generation',
    'directory_revision',
    'policy_revision',
  ]);
  const source = parseVaultRecordSource({
    storage_version: item['storage_version'],
    owner_id: item['owner_id'],
    vault_id: item['vault_id'],
    origin: item['origin'],
    collection_id: item['collection_id'],
    record_id: item['record_id'],
    kind: item['kind'],
    revision: item['record_revision'],
    ciphertext_sha256: item['ciphertext_sha256'],
  });
  if (
    source.storage_version !== 2 ||
    source.collection_id !== 'personal' ||
    source.record_id !== 'name' ||
    source.kind !== 'name'
  )
    throw new OwnerNameSharingError('invalid_status');
  if (item['status'] !== 'active' && item['status'] !== 'revoked')
    throw new OwnerNameSharingError('invalid_status');
  if (item['authority_current'] !== 0 && item['authority_current'] !== 1)
    throw new OwnerNameSharingError('invalid_status');
  return Object.freeze({
    storage_version: 2,
    owner_id: source.owner_id,
    vault_id: source.vault_id,
    origin: source.origin,
    collection_id: 'personal',
    record_id: 'name',
    kind: 'name',
    record_revision: source.revision,
    ciphertext_sha256: source.ciphertext_sha256,
    key_generation: safeInt(item['key_generation'], 1),
    owner_key_revision: safeInt(item['owner_key_revision'], 1),
    version: safeInt(item['version'], 1),
    status: item['status'],
    expires_at: safeInt(item['expires_at'], 1),
    authority_current: item['authority_current'] === 1,
    recipient_key_id: text(item['recipient_key_id'], 43),
    recipient_generation: safeInt(item['recipient_generation'], 1),
    directory_revision: safeInt(item['directory_revision'], 1),
    policy_revision: safeInt(item['policy_revision'], 1),
  });
}

const RELEASE_CLIENT_FIELDS = [
  'client_id',
  'sector_identifier',
  'client_revision',
  'connection_grant_version',
  'release_version',
  'release_status',
  'expires_at',
  'source_storage_version',
  'source_origin',
  'source_vault_id',
  'source_collection_id',
  'source_record_id',
  'source_kind',
  'attribute_revision',
  'source_ciphertext_sha256',
  'source_key_generation',
  'source_owner_key_revision',
  'system_grant_version',
  'authority_current',
] as const;

function parseReleaseClient(value: unknown): OwnerNameReleaseClient {
  const item = object(value);
  exact(item, RELEASE_CLIENT_FIELDS);
  const statusValue = item['release_status'];
  const releaseStatus: OwnerNameReleaseClient['release_status'] =
    statusValue === null ? null : (statusValue as 'active' | 'revoked');
  if (statusValue !== null && statusValue !== 'active' && statusValue !== 'revoked')
    throw new OwnerNameSharingError('invalid_status');
  const authorityCurrent = flag(item['authority_current']);
  const parsed = {
    client_id: text(item['client_id'], 128),
    sector_identifier: text(item['sector_identifier'], 2048),
    client_revision: safeInt(item['client_revision']),
    connection_grant_version: safeInt(item['connection_grant_version']),
    release_version: nullableInt(item['release_version']),
    release_status: releaseStatus,
    expires_at: nullableInt(item['expires_at'], 1),
    source_storage_version: nullableInt(item['source_storage_version'], 1),
    source_origin: nullableText(item['source_origin'], 256),
    source_vault_id: nullableText(item['source_vault_id'], 128),
    source_collection_id: nullableText(item['source_collection_id'], 64),
    source_record_id: nullableText(item['source_record_id'], 64),
    source_kind: nullableText(item['source_kind'], 64),
    attribute_revision: nullableInt(item['attribute_revision'], 1),
    source_ciphertext_sha256: nullableText(item['source_ciphertext_sha256'], 43),
    source_key_generation: nullableInt(item['source_key_generation'], 1),
    source_owner_key_revision: nullableInt(item['source_owner_key_revision'], 1),
    system_grant_version: nullableInt(item['system_grant_version'], 1),
    authority_current: authorityCurrent,
    current: false,
    eligible: false,
  };
  const fields = [
    parsed.release_version,
    parsed.release_status,
    parsed.expires_at,
    parsed.source_storage_version,
    parsed.source_origin,
    parsed.source_vault_id,
    parsed.source_collection_id,
    parsed.source_record_id,
    parsed.source_kind,
    parsed.attribute_revision,
    parsed.source_ciphertext_sha256,
    parsed.source_key_generation,
    parsed.source_owner_key_revision,
    parsed.system_grant_version,
  ];
  if (
    parsed.release_version === null
      ? fields.some((v) => v !== null)
      : fields.some((v) => v === null)
  )
    throw new OwnerNameSharingError('invalid_status');
  return Object.freeze(parsed);
}

function parseSharing(value: unknown): OwnerNameSharingSnapshot['sharing'] {
  const item = object(value);
  exact(item, ['enabled', 'policy_revision', 'grant_ttl_seconds', 'grant']);
  const enabled = strictBoolean(item['enabled']);
  const policyRevision = safeInt(item['policy_revision'], 1);
  const grantTtl = safeInt(item['grant_ttl_seconds'], 60);
  const grant = parseSystemGrant(item['grant']);
  return Object.freeze({
    enabled,
    policy_revision: policyRevision,
    grant_ttl_seconds: grantTtl,
    grant,
    authorityCurrent: Boolean(
      enabled &&
      grant &&
      grant.status === 'active' &&
      grant.expires_at > Math.floor(Date.now() / 1000) &&
      grant.authority_current &&
      grant.policy_revision === policyRevision,
    ),
  });
}

function parseReleases(value: unknown): OwnerNameSharingSnapshot['releases'] {
  const item = object(value);
  exact(item, ['enabled', 'policy_revision', 'ttl_seconds', 'clients']);
  if (!Array.isArray(item['clients']) || item['clients'].length > 100)
    throw new OwnerNameSharingError('invalid_status');
  const clients = item['clients'].map(parseReleaseClient);
  if (new Set(clients.map((client) => client.client_id)).size !== clients.length)
    throw new OwnerNameSharingError('invalid_status');
  return Object.freeze({
    enabled: strictBoolean(item['enabled']),
    policy_revision: safeInt(item['policy_revision'], 1),
    ttl_seconds: safeInt(item['ttl_seconds'], 60),
    clients: Object.freeze(clients),
  });
}

export class OwnerNameSharing {
  private readonly owner: OwnerVaultController;
  private readonly checkpointStorage: Pick<Storage, 'getItem' | 'setItem'>;
  private readonly snapshots = new WeakSet<object>();
  private readonly operations = new WeakMap<object, InternalOperation>();

  constructor(
    owner: OwnerVaultController,
    checkpointStorage: Pick<Storage, 'getItem' | 'setItem'>,
  ) {
    this.owner = owner;
    this.checkpointStorage = checkpointStorage;
  }

  private async json(path: string): Promise<unknown> {
    const response = await this.owner.scope.request(path, { cache: 'no-store' });
    if (!response.ok) throw new OwnerNameSharingError('status_unavailable');
    return response.json();
  }

  private async readHead(): Promise<{
    head: OwnerRecordHead;
    source: VaultRecordSource;
    authority: VaultRecordAuthority;
    record: OwnerRecord;
    name: string;
  }> {
    const token = this.owner.checkpoint();
    const { stored } = this.owner.lease();
    const store = new OwnerRecordStore(this.owner, OWNER_NAME);
    const head = await store.read();
    this.owner.assertCurrent(token);
    if (head.deleted || !head.record) throw new OwnerNameSharingError('name_unavailable');
    const record = Object.freeze({ ...head.record });
    const source = parseVaultRecordSource({
      storage_version: 2,
      origin: stored.context.origin,
      owner_id: stored.context.ownerId,
      vault_id: stored.context.vaultId,
      collection_id: 'personal',
      record_id: 'name',
      kind: 'name',
      revision: head.revision,
      ciphertext_sha256: await vaultCiphertextDigest(record.ciphertext),
    });
    const authority = parseVaultRecordAuthority({
      key_generation: stored.context.keyGeneration,
      owner_key_revision: stored.revision,
    });
    const plaintext = await store.readPlaintext(head);
    let name: string;
    try {
      this.owner.assertCurrent(token);
      name = nameFrom(plaintext);
    } finally {
      plaintext.fill(0);
    }
    return { head, source, authority, record, name };
  }

  private async checkOwner(): Promise<number> {
    const token = this.owner.checkpoint();
    await this.owner.verifyAuthority();
    this.owner.assertCurrent(token);
    return token;
  }

  async load(): Promise<OwnerNameSharingSnapshot> {
    const token = await this.checkOwner();
    const first = await this.readHead();
    const [recipientResult, sharingValue, releasesValue] = await Promise.all([
      fetchVerifiedRecordUserInfoRecipient(fetch, this.checkpointStorage).then(
        (recipient) => ({ recipient }),
        () => ({ recipient: null }),
      ),
      this.json(SHARE_PATH),
      this.json(RELEASE_PATH),
    ]);
    this.owner.assertCurrent(token);
    const recipient = recipientResult.recipient;
    const sharing = parseSharing(sharingValue);
    const releases = parseReleases(releasesValue);
    await this.owner.verifyAuthority();
    this.owner.assertCurrent(token);
    const second = await this.readHead();
    this.owner.assertCurrent(token);
    if (
      !same(first.source, second.source) ||
      !same(first.authority, second.authority) ||
      !same(first.record, second.record) ||
      first.name !== second.name
    )
      throw new OwnerNameSharingError('source_changed');
    const grant = sharing.grant;
    const authorityCurrent = Boolean(
      sharing.authorityCurrent &&
      grant &&
      same(
        parseVaultRecordSource({
          storage_version: grant.storage_version,
          owner_id: grant.owner_id,
          origin: grant.origin,
          vault_id: grant.vault_id,
          collection_id: grant.collection_id,
          record_id: grant.record_id,
          kind: grant.kind,
          revision: grant.record_revision,
          ciphertext_sha256: grant.ciphertext_sha256,
        }),
        first.source,
      ) &&
      grant.key_generation === first.authority.key_generation &&
      grant.owner_key_revision === first.authority.owner_key_revision &&
      recipient !== null &&
      grant.recipient_key_id === recipient.key_id &&
      grant.recipient_generation === recipient.generation &&
      grant.directory_revision === recipient.revision,
    );
    const clients = releases.clients.map((client) => {
      const activeReleaseCurrent = Boolean(
        releases.enabled &&
        authorityCurrent &&
        client.authority_current &&
        client.release_status === 'active' &&
        client.expires_at !== null &&
        client.expires_at > Math.floor(Date.now() / 1000) &&
        client.source_storage_version === first.source.storage_version &&
        client.source_origin === first.source.origin &&
        client.source_vault_id === first.source.vault_id &&
        client.source_collection_id === first.source.collection_id &&
        client.source_record_id === first.source.record_id &&
        client.source_kind === first.source.kind &&
        client.attribute_revision === first.source.revision &&
        client.source_ciphertext_sha256 === first.source.ciphertext_sha256 &&
        client.source_key_generation === first.authority.key_generation &&
        client.source_owner_key_revision === first.authority.owner_key_revision &&
        client.system_grant_version === grant?.version,
      );
      return Object.freeze({
        ...client,
        current: activeReleaseCurrent,
        // The endpoint only lists active private_key_jwt connections. A current
        // release is not required to offer a new consent or renewal.
        eligible: Boolean(releases.enabled && authorityCurrent),
      });
    });
    const snapshot: OwnerNameSharingSnapshot = Object.freeze({
      name: first.name,
      source: first.source,
      authority: first.authority,
      record: first.record,
      recipient,
      sharing: Object.freeze({ ...sharing, authorityCurrent }),
      releases: Object.freeze({ ...releases, clients: Object.freeze(clients) }),
    });
    this.snapshots.add(snapshot);
    return snapshot;
  }

  private async current(snapshot: OwnerNameSharingSnapshot): Promise<OwnerNameSharingSnapshot> {
    if (!this.snapshots.has(snapshot)) throw new OwnerNameSharingError('stale_snapshot');
    const fresh = await this.load();
    if (!same(snapshot, fresh)) throw new OwnerNameSharingError('stale_snapshot');
    return fresh;
  }

  private async prepare(
    action: OwnerNameOperationAction,
    snapshot: OwnerNameSharingSnapshot,
    clientId: string | null,
  ): Promise<PreparedOwnerNameOperation> {
    const fresh = await this.current(snapshot);
    const token = this.owner.checkpoint();
    await this.owner.verifyAuthority();
    this.owner.assertCurrent(token);
    const rechecked = await this.readHead();
    if (
      !same(rechecked.source, fresh.source) ||
      !same(rechecked.authority, fresh.authority) ||
      !same(rechecked.record, fresh.record) ||
      rechecked.name !== fresh.name
    )
      throw new OwnerNameSharingError('source_changed');

    let method: 'POST' | 'DELETE';
    let path: string;
    let ifMatch: number;
    let body: string;
    if (action === 'share') {
      if (!fresh.sharing.enabled) throw new OwnerNameSharingError('sharing_disabled');
      if (!fresh.recipient) throw new OwnerNameSharingError('recipient_unavailable');
      const { session } = this.owner.lease();
      const frame = await session.sealUserInfoRecipient(
        fresh.record,
        fresh.source,
        fresh.authority,
        fresh.recipient,
      );
      try {
        this.owner.assertCurrent(token);
        const currentHead = await this.readHead();
        if (
          !same(currentHead.source, fresh.source) ||
          !same(currentHead.authority, fresh.authority)
        )
          throw new OwnerNameSharingError('source_changed');
        body = JSON.stringify({
          source: fresh.source,
          authority: fresh.authority,
          key_id: fresh.recipient.key_id,
          generation: fresh.recipient.generation,
          directory_revision: fresh.recipient.revision,
          policy_revision: fresh.sharing.policy_revision,
          expected_grant_version: fresh.sharing.grant?.version ?? 0,
          frame: encodeBase64Url(frame),
        });
      } finally {
        frame.fill(0);
      }
      method = 'POST';
      path = SHARE_PATH;
      ifMatch = fresh.source.revision;
    } else if (action === 'revoke-share') {
      const grant = fresh.sharing.grant;
      if (!grant || grant.status !== 'active') throw new OwnerNameSharingError('share_not_active');
      body = JSON.stringify({ source: fresh.source, authority: fresh.authority });
      method = 'DELETE';
      path = SHARE_PATH;
      ifMatch = grant.version;
    } else if (action === 'release') {
      if (!fresh.sharing.authorityCurrent || !fresh.releases.enabled)
        throw new OwnerNameSharingError('share_not_eligible');
      const client = fresh.releases.clients.find((entry) => entry.client_id === clientId);
      if (!client || !client.eligible) throw new OwnerNameSharingError('client_not_eligible');
      body = JSON.stringify({
        expected_release_version: client.release_version ?? 0,
        source: fresh.source,
        authority: fresh.authority,
        client_id: client.client_id,
        client_revision: client.client_revision,
        connection_grant_version: client.connection_grant_version,
        policy_revision: fresh.releases.policy_revision,
      });
      method = 'POST';
      path = RELEASE_PATH;
      ifMatch = fresh.sharing.grant!.version;
    } else {
      const client = fresh.releases.clients.find((entry) => entry.client_id === clientId);
      if (!client || client.release_version === null || client.release_status !== 'active')
        throw new OwnerNameSharingError('release_not_active');
      body = JSON.stringify({ client_id: client.client_id });
      method = 'DELETE';
      path = RELEASE_PATH;
      ifMatch = client.release_version;
    }
    this.owner.assertCurrent(token);
    const operationId = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const operation = Object.freeze({ action, clientId, operationId });
    this.operations.set(operation, Object.freeze({ method, path, ifMatch, body }));
    return operation;
  }

  prepareShare(snapshot: OwnerNameSharingSnapshot): Promise<PreparedOwnerNameOperation> {
    return this.prepare('share', snapshot, null);
  }
  prepareRevokeShare(snapshot: OwnerNameSharingSnapshot): Promise<PreparedOwnerNameOperation> {
    return this.prepare('revoke-share', snapshot, null);
  }
  prepareRelease(
    snapshot: OwnerNameSharingSnapshot,
    clientId: string,
  ): Promise<PreparedOwnerNameOperation> {
    return this.prepare('release', snapshot, clientId);
  }
  prepareRevokeRelease(
    snapshot: OwnerNameSharingSnapshot,
    clientId: string,
  ): Promise<PreparedOwnerNameOperation> {
    return this.prepare('revoke-release', snapshot, clientId);
  }

  async commit(operation: PreparedOwnerNameOperation): Promise<OwnerNameSharingSnapshot> {
    const internal = this.operations.get(operation);
    if (!internal) throw new OwnerNameSharingError('invalid_operation');
    const token = this.owner.checkpoint();
    const response = await this.owner.scope.request(internal.path, {
      method: internal.method,
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        'X-Operation-ID': operation.operationId,
        'If-Match': `"${internal.ifMatch}"`,
      },
      body: internal.body,
    });
    if (!response.ok) {
      let code = 'sharing_unavailable';
      try {
        const value = object(await response.json());
        if (typeof value['error'] === 'string') code = value['error'];
      } catch {
        /* Keep mutation bytes in memory for an explicit exact retry. */
      }
      const definitelyRejected =
        response.status >= 400 &&
        response.status < 500 &&
        response.status !== 408 &&
        response.status !== 429;
      if (definitelyRejected) this.operations.delete(operation);
      throw new OwnerNameSharingError(code, definitelyRejected);
    }
    let receiptValue: unknown;
    try {
      receiptValue = await response.json();
    } catch {
      throw new OwnerNameSharingError('invalid_acknowledgement');
    }
    let receipt: ObjectValue;
    try {
      receipt = object(receiptValue, 'invalid_acknowledgement');
    } catch {
      throw new OwnerNameSharingError('invalid_acknowledgement');
    }
    this.owner.assertCurrent(token);
    const action = operation.action;
    if (receipt['acknowledged'] !== true)
      throw new OwnerNameSharingError('invalid_acknowledgement');
    if (action === 'release' || action === 'revoke-release') {
      if (
        receipt['client_id'] !== operation.clientId ||
        !Number.isSafeInteger(receipt['release_version']) ||
        (receipt['release_version'] as number) < 1 ||
        Object.keys(receipt).length !== 3
      )
        throw new OwnerNameSharingError('invalid_acknowledgement');
    } else if (
      !Number.isSafeInteger(receipt['grant_version']) ||
      (receipt['grant_version'] as number) < 1 ||
      !Number.isSafeInteger(receipt['record_revision']) ||
      (receipt['record_revision'] as number) < 1 ||
      Object.keys(receipt).length !== 3
    ) {
      throw new OwnerNameSharingError('invalid_acknowledgement');
    }
    // Never infer current authorization from a durable historical receipt.
    // Keeping this opaque operation permits only an exact retry after failures.
    return this.load();
  }
}
