// Owner-authorized grants for exactly one current Owner Vault record.
// Raw bearer credentials and prepared request bytes are retained in-memory only.
import { OwnerRecordDisclosure, type DisclosureRecord } from './vault-owner-disclosure.ts';
import {
  OwnerNoteProposals,
  type OwnerNoteProposalSnapshot,
  type OwnerNoteGrant,
} from './vault-owner-note-proposals.ts';
import { OwnerRecordStore, OWNER_NAME } from './vault-owner-record-store.ts';
import { agentKeyId, type AgentRecipient } from './agent-crypto.ts';
import { encodeBase64Url } from './vault-crypto.ts';
import { decodeOwnerNote, type OwnerNote } from './vault-note.ts';
import type { OwnerVaultController } from './vault-owner-controller.ts';
import { parseRecordNoteTarget, type RecordNoteTarget } from './vault-record-approval.ts';
import {
  parseVaultRecordAuthority,
  parseVaultRecordSource,
  vaultCiphertextDigest,
  type VaultRecordAuthority,
  type VaultRecordSource,
} from './vault-record-source.ts';

type Obj = Record<string, unknown>;
const OPAQUE = /^[A-Za-z0-9_-]{43}$/;
export type OwnerAgentSourcePreview = Readonly<{
  id: DisclosureRecord;
  available: boolean;
  revision: number;
  deleted: boolean;
  target: OwnerAgentRecordTarget;
  source: VaultRecordSource | null;
  authority: VaultRecordAuthority;
  text: string | null;
  note: OwnerNote | null;
}>;
export type OwnerAgentRecordTarget = Readonly<{
  storage_version: 2;
  origin: string;
  owner_id: string;
  vault_id: string;
  collection_id: 'personal';
  record_id: DisclosureRecord;
  kind: DisclosureRecord;
  revision: number;
  ciphertext_sha256: string | null;
  deleted: boolean;
}>;
export type OwnerAgentCapability = Readonly<{
  state: 'unknown' | 'active' | 'stale';
  target: RecordNoteTarget | null;
  authority: VaultRecordAuthority | null;
  expires_at: number | null;
}>;
export type OwnerAgentGrantRecord = OwnerNoteGrant & Readonly<{ capability: OwnerAgentCapability }>;
export type OwnerAgentGrantSnapshot = Readonly<{
  sources: Readonly<Record<DisclosureRecord, OwnerAgentSourcePreview>>;
  recipient: Readonly<AgentRecipient>;
  grants: readonly OwnerAgentGrantRecord[];
}>;
export type OwnerAgentGrantOptions = Readonly<{
  delegate: string;
  provider: string;
  operations: readonly ('read' | 'list' | 'search' | 'propose')[];
  expiresAt: number;
}>;
export type PreparedOwnerAgentGrant = Readonly<{ grantId: string; sourceId: DisclosureRecord }>;
export type PreparedOwnerAgentCapability = Readonly<{ grantId: string }>;
export type PreparedOwnerAgentRevoke = Readonly<{ grantId: string }>;
export type OwnerAgentGrantResult = Readonly<{
  snapshot: OwnerAgentGrantSnapshot;
  grantId: string;
  expiresAt: number;
  token: string;
}>;
export type OwnerAgentCapabilityResult = Readonly<{
  snapshot: OwnerAgentGrantSnapshot;
  grantId: string;
  expiresAt: number;
}>;

export class OwnerAgentGrantError extends Error {
  readonly code: string;
  readonly definitelyRejected: boolean;
  constructor(code: string, definitelyRejected = false) {
    super(code);
    this.name = 'OwnerAgentGrantError';
    this.code = code;
    this.definitelyRejected = definitelyRejected;
  }
}
type GrantBody = {
  body: string;
  token: string;
  expiresAt: number;
  source: DisclosureRecord;
  delivered: boolean;
};
type CapabilityBody = Readonly<{
  body: string;
  target: RecordNoteTarget;
  authority: VaultRecordAuthority;
  grantExpiry: number;
}>;
type RevokeBody = Readonly<{ body: string }>;
type CapabilityReceipt = Readonly<{
  target: RecordNoteTarget;
  authority: VaultRecordAuthority;
  expires_at: number;
}>;

function obj(value: unknown, code = 'invalid_status'): Obj {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new OwnerAgentGrantError(code);
  return value as Obj;
}
function exact(value: Obj, fields: readonly string[], code = 'invalid_status'): void {
  if (
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  )
    throw new OwnerAgentGrantError(code);
}
function text(value: unknown, max: number): string {
  if (typeof value !== 'string' || !value || value.length > max)
    throw new OwnerAgentGrantError('invalid_status');
  return value;
}
function int(value: unknown, min = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min)
    throw new OwnerAgentGrantError('invalid_status');
  return value;
}
function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
function randomOpaque(): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}
function classify(response: Response, fallback: string): never {
  let code = fallback;
  throw new OwnerAgentGrantError(
    code,
    response.status >= 400 &&
      response.status < 500 &&
      response.status !== 408 &&
      response.status !== 429,
  );
}
async function readJson(response: Response, fallback: string): Promise<unknown> {
  if (!response.ok) {
    try {
      const error = obj(await response.json());
      if (typeof error['error'] === 'string') return classify(response, error['error']);
    } catch (error) {
      if (error instanceof OwnerAgentGrantError) throw error;
    }
    return classify(response, fallback);
  }
  try {
    return await response.json();
  } catch {
    throw new OwnerAgentGrantError('invalid_acknowledgement');
  }
}

function recipient(value: unknown): AgentRecipient {
  const item = obj(value);
  exact(item, ['public_jwk', 'key_id', 'resource', 'enabled']);
  if (
    !item['public_jwk'] ||
    typeof item['public_jwk'] !== 'object' ||
    Array.isArray(item['public_jwk']) ||
    typeof item['enabled'] !== 'boolean'
  )
    throw new OwnerAgentGrantError('invalid_status');
  const result = Object.freeze({
    public_jwk: item['public_jwk'] as JsonWebKey,
    key_id: text(item['key_id'], 43),
    resource: text(item['resource'], 256),
    enabled: item['enabled'],
  });
  if (!OPAQUE.test(result.key_id)) throw new OwnerAgentGrantError('invalid_status');
  return result;
}
function availableRecord(
  record: OwnerAgentSourcePreview,
): record is OwnerAgentSourcePreview & { source: VaultRecordSource } {
  return record.available && record.source !== null;
}

export class OwnerAgentGrants {
  private readonly owner: OwnerVaultController;
  private readonly proposalStatus: OwnerNoteProposals;
  private readonly snapshots = new WeakSet<object>();
  private readonly grantOps = new WeakMap<object, GrantBody>();
  private readonly capabilityOps = new WeakMap<object, CapabilityBody>();
  private readonly revokeOps = new WeakMap<object, RevokeBody>();
  private readonly capabilities = new Map<string, CapabilityReceipt>();
  constructor(owner: OwnerVaultController) {
    this.owner = owner;
    this.proposalStatus = new OwnerNoteProposals(owner);
  }

  private async namePreview(token: number): Promise<OwnerAgentSourcePreview> {
    const { stored } = this.owner.lease(),
      store = new OwnerRecordStore(this.owner, OWNER_NAME);
    const head = await store.read();
    this.owner.assertCurrent(token);
    const authority = parseVaultRecordAuthority({
      key_generation: stored.context.keyGeneration,
      owner_key_revision: stored.revision,
    });
    const source =
      head.record && !head.deleted
        ? parseVaultRecordSource({
            storage_version: 2,
            origin: stored.context.origin,
            owner_id: stored.context.ownerId,
            vault_id: stored.context.vaultId,
            collection_id: 'personal',
            record_id: 'name',
            kind: 'name',
            revision: head.revision,
            ciphertext_sha256: await vaultCiphertextDigest(head.record.ciphertext),
          })
        : null;
    const target: OwnerAgentRecordTarget = Object.freeze({
      storage_version: 2,
      origin: stored.context.origin,
      owner_id: stored.context.ownerId,
      vault_id: stored.context.vaultId,
      collection_id: 'personal',
      record_id: 'name',
      kind: 'name',
      revision: head.revision,
      ciphertext_sha256: source?.ciphertext_sha256 ?? null,
      deleted: head.deleted,
    });
    let display: string | null = null;
    if (head.record && !head.deleted) {
      const bytes = await store.readPlaintext(head);
      try {
        this.owner.assertCurrent(token);
        display = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
        if (!display.length || display.length > 256)
          throw new OwnerAgentGrantError('source_unavailable');
      } finally {
        bytes.fill(0);
      }
    }
    const fresh = await store.read();
    this.owner.assertCurrent(token);
    if (!same(head, fresh)) throw new OwnerAgentGrantError('source_changed');
    await this.owner.verifyAuthority();
    this.owner.assertCurrent(token);
    return Object.freeze({
      id: 'name',
      available: Boolean(source),
      revision: head.revision,
      deleted: head.deleted,
      target,
      source,
      authority,
      text: display,
      note: null,
    });
  }
  async load(): Promise<OwnerAgentGrantSnapshot> {
    const token = this.owner.checkpoint();
    await this.owner.verifyAuthority();
    this.owner.assertCurrent(token);
    // Both readers verify the shared display lease. Running them concurrently
    // would make one reader observe the other's session-check suspension.
    const agentStatus = await this.proposalStatus.load();
    const name = await this.namePreview(token);
    this.owner.assertCurrent(token);
    const noteHead = agentStatus.head;
    const note: OwnerAgentSourcePreview = Object.freeze({
      id: 'owner_note',
      available: Boolean(noteHead.source && !noteHead.deleted),
      revision: noteHead.revision,
      deleted: noteHead.deleted,
      target: noteHead.target,
      source: noteHead.source,
      authority: noteHead.authority,
      text: noteHead.value ? JSON.stringify(noteHead.value) : null,
      note: noteHead.value,
    });
    if ((await agentKeyId(agentStatus.recipient.public_jwk)) !== agentStatus.recipient.key_id)
      throw new OwnerAgentGrantError('invalid_status');
    const now = Math.floor(Date.now() / 1000);
    const grants = agentStatus.grants.map((grant) => {
      const cap = this.capabilities.get(grant.grant_id);
      const capCurrent = Boolean(
        cap &&
        grant.active &&
        cap.expires_at > now &&
        cap.expires_at <= grant.expires_at &&
        same(cap.target, note.target) &&
        same(cap.authority, note.authority),
      );
      return Object.freeze({
        ...grant,
        capability: Object.freeze({
          state: cap
            ? capCurrent
              ? ('active' as const)
              : ('stale' as const)
            : ('unknown' as const),
          target: cap?.target ?? null,
          authority: cap?.authority ?? null,
          expires_at: cap?.expires_at ?? null,
        }),
      });
    });
    const snapshot = Object.freeze({
      sources: Object.freeze({ name, owner_note: note }),
      recipient: agentStatus.recipient,
      grants: Object.freeze(grants),
    });
    this.snapshots.add(snapshot);
    return snapshot;
  }
  private async current(snapshot: OwnerAgentGrantSnapshot): Promise<OwnerAgentGrantSnapshot> {
    if (!this.snapshots.has(snapshot)) throw new OwnerAgentGrantError('stale_snapshot');
    const fresh = await this.load();
    if (!same(snapshot, fresh)) throw new OwnerAgentGrantError('stale_snapshot');
    return fresh;
  }
  async prepareGrant(
    snapshot: OwnerAgentGrantSnapshot,
    sourceId: DisclosureRecord,
    options: OwnerAgentGrantOptions,
  ): Promise<PreparedOwnerAgentGrant> {
    const fresh = await this.current(snapshot),
      sourcePreview = fresh.sources[sourceId];
    if (!availableRecord(sourcePreview)) throw new OwnerAgentGrantError('source_unavailable');
    if (!fresh.recipient.enabled) throw new OwnerAgentGrantError('recipient_disabled');
    const delegate = options.delegate,
      provider = options.provider.trim(),
      operations = [...options.operations];
    if (
      !/^[A-Za-z0-9_-]{1,80}$/.test(delegate) ||
      !provider ||
      provider.length > 160 ||
      !operations.includes('read') ||
      !operations.includes('list') ||
      (operations as readonly string[]).some(
        (op) => !['read', 'list', 'search', 'propose'].includes(op),
      ) ||
      new Set(operations).size !== operations.length
    )
      throw new OwnerAgentGrantError('invalid_options');
    const now = Math.floor(Date.now() / 1000),
      expiresAt = int(options.expiresAt, now + 60);
    if (expiresAt > now + 86400) throw new OwnerAgentGrantError('invalid_expiry');
    const token = `mag_${randomOpaque()}`,
      tokenHash = encodeBase64Url(
        new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))),
      );
    const grantId = randomOpaque(),
      checkpoint = this.owner.checkpoint();
    const prepared = await new OwnerRecordDisclosure(this.owner).prepareSnapshot(
      sourceId,
      fresh.recipient,
      { grant_id: grantId, expires_at: expiresAt },
    );
    this.owner.assertCurrent(checkpoint);
    if (
      !same(prepared.source, sourcePreview.source) ||
      !same(prepared.authority, sourcePreview.authority)
    )
      throw new OwnerAgentGrantError('source_changed');
    const latest = await this.current(snapshot);
    if (
      !same(latest.recipient, fresh.recipient) ||
      !same(latest.sources[sourceId].source, sourcePreview.source)
    )
      throw new OwnerAgentGrantError('source_changed');
    const body = JSON.stringify({
      storage_version: 2,
      grant_id: grantId,
      delegate,
      provider,
      resource: fresh.recipient.resource,
      recipient_key_id: fresh.recipient.key_id,
      operations,
      token_hash: tokenHash,
      expires_at: expiresAt,
      source: prepared.source,
      authority: prepared.authority,
      document_ids: [sourceId],
      envelope: prepared.envelope,
    });
    const operation = Object.freeze({ grantId, sourceId });
    this.grantOps.set(operation, { body, token, expiresAt, source: sourceId, delivered: false });
    return operation;
  }
  async commitGrant(operation: PreparedOwnerAgentGrant): Promise<OwnerAgentGrantResult> {
    const request = this.grantOps.get(operation);
    if (!request) throw new OwnerAgentGrantError('invalid_operation');
    if (request.delivered) throw new OwnerAgentGrantError('token_already_delivered', true);
    let response: Response;
    try {
      response = await this.owner.scope.request('/vault/agents/grants', {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: request.body,
      });
    } catch {
      throw new OwnerAgentGrantError('grant_unavailable');
    }
    const result = obj(await readJson(response, 'grant_unavailable'));
    exact(result, ['grant_id', 'expires_at'], 'invalid_acknowledgement');
    if (result['grant_id'] !== operation.grantId || result['expires_at'] !== request.expiresAt)
      throw new OwnerAgentGrantError('invalid_acknowledgement');
    const snapshot = await this.load();
    const acknowledged = snapshot.grants.find((grant) => grant.grant_id === operation.grantId);
    if (!acknowledged || acknowledged.expires_at !== request.expiresAt)
      throw new OwnerAgentGrantError('grant_unconfirmed');
    request.delivered = true;
    const body = JSON.parse(request.body) as Record<string, unknown>;
    if (
      acknowledged.delegate !== body['delegate'] ||
      acknowledged.provider !== body['provider'] ||
      acknowledged.resource !== body['resource'] ||
      acknowledged.recipient_key_id !== body['recipient_key_id'] ||
      !same(acknowledged.operations, body['operations']) ||
      !same(acknowledged.document_ids, body['document_ids']) ||
      !same(acknowledged.source, body['source']) ||
      !same(acknowledged.authority, body['authority'])
    )
      throw new OwnerAgentGrantError('grant_mismatch', true);
    if (!acknowledged.active || acknowledged.expires_at <= Math.floor(Date.now() / 1000))
      throw new OwnerAgentGrantError('grant_inactive', true);
    return Object.freeze({
      snapshot,
      grantId: operation.grantId,
      expiresAt: request.expiresAt,
      token: request.token,
    });
  }
  async prepareCapability(
    snapshot: OwnerAgentGrantSnapshot,
    grantId: string,
  ): Promise<PreparedOwnerAgentCapability> {
    const fresh = await this.current(snapshot),
      grant = fresh.grants.find((entry) => entry.grant_id === grantId);
    if (
      !grant ||
      !grant.active ||
      grant.expires_at <= Math.floor(Date.now() / 1000) ||
      !grant.operations.includes('propose')
    )
      throw new OwnerAgentGrantError('grant_unavailable');
    if (!fresh.recipient.enabled) throw new OwnerAgentGrantError('recipient_disabled');
    const cap = fresh.grants.find((entry) => entry.grant_id === grantId)?.capability;
    if (
      cap?.state === 'active' &&
      same(cap.target, fresh.sources.owner_note.target) &&
      same(cap.authority, fresh.sources.owner_note.authority)
    )
      throw new OwnerAgentGrantError('capability_exists');
    const target = parseRecordNoteTarget(fresh.sources.owner_note.target);
    const operation = Object.freeze({ grantId });
    this.capabilityOps.set(
      operation,
      Object.freeze({
        body: JSON.stringify({
          grant_id: grantId,
          target,
          authority: fresh.sources.owner_note.authority,
        }),
        target,
        authority: fresh.sources.owner_note.authority,
        grantExpiry: grant.expires_at,
      }),
    );
    return operation;
  }
  async commitCapability(
    operation: PreparedOwnerAgentCapability,
  ): Promise<OwnerAgentCapabilityResult> {
    const request = this.capabilityOps.get(operation);
    if (!request) throw new OwnerAgentGrantError('invalid_operation');
    let response: Response;
    try {
      response = await this.owner.scope.request('/vault/agents/record-capability', {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: request.body,
      });
    } catch {
      throw new OwnerAgentGrantError('capability_unavailable');
    }
    const result = obj(await readJson(response, 'capability_unavailable'));
    exact(result, ['grant_id', 'target', 'authority', 'expires_at'], 'invalid_acknowledgement');
    const target = parseRecordNoteTarget(result['target']),
      authority = parseVaultRecordAuthority(result['authority']),
      expiresAt = int(result['expires_at'], 1);
    if (
      result['grant_id'] !== operation.grantId ||
      !same(target, request.target) ||
      !same(authority, request.authority) ||
      expiresAt > request.grantExpiry ||
      expiresAt > Math.floor(Date.now() / 1000) + 3600 ||
      expiresAt <= Math.floor(Date.now() / 1000)
    )
      throw new OwnerAgentGrantError('invalid_acknowledgement');
    this.capabilities.set(
      operation.grantId,
      Object.freeze({ target, authority, expires_at: expiresAt }),
    );
    const snapshot = await this.load();
    return Object.freeze({ snapshot, grantId: operation.grantId, expiresAt });
  }
  async prepareRevoke(
    snapshot: OwnerAgentGrantSnapshot,
    grantId: string,
  ): Promise<PreparedOwnerAgentRevoke> {
    if (
      !this.snapshots.has(snapshot) ||
      !snapshot.grants.some((grant) => grant.grant_id === grantId)
    )
      throw new OwnerAgentGrantError('grant_unavailable');
    const checkpoint = this.owner.checkpoint();
    await this.owner.verifyAuthority();
    this.owner.assertCurrent(checkpoint);
    const operation = Object.freeze({ grantId });
    this.revokeOps.set(operation, Object.freeze({ body: JSON.stringify({ grant_id: grantId }) }));
    return operation;
  }
  async revoke(operation: PreparedOwnerAgentRevoke): Promise<OwnerAgentGrantSnapshot> {
    const request = this.revokeOps.get(operation);
    if (!request) throw new OwnerAgentGrantError('invalid_operation');
    let response: Response;
    try {
      response = await this.owner.scope.request('/vault/agents/revoke', {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: request.body,
      });
    } catch {
      throw new OwnerAgentGrantError('revoke_unavailable');
    }
    const result = obj(await readJson(response, 'revoke_unavailable'));
    exact(result, ['revoked'], 'invalid_acknowledgement');
    if (result['revoked'] !== true) throw new OwnerAgentGrantError('invalid_acknowledgement');
    this.capabilities.delete(operation.grantId);
    const snapshot = await this.load();
    const grant = snapshot.grants.find((entry) => entry.grant_id === operation.grantId);
    if (!grant || grant.active) throw new OwnerAgentGrantError('revoke_unconfirmed');
    return snapshot;
  }
}
