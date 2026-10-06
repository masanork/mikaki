// Owner-only review and commit flow for existing record-v2 owner-note proposals.
// Proposal text is untrusted content; operation bodies remain opaque and in memory.
import { agentKeyId, type AgentRecipient } from './agent-crypto.ts';
import { encodeBase64Url } from './vault-crypto.ts';
import { OwnerRecordStore, OWNER_NOTE } from './vault-owner-record-store.ts';
import type { OwnerVaultController } from './vault-owner-controller.ts';
import type { OwnerRecord } from './vault-owner-crypto.ts';
import {
  parseApprovedRecordNote,
  parseRecordNoteTarget,
  type RecordNoteTarget,
} from './vault-record-approval.ts';
import {
  parseVaultRecordAuthority,
  parseVaultRecordSource,
  vaultCiphertextDigest,
  type VaultRecordAuthority,
} from './vault-record-source.ts';
import { decodeOwnerNote, parseOwnerNote, type OwnerNote } from './vault-note.ts';

type ObjectValue = Record<string, unknown>;
export type OwnerNoteHead = Readonly<{
  revision: number;
  deleted: boolean;
  target: RecordNoteTarget;
  source: ReturnType<typeof parseVaultRecordSource> | null;
  authority: VaultRecordAuthority;
  record: OwnerRecord | null;
  value: OwnerNote | null;
}>;
export type OwnerNoteGrant = Readonly<{
  grant_id: string;
  revision: number;
  active: boolean;
  expires_at: number;
  recipient_key_id: string;
  resource: string;
}>;
export type OwnerNoteRecipient = Readonly<AgentRecipient>;
export type OwnerNoteProposal = Readonly<{
  proposal_id: string;
  request_hash: string;
  grant_id: string;
  grant_revision: number;
  state: 'pending' | 'approved' | 'rejected' | 'invalid' | 'committed';
  expires_at: number;
  payload: string | null;
  value: OwnerNote | null;
  target: RecordNoteTarget;
  authority: VaultRecordAuthority;
  delegate: string;
  provider: string;
  matchingGrantActive: boolean;
  targetCurrent: boolean;
  operation_id: string | null;
  candidate: string | null;
  result_revision: number | null;
}>;
export type OwnerNoteProposalSnapshot = Readonly<{
  head: OwnerNoteHead;
  grants: readonly OwnerNoteGrant[];
  recipient: OwnerNoteRecipient;
  proposals: readonly OwnerNoteProposal[];
}>;
export type PreparedOwnerNoteDecision = Readonly<{
  proposalId: string;
  approve: boolean;
}>;
export type PreparedOwnerNoteCommit = Readonly<{
  proposalId: string;
  operationId: string;
}>;

export class OwnerNoteProposalError extends Error {
  readonly code: string;
  readonly definitelyRejected: boolean;
  constructor(code: string, definitelyRejected = false) {
    super(code);
    this.name = 'OwnerNoteProposalError';
    this.code = code;
    this.definitelyRejected = definitelyRejected;
  }
}

type DecisionRequest = Readonly<{
  body: string;
  proposalId: string;
  requestHash: string;
  expectedState: 'approved' | 'rejected';
  target: RecordNoteTarget;
  authority: VaultRecordAuthority;
  expiresAt: number;
}>;
type CommitRequest = {
  preparedBody: string;
  candidate: string;
  proof: unknown;
  requestHash: string;
  target: RecordNoteTarget;
  expectedRevision: number;
  expectedHead: OwnerNoteHead;
  prepareAcknowledged: boolean;
};
const ID = /^[A-Za-z0-9_-]{43}$/;
const PROPOSAL_FIELDS = [
  'proposal_id',
  'grant_id',
  'grant_revision',
  'request_hash',
  'attribute_id',
  'base_revision',
  'payload',
  'expires_at',
  'created_at',
  'state',
  'storage_version',
  'target_origin',
  'target_vault_id',
  'target_collection_id',
  'target_record_id',
  'target_kind',
  'target_ciphertext_sha256',
  'target_deleted',
  'target_key_generation',
  'target_owner_key_revision',
  'delegate',
  'provider',
  'operation_id',
  'candidate',
  'result_revision',
  'target',
  'authority',
  'destination',
  'untrusted_content',
];
const GRANT_FIELDS = [
  'grant_id',
  'account_id',
  'delegate',
  'provider',
  'resource',
  'source_revision',
  'operations',
  'document_ids',
  'created_at',
  'expires_at',
  'revoked',
  'revision',
  'recipient_key_id',
  'storage_version',
  'source_origin',
  'source_vault_id',
  'source_collection_id',
  'source_record_id',
  'source_kind',
  'source_ciphertext_sha256',
  'source_key_generation',
  'source_owner_key_revision',
  'active',
];

function obj(value: unknown, code = 'invalid_status'): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new OwnerNoteProposalError(code);
  return value as ObjectValue;
}
function exact(value: ObjectValue, fields: readonly string[], code = 'invalid_status'): void {
  if (
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  )
    throw new OwnerNoteProposalError(code);
}
function int(value: unknown, min = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min)
    throw new OwnerNoteProposalError('invalid_status');
  return value;
}
function id(value: unknown): string {
  if (typeof value !== 'string' || !ID.test(value))
    throw new OwnerNoteProposalError('invalid_status');
  return value;
}
function text(value: unknown, max = 256): string {
  if (typeof value !== 'string' || !value || value.length > max)
    throw new OwnerNoteProposalError('invalid_status');
  return value;
}
function nullableString(value: unknown, max = 100_000): string | null {
  if (value === null) return null;
  if (typeof value !== 'string' || value.length > max)
    throw new OwnerNoteProposalError('invalid_status');
  return value;
}
function bool(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new OwnerNoteProposalError('invalid_status');
  return value;
}
function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
function freezeNote(value: OwnerNote): OwnerNote {
  Object.freeze(value.provenance);
  return Object.freeze(value);
}
function rejected(response: Response, code: string): never {
  throw new OwnerNoteProposalError(
    code,
    response.status >= 400 &&
      response.status < 500 &&
      response.status !== 408 &&
      response.status !== 429,
  );
}
async function responseJson(response: Response, code: string): Promise<unknown> {
  if (!response.ok) {
    let error = code;
    try {
      const body = obj(await response.json());
      if (typeof body['error'] === 'string') error = body['error'];
    } catch {
      /* status is definitive even if its body is malformed */
    }
    return rejected(response, error);
  }
  try {
    return await response.json();
  } catch {
    throw new OwnerNoteProposalError('invalid_acknowledgement');
  }
}

function parseGrant(value: unknown, ownerId: string): OwnerNoteGrant {
  const item = obj(value);
  exact(item, GRANT_FIELDS);
  if (
    item['storage_version'] !== 2 ||
    (item['revoked'] !== 0 && item['revoked'] !== 1) ||
    item['account_id'] !== ownerId
  )
    throw new OwnerNoteProposalError('invalid_status');
  if (item['active'] !== 0 && item['active'] !== 1)
    throw new OwnerNoteProposalError('invalid_status');
  if (item['active'] === 1 && item['revoked'] !== 0)
    throw new OwnerNoteProposalError('invalid_status');
  return Object.freeze({
    grant_id: id(item['grant_id']),
    revision: int(item['revision'], 1),
    active: item['active'] === 1,
    expires_at: int(item['expires_at'], 1),
    recipient_key_id: id(item['recipient_key_id']),
    resource: text(item['resource'], 2048),
  });
}
function parseRecipient(value: unknown): OwnerNoteRecipient {
  const item = obj(value);
  exact(item, ['public_jwk', 'key_id', 'resource', 'enabled']);
  if (
    !item['public_jwk'] ||
    typeof item['public_jwk'] !== 'object' ||
    Array.isArray(item['public_jwk'])
  )
    throw new OwnerNoteProposalError('invalid_status');
  const recipient = {
    key_id: id(item['key_id']),
    resource: text(item['resource'], 2048),
    public_jwk: item['public_jwk'] as JsonWebKey,
    enabled: bool(item['enabled']),
  };
  return Object.freeze(recipient);
}
function parseProposal(
  value: unknown,
  owner: string,
  head: OwnerNoteHead,
  grants: Map<string, OwnerNoteGrant>,
): OwnerNoteProposal {
  const item = obj(value);
  exact(item, PROPOSAL_FIELDS);
  if (
    item['storage_version'] !== 2 ||
    item['attribute_id'] !== 'owner_note' ||
    item['destination'] !== 'owner-vault-record' ||
    item['untrusted_content'] !== true
  )
    throw new OwnerNoteProposalError('invalid_status');
  const proposalId = id(item['proposal_id']),
    requestHash = id(item['request_hash']),
    grantId = id(item['grant_id']);
  const state = item['state'];
  if (!['pending', 'approved', 'rejected', 'invalid', 'committed'].includes(String(state)))
    throw new OwnerNoteProposalError('invalid_status');
  const grantRevision = int(item['grant_revision'], 1),
    expiresAt = int(item['expires_at'], 1);
  if (item['created_at'] === undefined || int(item['created_at'], 1) >= expiresAt)
    throw new OwnerNoteProposalError('invalid_status');
  const target = parseRecordNoteTarget(item['target']);
  if (
    target.owner_id !== owner ||
    target.record_id !== 'owner_note' ||
    target.kind !== 'owner_note'
  )
    throw new OwnerNoteProposalError('invalid_status');
  const authority = parseVaultRecordAuthority(item['authority']);
  if (item['target_deleted'] !== 0 && item['target_deleted'] !== 1)
    throw new OwnerNoteProposalError('invalid_status');
  const columnsTarget = parseRecordNoteTarget({
    storage_version: item['storage_version'],
    origin: item['target_origin'],
    owner_id: owner,
    vault_id: item['target_vault_id'],
    collection_id: item['target_collection_id'],
    record_id: item['target_record_id'],
    kind: item['target_kind'],
    revision: item['base_revision'],
    ciphertext_sha256: item['target_ciphertext_sha256'],
    deleted: item['target_deleted'] === 1,
  });
  if (
    !same(target, columnsTarget) ||
    int(item['target_key_generation'], 1) !== authority.key_generation ||
    int(item['target_owner_key_revision'], 1) !== authority.owner_key_revision
  )
    throw new OwnerNoteProposalError('invalid_status');
  const payload = nullableString(item['payload'], 16_384);
  let valueNote: OwnerNote | null = null;
  if (payload !== null) {
    const bytes = new TextEncoder().encode(payload);
    try {
      valueNote = freezeNote(parseOwnerNote(JSON.parse(payload)));
      if (!same(JSON.parse(payload), valueNote)) throw new Error('noncanonical');
    } catch {
      throw new OwnerNoteProposalError('invalid_status');
    } finally {
      bytes.fill(0);
    }
  }
  const grant = grants.get(grantId);
  const targetCurrent = Boolean(same(target, head.target) && same(authority, head.authority));
  const operationId = item['operation_id'] === null ? null : id(item['operation_id']);
  const candidate = nullableString(item['candidate'], 49_152);
  const resultRevision = item['result_revision'] === null ? null : int(item['result_revision'], 1);
  if (
    (operationId === null) !== (candidate === null) ||
    (state === 'committed') !== (resultRevision !== null)
  )
    throw new OwnerNoteProposalError('invalid_status');
  if (candidate !== null) {
    let parsedCandidate: unknown;
    try {
      parsedCandidate = JSON.parse(candidate);
    } catch {
      throw new OwnerNoteProposalError('invalid_status');
    }
    const body = obj(parsedCandidate);
    exact(body, [
      'format_version',
      'vault_id',
      'key_generation',
      'owner_key_revision',
      'kind',
      'revision',
      'ciphertext',
      'key_envelope',
    ]);
    if (
      JSON.stringify(body) !== candidate ||
      body['format_version'] !== 2 ||
      body['vault_id'] !== target.vault_id ||
      body['key_generation'] !== authority.key_generation ||
      body['owner_key_revision'] !== authority.owner_key_revision ||
      body['kind'] !== 'owner_note' ||
      body['revision'] !== target.revision + 1 ||
      typeof body['ciphertext'] !== 'string' ||
      typeof body['key_envelope'] !== 'string'
    )
      throw new OwnerNoteProposalError('invalid_status');
  }
  if (resultRevision !== null && resultRevision !== target.revision + 1)
    throw new OwnerNoteProposalError('invalid_status');
  return Object.freeze({
    proposal_id: proposalId,
    request_hash: requestHash,
    grant_id: grantId,
    grant_revision: grantRevision,
    state: state as OwnerNoteProposal['state'],
    expires_at: expiresAt,
    payload,
    value: valueNote,
    target,
    authority,
    delegate: text(item['delegate']),
    provider: text(item['provider']),
    matchingGrantActive: Boolean(
      grant?.active &&
      grant.revision === grantRevision &&
      grant.expires_at > Math.floor(Date.now() / 1000),
    ),
    targetCurrent,
    operation_id: operationId,
    candidate,
    result_revision: resultRevision,
  });
}

export class OwnerNoteProposals {
  private readonly owner: OwnerVaultController;
  private readonly snapshots = new WeakSet<object>();
  private readonly decisions = new WeakMap<object, DecisionRequest>();
  private readonly commits = new WeakMap<object, CommitRequest>();
  constructor(owner: OwnerVaultController) {
    this.owner = owner;
  }

  private async json(path: string, init?: RequestInit): Promise<unknown> {
    try {
      const response = await this.owner.scope.request(path, { cache: 'no-store', ...init });
      return responseJson(response, 'proposal_unavailable');
    } catch (error) {
      if (error instanceof OwnerNoteProposalError) throw error;
      throw new OwnerNoteProposalError('proposal_unavailable');
    }
  }
  private async readHead(): Promise<OwnerNoteHead> {
    const checkpoint = this.owner.checkpoint(),
      { stored } = this.owner.lease(),
      store = new OwnerRecordStore(this.owner, OWNER_NOTE);
    const head = await store.read();
    this.owner.assertCurrent(checkpoint);
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
            record_id: 'owner_note',
            kind: 'owner_note',
            revision: head.revision,
            ciphertext_sha256: await vaultCiphertextDigest(head.record.ciphertext),
          })
        : null;
    const target = parseRecordNoteTarget({
      storage_version: 2,
      origin: stored.context.origin,
      owner_id: stored.context.ownerId,
      vault_id: stored.context.vaultId,
      collection_id: 'personal',
      record_id: 'owner_note',
      kind: 'owner_note',
      revision: head.revision,
      ciphertext_sha256: source?.ciphertext_sha256 ?? null,
      deleted: head.deleted,
    });
    let value: OwnerNote | null = null;
    if (head.record && !head.deleted) {
      const plaintext = await store.readPlaintext(head);
      try {
        this.owner.assertCurrent(checkpoint);
        value = freezeNote(decodeOwnerNote(plaintext));
      } finally {
        plaintext.fill(0);
      }
    }
    this.owner.assertCurrent(checkpoint);
    return Object.freeze({
      revision: head.revision,
      deleted: head.deleted,
      target,
      source,
      authority,
      record: head.record,
      value,
    });
  }
  async load(): Promise<OwnerNoteProposalSnapshot> {
    const checkpoint = this.owner.checkpoint();
    await this.owner.verifyAuthority();
    this.owner.assertCurrent(checkpoint);
    const firstHead = await this.readHead();
    const statusValue = await this.json('/vault/agents/record-status');
    this.owner.assertCurrent(checkpoint);
    const status = obj(statusValue);
    exact(status, [
      'grants',
      'audit',
      'proposals',
      'drafts',
      'storage_version',
      'record_proposals',
      'recipient',
    ]);
    if (
      status['storage_version'] !== 2 ||
      !Array.isArray(status['grants']) ||
      status['grants'].length > 100 ||
      !Array.isArray(status['record_proposals']) ||
      status['record_proposals'].length > 20
    )
      throw new OwnerNoteProposalError('invalid_status');
    if (
      !Array.isArray(status['audit']) ||
      !Array.isArray(status['proposals']) ||
      !Array.isArray(status['drafts'])
    )
      throw new OwnerNoteProposalError('invalid_status');
    const ownerId = this.owner.scope.identity!.account_id;
    const grants = (status['grants'] as unknown[]).map((grant) => parseGrant(grant, ownerId)),
      grantMap = new Map(grants.map((grant) => [grant.grant_id, grant]));
    if (grantMap.size !== grants.length) throw new OwnerNoteProposalError('invalid_status');
    const recipient = parseRecipient(status['recipient']);
    if ((await agentKeyId(recipient.public_jwk)) !== recipient.key_id)
      throw new OwnerNoteProposalError('invalid_status');
    const head = await this.readHead();
    this.owner.assertCurrent(checkpoint);
    if (!same(firstHead, head)) throw new OwnerNoteProposalError('source_changed');
    const proposals = (status['record_proposals'] as unknown[]).map((proposal) =>
      parseProposal(proposal, ownerId, head, grantMap),
    );
    if (new Set(proposals.map((proposal) => proposal.proposal_id)).size !== proposals.length)
      throw new OwnerNoteProposalError('invalid_status');
    await this.owner.verifyAuthority();
    this.owner.assertCurrent(checkpoint);
    const finalHead = await this.readHead();
    this.owner.assertCurrent(checkpoint);
    if (!same(head, finalHead)) throw new OwnerNoteProposalError('source_changed');
    const snapshot = Object.freeze({
      head,
      grants: Object.freeze(grants),
      recipient,
      proposals: Object.freeze(proposals),
    });
    this.snapshots.add(snapshot);
    return snapshot;
  }
  private async current(snapshot: OwnerNoteProposalSnapshot): Promise<OwnerNoteProposalSnapshot> {
    if (!this.snapshots.has(snapshot)) throw new OwnerNoteProposalError('stale_snapshot');
    const fresh = await this.load();
    if (!same(snapshot, fresh)) throw new OwnerNoteProposalError('stale_snapshot');
    return fresh;
  }
  async prepareDecision(
    snapshot: OwnerNoteProposalSnapshot,
    proposalId: string,
    approve: boolean,
  ): Promise<PreparedOwnerNoteDecision> {
    const fresh = await this.current(snapshot),
      proposal = fresh.proposals.find((entry) => entry.proposal_id === proposalId);
    if (
      !proposal ||
      proposal.state !== 'pending' ||
      !proposal.matchingGrantActive ||
      !proposal.targetCurrent ||
      proposal.expires_at <= Math.floor(Date.now() / 1000)
    )
      throw new OwnerNoteProposalError('proposal_unavailable');
    if (approve && !proposal.payload) throw new OwnerNoteProposalError('proposal_unavailable');
    const operation = Object.freeze({ proposalId, approve });
    this.decisions.set(
      operation,
      Object.freeze({
        body: JSON.stringify({
          proposal_id: proposal.proposal_id,
          request_hash: proposal.request_hash,
          approve,
        }),
        proposalId: proposal.proposal_id,
        requestHash: proposal.request_hash,
        expectedState: approve ? 'approved' : 'rejected',
        target: proposal.target,
        authority: proposal.authority,
        expiresAt: proposal.expires_at,
      }),
    );
    return operation;
  }
  async decide(operation: PreparedOwnerNoteDecision): Promise<OwnerNoteProposalSnapshot> {
    const request = this.decisions.get(operation);
    if (!request) throw new OwnerNoteProposalError('invalid_operation');
    const token = this.owner.checkpoint();
    let receiptValue: unknown;
    try {
      const response = await this.owner.scope.request('/vault/agents/record-decide', {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json' },
        body: request.body,
      });
      receiptValue = await responseJson(response, 'decision_unavailable');
    } catch (error) {
      if (error instanceof OwnerNoteProposalError) throw error;
      throw new OwnerNoteProposalError('decision_unavailable');
    }
    const receipt = obj(receiptValue);
    exact(
      receipt,
      [
        'proposal_id',
        'request_hash',
        'state',
        'target',
        'authority',
        'expires_at',
        'destination',
        'untrusted_content',
      ],
      'invalid_acknowledgement',
    );
    if (
      receipt['proposal_id'] !== request.proposalId ||
      receipt['request_hash'] !== request.requestHash ||
      receipt['state'] !== request.expectedState ||
      !same(parseRecordNoteTarget(receipt['target']), request.target) ||
      !same(parseVaultRecordAuthority(receipt['authority']), request.authority) ||
      receipt['expires_at'] !== request.expiresAt ||
      receipt['destination'] !== 'owner-vault-record' ||
      receipt['untrusted_content'] !== true
    )
      throw new OwnerNoteProposalError('invalid_acknowledgement');
    this.owner.assertCurrent(token);
    return this.load();
  }
  async prepareCommit(
    snapshot: OwnerNoteProposalSnapshot,
    proposalId: string,
  ): Promise<PreparedOwnerNoteCommit> {
    const fresh = await this.current(snapshot),
      proposal = fresh.proposals.find((entry) => entry.proposal_id === proposalId);
    if (
      !proposal ||
      proposal.state !== 'approved' ||
      !proposal.payload ||
      !proposal.matchingGrantActive ||
      !proposal.targetCurrent ||
      proposal.expires_at <= Math.floor(Date.now() / 1000)
    )
      throw new OwnerNoteProposalError('proposal_unavailable');
    if (proposal.operation_id !== null || proposal.candidate !== null)
      throw new OwnerNoteProposalError('prepared_operation_exists');
    const grant = fresh.grants.find((entry) => entry.grant_id === proposal.grant_id)!;
    if (
      !grant.active ||
      grant.revision !== proposal.grant_revision ||
      grant.recipient_key_id !== fresh.recipient.key_id ||
      grant.resource !== fresh.recipient.resource ||
      !fresh.recipient.enabled
    )
      throw new OwnerNoteProposalError('grant_unavailable');
    const approved = parseApprovedRecordNote({
      proposal_id: proposal.proposal_id,
      request_hash: proposal.request_hash,
      grant_id: proposal.grant_id,
      payload: proposal.payload,
      expires_at: proposal.expires_at,
      target: proposal.target,
      authority: proposal.authority,
    });
    const checkpoint = this.owner.checkpoint(),
      { session, stored } = this.owner.lease();
    await this.owner.verifyAuthority();
    this.owner.assertCurrent(checkpoint);
    const operationId = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const sealed = await session.sealApprovedNote(approved, operationId, {
      key_id: fresh.recipient.key_id,
      public_jwk: fresh.recipient.public_jwk,
      resource: fresh.recipient.resource,
      enabled: fresh.recipient.enabled,
    });
    this.owner.assertCurrent(checkpoint);
    const head = await this.readHead();
    if (!same(head, fresh.head) || stored.context.ownerId !== this.owner.scope.identity!.account_id)
      throw new OwnerNoteProposalError('source_changed');
    const preparedBody = JSON.stringify({
      proposal_id: sealed.proposal_id,
      request_hash: sealed.request_hash,
      operation_id: sealed.operation_id,
      candidate: sealed.candidate,
      proof: sealed.proof,
    });
    const operation = Object.freeze({ proposalId, operationId });
    this.commits.set(operation, {
      preparedBody,
      candidate: sealed.candidate,
      proof: sealed.proof,
      requestHash: sealed.request_hash,
      target: proposal.target,
      expectedRevision: proposal.target.revision,
      expectedHead: head,
      prepareAcknowledged: false,
    });
    return operation;
  }
  async recoverCommit(
    snapshot: OwnerNoteProposalSnapshot,
    proposalId: string,
  ): Promise<PreparedOwnerNoteCommit> {
    const fresh = await this.current(snapshot),
      proposal = fresh.proposals.find((entry) => entry.proposal_id === proposalId);
    if (
      !proposal ||
      proposal.state !== 'approved' ||
      !proposal.payload ||
      !proposal.operation_id ||
      !proposal.candidate ||
      !proposal.matchingGrantActive ||
      !proposal.targetCurrent ||
      proposal.expires_at <= Math.floor(Date.now() / 1000)
    )
      throw new OwnerNoteProposalError('recovery_unavailable');
    const checkpoint = this.owner.checkpoint(),
      { session } = this.owner.lease();
    await this.owner.verifyAuthority();
    this.owner.assertCurrent(checkpoint);
    const candidate = JSON.parse(proposal.candidate) as {
      vault_id: string;
      revision: number;
      ciphertext: string;
      key_envelope: string;
    };
    const plaintext = await session.open(
      { format_version: 2, ciphertext: candidate.ciphertext, key_envelope: candidate.key_envelope },
      {
        collectionId: 'personal',
        recordId: 'owner_note',
        kind: 'owner_note',
        revision: candidate.revision,
      },
    );
    const expected = new TextEncoder().encode(proposal.payload);
    try {
      this.owner.assertCurrent(checkpoint);
      if (
        plaintext.length !== expected.length ||
        plaintext.some((byte, index) => byte !== expected[index])
      )
        throw new OwnerNoteProposalError('recovery_candidate_mismatch');
    } finally {
      plaintext.fill(0);
      expected.fill(0);
    }
    const head = await this.readHead();
    this.owner.assertCurrent(checkpoint);
    if (!same(head, fresh.head)) throw new OwnerNoteProposalError('source_changed');
    const operation = Object.freeze({ proposalId, operationId: proposal.operation_id });
    this.commits.set(operation, {
      preparedBody: '',
      candidate: proposal.candidate,
      proof: null,
      requestHash: proposal.request_hash,
      target: proposal.target,
      expectedRevision: proposal.target.revision,
      expectedHead: head,
      prepareAcknowledged: true,
    });
    return operation;
  }
  async commit(operation: PreparedOwnerNoteCommit): Promise<OwnerNoteProposalSnapshot> {
    const request = this.commits.get(operation);
    if (!request) throw new OwnerNoteProposalError('invalid_operation');
    const token = this.owner.checkpoint();
    if (!request.prepareAcknowledged) {
      let preparedValue: ObjectValue;
      try {
        const prepared = await this.owner.scope.request('/vault/agents/record-prepare', {
          method: 'POST',
          cache: 'no-store',
          headers: { 'Content-Type': 'application/json' },
          body: request.preparedBody,
        });
        preparedValue = obj(await responseJson(prepared, 'prepare_unavailable'));
      } catch (error) {
        if (error instanceof OwnerNoteProposalError) throw error;
        throw new OwnerNoteProposalError('prepare_unavailable');
      }
      exact(preparedValue, ['proposal_id', 'operation_id', 'candidate_sha256']);
      const candidateHash = encodeBase64Url(
        new Uint8Array(
          await crypto.subtle.digest('SHA-256', new TextEncoder().encode(request.candidate)),
        ),
      );
      if (
        preparedValue['proposal_id'] !== operation.proposalId ||
        preparedValue['operation_id'] !== operation.operationId ||
        preparedValue['candidate_sha256'] !== candidateHash
      )
        throw new OwnerNoteProposalError('invalid_acknowledgement');
      this.owner.assertCurrent(token);
      request.prepareAcknowledged = true;
    }
    const headers = new Headers({
      'Content-Type': 'application/json',
      'X-Operation-ID': operation.operationId,
      'X-Attribute-Proposal': operation.proposalId,
      'X-Proposal-Hash': request.requestHash,
    });
    if (request.expectedRevision === 0) headers.set('If-None-Match', '*');
    else headers.set('If-Match', `"${request.expectedRevision}"`);
    let commitReceipt: ObjectValue;
    try {
      const commit = await this.owner.scope.request('/vault/records/personal/owner_note/approved', {
        method: 'POST',
        cache: 'no-store',
        headers,
        body: request.candidate,
      });
      commitReceipt = obj(await responseJson(commit, 'commit_unavailable'));
    } catch (error) {
      if (error instanceof OwnerNoteProposalError) throw error;
      throw new OwnerNoteProposalError('commit_unavailable');
    }
    const receipt = commitReceipt;
    if (
      Object.keys(receipt).length !== 2 ||
      receipt['revision'] !== request.expectedRevision + 1 ||
      receipt['deleted'] !== false
    )
      throw new OwnerNoteProposalError('invalid_acknowledgement');
    this.owner.assertCurrent(token);
    // The receipt acknowledges this exact historical operation only. Another tab
    // may already have advanced the head, so report freshly loaded truth without
    // requiring this candidate to remain current.
    return this.load();
  }
}
