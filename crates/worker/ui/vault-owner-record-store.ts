import { encodeBase64Url } from './vault-crypto.ts';
import type { OwnerRecord } from './vault-owner-crypto.ts';
import type { OwnerVaultController } from './vault-owner-controller.ts';

export type OwnerRecordTarget = Readonly<{ collectionId: string; recordId: string; kind: string }>;
export const OWNER_NAME: OwnerRecordTarget = Object.freeze({
  collectionId: 'personal',
  recordId: 'name',
  kind: 'name',
});
export const OWNER_NOTE: OwnerRecordTarget = Object.freeze({
  collectionId: 'personal',
  recordId: 'owner_note',
  kind: 'owner_note',
});
export type OwnerRecordHead = Readonly<{
  revision: number;
  deleted: boolean;
  record: OwnerRecord | null;
}>;
export type PreparedOwnerMutation = Readonly<{
  method: 'PUT' | 'DELETE';
  expectedRevision: number;
  operationId: string;
  body: string;
}>;
export class OwnerRecordError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new OwnerRecordError('invalid_record');
  return value as Record<string, unknown>;
}
function revision(response: Response): number {
  const match = /^"([1-9][0-9]*)"$/.exec(response.headers.get('etag') ?? '');
  if (!match || !Number.isSafeInteger(Number(match[1])))
    throw new OwnerRecordError('invalid_record');
  return Number(match[1]);
}
export class OwnerRecordStore {
  readonly target: OwnerRecordTarget;
  private readonly endpoint: string;
  private readonly prepared = new WeakSet<PreparedOwnerMutation>();
  private readonly owner: OwnerVaultController;
  constructor(owner: OwnerVaultController, target: OwnerRecordTarget) {
    this.owner = owner;
    for (const value of Object.values(target))
      if (!/^[A-Za-z0-9_-]{1,128}$/.test(value)) throw new Error('invalid target');
    this.target = Object.freeze({ ...target });
    this.endpoint = `/vault/records/${target.collectionId}/${target.recordId}`;
  }
  private authorityChanged(): never {
    this.owner.lock('unconfirmed');
    throw new OwnerRecordError('owner_key_changed');
  }
  private async failure(response: Response): Promise<never> {
    let code = 'storage_unavailable';
    try {
      const value = object(await response.json());
      if (typeof value['error'] === 'string') code = value['error'];
    } catch {
      /* Fail closed on malformed errors. */
    }
    if (code === 'owner_key_changed' || code === 'owner_key_unavailable') this.authorityChanged();
    // A concurrent head read may fail without revoking the owner's lease.
    // Recheck the root before keeping other drafts and plaintext available.
    if (code === 'record_changed') await this.owner.verifyAuthority();
    throw new OwnerRecordError(code);
  }
  async read(): Promise<OwnerRecordHead> {
    const token = this.owner.checkpoint(),
      { stored } = this.owner.lease();
    const response = await this.owner.scope.request(this.endpoint, { cache: 'no-store' });
    if (response.status !== 404 && !response.ok) return this.failure(response);
    const value = object(await response.json());
    this.owner.assertCurrent(token);
    if (response.status === 404) {
      if (value['error'] !== 'not_found') throw new OwnerRecordError('invalid_record');
      if (value['deleted'] === true)
        return Object.freeze({ revision: revision(response), deleted: true, record: null });
      if (Object.keys(value).length !== 1 || response.headers.has('etag'))
        throw new OwnerRecordError('invalid_record');
      return Object.freeze({ revision: 0, deleted: false, record: null });
    }
    const c = stored.context;
    if (
      value['owner_id'] !== c.ownerId ||
      value['origin'] !== c.origin ||
      value['vault_id'] !== c.vaultId ||
      value['key_generation'] !== c.keyGeneration ||
      value['owner_key_revision'] !== stored.revision
    )
      this.authorityChanged();
    const headRevision = revision(response);
    if (
      value['format_version'] !== 2 ||
      value['collection_id'] !== this.target.collectionId ||
      value['record_id'] !== this.target.recordId ||
      value['kind'] !== this.target.kind ||
      value['revision'] !== headRevision ||
      typeof value['ciphertext'] !== 'string' ||
      typeof value['key_envelope'] !== 'string'
    )
      throw new OwnerRecordError('invalid_record');
    return Object.freeze({
      revision: headRevision,
      deleted: false,
      record: Object.freeze({
        format_version: 2 as const,
        ciphertext: value['ciphertext'],
        key_envelope: value['key_envelope'],
      }),
    });
  }
  async readPlaintext(head: OwnerRecordHead): Promise<Uint8Array<ArrayBuffer>> {
    const token = this.owner.checkpoint();
    if (!head.record || head.deleted) throw new OwnerRecordError('not_found');
    const bytes = await this.owner
      .lease()
      .session.open(head.record, { ...this.target, revision: head.revision });
    try {
      this.owner.assertCurrent(token);
      return bytes;
    } catch (error) {
      bytes.fill(0);
      throw error;
    }
  }
  async prepare(
    method: 'PUT' | 'DELETE',
    expectedRevision: number,
    plaintext?: Uint8Array<ArrayBuffer>,
  ): Promise<PreparedOwnerMutation> {
    const token = this.owner.checkpoint(),
      { session, stored } = this.owner.lease();
    if (
      !Number.isSafeInteger(expectedRevision) ||
      expectedRevision < 0 ||
      expectedRevision >= Number.MAX_SAFE_INTEGER ||
      (method === 'DELETE' && expectedRevision === 0)
    )
      throw new OwnerRecordError('invalid_record');
    const context = {
      format_version: 2 as const,
      vault_id: stored.context.vaultId,
      key_generation: stored.context.keyGeneration,
      owner_key_revision: stored.revision,
      kind: this.target.kind,
      revision: expectedRevision + 1,
    };
    let record: OwnerRecord | undefined;
    if (method === 'PUT') {
      if (!plaintext) throw new OwnerRecordError('invalid_record');
      record = await session.seal(plaintext, { ...this.target, revision: context.revision });
    }
    this.owner.assertCurrent(token);
    const operation = Object.freeze({
      method,
      expectedRevision,
      operationId: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
      body: JSON.stringify({
        ...context,
        ...(record ? { ciphertext: record.ciphertext, key_envelope: record.key_envelope } : {}),
      }),
    });
    this.prepared.add(operation);
    return operation;
  }
  async commit(operation: PreparedOwnerMutation): Promise<{ revision: number; deleted: boolean }> {
    const token = this.owner.checkpoint();
    this.owner.lease();
    if (!this.prepared.has(operation)) throw new OwnerRecordError('invalid_operation');
    const response = await this.owner.scope.request(this.endpoint, {
      method: operation.method,
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        'X-Operation-ID': operation.operationId,
        ...(operation.expectedRevision === 0
          ? { 'If-None-Match': '*' }
          : { 'If-Match': `"${operation.expectedRevision}"` }),
      },
      body: operation.body,
    });
    if (!response.ok) return this.failure(response);
    const value = object(await response.json());
    this.owner.assertCurrent(token);
    if (
      value['revision'] !== operation.expectedRevision + 1 ||
      value['revision'] !== revision(response) ||
      value['deleted'] !== (operation.method === 'DELETE')
    )
      throw new OwnerRecordError('invalid_record');
    return { revision: value['revision'] as number, deleted: value['deleted'] as boolean };
  }
}
