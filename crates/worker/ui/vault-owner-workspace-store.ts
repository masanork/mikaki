import { encodeBase64Url } from './vault-crypto.ts';
import type { OwnerRecord, OwnerRecordContext } from './vault-owner-crypto.ts';
import type { OwnerKeySession } from './vault-owner-session.ts';
import type { StoredOwnerKey } from './vault-owner-store.ts';
import type { VaultScope } from './vault-lifecycle.ts';

export type OwnerRecordHead = {
  record_id: string;
  kind: string;
  revision: number;
  deleted: boolean;
};
export type PreparedOwnerWrite = Readonly<{
  endpoint: string;
  method: 'PUT' | 'DELETE';
  body: string;
  operation: string;
  previousRevision: number;
  revision: number;
}>;
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('invalid record response');
  return value as Record<string, unknown>;
}
function identifier(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
}
function revision(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}
export class OwnerRecordStore {
  constructor(
    private readonly scope: VaultScope,
    private readonly session: OwnerKeySession,
    private readonly root: StoredOwnerKey,
  ) {}
  private check(value: unknown, collection: string): Record<string, unknown> {
    const v = object(value),
      c = this.root.context;
    if (
      v['format_version'] !== 2 ||
      v['owner_id'] !== c.ownerId ||
      v['origin'] !== c.origin ||
      v['vault_id'] !== c.vaultId ||
      v['key_generation'] !== c.keyGeneration ||
      v['owner_key_revision'] !== this.root.revision ||
      v['collection_id'] !== collection
    )
      throw new Error('record context changed');
    this.scope.assert();
    if (!this.session.opened) throw new Error('owner key locked');
    return v;
  }
  private endpoint(collection: string, id?: string): string {
    if (!identifier(collection) || (id !== undefined && !identifier(id)))
      throw new Error('invalid record target');
    return `/vault/records/${collection}${id === undefined ? '' : `/${id}`}`;
  }
  async list(collection: string): Promise<OwnerRecordHead[]> {
    const heads: OwnerRecordHead[] = [],
      seen = new Set<string>();
    let after: string | null = null;
    for (let page = 0; page < 6; page++) {
      const response = await this.scope.request(
        this.endpoint(collection) + (after ? `?after=${after}` : ''),
        { cache: 'no-store' },
      );
      if (!response.ok) throw new Error('record list unavailable');
      const value = this.check(await response.json(), collection);
      if (!Array.isArray(value['records'])) throw new Error('invalid record list');
      for (const entry of value['records']) {
        const v = object(entry);
        if (
          !identifier(v['record_id']) ||
          !identifier(v['kind']) ||
          !revision(v['revision']) ||
          typeof v['deleted'] !== 'boolean' ||
          v['key_generation'] !== this.root.context.keyGeneration ||
          seen.has(v['record_id'])
        )
          throw new Error('invalid record head');
        seen.add(v['record_id']);
        heads.push({
          record_id: v['record_id'],
          kind: v['kind'],
          revision: v['revision'],
          deleted: v['deleted'],
        });
      }
      const next = value['next_cursor'];
      if (next === null) return heads;
      if (!identifier(next) || next === after || next !== heads.at(-1)?.record_id)
        throw new Error('invalid record cursor');
      after = next;
    }
    throw new Error('record list limit exceeded');
  }
  async read(
    collection: string,
    id: string,
    kind: string,
  ): Promise<{ revision: number; plaintext: Uint8Array<ArrayBuffer> | null }> {
    const response = await this.scope.request(this.endpoint(collection, id), { cache: 'no-store' });
    if (response.status === 404) {
      const value = object(await response.json());
      if (value['error'] !== 'not_found') throw new Error('record unavailable');
      const etag = response.headers.get('etag');
      if (etag === null && value['deleted'] !== true) return { revision: 0, plaintext: null };
      const match = /^"([1-9][0-9]*)"$/.exec(etag ?? '');
      const n = Number(match?.[1]);
      if (!match || !revision(n) || value['deleted'] !== true) throw new Error('invalid tombstone');
      return { revision: n, plaintext: null };
    }
    if (!response.ok) throw new Error('record unavailable');
    const value = this.check(await response.json(), collection);
    if (
      value['record_id'] !== id ||
      value['kind'] !== kind ||
      !revision(value['revision']) ||
      response.headers.get('etag') !== `"${value['revision']}"` ||
      typeof value['ciphertext'] !== 'string' ||
      typeof value['key_envelope'] !== 'string'
    )
      throw new Error('invalid record response');
    const item = { collectionId: collection, recordId: id, kind, revision: value['revision'] };
    const record: OwnerRecord = {
      format_version: 2,
      ciphertext: value['ciphertext'],
      key_envelope: value['key_envelope'],
    };
    return { revision: item.revision, plaintext: await this.session.open(record, item) };
  }
  async prepare(
    collection: string,
    id: string,
    kind: string,
    previousRevision: number,
    plaintext: Uint8Array<ArrayBuffer> | null,
  ): Promise<PreparedOwnerWrite> {
    if (
      !Number.isSafeInteger(previousRevision) ||
      previousRevision < 0 ||
      previousRevision >= Number.MAX_SAFE_INTEGER ||
      !identifier(kind) ||
      (!plaintext && previousRevision === 0)
    )
      throw new Error('invalid write');
    const endpoint = this.endpoint(collection, id),
      next = previousRevision + 1;
    const item: OwnerRecordContext = {
      collectionId: collection,
      recordId: id,
      kind,
      revision: next,
    };
    const sealed = plaintext ? await this.session.seal(plaintext, item) : null;
    this.scope.assert();
    if (!this.session.opened) throw new Error('owner key locked');
    return Object.freeze({
      endpoint,
      method: plaintext ? 'PUT' : 'DELETE',
      body: JSON.stringify({
        format_version: 2,
        vault_id: this.root.context.vaultId,
        key_generation: this.root.context.keyGeneration,
        owner_key_revision: this.root.revision,
        kind,
        revision: next,
        ...sealed,
      }),
      operation: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
      previousRevision,
      revision: next,
    });
  }
  async commit(write: PreparedOwnerWrite): Promise<void> {
    this.scope.assert();
    if (!this.session.opened) throw new Error('owner key locked');
    const response = await this.scope.request(write.endpoint, {
      method: write.method,
      headers: {
        'Content-Type': 'application/json',
        'X-Operation-ID': write.operation,
        [write.previousRevision === 0 ? 'If-None-Match' : 'If-Match']:
          write.previousRevision === 0 ? '*' : `"${write.previousRevision}"`,
      },
      body: write.body,
    });
    if (response.status === 409) throw new Error('record conflict');
    if (!response.ok) throw new Error('record write unconfirmed');
    const value = object(await response.json());
    if (
      value['revision'] !== write.revision ||
      value['deleted'] !== (write.method === 'DELETE') ||
      response.headers.get('etag') !== `"${write.revision}"`
    )
      throw new Error('record write unconfirmed');
    this.scope.assert();
  }
}
