import type { OwnerVaultController } from './vault-owner-controller.ts';
import { OwnerRecordStore, type PreparedOwnerMutation } from './vault-owner-record-store.ts';

export type OwnerRecordHead = {
  record_id: string;
  kind: string;
  revision: number;
  deleted: boolean;
};
export type PreparedOwnerWrite = Readonly<{
  store: OwnerRecordStore;
  mutation: PreparedOwnerMutation;
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
// Collection discovery for the archive UI; all record crypto, root fences and exact
// mutation retries use the canonical store shared with the name/note preview.
export class OwnerWorkspaceStore {
  constructor(private readonly owner: OwnerVaultController) {}
  private check(value: unknown, collection: string): Record<string, unknown> {
    const v = object(value),
      root = this.owner.lease().stored,
      c = root.context;
    if (
      v['format_version'] !== 2 ||
      v['owner_id'] !== c.ownerId ||
      v['origin'] !== c.origin ||
      v['vault_id'] !== c.vaultId ||
      v['key_generation'] !== c.keyGeneration ||
      v['owner_key_revision'] !== root.revision
    ) {
      this.owner.lock('unconfirmed');
      throw new Error('record context changed');
    }
    if (v['collection_id'] !== collection) throw new Error('invalid record collection');
    return v;
  }
  private endpoint(collection: string, id?: string): string {
    if (!identifier(collection) || (id !== undefined && !identifier(id)))
      throw new Error('invalid record target');
    return `/vault/records/${collection}${id === undefined ? '' : `/${id}`}`;
  }
  async list(collection: string): Promise<OwnerRecordHead[]> {
    const token = this.owner.checkpoint();
    const heads: OwnerRecordHead[] = [],
      seen = new Set<string>();
    let after: string | null = null;
    for (let page = 0; page < 6; page++) {
      const response = await this.owner.scope.request(
        this.endpoint(collection) + (after ? `?after=${after}` : ''),
        { cache: 'no-store' },
      );
      if (!response.ok) throw new Error('record list unavailable');
      const raw: unknown = await response.json();
      this.owner.assertCurrent(token);
      const value = this.check(raw, collection);
      if (!Array.isArray(value['records'])) throw new Error('invalid record list');
      for (const entry of value['records']) {
        const v = object(entry);
        if (
          !identifier(v['record_id']) ||
          !identifier(v['kind']) ||
          !revision(v['revision']) ||
          typeof v['deleted'] !== 'boolean' ||
          v['key_generation'] !== this.owner.lease().stored.context.keyGeneration ||
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
  private record(collectionId: string, recordId: string, kind: string): OwnerRecordStore {
    return new OwnerRecordStore(this.owner, { collectionId, recordId, kind });
  }
  async read(
    collection: string,
    id: string,
    kind: string,
  ): Promise<{ revision: number; plaintext: Uint8Array<ArrayBuffer> | null }> {
    const store = this.record(collection, id, kind),
      head = await store.read();
    return {
      revision: head.revision,
      plaintext: head.record ? await store.readPlaintext(head) : null,
    };
  }
  async prepare(
    collection: string,
    id: string,
    kind: string,
    previousRevision: number,
    plaintext: Uint8Array<ArrayBuffer> | null,
  ): Promise<PreparedOwnerWrite> {
    const store = this.record(collection, id, kind);
    const mutation = await store.prepare(
      plaintext ? 'PUT' : 'DELETE',
      previousRevision,
      plaintext ?? undefined,
    );
    return Object.freeze({ store, mutation });
  }
  async commit(write: PreparedOwnerWrite): Promise<void> {
    await write.store.commit(write.mutation);
  }
}
