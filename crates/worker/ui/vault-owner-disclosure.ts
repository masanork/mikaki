// Preparation only. No network grant, recipient authority or owner-key export is created here.
import type { OwnerVaultController } from './vault-owner-controller.ts';
import {
  OwnerRecordStore,
  OWNER_NAME,
  OWNER_NOTE,
  type OwnerRecordHead,
} from './vault-owner-record-store.ts';
import { decodeOwnerNote } from './vault-note.ts';
import { encodeBase64Url } from './vault-crypto.ts';
import type { AgentRecipient, AgentDocument } from './agent-crypto.ts';
import { sealRecordAgentSnapshot, type RecordAgentEnvelope } from './agent-record-crypto.ts';
import {
  parseVaultRecordSource,
  parseVaultRecordAuthority,
  vaultCiphertextDigest,
  type VaultRecordSource,
  type VaultRecordAuthority,
} from './vault-record-source.ts';

export type DisclosureRecord = 'name' | 'owner_note';
type Selected = Readonly<{
  store: OwnerRecordStore;
  head: OwnerRecordHead;
  source: VaultRecordSource;
  authority: VaultRecordAuthority;
  document: Readonly<AgentDocument>;
}>;
export type PreparedLocalRecordExport = Readonly<{
  id: string;
  bundle: string;
  grant: string;
  expires_at: number;
  sources: readonly Readonly<{ source: VaultRecordSource; authority: VaultRecordAuthority }>[];
}>;
export type PreparedRecordSnapshot = Readonly<{
  source: VaultRecordSource;
  authority: VaultRecordAuthority;
  document_id: DisclosureRecord;
  envelope: RecordAgentEnvelope;
}>;

export class OwnerRecordDisclosure {
  private readonly owner: OwnerVaultController;
  private readonly clock: () => number;
  constructor(
    owner: OwnerVaultController,
    clock: () => number = () => Math.floor(Date.now() / 1000),
  ) {
    this.owner = owner;
    this.clock = clock;
  }
  private async selected(target: DisclosureRecord, token: number): Promise<Selected> {
    if (target !== 'name' && target !== 'owner_note')
      throw new Error('Unsupported selected record');
    const store = new OwnerRecordStore(this.owner, target === 'name' ? OWNER_NAME : OWNER_NOTE);
    const { stored } = this.owner.lease();
    const authority = parseVaultRecordAuthority({
      key_generation: stored.context.keyGeneration,
      owner_key_revision: stored.revision,
    });
    const head = await store.read();
    this.owner.assertCurrent(token);
    if (!head.record || head.deleted) throw new Error('Selected record unavailable');
    const source = parseVaultRecordSource({
      storage_version: 2,
      origin: stored.context.origin,
      owner_id: stored.context.ownerId,
      vault_id: stored.context.vaultId,
      collection_id: store.target.collectionId,
      record_id: store.target.recordId,
      kind: store.target.kind,
      revision: head.revision,
      ciphertext_sha256: await vaultCiphertextDigest(head.record.ciphertext),
    });
    this.owner.assertCurrent(token);
    const bytes = await store.readPlaintext(head);
    try {
      const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
      if (target === 'owner_note') decodeOwnerNote(bytes);
      else if (!text.length || text.length > 256) throw new Error('Invalid saved name');
      this.owner.assertCurrent(token);
      return Object.freeze({
        store,
        head,
        source,
        authority,
        document: Object.freeze({
          id: target,
          title: target === 'name' ? 'Saved name' : 'Saved owner note',
          source: `vault-record:${target}:${head.revision}`,
          text,
        }),
      });
    } finally {
      bytes.fill(0);
    }
  }
  private async confirm(selected: readonly Selected[], token: number): Promise<void> {
    // A read is an observation, not a perpetual freshness claim. Never replace a
    // selected source with a different current head or silently reseal a retry.
    for (const item of selected) {
      const fresh = await item.store.read();
      this.owner.assertCurrent(token);
      if (JSON.stringify(fresh) !== JSON.stringify(item.head))
        throw new Error('Selected source changed');
    }
    await this.owner.verifyAuthority();
    this.owner.assertCurrent(token);
  }
  async prepareLocalExport(
    selection: readonly DisclosureRecord[],
    options: Readonly<{ delegate: string; service: string; ttl: number }>,
  ): Promise<PreparedLocalRecordExport> {
    const token = this.owner.checkpoint();
    const targets = [...selection];
    const { delegate, service, ttl } = options;
    if (
      targets.length < 1 ||
      targets.length > 2 ||
      new Set(targets).size !== targets.length ||
      !/^[A-Za-z0-9_-]{1,80}$/.test(delegate) ||
      !service.trim() ||
      service.length > 160 ||
      !Number.isSafeInteger(ttl) ||
      ttl < 60 ||
      ttl > 86400
    )
      throw new Error('Invalid export selection');
    const selected: Selected[] = [];
    try {
      for (const target of targets) selected.push(await this.selected(target, token));
      await this.confirm(selected, token);
      const start = this.clock();
      if (!Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(start + ttl))
        throw new Error('Invalid export time');
      const documents = selected.map((item) => ({
        ...item.document,
        source_info: {
          kind: 'vault-record',
          source: item.source,
          authority: item.authority,
          provenance: 'self-asserted',
          confirmed_at: start,
        },
      }));
      const bundle = JSON.stringify({
        version: 2,
        owner: selected[0]!.source.owner_id,
        collection: 'vault-records',
        documents,
      });
      const bundleBytes = new TextEncoder().encode(bundle);
      let digest: Uint8Array<ArrayBuffer>;
      try {
        digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bundleBytes));
      } finally {
        bundleBytes.fill(0);
      }
      await this.confirm(selected, token);
      if (this.clock() < start || this.clock() >= start + ttl)
        throw new Error('Export expired during preparation');
      const id = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
      const sources = Object.freeze(
        selected.map(({ source, authority }) => Object.freeze({ source, authority })),
      );
      const grant = JSON.stringify({
        version: 2,
        id,
        owner: selected[0]!.source.owner_id,
        collection: 'vault-records',
        delegate,
        service,
        export_sha256: Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join(''),
        document_ids: documents.map((document) => document.id),
        sources,
        operations: ['list', 'search', 'read'],
        not_before: start,
        expires_at: start + ttl,
        revoked: false,
      });
      this.owner.assertCurrent(token);
      return Object.freeze({ id, bundle, grant, expires_at: start + ttl, sources });
    } finally {
      // Strings in the explicitly returned copy cannot be reliably erased. Do
      // not retain a second plaintext/snapshot cache on this controller.
      selected.length = 0;
    }
  }
  async prepareSnapshot(
    target: DisclosureRecord,
    recipient: AgentRecipient,
    options: Readonly<{ grant_id: string; expires_at: number }>,
  ): Promise<PreparedRecordSnapshot> {
    const token = this.owner.checkpoint();
    const { grant_id, expires_at } = options;
    const destination = { ...recipient, public_jwk: { ...recipient.public_jwk } };
    if (destination.enabled === false) throw new Error('Recipient disabled');
    const time = this.clock();
    if (
      !Number.isSafeInteger(time) ||
      !Number.isSafeInteger(expires_at) ||
      expires_at < time + 60 ||
      expires_at > time + 86400
    )
      throw new Error('Invalid snapshot expiry');
    const selected = await this.selected(target, token);
    const envelope = await sealRecordAgentSnapshot([selected.document], destination, {
      owner: selected.source.owner_id,
      grant_id,
      key_id: destination.key_id,
      resource: destination.resource,
      expires_at,
      source: selected.source,
      authority: selected.authority,
    });
    this.owner.assertCurrent(token);
    await this.confirm([selected], token);
    if (this.clock() < time || this.clock() >= expires_at)
      throw new Error('Snapshot expired during preparation');
    return Object.freeze({
      source: selected.source,
      authority: selected.authority,
      document_id: target,
      envelope,
    });
  }
}
