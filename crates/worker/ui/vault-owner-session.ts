// Candidate owner-key lease. No production caller yet; never persists secrets.
import { VaultScope } from './vault-lifecycle.ts';
import { decodeBase64Url, encodeBase64Url } from './vault-crypto.ts';
import {
  openOwnerKey,
  createOwnerKey,
  openOwnerRecord,
  ownerKeyContext,
  parseOwnerKeyEnvelope,
  sealOwnerRecord,
  type OwnerKeyContext,
  type OwnerKeyEnvelope,
  type OwnerRecord,
  type OwnerRecordContext,
} from './vault-owner-crypto.ts';

type Bytes = Uint8Array<ArrayBuffer>;
export type OwnerPrfEvaluator = (
  credential: Bytes,
  input: Bytes,
  signal: AbortSignal,
) => Promise<{ credentialId: Bytes; output: Bytes }>;
export class OwnerKeySession {
  private key: CryptoKey | null = null;
  private generation = 0;
  private pending = false;
  private suspended = false;
  private disposed = false;
  private readonly context: OwnerKeyContext;
  private readonly identity: string;
  private readonly scope: VaultScope;
  private readonly visible: () => boolean;
  private readonly clear = () => {
    this.generation++;
    this.key = null;
  };
  constructor(
    scope: VaultScope,
    context: OwnerKeyContext,
    visible: () => boolean = () =>
      typeof document === 'undefined' || document.visibilityState === 'visible',
  ) {
    this.scope = scope;
    this.visible = visible;
    this.context = ownerKeyContext(context);
    scope.assert();
    if (!scope.identity || scope.identity.account_id !== this.context.ownerId)
      throw new Error('owner identity required');
    this.identity = JSON.stringify(scope.identity);
    scope.signal.addEventListener('abort', this.clear, { once: true });
  }
  private assert(): void {
    this.scope.assert();
    if (JSON.stringify(this.scope.identity) !== this.identity) {
      this.scope.end('session');
      throw new Error('session changed');
    }
    if (this.disposed || this.suspended || !this.visible())
      throw new DOMException('Owner Vault unavailable', 'AbortError');
  }
  get opened(): boolean {
    try {
      this.assert();
      return this.key !== null;
    } catch {
      return false;
    }
  }
  async unlock(value: unknown, evaluate: OwnerPrfEvaluator): Promise<void> {
    this.assert();
    if (this.pending) throw new Error('unlock pending');
    if (this.key) return;
    const envelope = parseOwnerKeyEnvelope(value);
    if (envelope.credential_id !== this.scope.identity?.credential_id)
      throw new Error('credential not bound to session');
    this.pending = true;
    const generation = this.generation;
    let output: Bytes | undefined;
    try {
      await this.scope.ensure();
      this.assert();
      const result = await evaluate(
        decodeBase64Url(envelope.credential_id),
        decodeBase64Url(envelope.prf_input),
        this.scope.signal,
      );
      output = result.output;
      this.assert();
      if (
        generation !== this.generation ||
        encodeBase64Url(result.credentialId) !== envelope.credential_id
      )
        throw new Error('stale/wrong credential');
      const key = await openOwnerKey(envelope, this.context, result.credentialId, output);
      this.assert();
      if (generation !== this.generation) throw new Error('stale unlock');
      this.key = key;
    } finally {
      output?.fill(0);
      this.pending = false;
    }
  }
  async initialize(evaluate: OwnerPrfEvaluator): Promise<OwnerKeyEnvelope> {
    this.assert();
    if (this.pending || this.key) throw new Error('owner key already open/pending');
    const credential = decodeBase64Url(this.scope.identity!.credential_id);
    const input = crypto.getRandomValues(new Uint8Array(32));
    const generation = this.generation;
    this.pending = true;
    let output: Bytes | undefined;
    try {
      await this.scope.ensure();
      this.assert();
      const result = await evaluate(credential, input, this.scope.signal);
      output = result.output;
      this.assert();
      if (
        generation !== this.generation ||
        encodeBase64Url(result.credentialId) !== encodeBase64Url(credential)
      )
        throw new Error('stale/wrong credential');
      const created = await createOwnerKey(this.context, credential, input, output);
      this.assert();
      if (generation !== this.generation) throw new Error('stale initialization');
      this.key = created.key;
      return created.envelope;
    } finally {
      output?.fill(0);
      this.pending = false;
    }
  }
  suspend(): void {
    this.suspended = true;
    this.generation++;
  }
  async resume(): Promise<void> {
    if (this.disposed || !this.visible())
      throw new DOMException('Owner Vault unavailable', 'AbortError');
    const generation = this.generation;
    await this.scope.verify();
    await this.scope.ensure();
    if (generation !== this.generation) throw new Error('stale resume');
    this.suspended = false;
    this.assert();
  }
  lock(): void {
    this.scope.end('manual');
    this.clear();
  }
  dispose(): void {
    this.disposed = true;
    this.clear();
    this.scope.signal.removeEventListener('abort', this.clear);
  }
  async seal(plaintext: Bytes, item: OwnerRecordContext): Promise<OwnerRecord> {
    this.assert();
    const key = this.key,
      generation = this.generation;
    if (!key) throw new Error('owner key locked');
    const sealed = await sealOwnerRecord(plaintext, key, this.context, item);
    this.assert();
    if (generation !== this.generation) throw new Error('stale seal');
    return sealed;
  }
  async open(record: OwnerRecord, item: OwnerRecordContext): Promise<Bytes> {
    this.assert();
    const key = this.key,
      generation = this.generation;
    if (!key) throw new Error('owner key locked');
    const plaintext = await openOwnerRecord(record, key, this.context, item);
    try {
      this.assert();
      if (generation !== this.generation) throw new Error('stale read');
      return plaintext;
    } catch (error) {
      plaintext.fill(0);
      throw error;
    }
  }
}
