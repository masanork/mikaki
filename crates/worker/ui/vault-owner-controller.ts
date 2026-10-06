import { VaultScope, type LockReason } from './vault-lifecycle.ts';
import { decodeBase64Url, encodeBase64Url } from './vault-crypto.ts';
import { rewrapOwnerKey } from './vault-owner-crypto.ts';
import {
  openOwnerVault,
  readOwnerKey,
  createOwnerKeyWrapperOperation,
  type OwnerKeyWrapperOperation,
  type StoredOwnerKey,
} from './vault-owner-store.ts';
import type { OwnerKeySession, OwnerPrfEvaluator } from './vault-owner-session.ts';

// WebAuthn performs the required user-verification ceremony. Check the returned
// credential, not just the allowCredentials request, before consuming its PRF.
export const evaluateOwnerPrf: OwnerPrfEvaluator = async (credentialId, input, signal) => {
  if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('prf_unsupported');
  signal.throwIfAborted();
  const credential = await navigator.credentials.get({
    signal,
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      userVerification: 'required',
      timeout: 120000,
      extensions: { prf: { eval: { first: input } } },
    },
  });
  if (!(credential instanceof PublicKeyCredential)) throw new Error('wrong_credential');
  const result = credential.getClientExtensionResults().prf?.results?.first;
  const output = result instanceof ArrayBuffer ? new Uint8Array(result) : undefined;
  try {
    if (encodeBase64Url(new Uint8Array(credential.rawId)) !== encodeBase64Url(credentialId))
      throw new Error('wrong_credential');
    if (!output || output.byteLength !== 32) throw new Error('prf_unsupported');
    signal.throwIfAborted();
    if (document.visibilityState !== 'visible') throw new DOMException('Hidden', 'AbortError');
    return { credentialId: new Uint8Array(credential.rawId), output };
  } catch (error) {
    output?.fill(0);
    throw error;
  }
};

export class OwnerVaultController {
  private epoch = 0;
  private suspended = false;
  private disposed = false;
  private opening = false;
  private opened: { session: OwnerKeySession; stored: StoredOwnerKey } | null = null;
  readonly scope: VaultScope;
  readonly origin: string;
  private readonly evaluate: OwnerPrfEvaluator;
  private readonly visible: () => boolean;
  constructor(
    scope: VaultScope,
    origin: string,
    evaluate: OwnerPrfEvaluator = evaluateOwnerPrf,
    visible = () => typeof document === 'undefined' || document.visibilityState === 'visible',
  ) {
    this.scope = scope;
    this.origin = origin;
    this.evaluate = evaluate;
    this.visible = visible;
    scope.signal.addEventListener('abort', this.dispose, { once: true });
  }
  private assertAvailable(): void {
    this.scope.assert();
    if (this.disposed || this.suspended || !this.visible())
      throw new DOMException('Owner Vault unavailable', 'AbortError');
  }
  checkpoint(): number {
    this.assertAvailable();
    return this.epoch;
  }
  assertCurrent(token: number): void {
    this.assertAvailable();
    if (token !== this.epoch) throw new DOMException('Stale Vault operation', 'AbortError');
  }
  lease(): { session: OwnerKeySession; stored: StoredOwnerKey } {
    this.assertAvailable();
    if (!this.opened?.session.opened) throw new Error('owner_key_locked');
    return this.opened;
  }
  async open(): Promise<void> {
    this.assertAvailable();
    if (this.opening) throw new Error('unlock_pending');
    if (this.opened) return;
    const token = this.checkpoint();
    this.opening = true;
    let candidate: Awaited<ReturnType<typeof openOwnerVault>> | undefined;
    try {
      await this.scope.verify();
      this.assertCurrent(token);
      candidate = await openOwnerVault(
        this.scope,
        this.origin,
        async (credential, input, signal) => {
          this.assertCurrent(token);
          const result = await this.evaluate(credential, input, signal);
          try {
            this.assertCurrent(token);
            return result;
          } catch (error) {
            result.output.fill(0);
            throw error;
          }
        },
        () => this.assertCurrent(token),
      );
      this.assertCurrent(token);
      this.opened = { session: candidate.session, stored: candidate.stored };
    } catch (error) {
      candidate?.session.dispose();
      throw error;
    } finally {
      this.opening = false;
    }
  }
  async verifyAuthority(): Promise<void> {
    const token = this.checkpoint(),
      { stored } = this.lease();
    try {
      await this.scope.verify();
      await this.scope.ensure();
      this.assertCurrent(token);
      const current = await readOwnerKey(this.scope, this.origin);
      this.assertCurrent(token);
      if (!current || JSON.stringify(current) !== JSON.stringify(stored))
        throw new Error('owner_key_changed');
    } catch (error) {
      if (token === this.epoch && !this.suspended && !this.disposed && this.visible())
        this.lock('unconfirmed');
      throw error;
    }
  }
  async prepareWrapper(targetId: string): Promise<OwnerKeyWrapperOperation> {
    const token = this.checkpoint();
    const { stored } = this.lease();
    if (targetId === stored.envelope.credential_id) throw new Error('source_wrapper_required');
    await this.verifyAuthority();
    this.assertCurrent(token);
    let sourceOutput: Uint8Array<ArrayBuffer> | undefined;
    let targetOutput: Uint8Array<ArrayBuffer> | undefined;
    try {
      const sourceId = decodeBase64Url(stored.envelope.credential_id);
      const source = await this.evaluate(
        sourceId,
        decodeBase64Url(stored.envelope.prf_input),
        this.scope.signal,
      );
      sourceOutput = source.output;
      this.assertCurrent(token);
      if (encodeBase64Url(source.credentialId) !== stored.envelope.credential_id)
        throw new Error('wrong_credential');
      const targetInput = crypto.getRandomValues(new Uint8Array(32));
      const target = await this.evaluate(decodeBase64Url(targetId), targetInput, this.scope.signal);
      targetOutput = target.output;
      this.assertCurrent(token);
      if (encodeBase64Url(target.credentialId) !== targetId) throw new Error('wrong_credential');
      const envelope = await rewrapOwnerKey(
        stored.envelope,
        stored.context,
        sourceId,
        sourceOutput,
        target.credentialId,
        targetInput,
        targetOutput,
      );
      this.assertCurrent(token);
      await this.verifyAuthority();
      this.assertCurrent(token);
      return createOwnerKeyWrapperOperation('PUT', stored, targetId, envelope);
    } finally {
      sourceOutput?.fill(0);
      targetOutput?.fill(0);
    }
  }
  async prepareWrapperRemoval(targetId: string): Promise<OwnerKeyWrapperOperation> {
    const token = this.checkpoint();
    const { stored } = this.lease();
    if (targetId === stored.envelope.credential_id) throw new Error('source_wrapper_required');
    await this.verifyAuthority();
    this.assertCurrent(token);
    return createOwnerKeyWrapperOperation('DELETE', stored, targetId);
  }
  suspend(): void {
    this.epoch++;
    this.suspended = true;
    this.opened?.session.suspend();
  }
  async resume(): Promise<void> {
    if (this.disposed || !this.visible()) throw new DOMException('Unavailable', 'AbortError');
    const token = this.epoch;
    const opened = this.opened;
    try {
      if (opened) {
        await opened.session.resume();
        const current = await readOwnerKey(this.scope, this.origin);
        if (!current || JSON.stringify(current) !== JSON.stringify(opened.stored))
          throw new Error('owner_key_changed');
      } else {
        await this.scope.verify();
        await this.scope.ensure();
      }
    } catch (error) {
      if (token === this.epoch) this.lock('unconfirmed');
      throw error;
    }
    if (token !== this.epoch || this.disposed || !this.visible())
      throw new DOMException('Stale Vault resume', 'AbortError');
    this.suspended = false;
    this.assertAvailable();
  }
  lock(reason: LockReason = 'manual'): void {
    this.scope.end(reason);
    this.dispose();
  }
  readonly dispose = (): void => {
    if (this.disposed) return;
    this.disposed = true;
    this.epoch++;
    this.opened?.session.dispose();
    this.opened = null;
    this.scope.signal.removeEventListener('abort', this.dispose);
  };
}
