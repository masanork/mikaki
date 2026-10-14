import { encodeBase64Url } from './vault-crypto.ts';

// Public, versioned input; the credential's PRF secret and the returned output
// remain private. Existing random-input wrappers are retained during adoption.
export function ownerLoginPrfInput(): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode('mikaki-vault-signin-prf-input-v1');
}

// One short-lived, document-local handoff. Never serialized or stored, and never
// reused after lock, a hidden document, navigation or a failed login.
export class OwnerLoginPrf {
  private output: Uint8Array<ArrayBuffer> | null;
  private readonly credential: string;
  readonly provided: boolean;
  private readonly deadline = Date.now() + 60_000;
  private readonly timeout: ReturnType<typeof setTimeout>;
  constructor(credential: Uint8Array<ArrayBuffer>, output?: Uint8Array<ArrayBuffer>) {
    this.credential = encodeBase64Url(credential);
    this.output = output?.byteLength === 32 ? output : null;
    this.provided = this.output !== null;
    if (!this.output) output?.fill(0);
    this.timeout = setTimeout(this.dispose, 60_000);
    window.addEventListener('pagehide', this.dispose, { once: true });
    document.addEventListener('visibilitychange', this.visibility);
  }
  get supported(): boolean {
    return this.output !== null && Date.now() < this.deadline;
  }
  consume(
    credential: Uint8Array<ArrayBuffer>,
    input: Uint8Array<ArrayBuffer>,
    signal: AbortSignal,
  ) {
    if (signal.aborted) {
      this.dispose();
      signal.throwIfAborted();
    }
    if (encodeBase64Url(credential) !== this.credential) {
      this.dispose();
      throw new Error('wrong_credential');
    }
    if (document.visibilityState !== 'visible' || Date.now() >= this.deadline) {
      this.dispose();
      throw new DOMException('Login unlock expired', 'AbortError');
    }
    if (encodeBase64Url(input) !== encodeBase64Url(ownerLoginPrfInput())) {
      // A legacy wrapper needs one owner-present adoption ceremony. It must not
      // be replaced or decrypted with an output from a different PRF input.
      this.dispose();
      return null;
    }
    const output = this.output;
    this.output = null;
    this.dispose();
    if (!output) return null;
    return { credentialId: credential.slice(), output };
  }
  private readonly visibility = () => {
    if (document.visibilityState === 'hidden') this.dispose();
  };
  readonly dispose = () => {
    this.output?.fill(0);
    this.output = null;
    clearTimeout(this.timeout);
    window.removeEventListener('pagehide', this.dispose);
    document.removeEventListener('visibilitychange', this.visibility);
  };
}
