// A local display lease, independent of server authorization and SSO renewal.
export const VAULT_IDLE_MS = 15 * 60_000;
export const VAULT_ABSOLUTE_MS = 60 * 60_000;
export type LockReason =
  'manual' | 'idle' | 'absolute' | 'session' | 'unconfirmed' | 'external' | 'pagehide';
export type VaultIdentity = { account_id: string; credential_id: string; session_tag: string };
export function parseVaultIdentity(value: unknown): VaultIdentity {
  if (typeof value !== 'object' || value === null) throw new Error('Invalid Vault session');
  const v = value as Partial<VaultIdentity>;
  if (
    typeof v.account_id !== 'string' ||
    !v.account_id ||
    typeof v.credential_id !== 'string' ||
    !v.credential_id ||
    typeof v.session_tag !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/.test(v.session_tag)
  )
    throw new Error('Invalid Vault session');
  return { account_id: v.account_id, credential_id: v.credential_id, session_tag: v.session_tag };
}
export class VaultScope {
  private readonly controller = new AbortController();
  private readonly started: number;
  private readonly monotonicStarted: number;
  private activityAt: number;
  private monotonicActivityAt: number;
  private lastWall: number;
  private verification: Promise<void> | null = null;
  identity: VaultIdentity | null = null;
  private readonly invalid: (reason: LockReason) => void;
  private readonly wall: () => number;
  private readonly monotonic: () => number;
  private readonly transport: typeof fetch;
  constructor(
    invalid: (reason: LockReason) => void,
    wall = () => Date.now(),
    monotonic = () => performance.now(),
    transport: typeof fetch = (...args) => fetch(...args),
  ) {
    this.invalid = invalid;
    this.wall = wall;
    this.monotonic = monotonic;
    this.transport = transport;
    this.started = this.activityAt = this.lastWall = wall();
    this.monotonicStarted = this.monotonicActivityAt = monotonic();
  }
  get signal(): AbortSignal {
    return this.controller.signal;
  }
  expired(): LockReason | null {
    const wall = this.wall(),
      mono = this.monotonic();
    if (
      wall < this.lastWall ||
      wall - this.started >= VAULT_ABSOLUTE_MS ||
      mono - this.monotonicStarted >= VAULT_ABSOLUTE_MS
    )
      return 'absolute';
    this.lastWall = wall;
    if (wall - this.activityAt >= VAULT_IDLE_MS || mono - this.monotonicActivityAt >= VAULT_IDLE_MS)
      return 'idle';
    return null;
  }
  activity(): void {
    this.assert();
    this.activityAt = this.wall();
    this.monotonicActivityAt = this.monotonic();
  }
  end(reason: LockReason): void {
    if (this.signal.aborted) return;
    this.controller.abort();
    this.invalid(reason);
  }
  assert(): void {
    const expired = this.expired();
    if (expired) this.end(expired);
    if (this.signal.aborted) throw new DOMException('Vault is locked', 'AbortError');
    if (this.verification) throw new DOMException('Vault session is being checked', 'AbortError');
  }
  async ensure(): Promise<void> {
    if (this.verification) await this.verification;
    this.assert();
  }
  observe(value: unknown): void {
    if (this.signal.aborted) throw new DOMException('Vault is locked', 'AbortError');
    let identity: VaultIdentity;
    try {
      identity = parseVaultIdentity(value);
    } catch (error) {
      this.end('unconfirmed');
      throw error;
    }
    if (this.identity && JSON.stringify(this.identity) !== JSON.stringify(identity)) {
      this.end('session');
      throw new DOMException('Vault session changed', 'AbortError');
    }
    this.identity = identity;
  }
  readonly request: typeof fetch = async (input, init) => {
    await this.ensure();
    const signal = init?.signal ? AbortSignal.any([init.signal, this.signal]) : this.signal;
    const response = await this.transport(input, { ...init, signal });
    await this.ensure();
    if (response.status === 401 && this.identity) {
      this.end('session');
      throw new DOMException('Vault session ended', 'AbortError');
    }
    // A forbidden target may be a grant/policy rejection within a valid SSO.
    // Confirm the session before treating that response as a panel-local error.
    if (response.status === 403 && this.identity) {
      await this.verify();
      await this.ensure();
    }
    if (
      new URL(
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
        'https://vault.invalid',
      ).pathname === '/vault/session' &&
      response.ok
    )
      this.observe(await response.clone().json());
    return response;
  };
  verify(): Promise<void> {
    if (this.verification) return this.verification;
    this.assert();
    const check = async () => {
      try {
        const response = await this.transport('/vault/session', {
          cache: 'no-store',
          signal: this.signal,
        });
        if (!response.ok) {
          this.end([401, 403].includes(response.status) ? 'session' : 'unconfirmed');
          return;
        }
        if (this.signal.aborted) return;
        this.observe(await response.json());
      } catch {
        this.end('unconfirmed');
      }
    };
    this.verification = check().finally(() => {
      this.verification = null;
    });
    return this.verification;
  }
}
