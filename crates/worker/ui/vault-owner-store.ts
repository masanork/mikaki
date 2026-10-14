// New-format bootstrap only; no legacy imports or implicit key reset/rotation.
import { VaultScope } from './vault-lifecycle.ts';
import { decodeBase64Url, encodeBase64Url } from './vault-crypto.ts';
import { ownerLoginPrfInput } from './vault-login-prf.ts';
import {
  OWNER_KEY_SUITE,
  ownerKeyContext,
  parseOwnerKeyEnvelope,
  wrapOwnerKeyForLogin,
  type OwnerKeyContext,
  type OwnerKeyEnvelope,
} from './vault-owner-crypto.ts';
import { OwnerKeySession, type OwnerPrfEvaluator } from './vault-owner-session.ts';

export type StoredOwnerKey = Readonly<{
  context: OwnerKeyContext;
  revision: number;
  envelope: OwnerKeyEnvelope;
  loginEnvelope?: OwnerKeyEnvelope;
}>;
export function sameOwnerAuthority(a: StoredOwnerKey, b: StoredOwnerKey): boolean {
  // Adding same-credential login custody cannot change existing leases/grants.
  return (
    a.revision === b.revision &&
    JSON.stringify(a.context) === JSON.stringify(b.context) &&
    JSON.stringify(a.envelope) === JSON.stringify(b.envelope)
  );
}
const endpoint = '/vault/owner-key';
const wrappersEndpoint = '/vault/owner-key/wrappers';

export type OwnerKeyWrapper = Readonly<{ credentialId: string; active: boolean }>;
export type OwnerKeyWrapperRegistry = Readonly<{
  vaultId: string;
  keyGeneration: number;
  revision: number;
  credentials: readonly OwnerKeyWrapper[];
}>;
export type OwnerKeyWrapperOperation = Readonly<{
  method: 'PUT' | 'DELETE';
  action: 'add' | 'remove';
  operationId: string;
  expectedRevision: number;
  credentialId: string;
  vaultId: string;
  keyGeneration: number;
  body: string;
}>;
export type OwnerKeyWrapperReceipt = Readonly<{
  operationId: string;
  action: 'add' | 'remove';
  credentialId: string;
  vaultId: string;
  keyGeneration: number;
  previousRevision: number;
  revision: number;
}>;

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('invalid owner-key wrapper response');
  return value as Record<string, unknown>;
}

function canonicalCredentialId(value: unknown): string {
  if (typeof value !== 'string') throw new Error('invalid owner-key wrapper credential');
  const decoded = decodeBase64Url(value);
  if (decoded.byteLength < 1 || decoded.byteLength > 512 || encodeBase64Url(decoded) !== value)
    throw new Error('invalid owner-key wrapper credential');
  decoded.fill(0);
  return value;
}

export async function readOwnerKeyWrappers(
  scope: VaultScope,
  stored: StoredOwnerKey,
): Promise<OwnerKeyWrapperRegistry> {
  const response = await scope.request(wrappersEndpoint, { cache: 'no-store' });
  if (!response.ok)
    throw new Error(response.status === 409 ? 'owner_key_changed' : 'wrappers_unavailable');
  const item = record(await response.json());
  if (
    Object.keys(item).sort().join(',') !== 'credentials,key_generation,revision,vault_id' ||
    item['vault_id'] !== stored.context.vaultId ||
    item['key_generation'] !== stored.context.keyGeneration ||
    typeof item['revision'] !== 'number' ||
    !Number.isSafeInteger(item['revision']) ||
    item['revision'] !== stored.revision ||
    !Array.isArray(item['credentials']) ||
    item['credentials'].length > 10
  )
    throw new Error('owner_key_changed');
  if (response.headers.get('etag') !== `"${stored.revision}"`) throw new Error('owner_key_changed');
  const seen = new Set<string>();
  const credentials = item['credentials'].map((entry): OwnerKeyWrapper => {
    const value = record(entry);
    if (
      Object.keys(value).sort().join(',') !== 'active,credential_id' ||
      (value['active'] !== 0 && value['active'] !== 1)
    )
      throw new Error('invalid owner-key wrapper response');
    const credentialId = canonicalCredentialId(value['credential_id']);
    if (seen.has(credentialId)) throw new Error('invalid owner-key wrapper response');
    seen.add(credentialId);
    return Object.freeze({ credentialId, active: value['active'] === 1 });
  });
  if (
    !credentials.some(
      (credential) =>
        credential.credentialId === scope.identity?.credential_id && credential.active,
    )
  )
    throw new Error('owner_key_changed');
  return Object.freeze({
    vaultId: stored.context.vaultId,
    keyGeneration: stored.context.keyGeneration,
    revision: stored.revision,
    credentials: Object.freeze(credentials),
  });
}

export function createOwnerKeyWrapperOperation(
  method: 'PUT' | 'DELETE',
  stored: StoredOwnerKey,
  credentialId: string,
  ownerEnvelope?: OwnerKeyEnvelope,
): OwnerKeyWrapperOperation {
  canonicalCredentialId(credentialId);
  if (method === 'PUT') {
    if (!ownerEnvelope || ownerEnvelope.credential_id !== credentialId)
      throw new Error('invalid owner-key wrapper');
  } else if (ownerEnvelope) throw new Error('invalid owner-key wrapper');
  const action = method === 'PUT' ? 'add' : 'remove';
  const body = JSON.stringify(
    method === 'PUT'
      ? {
          format_version: 2,
          suite: OWNER_KEY_SUITE,
          vault_id: stored.context.vaultId,
          key_generation: stored.context.keyGeneration,
          owner_envelope: ownerEnvelope,
        }
      : {
          format_version: 2,
          suite: OWNER_KEY_SUITE,
          vault_id: stored.context.vaultId,
          key_generation: stored.context.keyGeneration,
          credential_id: credentialId,
        },
  );
  return Object.freeze({
    method,
    action,
    operationId: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    expectedRevision: stored.revision,
    credentialId,
    vaultId: stored.context.vaultId,
    keyGeneration: stored.context.keyGeneration,
    body,
  });
}

export async function commitOwnerKeyWrapperOperation(
  scope: VaultScope,
  operation: OwnerKeyWrapperOperation,
): Promise<OwnerKeyWrapperReceipt> {
  const response = await scope.request(wrappersEndpoint, {
    method: operation.method,
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      'If-Match': `"${operation.expectedRevision}"`,
      'X-Operation-ID': operation.operationId,
    },
    body: operation.body,
  });
  if (!response.ok) {
    if (response.status === 409) throw new Error('owner_wrapper_conflict');
    if (response.status === 403) throw new Error('owner_wrapper_origin');
    if (response.status === 401) throw new Error('owner_wrapper_session');
    if (response.status >= 400 && response.status < 500) throw new Error('owner_wrapper_rejected');
    throw new Error('owner_wrapper_unavailable');
  }
  const item = record(await response.json().catch(() => null));
  if (
    Object.keys(item).sort().join(',') !==
      'action,credential_id,key_generation,operation_id,previous_revision,revision,vault_id' ||
    item['operation_id'] !== operation.operationId ||
    item['action'] !== operation.action ||
    item['credential_id'] !== operation.credentialId ||
    item['vault_id'] !== operation.vaultId ||
    item['key_generation'] !== operation.keyGeneration ||
    item['previous_revision'] !== operation.expectedRevision ||
    item['revision'] !== operation.expectedRevision + 1 ||
    response.headers.get('etag') !== `"${operation.expectedRevision + 1}"`
  )
    throw new Error('owner_wrapper_unconfirmed');
  return Object.freeze({
    operationId: operation.operationId,
    action: operation.action,
    credentialId: operation.credentialId,
    vaultId: operation.vaultId,
    keyGeneration: operation.keyGeneration,
    previousRevision: operation.expectedRevision,
    revision: operation.expectedRevision + 1,
  });
}

function parse(value: unknown, origin: string, scope: VaultScope): StoredOwnerKey {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('invalid owner-key response');
  const item = value as Record<string, unknown>;
  if (
    item['format_version'] !== 2 ||
    item['suite'] !== OWNER_KEY_SUITE ||
    item['origin'] !== origin ||
    item['owner_id'] !== scope.identity?.account_id ||
    typeof item['vault_id'] !== 'string' ||
    typeof item['key_generation'] !== 'number' ||
    typeof item['revision'] !== 'number' ||
    !Number.isSafeInteger(item['revision']) ||
    item['revision'] < 1
  )
    throw new Error('unsupported/mismatched owner key');
  const context = ownerKeyContext({
    origin,
    ownerId: scope.identity!.account_id,
    vaultId: item['vault_id'],
    keyGeneration: item['key_generation'],
  });
  const envelope = parseOwnerKeyEnvelope(item['owner_envelope']);
  if (envelope.credential_id !== scope.identity?.credential_id)
    throw new Error('wrong stored credential');
  const loginEnvelope =
    item['login_envelope'] === undefined
      ? undefined
      : parseOwnerKeyEnvelope(item['login_envelope']);
  if (
    loginEnvelope &&
    (loginEnvelope.credential_id !== envelope.credential_id ||
      loginEnvelope.prf_input !== encodeBase64Url(ownerLoginPrfInput()))
  )
    throw new Error('invalid login wrapper');
  return Object.freeze({
    context,
    revision: item['revision'],
    envelope,
    ...(loginEnvelope ? { loginEnvelope } : {}),
  });
}
export async function readOwnerKey(
  scope: VaultScope,
  origin: string,
  includeLogin = false,
): Promise<StoredOwnerKey | null> {
  const response = await scope.request(endpoint, { cache: 'no-store' });
  const value: unknown = await response.json();
  if (
    response.status === 404 &&
    value &&
    typeof value === 'object' &&
    'error' in value &&
    value.error === 'owner_key_missing'
  )
    return null;
  if (!response.ok)
    throw new Error(
      response.status === 409 &&
        value &&
        typeof value === 'object' &&
        'error' in value &&
        value.error === 'credential_not_wrapped'
        ? 'credential_not_wrapped'
        : 'owner-key read unavailable',
    );
  const stored = parse(value, origin, scope);
  if (response.headers.get('etag') !== `"${stored.revision}"`)
    throw new Error('owner-key revision mismatch');
  // Keep the primary representation/ETag unchanged by additive login custody.
  // Load the separate immutable resource only for old random-input wrappers.
  if (includeLogin && stored.envelope.prf_input !== encodeBase64Url(ownerLoginPrfInput())) {
    const login = await scope.request('/vault/owner-key/login-wrap', { cache: 'no-store' });
    const value: unknown = await login.json();
    if (
      login.status === 404 &&
      value &&
      typeof value === 'object' &&
      'error' in value &&
      value.error === 'login_wrapper_missing'
    )
      return stored;
    if (!login.ok) throw new Error('login-wrapper read unavailable');
    const current = parse(value, origin, scope);
    if (
      !current.loginEnvelope ||
      !sameOwnerAuthority(current, stored) ||
      login.headers.get('etag') !== `"${stored.revision}"`
    )
      throw new Error('owner_key_changed');
    return current;
  }
  return stored;
}
export async function openOwnerVault(
  scope: VaultScope,
  origin: string,
  evaluate: OwnerPrfEvaluator,
  assertCurrent: () => void = () => scope.assert(),
  preferLogin = false,
): Promise<{ session: OwnerKeySession; stored: StoredOwnerKey; created: boolean }> {
  await scope.ensure();
  assertCurrent();
  const current = await readOwnerKey(scope, origin, true);
  assertCurrent();
  if (current) {
    const session = new OwnerKeySession(scope, current.context);
    try {
      let loginEnvelope: OwnerKeyEnvelope | undefined;
      await session.unlock(
        (preferLogin ? current.loginEnvelope : undefined) ?? current.envelope,
        async (credential, input, signal) => {
          const result = await evaluate(credential, input, signal);
          try {
            assertCurrent();
            if (
              !current.loginEnvelope &&
              result.loginOutput &&
              current.envelope.prf_input !== encodeBase64Url(ownerLoginPrfInput())
            ) {
              loginEnvelope = await wrapOwnerKeyForLogin(
                current.envelope,
                current.context,
                result.credentialId,
                result.output.slice(),
                result.loginOutput.slice(),
              );
              assertCurrent();
            }
            return result;
          } catch (error) {
            result.output.fill(0);
            throw error;
          } finally {
            result.loginOutput?.fill(0);
          }
        },
      );
      assertCurrent();
      if (loginEnvelope) {
        // An additive, immutable same-credential wrap. Exact candidate retries
        // never overwrite either envelope or change grants/record revisions.
        const body = JSON.stringify({
          format_version: 2,
          suite: OWNER_KEY_SUITE,
          vault_id: current.context.vaultId,
          key_generation: current.context.keyGeneration,
          owner_envelope: loginEnvelope,
        });
        try {
          assertCurrent();
          await scope.request('/vault/owner-key/login-wrap', {
            method: 'PUT',
            cache: 'no-store',
            headers: { 'Content-Type': 'application/json', 'If-Match': `"${current.revision}"` },
            body,
          });
        } catch {
          // Reconcile a lost response; ordinary unlock remains usable if the
          // optional upgrade was not admitted. Never regenerate the root.
        }
        assertCurrent();
        const observed = await readOwnerKey(scope, origin, true);
        assertCurrent();
        if (
          !observed ||
          JSON.stringify(observed.context) !== JSON.stringify(current.context) ||
          observed.revision !== current.revision ||
          JSON.stringify(observed.envelope) !== JSON.stringify(current.envelope)
        )
          throw new Error('owner_key_changed');
        return { session, stored: observed, created: false };
      }
      return { session, stored: current, created: false };
    } catch (error) {
      session.dispose();
      throw error;
    }
  }
  if (!scope.identity) throw new Error('owner identity required');
  const context = ownerKeyContext({
    origin,
    ownerId: scope.identity.account_id,
    vaultId: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    keyGeneration: 1,
  });
  const session = new OwnerKeySession(scope, context);
  try {
    const envelope = await session.initialize(evaluate);
    // A visibility/session generation may change while WebCrypto is pending.
    // Do not submit a bootstrap after its initiating operation was invalidated.
    assertCurrent();
    const body = JSON.stringify({
      format_version: 2,
      suite: OWNER_KEY_SUITE,
      vault_id: context.vaultId,
      key_generation: 1,
      owner_envelope: envelope,
    });
    const operation = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    let stored: StoredOwnerKey | null = null;
    try {
      assertCurrent();
      const response = await scope.request(endpoint, {
        method: 'PUT',
        cache: 'no-store',
        headers: {
          'Content-Type': 'application/json',
          'If-None-Match': '*',
          'X-Operation-ID': operation,
        },
        body,
      });
      assertCurrent();
      if (!response.ok) throw new Error('owner-key creation unavailable');
      stored = parse(await response.json(), origin, scope);
      assertCurrent();
      if (response.headers.get('etag') !== `"${stored.revision}"`)
        throw new Error('owner-key revision mismatch');
    } catch {
      // A lost response never causes a new root to replace an existing one.
      // Reconcile by reading the exact encrypted candidate before returning.
      await scope.ensure();
      assertCurrent();
      stored = await readOwnerKey(scope, origin);
      assertCurrent();
    }
    if (
      !stored ||
      stored.revision !== 1 ||
      JSON.stringify(stored.context) !== JSON.stringify(context) ||
      JSON.stringify(stored.envelope) !== JSON.stringify(envelope)
    )
      throw new Error('owner-key creation conflict/unconfirmed');
    assertCurrent();
    if (!session.opened) throw new Error('owner session ended');
    return { session, stored, created: true };
  } catch (error) {
    session.dispose();
    throw error;
  }
}
