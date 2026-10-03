// New-format bootstrap only; no legacy imports or implicit key reset/rotation.
import { VaultScope } from './vault-lifecycle.ts';
import { encodeBase64Url } from './vault-crypto.ts';
import {
  OWNER_KEY_SUITE,
  ownerKeyContext,
  parseOwnerKeyEnvelope,
  type OwnerKeyContext,
  type OwnerKeyEnvelope,
} from './vault-owner-crypto.ts';
import { OwnerKeySession, type OwnerPrfEvaluator } from './vault-owner-session.ts';

export type StoredOwnerKey = Readonly<{
  context: OwnerKeyContext;
  revision: number;
  envelope: OwnerKeyEnvelope;
}>;
const endpoint = '/vault/owner-key';

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
  return Object.freeze({ context, revision: item['revision'], envelope });
}
async function read(scope: VaultScope, origin: string): Promise<StoredOwnerKey | null> {
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
  if (!response.ok) throw new Error('owner-key read unavailable');
  const stored = parse(value, origin, scope);
  if (response.headers.get('etag') !== `"${stored.revision}"`)
    throw new Error('owner-key revision mismatch');
  return stored;
}
export async function openOwnerVault(
  scope: VaultScope,
  origin: string,
  evaluate: OwnerPrfEvaluator,
): Promise<{ session: OwnerKeySession; stored: StoredOwnerKey; created: boolean }> {
  await scope.ensure();
  const current = await read(scope, origin);
  if (current) {
    const session = new OwnerKeySession(scope, current.context);
    try {
      await session.unlock(current.envelope, evaluate);
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
      if (!response.ok) throw new Error('owner-key creation unavailable');
      stored = parse(await response.json(), origin, scope);
      if (response.headers.get('etag') !== `"${stored.revision}"`)
        throw new Error('owner-key revision mismatch');
    } catch {
      // A lost response never causes a new root to replace an existing one.
      // Reconcile by reading the exact encrypted candidate before returning.
      await scope.ensure();
      stored = await read(scope, origin);
    }
    if (
      !stored ||
      stored.revision !== 1 ||
      JSON.stringify(stored.context) !== JSON.stringify(context) ||
      JSON.stringify(stored.envelope) !== JSON.stringify(envelope)
    )
      throw new Error('owner-key creation conflict/unconfirmed');
    scope.assert();
    if (!session.opened) throw new Error('owner session ended');
    return { session, stored, created: true };
  } catch (error) {
    session.dispose();
    throw error;
  }
}
