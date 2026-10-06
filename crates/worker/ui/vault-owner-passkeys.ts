import type { OwnerVaultController } from './vault-owner-controller.ts';
import { decodeBase64Url, encodeBase64Url } from './vault-crypto.ts';

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('invalid passkey response');
  return value as Record<string, unknown>;
}
function credentialId(value: unknown): string {
  if (typeof value !== 'string') throw new Error('invalid credential');
  const bytes = decodeBase64Url(value);
  if (!bytes.length || bytes.length > 512 || encodeBase64Url(bytes) !== value)
    throw new Error('invalid credential');
  return value;
}
export async function listOwnerPasskeys(owner: OwnerVaultController): Promise<string[]> {
  const token = owner.checkpoint();
  const response = await owner.scope.request('/vault/passkeys', { cache: 'no-store' });
  if (!response.ok) throw new Error('passkeys_unavailable');
  const value: unknown = await response.json();
  owner.assertCurrent(token);
  if (!Array.isArray(value) || value.length > 10) throw new Error('invalid passkey response');
  const ids = value.map((item) => credentialId(object(item)['credential_id']));
  if (new Set(ids).size !== ids.length) throw new Error('invalid passkey response');
  return ids;
}

export type PreparedPasskeyRegistration = Readonly<{ credentialId: string; body: string }>;
export async function prepareOwnerPasskey(
  owner: OwnerVaultController,
): Promise<PreparedPasskeyRegistration> {
  const token = owner.checkpoint();
  owner.lease();
  await owner.verifyAuthority();
  owner.assertCurrent(token);
  const response = await owner.scope.request('/vault/passkeys/start', {
    method: 'POST',
    cache: 'no-store',
  });
  if (!response.ok) throw new Error('fresh_login_or_capacity_required');
  const options = object(await response.json());
  owner.assertCurrent(token);
  if (
    typeof options['transaction_id'] !== 'string' ||
    typeof options['challenge'] !== 'string' ||
    typeof options['user_handle'] !== 'string' ||
    options['rp_id'] !== new URL(owner.origin).hostname ||
    !Array.isArray(options['exclude_credentials']) ||
    options['exclude_credentials'].length > 10
  )
    throw new Error('invalid passkey response');
  const created = await navigator.credentials.create({
    signal: owner.scope.signal,
    publicKey: {
      challenge: decodeBase64Url(options['challenge']),
      rp: { id: options['rp_id'], name: 'mikaki' },
      user: {
        id: decodeBase64Url(options['user_handle']),
        name: 'mikaki account',
        displayName: 'mikaki',
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: options['exclude_credentials'].map((item) => ({
        type: 'public-key',
        id: decodeBase64Url(credentialId(object(item)['credential_id'])),
      })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
      timeout: 120000,
      extensions: { credProps: true, prf: {} },
    },
  });
  owner.assertCurrent(token);
  if (
    !(created instanceof PublicKeyCredential) ||
    !(created.response instanceof AuthenticatorAttestationResponse) ||
    created.getClientExtensionResults().credProps?.rk !== true
  )
    throw new Error('discoverable passkey required');
  const id = encodeBase64Url(new Uint8Array(created.rawId));
  if (created.id !== id) throw new Error('invalid credential');
  return Object.freeze({
    credentialId: id,
    body: JSON.stringify({
      transaction_id: options['transaction_id'],
      response: {
        id,
        client_data: encodeBase64Url(new Uint8Array(created.response.clientDataJSON)),
        attestation: encodeBase64Url(new Uint8Array(created.response.attestationObject)),
      },
    }),
  });
}
export async function finishOwnerPasskey(
  owner: OwnerVaultController,
  prepared: PreparedPasskeyRegistration,
): Promise<void> {
  const token = owner.checkpoint();
  await owner.scope.verify();
  owner.assertCurrent(token);
  const response = await owner.scope.request('/vault/passkeys/finish', {
    method: 'POST',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: prepared.body,
  });
  if (!response.ok) throw new Error('registration_unconfirmed');
  const result = object(await response.json());
  owner.assertCurrent(token);
  if (result['credential_id'] !== prepared.credentialId)
    throw new Error('registration_unconfirmed');
}
