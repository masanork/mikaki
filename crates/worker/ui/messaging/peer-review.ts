/** Public contact transport. Identity/fingerprint interpretation belongs to the
 * pinned Rust verifier, never to unverified JWT decoding in the screen. */
import type { DeviceIdentity } from './device-store.js';
import { exact, decode, encode } from './delivery-types.ts';

export type PeerContact = { scope: string; binding: string };
export type VerifiedDevice = {
  device: DeviceIdentity;
  fingerprint: string;
  revision: number;
  status: 'active' | 'revoked';
  issued_at: number;
  expires_at: number;
};
export type PeerObservation =
  'unconfirmed' | 'current' | 'key_changed' | 'revoked' | 'registry_conflict';
export type PeerTrust = {
  peer: {
    accepted: VerifiedDevice;
    latest: VerifiedDevice;
    state: Exclude<PeerObservation, 'unconfirmed'> | 'expired';
  } | null;
  group_usable: boolean;
};
export type PeerReview = {
  id: string;
  contact: PeerContact;
  verified: VerifiedDevice;
  observation: PeerObservation;
};
export function verifiedDevice(value: VerifiedDevice): VerifiedDevice {
  exact(value, ['device', 'fingerprint', 'revision', 'status', 'issued_at', 'expires_at']);
  exact(value.device, ['issuer', 'account_id', 'device_id', 'generation']);
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const issuer = new URL(value.device.issuer);
  if (
    issuer.protocol !== 'https:' ||
    issuer.origin !== value.device.issuer ||
    !uuid.test(value.device.account_id) ||
    !uuid.test(value.device.device_id) ||
    !Number.isSafeInteger(value.device.generation) ||
    value.device.generation < 1 ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 1 ||
    !Number.isSafeInteger(value.issued_at) ||
    value.issued_at < 0 ||
    !Number.isSafeInteger(value.expires_at) ||
    value.expires_at <= value.issued_at ||
    value.expires_at - value.issued_at > 300 ||
    !['active', 'revoked'].includes(value.status)
  )
    throw new Error('invalid_peer_review');
  decode(value.fingerprint, 32);
  return structuredClone(value);
}
const PREFIX = 'mikaki-device-v1:';
export function contact(value: PeerContact): PeerContact {
  exact(value, ['scope', 'binding']);
  decode(value.scope, 32);
  if (typeof value.binding !== 'string' || !value.binding || value.binding.length > 4096)
    throw new Error('invalid_peer_contact');
  return { scope: value.scope, binding: value.binding };
}
export function contactCode(value: PeerContact): string {
  return PREFIX + encode(new TextEncoder().encode(JSON.stringify(contact(value))));
}
export function parseContactCode(value: string): PeerContact {
  try {
    if (!value.startsWith(PREFIX) || value.length > 8192) throw new Error();
    return contact(
      JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(decode(value.slice(PREFIX.length))),
      ) as PeerContact,
    );
  } catch {
    throw new Error('invalid_peer_contact');
  }
}
