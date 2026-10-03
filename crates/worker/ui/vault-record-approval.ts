// An exact owner-note write target is distinct from a readable saved source.
import {
  parseVaultRecordSource,
  parseVaultRecordAuthority,
  type VaultRecordSource,
  type VaultRecordAuthority,
} from './vault-record-source.ts';
import { decodeOwnerNote } from './vault-note.ts';

export type RecordNoteTarget = Readonly<
  Omit<VaultRecordSource, 'revision' | 'ciphertext_sha256' | 'record_id' | 'kind'> & {
    record_id: 'owner_note';
    kind: 'owner_note';
    revision: number;
    ciphertext_sha256: string | null;
    deleted: boolean;
  }
>;
export type ApprovedRecordNote = Readonly<{
  proposal_id: string;
  request_hash: string;
  grant_id: string;
  payload: string;
  expires_at: number;
  target: RecordNoteTarget;
  authority: VaultRecordAuthority;
}>;
export function parseRecordNoteTarget(value: unknown): RecordNoteTarget {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Invalid note target');
  const input = value as Record<string, unknown>;
  const fields = [
    'storage_version',
    'origin',
    'owner_id',
    'vault_id',
    'collection_id',
    'record_id',
    'kind',
    'revision',
    'ciphertext_sha256',
    'deleted',
  ];
  if (
    Object.keys(input).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(input, field)) ||
    input['storage_version'] !== 2 ||
    input['record_id'] !== 'owner_note' ||
    input['kind'] !== 'owner_note' ||
    typeof input['revision'] !== 'number' ||
    !Number.isSafeInteger(input['revision']) ||
    input['revision'] < 0 ||
    input['revision'] >= Number.MAX_SAFE_INTEGER ||
    typeof input['deleted'] !== 'boolean'
  )
    throw new Error('Invalid note target');
  const revision = input['revision'],
    deleted = input['deleted'],
    digest = input['ciphertext_sha256'];
  if (
    (revision === 0 && (deleted || digest !== null)) ||
    (revision > 0 && (deleted ? digest !== null : typeof digest !== 'string'))
  )
    throw new Error('Invalid note target head');
  const source = parseVaultRecordSource({
    storage_version: 2,
    origin: input['origin'],
    owner_id: input['owner_id'],
    vault_id: input['vault_id'],
    collection_id: input['collection_id'],
    record_id: 'owner_note',
    kind: 'owner_note',
    revision: revision || 1,
    ciphertext_sha256: typeof digest === 'string' ? digest : 'A'.repeat(43),
  });
  return Object.freeze({
    ...source,
    record_id: 'owner_note',
    kind: 'owner_note',
    revision,
    ciphertext_sha256: digest as string | null,
    deleted,
  });
}
export function parseApprovedRecordNote(value: ApprovedRecordNote): ApprovedRecordNote {
  if (
    Object.keys(value).length !== 7 ||
    ![value.proposal_id, value.request_hash, value.grant_id].every((id) =>
      /^[A-Za-z0-9_-]{43}$/.test(id),
    ) ||
    !Number.isSafeInteger(value.expires_at) ||
    value.expires_at < 1 ||
    typeof value.payload !== 'string'
  )
    throw new Error('Invalid record approval');
  const bytes = new Uint8Array(new TextEncoder().encode(value.payload));
  try {
    decodeOwnerNote(bytes);
  } finally {
    bytes.fill(0);
  }
  return Object.freeze({
    proposal_id: value.proposal_id,
    request_hash: value.request_hash,
    grant_id: value.grant_id,
    payload: value.payload,
    expires_at: value.expires_at,
    target: parseRecordNoteTarget(value.target),
    authority: parseVaultRecordAuthority(value.authority),
  });
}
