import { decodeOwnerNote, encodeOwnerNote, NOTE_ATTRIBUTE } from './vault-note.ts';
import {
  sealAttribute,
  openAttribute,
  parseOwnerEnvelope,
  withOpenedAttribute,
  newPrfInput,
  encodeBase64Url,
} from './vault-crypto.ts';
import { sealAgentValue, type AgentRecipient, type AgentEnvelope } from './agent-crypto.ts';

export type ApprovedNote = {
  proposal_id: string;
  request_hash: string;
  grant_id: string;
  payload: string;
  base_revision: number;
  expires_at: number;
};
export type PreparedNote = {
  proposal_id: string;
  request_hash: string;
  operation_id: string;
  candidate: string;
  proof: AgentEnvelope;
};

export async function prepareApprovedNote(
  proposal: ApprovedNote,
  owner: string,
  recipient: AgentRecipient,
  credential: Uint8Array<ArrayBuffer>,
  evaluate: (
    credential: Uint8Array<ArrayBuffer>,
    input: Uint8Array<ArrayBuffer>,
  ) => Promise<Uint8Array<ArrayBuffer>>,
): Promise<PreparedNote> {
  const value = decodeOwnerNote(new TextEncoder().encode(proposal.payload));
  const current = proposal.base_revision;
  const ownerKey = await currentOwnerKey(proposal, credential, evaluate);
  credential = ownerKey.credential;
  const input = ownerKey.input;
  const output = await evaluate(credential, input);
  const bytes = encodeOwnerNote(value);
  try {
    const sealed = await sealAttribute(
      bytes,
      output,
      credential,
      input,
      location.origin,
      NOTE_ATTRIBUTE,
      current + 1,
    );
    // Open the new owner envelope locally, verifying both readability and the exact value.
    return await withOpenedAttribute(
      sealed,
      output,
      credential,
      location.origin,
      NOTE_ATTRIBUTE,
      current + 1,
      async (restored, key) => {
        try {
          if (restored.length !== bytes.length || restored.some((byte, i) => byte !== bytes[i]))
            throw new Error('Candidate verification failed');
          const candidate = JSON.stringify(sealed);
          const candidate_sha256 = encodeBase64Url(
            new Uint8Array(
              await crypto.subtle.digest('SHA-256', new TextEncoder().encode(candidate)),
            ),
          );
          const proof = await sealAgentValue(
            {
              proposal_id: proposal.proposal_id,
              request_hash: proposal.request_hash,
              candidate_sha256,
              data_key: encodeBase64Url(key),
            },
            recipient,
            {
              owner,
              grant_id: proposal.grant_id,
              key_id: recipient.key_id,
              resource: recipient.resource,
              expires_at: proposal.expires_at,
              source_revision: current + 1,
            },
            'mikaki-approved-attribute-proof',
          );
          return {
            proposal_id: proposal.proposal_id,
            request_hash: proposal.request_hash,
            operation_id: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
            candidate,
            proof,
          };
        } finally {
          restored.fill(0);
        }
      },
    );
  } finally {
    output.fill(0);
    bytes.fill(0);
  }
}

async function currentOwnerKey(
  proposal: ApprovedNote,
  credential: Uint8Array<ArrayBuffer>,
  evaluate: (
    credential: Uint8Array<ArrayBuffer>,
    input: Uint8Array<ArrayBuffer>,
  ) => Promise<Uint8Array<ArrayBuffer>>,
) {
  const response = await fetch(`/vault/attributes/${NOTE_ATTRIBUTE}`, { cache: 'no-store' });
  if (response.status !== 200 && response.status !== 404) throw new Error('Note unavailable');
  const etag = response.headers.get('ETag');
  const current =
    etag === null && response.status === 404
      ? 0
      : /^"([1-9][0-9]*)"$/.test(etag ?? '')
        ? Number(etag!.slice(1, -1))
        : NaN;
  if (!Number.isSafeInteger(current) || current !== proposal.base_revision)
    throw new Error('Note changed');
  let input = newPrfInput();
  if (response.status === 200) {
    const raw: unknown = await response.json();
    if (
      typeof raw !== 'object' ||
      raw === null ||
      !('format_version' in raw) ||
      raw.format_version !== 1 ||
      !('ciphertext' in raw) ||
      typeof raw.ciphertext !== 'string' ||
      !('owner_envelope' in raw) ||
      typeof raw.owner_envelope !== 'string' ||
      !('revision' in raw) ||
      raw.revision !== current
    )
      throw new Error('Invalid note');
    const saved = {
      format_version: 1 as const,
      ciphertext: raw.ciphertext,
      owner_envelope: raw.owner_envelope,
    };
    const envelope = parseOwnerEnvelope(saved.owner_envelope);
    const output = await evaluate(envelope.credentialId, envelope.prfInput);
    try {
      const bytes = await openAttribute(
        saved,
        output,
        envelope.credentialId,
        location.origin,
        NOTE_ATTRIBUTE,
        current,
      );
      try {
        decodeOwnerNote(bytes);
      } finally {
        bytes.fill(0);
      }
    } finally {
      output.fill(0);
    }
    credential = envelope.credentialId;
    input = envelope.prfInput;
  }
  return { credential, input };
}

export async function verifyPreparedNote(
  proposal: ApprovedNote,
  candidate: string,
  credential: Uint8Array<ArrayBuffer>,
  evaluate: (
    credential: Uint8Array<ArrayBuffer>,
    input: Uint8Array<ArrayBuffer>,
  ) => Promise<Uint8Array<ArrayBuffer>>,
): Promise<void> {
  decodeOwnerNote(new TextEncoder().encode(proposal.payload));
  await currentOwnerKey(proposal, credential, evaluate);
  const raw: unknown = JSON.parse(candidate);
  if (
    typeof raw !== 'object' ||
    raw === null ||
    !('format_version' in raw) ||
    raw.format_version !== 1 ||
    !('ciphertext' in raw) ||
    typeof raw.ciphertext !== 'string' ||
    !('owner_envelope' in raw) ||
    typeof raw.owner_envelope !== 'string'
  )
    throw new Error('Invalid candidate');
  const sealed = {
    format_version: 1 as const,
    ciphertext: raw.ciphertext,
    owner_envelope: raw.owner_envelope,
  };
  const envelope = parseOwnerEnvelope(sealed.owner_envelope);
  const output = await evaluate(envelope.credentialId, envelope.prfInput);
  try {
    const bytes = await openAttribute(
      sealed,
      output,
      envelope.credentialId,
      location.origin,
      NOTE_ATTRIBUTE,
      proposal.base_revision + 1,
    );
    try {
      decodeOwnerNote(bytes);
      if (new TextDecoder().decode(bytes) !== proposal.payload)
        throw new Error('Altered candidate');
    } finally {
      bytes.fill(0);
    }
  } finally {
    output.fill(0);
  }
}
