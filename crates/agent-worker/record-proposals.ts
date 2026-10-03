// Explicit v2 owner-note proposals share the existing terminal approval state machine.
import { z } from 'zod';
import {
  opaque,
  digest,
  now,
  randomId,
  recordEnvelopeSchema,
  type Grant,
  type Owner,
} from './model.js';
import { activeJoin, ownerJoin, accessCondition, accessValues } from './store.js';
import { recordAuthority } from './tool-results.js';
import {
  parseRecordNoteTarget,
  type RecordNoteTarget,
} from '../worker/ui/vault-record-approval.js';
import {
  parseVaultRecordAuthority,
  parseVaultRecordSource,
  vaultCiphertextDigest,
  type VaultRecordAuthority,
} from '../worker/ui/vault-record-source.js';
import { parseOwnerNote, encodeOwnerNote, decodeOwnerNote } from '../worker/ui/vault-note.js';
import { openApprovedRecordProof } from '../worker/ui/agent-record-proof.js';
import { openOwnerRecordContentKey } from '../worker/ui/vault-record-content.js';
import { decodeBase64Url } from '../worker/ui/vault-crypto.js';

import { noteTargetSchema } from './record-contract.js';
export const capabilityInput = z.strictObject({
  grant_id: opaque,
  target: noteTargetSchema,
  authority: recordAuthority,
});
export const proposalInput = z.strictObject({
  storage_version: z.literal(2),
  proposal_id: opaque,
  target: noteTargetSchema,
  authority: recordAuthority,
  value: z.strictObject({
    type: z.literal('mikaki.owner-note'),
    version: z.literal(1),
    title: z.string(),
    text: z.string(),
    provenance: z.strictObject({ kind: z.literal('self-asserted') }),
  }),
  expires_at: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});
export const decisionInput = z.strictObject({
  proposal_id: opaque,
  request_hash: opaque,
  approve: z.boolean(),
});
export const prepareInput = z.strictObject({
  proposal_id: opaque,
  request_hash: opaque,
  operation_id: opaque,
  candidate: z.string().min(1).max(36864),
  proof: recordEnvelopeSchema,
});
const candidateSchema = z.strictObject({
  format_version: z.literal(2),
  vault_id: z.string(),
  key_generation: z.number().int().positive(),
  owner_key_revision: z.number().int().positive(),
  kind: z.literal('owner_note'),
  revision: z.number().int().positive(),
  ciphertext: z.string(),
  key_envelope: z.string(),
});
export const targetColumns = [
  'storage_version',
  'target_origin',
  'target_vault_id',
  'target_collection_id',
  'target_record_id',
  'target_kind',
  'target_ciphertext_sha256',
  'target_deleted',
  'target_key_generation',
  'target_owner_key_revision',
] as const;
type TargetRow = {
  storage_version: number;
  base_revision: number;
  target_origin: string;
  target_vault_id: string;
  target_collection_id: string;
  target_record_id: string;
  target_kind: string;
  target_ciphertext_sha256: string | null;
  target_deleted: number;
  target_key_generation: number;
  target_owner_key_revision: number;
};
type Capability = TargetRow & {
  grant_id: string;
  grant_revision: number;
  created_at: number;
  expires_at: number;
};
type Proposal = TargetRow & {
  proposal_id: string;
  grant_id: string;
  grant_revision: number;
  request_hash: string;
  payload: string | null;
  expires_at: number;
  state: string;
};
export function targetOf(row: TargetRow, owner: string): RecordNoteTarget {
  return parseRecordNoteTarget({
    storage_version: row.storage_version,
    origin: row.target_origin,
    owner_id: owner,
    vault_id: row.target_vault_id,
    collection_id: row.target_collection_id,
    record_id: row.target_record_id,
    kind: row.target_kind,
    revision: row.base_revision,
    ciphertext_sha256: row.target_ciphertext_sha256,
    deleted: row.target_deleted === 1,
  });
}
export function authorityOf(row: TargetRow): VaultRecordAuthority {
  return parseVaultRecordAuthority({
    key_generation: row.target_key_generation,
    owner_key_revision: row.target_owner_key_revision,
  });
}
function targetValues(target: RecordNoteTarget, authority: VaultRecordAuthority) {
  return [
    2,
    target.origin,
    target.vault_id,
    target.collection_id,
    target.record_id,
    target.kind,
    target.ciphertext_sha256,
    target.deleted ? 1 : 0,
    authority.key_generation,
    authority.owner_key_revision,
  ];
}
// Trusted aliases only. This predicate checks the target independently of the
// grant's selected read source; missing and positive tombstone heads stay distinct.
export function liveTarget(alias: string): string {
  return `${alias}.storage_version=2 AND EXISTS(SELECT 1 FROM vault_owner_key_head k
    WHERE k.account_id=g.account_id AND k.vault_id=${alias}.target_vault_id AND k.origin=${alias}.target_origin
      AND k.format_version=2 AND k.suite='PRF-HKDF-SHA256-AES256GCM-v2'
      AND k.key_generation=${alias}.target_key_generation AND k.revision=${alias}.target_owner_key_revision)
    AND ((${alias}.base_revision=0 AND ${alias}.target_deleted=0 AND ${alias}.target_ciphertext_sha256 IS NULL
      AND NOT EXISTS(SELECT 1 FROM vault_owner_record_head h WHERE h.account_id=g.account_id
        AND h.vault_id=${alias}.target_vault_id AND h.collection_id=${alias}.target_collection_id AND h.record_id=${alias}.target_record_id))
    OR (${alias}.base_revision>0 AND EXISTS(SELECT 1 FROM vault_owner_record_head h WHERE h.account_id=g.account_id
      AND h.vault_id=${alias}.target_vault_id AND h.collection_id=${alias}.target_collection_id AND h.record_id=${alias}.target_record_id
      AND h.kind=${alias}.target_kind AND h.format_version=2 AND h.revision=${alias}.base_revision
      AND h.key_generation=${alias}.target_key_generation AND h.deleted=${alias}.target_deleted
      AND h.ciphertext_sha256 IS ${alias}.target_ciphertext_sha256)))`;
}
function ownerFence(alias: string): string {
  return `EXISTS(SELECT 1 ${ownerJoin} AND EXISTS(SELECT 1 FROM vault_owner_key_wrap w
    WHERE w.account_id=ss.account_id AND w.key_generation=${alias}.target_key_generation AND w.credential_id=ss.credential_id))`;
}
const canPropose = `g.storage_version=2 AND EXISTS(SELECT 1 FROM json_each(g.operations) WHERE value='propose')`;
function capLive(alias: string) {
  return `(${canPropose}) AND (${alias}.grant_revision=g.revision AND ${alias}.expires_at>unixepoch()
    AND ${alias}.expires_at<=g.expires_at) AND (${liveTarget(alias)})`;
}
function exactTarget(left: string, right: string) {
  return [
    `${left}.base_revision=${right}.base_revision`,
    ...targetColumns.map((column) => `${left}.${column} IS ${right}.${column}`),
  ].join(' AND ');
}
function proposalScope(alias: string) {
  return `(${canPropose}) AND (g.grant_id=${alias}.grant_id AND g.revision=${alias}.grant_revision)
    AND EXISTS(SELECT 1 FROM agent_attribute_capability cap WHERE cap.grant_id=g.grant_id
      AND (${capLive('cap')}) AND cap.expires_at>=${alias}.expires_at AND (${exactTarget('cap', alias)}))`;
}
const activeArgs = (keyId: string, resource: string) => [now(), keyId, resource];
const ownerArgs = (owner: Owner) => [owner.secretHash, owner.account, now()];
function receipt(p: Proposal, account: string) {
  return {
    proposal_id: p.proposal_id,
    request_hash: p.request_hash,
    state: p.state,
    target: targetOf(p, account),
    authority: authorityOf(p),
    expires_at: p.expires_at,
    destination: 'owner-vault-record',
    untrusted_content: true,
  };
}
export async function allow(
  db: D1Database,
  owner: Owner,
  raw: unknown,
  keyId: string,
  resource: string,
) {
  const input = capabilityInput.parse(raw),
    target = parseRecordNoteTarget(input.target),
    authority = parseVaultRecordAuthority(input.authority),
    time = now();
  if (target.owner_id !== owner.account) throw new Error('Wrong owner');
  const session = db.withSession('first-primary');
  // The candidate row has exactly the shape used for the immutable stored cap.
  const columns = ['base_revision', ...targetColumns];
  await session.batch([
    session
      .prepare(
        `WITH selected(${columns.join(',')}) AS(VALUES(${columns.map(() => '?').join(',')}))
      INSERT INTO agent_attribute_capability(grant_id,attribute_id,base_revision,grant_revision,created_at,expires_at,${targetColumns.join(',')})
      SELECT g.grant_id,'owner_note',t.base_revision,g.revision,?,MIN(g.expires_at,?),${targetColumns.map((column) => `t.${column}`).join(',')}
      ${activeJoin.replace(' WHERE', ' CROSS JOIN selected t WHERE')} AND g.grant_id=? AND g.account_id=? AND ${canPropose}
      AND ${liveTarget('t')} AND ${ownerFence('t')}
      AND NOT EXISTS(SELECT 1 FROM agent_attribute_capability WHERE grant_id=g.grant_id)`,
      )
      .bind(
        target.revision,
        ...targetValues(target, authority),
        time,
        time + 3600,
        ...activeArgs(keyId, resource),
        input.grant_id,
        owner.account,
        ...ownerArgs(owner),
      ),
    session
      .prepare(
        `INSERT INTO agent_audit SELECT ?,g.grant_id,'record-capability','created','owner_note',?
      FROM agent_grant g JOIN agent_attribute_capability cap ON cap.grant_id=g.grant_id
      WHERE g.grant_id=? AND cap.created_at=? AND changes()>0`,
      )
      .bind(randomId(), time, input.grant_id, time),
  ]);
  const cap = await session
    .prepare(
      `SELECT cap.* FROM agent_attribute_capability cap WHERE cap.grant_id=? AND EXISTS(SELECT 1 ${activeJoin}
    AND g.grant_id=cap.grant_id AND g.account_id=? AND ${capLive('cap')} AND ${ownerFence('cap')})`,
    )
    .bind(input.grant_id, ...activeArgs(keyId, resource), owner.account, ...ownerArgs(owner))
    .first<Capability>();
  if (
    !cap ||
    JSON.stringify(targetOf(cap, owner.account)) !== JSON.stringify(target) ||
    JSON.stringify(authorityOf(cap)) !== JSON.stringify(authority)
  )
    throw new Error('Access denied');
  return { grant_id: cap.grant_id, target, authority, expires_at: cap.expires_at };
}
function liveProposal(
  session: Pick<D1Database, 'prepare'>,
  grant: Grant,
  proposalId: string,
  requestHash: string,
) {
  return session
    .prepare(
      `SELECT p.* FROM agent_attribute_proposal p WHERE p.proposal_id=? AND p.grant_id=?
      AND p.request_hash=? AND p.storage_version=2 AND p.expires_at>unixepoch()
      AND EXISTS(SELECT 1 ${activeJoin} AND g.revision=? AND (${proposalScope('p')}) AND (${accessCondition}))`,
    )
    .bind(
      proposalId,
      grant.grant_id,
      requestHash,
      ...activeArgs(grant.recipient_key_id, grant.resource),
      grant.revision,
      ...accessValues(grant),
    )
    .first<Proposal>();
}
// Last asynchronous disclosure gate in the public Worker. The generic grant
// refresh does not bind this separate write target or its explicit capability.
export async function refreshReceipt(db: D1Database, grant: Grant, value: Record<string, unknown>) {
  const current = await liveProposal(
    db.withSession('first-primary'),
    grant,
    opaque.parse(value.proposal_id),
    opaque.parse(value.request_hash),
  );
  if (!current) throw new Error('Access denied');
  return receipt(current, grant.account_id);
}
export async function propose(db: D1Database, grant: Grant, raw: unknown) {
  if (grant.storage_version !== 2) throw new Error('Record grant required');
  const input = proposalInput.parse(raw),
    target = parseRecordNoteTarget(input.target),
    authority = parseVaultRecordAuthority(input.authority);
  const bytes = encodeOwnerNote(parseOwnerNote(input.value));
  let payload: string;
  try {
    payload = new TextDecoder().decode(bytes);
  } finally {
    bytes.fill(0);
  }
  const time = now(),
    session = db.withSession('first-primary');
  const cap = await session
    .prepare(
      `SELECT cap.* FROM agent_attribute_capability cap WHERE cap.grant_id=?
    AND EXISTS(SELECT 1 ${activeJoin} AND g.grant_id=cap.grant_id AND g.revision=? AND ${capLive('cap')} AND ${accessCondition})`,
    )
    .bind(
      grant.grant_id,
      ...activeArgs(grant.recipient_key_id, grant.resource),
      grant.revision,
      ...accessValues(grant),
    )
    .first<Capability>();
  if (
    !cap ||
    JSON.stringify(targetOf(cap, grant.account_id)) !== JSON.stringify(target) ||
    JSON.stringify(authorityOf(cap)) !== JSON.stringify(authority) ||
    input.expires_at > cap.expires_at ||
    input.expires_at <= time ||
    input.expires_at > time + 3600
  )
    throw new Error('Access denied');
  const requestHash = await digest(
    JSON.stringify({
      version: 2,
      owner: grant.account_id,
      grant_id: grant.grant_id,
      grant_revision: grant.revision,
      destination: 'owner-vault-record',
      target,
      authority,
      payload,
      expires_at: input.expires_at,
    }),
  );
  // Proposal metadata is delegated output, unlike an owner-only historical
  // mutation acknowledgment. Recheck the exact capability, token and live target
  // after hashing/insertion and before every returned receipt, including retries.
  const liveReceipt = () => liveProposal(session, grant, input.proposal_id, requestHash);
  const existing = await session
    .prepare(
      `SELECT * FROM agent_attribute_proposal WHERE proposal_id=? AND grant_id=? AND storage_version=2`,
    )
    .bind(input.proposal_id, grant.grant_id)
    .first<Proposal>();
  if (existing) {
    if (existing.request_hash !== requestHash || existing.expires_at <= now())
      throw new Error('Conflict');
    const current = await liveReceipt();
    if (!current) throw new Error('Access denied');
    return receipt(current, grant.account_id);
  }
  await session.batch([
    session
      .prepare(
        `INSERT INTO agent_attribute_proposal(proposal_id,grant_id,grant_revision,request_hash,attribute_id,base_revision,payload,expires_at,created_at,${targetColumns.join(',')})
      SELECT ?,cap.grant_id,cap.grant_revision,?,'owner_note',cap.base_revision,?,?,?,${targetColumns.map((column) => `cap.${column}`).join(',')}
      FROM agent_attribute_capability cap WHERE cap.grant_id=? AND cap.expires_at>=? AND ?>unixepoch()
      AND EXISTS(SELECT 1 ${activeJoin} AND g.grant_id=cap.grant_id AND g.revision=? AND ${capLive('cap')} AND ${accessCondition})
      AND NOT EXISTS(SELECT 1 FROM agent_attribute_proposal WHERE proposal_id=?)
      AND (SELECT count(*) FROM agent_attribute_proposal p WHERE p.grant_id=cap.grant_id AND p.state IN('pending','approved'))<20`,
      )
      .bind(
        input.proposal_id,
        requestHash,
        payload,
        input.expires_at,
        time,
        grant.grant_id,
        input.expires_at,
        input.expires_at,
        ...activeArgs(grant.recipient_key_id, grant.resource),
        grant.revision,
        ...accessValues(grant),
        input.proposal_id,
      ),
    session
      .prepare(
        `INSERT INTO agent_audit SELECT ?,grant_id,'record-propose','pending','owner_note',? FROM agent_attribute_proposal
      WHERE proposal_id=? AND request_hash=? AND changes()>0`,
      )
      .bind(randomId(), time, input.proposal_id, requestHash),
  ]);
  const result = await liveReceipt();
  if (!result) throw new Error('Access denied');
  return receipt(result, grant.account_id);
}
export async function decide(
  db: D1Database,
  owner: Owner,
  raw: unknown,
  keyId: string,
  resource: string,
) {
  const input = decisionInput.parse(raw),
    state = input.approve ? 'approved' : 'rejected',
    session = db.withSession('first-primary');
  await session
    .prepare(
      `UPDATE agent_attribute_proposal SET state=?,payload=CASE WHEN ? THEN payload ELSE NULL END
    WHERE proposal_id=? AND request_hash=? AND storage_version=2 AND state='pending' AND expires_at>unixepoch()
      AND EXISTS(SELECT 1 ${activeJoin} AND g.account_id=? AND ${proposalScope('agent_attribute_proposal')} AND ${ownerFence('agent_attribute_proposal')})`,
    )
    .bind(
      state,
      input.approve ? 1 : 0,
      input.proposal_id,
      input.request_hash,
      ...activeArgs(keyId, resource),
      owner.account,
      ...ownerArgs(owner),
    )
    .run();
  const result = await session
    .prepare(
      `SELECT p.* FROM agent_attribute_proposal p WHERE p.proposal_id=? AND p.request_hash=? AND p.storage_version=2
    AND p.state=? AND p.expires_at>unixepoch() AND EXISTS(SELECT 1 ${activeJoin} AND g.account_id=? AND ${proposalScope('p')} AND ${ownerFence('p')})`,
    )
    .bind(
      input.proposal_id,
      input.request_hash,
      state,
      ...activeArgs(keyId, resource),
      owner.account,
      ...ownerArgs(owner),
    )
    .first<Proposal>();
  if (!result) throw new Error('Access denied');
  return receipt(result, owner.account);
}
export async function prepare(
  db: D1Database,
  owner: Owner,
  raw: unknown,
  key: { key: CryptoKey; key_id: string; resource: string },
  origin: string,
) {
  const input = prepareInput.parse(raw),
    session = db.withSession('first-primary');
  const p = await session
    .prepare(
      `SELECT p.* FROM agent_attribute_proposal p WHERE p.proposal_id=? AND p.request_hash=? AND p.storage_version=2
    AND p.state='approved' AND p.payload IS NOT NULL AND p.expires_at>unixepoch()
    AND EXISTS(SELECT 1 ${activeJoin} AND g.account_id=? AND ${proposalScope('p')} AND ${ownerFence('p')})`,
    )
    .bind(
      input.proposal_id,
      input.request_hash,
      ...activeArgs(key.key_id, key.resource),
      owner.account,
      ...ownerArgs(owner),
    )
    .first<Proposal>();
  if (!p || p.payload === null) throw new Error('Access denied');
  const target = targetOf(p, owner.account),
    authority = authorityOf(p);
  const candidate = candidateSchema.parse(JSON.parse(input.candidate));
  if (
    JSON.stringify(candidate) !== input.candidate ||
    target.origin !== origin ||
    candidate.vault_id !== target.vault_id ||
    candidate.key_generation !== authority.key_generation ||
    candidate.owner_key_revision !== authority.owner_key_revision ||
    candidate.revision !== target.revision + 1
  )
    throw new Error('Noncanonical or mismatched candidate');
  const envelope = decodeBase64Url(candidate.key_envelope);
  if (envelope.length !== 61 || envelope[0] !== 2) throw new Error('Invalid owner key envelope');
  const candidateHash = await digest(input.candidate);
  const source = parseVaultRecordSource({
    storage_version: 2,
    origin,
    owner_id: owner.account,
    vault_id: target.vault_id,
    collection_id: target.collection_id,
    record_id: target.record_id,
    kind: target.kind,
    revision: target.revision + 1,
    ciphertext_sha256: await vaultCiphertextDigest(candidate.ciphertext),
  });
  const dataKey = await openApprovedRecordProof(input.proof, key.key, {
    owner: owner.account,
    grant_id: p.grant_id,
    key_id: key.key_id,
    resource: key.resource,
    expires_at: p.expires_at,
    proposal_id: p.proposal_id,
    request_hash: p.request_hash,
    operation_id: input.operation_id,
    candidate_sha256: candidateHash,
    target,
    authority,
    candidate_source: source,
  });
  try {
    const bytes = await openOwnerRecordContentKey(candidate.ciphertext, dataKey, source);
    try {
      decodeOwnerNote(bytes);
      if (new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) !== p.payload)
        throw new Error('Altered approved value');
    } finally {
      bytes.fill(0);
    }
  } finally {
    dataKey.fill(0);
  }
  await session.batch([
    session
      .prepare(
        `INSERT INTO agent_attribute_commit(proposal_id,account_id,operation_id,candidate,candidate_sha256,origin,prepared_at,storage_version)
      SELECT p.proposal_id,?,?,?,?,?,?,2 FROM agent_attribute_proposal p WHERE p.proposal_id=? AND p.request_hash=? AND p.storage_version=2
      AND p.state='approved' AND p.payload IS NOT NULL AND p.expires_at>unixepoch()
      AND EXISTS(SELECT 1 ${activeJoin} AND g.account_id=? AND ${proposalScope('p')} AND ${ownerFence('p')})
      AND NOT EXISTS(SELECT 1 FROM agent_attribute_commit WHERE proposal_id=p.proposal_id)`,
      )
      .bind(
        owner.account,
        input.operation_id,
        input.candidate,
        candidateHash,
        origin,
        now(),
        p.proposal_id,
        p.request_hash,
        ...activeArgs(key.key_id, key.resource),
        owner.account,
        ...ownerArgs(owner),
      ),
    session
      .prepare(
        `INSERT INTO agent_audit SELECT ?,grant_id,'record-prepare','prepared','owner_note',? FROM agent_attribute_proposal
      WHERE proposal_id=? AND changes()>0`,
      )
      .bind(randomId(), now(), p.proposal_id),
  ]);
  const existing = await session
    .prepare(
      `SELECT ac.operation_id,ac.candidate_sha256 FROM agent_attribute_commit ac JOIN agent_attribute_proposal p ON p.proposal_id=ac.proposal_id
    WHERE ac.proposal_id=? AND ac.account_id=? AND ac.storage_version=2 AND p.state='approved' AND p.expires_at>unixepoch()
    AND EXISTS(SELECT 1 ${activeJoin} AND g.account_id=? AND ${proposalScope('p')} AND ${ownerFence('p')})`,
    )
    .bind(
      p.proposal_id,
      owner.account,
      ...activeArgs(key.key_id, key.resource),
      owner.account,
      ...ownerArgs(owner),
    )
    .first<{ operation_id: string; candidate_sha256: string }>();
  if (
    !existing ||
    existing.operation_id !== input.operation_id ||
    existing.candidate_sha256 !== candidateHash
  )
    throw new Error('Conflict');
  return {
    proposal_id: p.proposal_id,
    operation_id: existing.operation_id,
    candidate_sha256: existing.candidate_sha256,
  };
}
export async function status(db: D1Database, owner: Owner) {
  const rows = await db
    .withSession('first-primary')
    .prepare(
      `SELECT p.*,g.delegate,g.provider,ac.operation_id,ac.candidate,ac.result_revision
    FROM agent_attribute_proposal p JOIN agent_grant g ON g.grant_id=p.grant_id LEFT JOIN agent_attribute_commit ac ON ac.proposal_id=p.proposal_id
    WHERE g.account_id=? AND p.storage_version=2 AND (p.state='committed' OR p.expires_at>unixepoch())
    AND EXISTS(SELECT 1 ${ownerJoin}) ORDER BY p.created_at DESC LIMIT 20`,
    )
    .bind(owner.account, ...ownerArgs(owner))
    .all<
      Proposal & {
        operation_id: string | null;
        candidate: string | null;
        result_revision: number | null;
      }
    >();
  return rows.results.map((row) => ({ ...row, ...receipt(row, owner.account) }));
}
