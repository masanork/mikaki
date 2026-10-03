// The sole attribute proposal authority. HTTP and MCP only authenticate and call it.
import { z } from 'zod';
import { encodeOwnerNote, parseOwnerNote } from '../worker/ui/vault-note.js';
import { digest, now, opaque, randomId, envelopeSchema, type Grant, type Owner } from './model.js';
import { openAgentValue } from '../worker/ui/agent-crypto.js';
import {
  decodeBase64Url,
  openAttributeDataKey,
  parseOwnerEnvelope,
} from '../worker/ui/vault-crypto.js';
import { decodeOwnerNote } from '../worker/ui/vault-note.js';
import {
  activeJoin as grantJoin,
  ownerJoin as sessionJoin,
  accessCondition,
  accessValues,
} from './store.js';

// Recheck expiry on the durable database clock as well as the handler snapshot.
const activeJoin = `${grantJoin} AND g.expires_at>unixepoch() AND g.storage_version=1`;
const ownerJoin = `${sessionJoin} AND ss.expires_at>unixepoch()`;

const revision = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER - 1);
export const capabilityInput = z.strictObject({
  grant_id: opaque,
  attribute_id: z.literal('owner_note'),
  base_revision: revision,
});
export const proposalInput = z.strictObject({
  proposal_id: opaque,
  attribute_id: z.literal('owner_note'),
  base_revision: revision,
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
type Proposal = {
  proposal_id: string;
  grant_id: string;
  grant_revision: number;
  request_hash: string;
  attribute_id: 'owner_note';
  base_revision: number;
  payload: string | null;
  expires_at: number;
  created_at: number;
  state: 'pending' | 'approved' | 'rejected' | 'invalid' | 'committed';
};
// Revision 0 means never stored, not a deleted head. Tombstones keep their revision.
const target = `COALESCE((SELECT revision FROM vault_attribute_head
 WHERE account_id=g.account_id AND attribute_id='owner_note'),0)`;
const scope = `AND EXISTS(SELECT 1 FROM json_each(g.operations) WHERE value='propose')
 AND EXISTS(SELECT 1 FROM agent_attribute_capability cap WHERE cap.grant_id=g.grant_id
   AND cap.storage_version=1 AND cap.grant_revision=g.revision AND cap.attribute_id='owner_note'
   AND cap.base_revision=${target} AND cap.expires_at>? AND cap.expires_at>unixepoch())`;

export async function allow(
  db: D1Database,
  owner: Owner,
  raw: unknown,
  keyId: string,
  resource: string,
) {
  const input = capabilityInput.parse(raw),
    time = now();
  const session = db.withSession('first-primary');
  const statements = [
    session
      .prepare(
        `INSERT INTO agent_attribute_capability(grant_id,attribute_id,base_revision,grant_revision,created_at,expires_at)
      SELECT g.grant_id,?, ?,g.revision,?,MIN(g.expires_at,?) ${activeJoin}
      AND g.grant_id=? AND g.account_id=? AND ${target}=?
      AND EXISTS(SELECT 1 FROM json_each(g.operations) WHERE value='propose')
      AND EXISTS(SELECT 1 ${ownerJoin})
      AND NOT EXISTS(SELECT 1 FROM agent_attribute_capability WHERE grant_id=g.grant_id)`,
      )
      .bind(
        input.attribute_id,
        input.base_revision,
        time,
        time + 3600,
        time,
        keyId,
        resource,
        input.grant_id,
        owner.account,
        input.base_revision,
        owner.secretHash,
        owner.account,
        time,
      ),
    session
      .prepare(
        `INSERT INTO agent_audit SELECT ?,g.grant_id,'attribute-capability','created','owner_note',?
      FROM agent_grant g JOIN agent_attribute_capability cap ON cap.grant_id=g.grant_id
      WHERE g.grant_id=? AND cap.created_at=? AND changes()>0`,
      )
      .bind(randomId(), time, input.grant_id, time),
  ];
  await session.batch(statements);
  const cap = await session
    .prepare(
      `SELECT g.grant_id,
    (SELECT expires_at FROM agent_attribute_capability WHERE grant_id=g.grant_id) AS expires_at ${activeJoin}
    AND g.grant_id=? AND g.account_id=?
    AND EXISTS(SELECT 1 FROM agent_attribute_capability cap WHERE cap.grant_id=g.grant_id
      AND cap.base_revision=? AND cap.expires_at>? AND cap.expires_at>unixepoch() AND cap.grant_revision=g.revision)
    AND ${target}=?
    AND EXISTS(SELECT 1 ${ownerJoin})`,
    )
    .bind(
      time,
      keyId,
      resource,
      input.grant_id,
      owner.account,
      input.base_revision,
      time,
      input.base_revision,
      owner.secretHash,
      owner.account,
      time,
    )
    .first();
  if (!cap) throw new Error('Access denied');
  return cap;
}

function receipt(p: Proposal) {
  return {
    proposal_id: p.proposal_id,
    request_hash: p.request_hash,
    state: p.state,
    attribute_id: p.attribute_id,
    base_revision: p.base_revision,
    expires_at: p.expires_at,
    destination: 'owner-vault',
    untrusted_content: true,
  };
}

export async function propose(db: D1Database, grant: Grant, raw: unknown) {
  const input = proposalInput.parse(raw);
  const value = parseOwnerNote(input.value);
  const payload = new TextDecoder().decode(encodeOwnerNote(value));
  const requestHash = await digest(
    JSON.stringify({
      version: 1,
      owner: grant.account_id,
      grant_id: grant.grant_id,
      grant_revision: grant.revision,
      destination: 'owner-vault',
      attribute_id: input.attribute_id,
      base_revision: input.base_revision,
      payload,
      expires_at: input.expires_at,
    }),
  );
  const time = now(),
    session = db.withSession('first-primary');
  const authorized = await session
    .prepare(
      `SELECT g.grant_id ${activeJoin} AND g.grant_id=? AND g.revision=? ${scope} AND ${accessCondition}`,
    )
    .bind(
      time,
      grant.recipient_key_id,
      grant.resource,
      grant.grant_id,
      grant.revision,
      time,
      ...accessValues(grant),
    )
    .first();
  if (!authorized) throw new Error('Access denied');
  const existing = await session
    .prepare(
      'SELECT * FROM agent_attribute_proposal WHERE proposal_id=? AND grant_id=? AND expires_at>unixepoch()',
    )
    .bind(input.proposal_id, grant.grant_id)
    .first<Proposal>();
  if (existing) {
    if (existing.request_hash !== requestHash || existing.expires_at <= time)
      throw new Error('Conflict');
    return receipt(existing);
  }
  if (input.expires_at <= time || input.expires_at > time + 3600) throw new Error('Invalid expiry');
  await session.batch([
    session
      .prepare(
        `INSERT INTO agent_attribute_proposal
      (proposal_id,grant_id,grant_revision,request_hash,attribute_id,base_revision,payload,expires_at,created_at)
      SELECT ?,g.grant_id,g.revision,?,?,?,?,?,? ${activeJoin} AND g.grant_id=? AND g.revision=? ${scope}
      AND ${target}=? AND EXISTS(SELECT 1 FROM agent_attribute_capability cap WHERE cap.grant_id=g.grant_id AND cap.expires_at>=?)
      AND ?>unixepoch()
      AND ${accessCondition}
      AND NOT EXISTS(SELECT 1 FROM agent_attribute_proposal WHERE proposal_id=?)
      AND (SELECT count(*) FROM agent_attribute_proposal p WHERE p.grant_id=g.grant_id AND p.state IN('pending','approved'))<20`,
      )
      .bind(
        input.proposal_id,
        requestHash,
        input.attribute_id,
        input.base_revision,
        payload,
        input.expires_at,
        time,
        time,
        grant.recipient_key_id,
        grant.resource,
        grant.grant_id,
        grant.revision,
        time,
        input.base_revision,
        input.expires_at,
        input.expires_at,
        ...accessValues(grant),
        input.proposal_id,
      ),
    session
      .prepare(
        `INSERT INTO agent_audit SELECT ?,grant_id,'attribute-propose','pending',attribute_id,?
      FROM agent_attribute_proposal WHERE proposal_id=? AND request_hash=? AND changes()>0`,
      )
      .bind(randomId(), time, input.proposal_id, requestHash),
  ]);
  const result = await session
    .prepare(
      'SELECT * FROM agent_attribute_proposal WHERE proposal_id=? AND grant_id=? AND request_hash=? AND expires_at>unixepoch()',
    )
    .bind(input.proposal_id, grant.grant_id, requestHash)
    .first<Proposal>();
  if (!result) throw new Error('Access denied');
  return receipt(result);
}

export async function decide(
  db: D1Database,
  owner: Owner,
  raw: unknown,
  keyId: string,
  resource: string,
) {
  const input = decisionInput.parse(raw),
    time = now(),
    session = db.withSession('first-primary');
  const state = input.approve ? 'approved' : 'rejected';
  await session
    .prepare(
      `UPDATE agent_attribute_proposal SET state=?,payload=CASE WHEN ? THEN payload ELSE NULL END
    WHERE proposal_id=? AND request_hash=? AND state='pending' AND expires_at>? AND expires_at>unixepoch()
    AND EXISTS(SELECT 1 ${activeJoin} AND g.grant_id=agent_attribute_proposal.grant_id
      AND g.account_id=? AND g.revision=agent_attribute_proposal.grant_revision ${scope}
      AND ${target}=agent_attribute_proposal.base_revision AND EXISTS(SELECT 1 ${ownerJoin}))`,
    )
    .bind(
      state,
      input.approve ? 1 : 0,
      input.proposal_id,
      input.request_hash,
      time,
      time,
      keyId,
      resource,
      owner.account,
      time,
      owner.secretHash,
      owner.account,
      time,
    )
    .run();
  const result = await session
    .prepare(
      `SELECT p.* FROM agent_attribute_proposal p WHERE p.proposal_id=? AND p.request_hash=?
    AND p.state=? AND p.expires_at>? AND p.expires_at>unixepoch() AND EXISTS(SELECT 1 ${activeJoin}
      AND g.grant_id=p.grant_id AND g.account_id=? AND g.revision=p.grant_revision ${scope}
      AND ${target}=p.base_revision AND EXISTS(SELECT 1 ${ownerJoin}))`,
    )
    .bind(
      input.proposal_id,
      input.request_hash,
      state,
      time,
      time,
      keyId,
      resource,
      owner.account,
      time,
      owner.secretHash,
      owner.account,
      time,
    )
    .first<Proposal>();
  if (!result) throw new Error('Access denied');
  return receipt(result);
}

export async function status(db: D1Database, owner: Owner) {
  return (
    await db
      .withSession('first-primary')
      .prepare(
        `SELECT p.*,g.delegate,g.provider,ac.operation_id,ac.candidate,ac.result_revision,
    'owner-vault' AS destination FROM agent_attribute_proposal p JOIN agent_grant g ON g.grant_id=p.grant_id
    LEFT JOIN agent_attribute_commit ac ON ac.proposal_id=p.proposal_id
    WHERE g.account_id=? AND p.storage_version=1 AND (p.state='committed' OR (p.expires_at>? AND p.expires_at>unixepoch()))
      AND EXISTS(SELECT 1 ${ownerJoin}) ORDER BY p.created_at DESC LIMIT 20`,
      )
      .bind(owner.account, now(), owner.secretHash, owner.account, now())
      .all()
  ).results;
}

export const prepareInput = z.strictObject({
  proposal_id: opaque,
  request_hash: opaque,
  operation_id: opaque,
  candidate: z.string().min(1).max(40000),
  proof: envelopeSchema,
});
const candidateSchema = z.strictObject({
  format_version: z.literal(1),
  ciphertext: z.string(),
  owner_envelope: z.string(),
});
const proofSchema = z.strictObject({
  proposal_id: opaque,
  request_hash: opaque,
  candidate_sha256: opaque,
  data_key: opaque,
});

export async function prepare(
  db: D1Database,
  owner: Owner,
  raw: unknown,
  key: { key: CryptoKey; key_id: string; resource: string },
  origin: string,
) {
  const input = prepareInput.parse(raw),
    time = now(),
    session = db.withSession('first-primary');
  const p = await session
    .prepare(
      `SELECT p.* FROM agent_attribute_proposal p
    WHERE p.proposal_id=? AND p.request_hash=? AND p.storage_version=1 AND p.state='approved' AND p.payload IS NOT NULL
      AND p.expires_at>unixepoch() AND EXISTS(SELECT 1 ${activeJoin}
        AND g.grant_id=p.grant_id AND g.account_id=? AND g.revision=p.grant_revision
        ${scope} AND ${target}=p.base_revision AND EXISTS(SELECT 1 ${ownerJoin}))`,
    )
    .bind(
      input.proposal_id,
      input.request_hash,
      time,
      key.key_id,
      key.resource,
      owner.account,
      time,
      owner.secretHash,
      owner.account,
      time,
    )
    .first<Proposal>();
  if (!p) throw new Error('Access denied');
  const candidate = candidateSchema.parse(JSON.parse(input.candidate));
  if (JSON.stringify(candidate) !== input.candidate) throw new Error('Noncanonical candidate');
  parseOwnerEnvelope(candidate.owner_envelope);
  const candidateHash = await digest(input.candidate);
  const proof = proofSchema.parse(
    await openAgentValue(
      input.proof,
      key.key,
      {
        owner: owner.account,
        grant_id: p.grant_id,
        key_id: key.key_id,
        resource: key.resource,
        expires_at: p.expires_at,
        source_revision: p.base_revision + 1,
      },
      'mikaki-approved-attribute-proof',
    ),
  );
  if (
    proof.proposal_id !== p.proposal_id ||
    proof.request_hash !== p.request_hash ||
    proof.candidate_sha256 !== candidateHash
  )
    throw new Error('Invalid proof');
  const dataKey = decodeBase64Url(proof.data_key);
  try {
    const bytes = await openAttributeDataKey(
      candidate,
      dataKey,
      origin,
      p.attribute_id,
      p.base_revision + 1,
    );
    try {
      decodeOwnerNote(bytes);
      if (new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes) !== p.payload)
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
        `INSERT INTO agent_attribute_commit(proposal_id,account_id,operation_id,candidate,candidate_sha256,origin,prepared_at)
      SELECT p.proposal_id,g.account_id,?,?,?,?,? FROM agent_attribute_proposal p
      JOIN agent_grant g ON g.grant_id=p.grant_id WHERE p.proposal_id=? AND p.request_hash=?
      AND p.state='approved' AND p.payload IS NOT NULL AND p.expires_at>unixepoch()
      AND EXISTS(SELECT 1 ${activeJoin} AND g.grant_id=p.grant_id AND g.account_id=?
        AND g.revision=p.grant_revision ${scope} AND ${target}=p.base_revision AND EXISTS(SELECT 1 ${ownerJoin}))
      AND NOT EXISTS(SELECT 1 FROM agent_attribute_commit WHERE proposal_id=p.proposal_id)`,
      )
      .bind(
        input.operation_id,
        input.candidate,
        candidateHash,
        origin,
        time,
        input.proposal_id,
        input.request_hash,
        time,
        key.key_id,
        key.resource,
        owner.account,
        time,
        owner.secretHash,
        owner.account,
        time,
      ),
    session
      .prepare(
        `INSERT INTO agent_audit SELECT ?,p.grant_id,'attribute-prepare','prepared',p.attribute_id,?
      FROM agent_attribute_proposal p WHERE p.proposal_id=? AND changes()=1`,
      )
      .bind(randomId(), time, input.proposal_id),
  ]);
  const existing = await session
    .prepare(
      `SELECT operation_id,candidate_sha256 FROM agent_attribute_commit
    WHERE proposal_id=? AND account_id=?`,
    )
    .bind(p.proposal_id, owner.account)
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

export async function currentRevision(db: D1Database, owner: Owner) {
  const row = await db
    .withSession('first-primary')
    .prepare(
      `SELECT
    COALESCE((SELECT revision FROM vault_attribute_head WHERE account_id=ss.account_id
      AND attribute_id='owner_note'),0) AS revision ${ownerJoin}`,
    )
    .bind(owner.secretHash, owner.account, now())
    .first<{ revision: number }>();
  if (!row) throw new Error('Access denied');
  return row.revision;
}

export async function cleanup(db: D1Database) {
  await db.batch([
    db
      .prepare(
        `UPDATE agent_attribute_proposal SET state='invalid',payload=NULL WHERE expires_at<=? AND state IN('pending','approved')`,
      )
      .bind(now()),
    db.prepare('DELETE FROM agent_attribute_proposal WHERE created_at<?').bind(now() - 30 * 86400),
  ]);
}
