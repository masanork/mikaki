import {
  digest,
  grantInput,
  now,
  randomId,
  type Grant,
  type Owner,
  type Operation,
  type Proposal,
} from './model.js';
import { authorizationDetailsCondition } from './authorization-details.js';

// One source predicate for creation, disclosure, audit, status, and OAuth. A label
// or same-named v1 attribute can never satisfy a v2 source identity.
export const liveSource = `((g.storage_version=1 AND EXISTS(
 SELECT 1 FROM vault_attribute_head h WHERE h.account_id=g.account_id AND h.attribute_id='name'
 AND h.deleted=0 AND h.revision=g.source_revision)) OR (g.storage_version=2 AND EXISTS(
 SELECT 1 FROM vault_owner_record_head h JOIN vault_owner_key_head k
 ON k.account_id=h.account_id AND k.vault_id=h.vault_id
 WHERE h.account_id=g.account_id AND h.vault_id=g.source_vault_id
 AND h.collection_id=g.source_collection_id AND h.record_id=g.source_record_id
 AND h.kind=g.source_kind AND h.revision=g.source_revision AND h.deleted=0 AND h.format_version=2
 AND h.ciphertext_sha256=g.source_ciphertext_sha256 AND h.key_generation=g.source_key_generation
 AND k.origin=g.source_origin AND k.key_generation=g.source_key_generation
 AND k.revision=g.source_owner_key_revision AND k.format_version=2
 AND k.suite='PRF-HKDF-SHA256-AES256GCM-v2')))`;
// Every authorization-sensitive read starts a fresh primary session and includes the full join.
export const activeJoin = `FROM agent_grant g
 JOIN agent_recipient_key rk ON rk.key_id=g.recipient_key_id AND rk.state='active'
 JOIN account_security a ON a.account_id=g.account_id AND a.active=1 AND a.epoch=g.owner_epoch
 JOIN credential c ON c.credential_id=g.credential_id AND c.account_id=g.account_id AND c.active=1
 WHERE g.revoked=0 AND g.expires_at>? AND g.expires_at>unixepoch()
 AND g.recipient_key_id=? AND g.resource=? AND g.encrypted_snapshot IS NOT NULL AND ${liveSource}`;
export const ownerJoin = `FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id
 JOIN account_security a ON a.account_id=ss.account_id AND a.active=1 AND a.epoch=ss.epoch
 JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1
 WHERE sx.secret_hash=? AND ss.account_id=? AND ss.revoked=0 AND ss.expires_at>? AND ss.expires_at>unixepoch()`;

const oauthAccess = `SELECT t.scopes FROM agent_oauth_token t
  JOIN agent_oauth_client oc ON oc.client_id=t.client_id AND oc.active=1
  WHERE t.token_hash=? AND t.grant_id=g.grant_id AND t.grant_revision=g.revision
    AND t.resource=g.resource AND t.revoked=0 AND t.expires_at>unixepoch()
    AND ${authorizationDetailsCondition('t.authorization_details')}
    AND NOT EXISTS(SELECT 1 FROM json_each(t.scopes) s
      WHERE NOT EXISTS(SELECT 1 FROM json_each(g.operations) o WHERE o.value=s.value))`;
// Rechecked inside each side-effect statement, including individual token revocation.
export const accessCondition = `(g.token_hash=? OR EXISTS(${oauthAccess}))`;
export const accessValues = (grant: Grant) => [
  grant.access_token_hash ?? grant.token_hash,
  grant.access_token_hash ?? grant.token_hash,
];

export async function ownerActive(db: D1Database, owner: Owner) {
  return (
    (await db
      .withSession('first-primary')
      .prepare(`SELECT ss.account_id ${ownerJoin}`)
      .bind(owner.secretHash, owner.account, now())
      .first()) !== null
  );
}

export async function active(
  db: D1Database,
  tokenHash: string,
  keyId: string,
  resource: string,
): Promise<Grant> {
  const grant = await db
    .withSession('first-primary')
    .prepare(
      `SELECT g.*,CASE WHEN g.token_hash=? THEN g.operations ELSE (${oauthAccess}) END AS operations
      ${activeJoin} AND ${accessCondition}`,
    )
    .bind(tokenHash, tokenHash, now(), keyId, resource, tokenHash, tokenHash)
    .first<Grant>();
  if (!grant || !grant.encrypted_snapshot) throw new Error('Access denied');
  return { ...grant, access_token_hash: tokenHash };
}

export async function createGrant(
  db: D1Database,
  owner: Owner,
  input: ReturnType<typeof grantInput.parse>,
) {
  const requestHash = await digest(JSON.stringify(input));
  const existing = await db
    .withSession('first-primary')
    .prepare('SELECT request_hash FROM agent_grant WHERE grant_id=? AND account_id=?')
    .bind(input.grant_id, owner.account)
    .first<{ request_hash: string }>();
  if (existing) {
    if (existing.request_hash !== requestHash || !(await ownerActive(db, owner)))
      throw new Error('Conflict');
    return;
  }
  const time = now();
  if (input.expires_at < time + 60 || input.expires_at > time + 86400)
    throw new Error('Invalid expiry');
  const session = db.withSession('first-primary');
  const version = input.storage_version === 2 ? 2 : 1;
  const source = input.storage_version === 2 ? input.source : null;
  const authority = input.storage_version === 2 ? input.authority : null;
  if (source && source.owner_id !== owner.account) throw new Error('Owner mismatch');
  const sourceRevision =
    input.storage_version === 2 ? input.source.revision : input.source_revision;
  const sourceColumns = [
    'storage_version',
    'account_id',
    'source_revision',
    'source_origin',
    'source_vault_id',
    'source_collection_id',
    'source_record_id',
    'source_kind',
    'source_ciphertext_sha256',
    'source_key_generation',
    'source_owner_key_revision',
  ];
  const sourceValues = [
    version,
    owner.account,
    sourceRevision,
    source?.origin ?? null,
    source?.vault_id ?? null,
    source?.collection_id ?? null,
    source?.record_id ?? null,
    source?.kind ?? null,
    source?.ciphertext_sha256 ?? null,
    authority?.key_generation ?? null,
    authority?.owner_key_revision ?? null,
  ];
  const result = await session.batch([
    session
      .prepare(
        `WITH proposed(${sourceColumns.join(',')}) AS (VALUES(${sourceColumns.map(() => '?').join(',')}))
      INSERT INTO agent_grant (
      grant_id,account_id,owner_epoch,credential_id,delegate,provider,resource,source_revision,
      recipient_key_id,operations,document_ids,encrypted_snapshot,token_hash,request_hash,created_at,expires_at,
      storage_version,source_origin,source_vault_id,source_collection_id,source_record_id,source_kind,
      source_ciphertext_sha256,source_key_generation,source_owner_key_revision
    ) SELECT ?,ss.account_id,ss.epoch,ss.credential_id,?,?,?,g.source_revision,?,?,?,?,?,?,?,?,
      g.storage_version,g.source_origin,g.source_vault_id,g.source_collection_id,g.source_record_id,g.source_kind,
      g.source_ciphertext_sha256,g.source_key_generation,g.source_owner_key_revision
      ${ownerJoin.replace(' WHERE', ' CROSS JOIN proposed g WHERE')} AND ss.expires_at>unixepoch()
      AND ${liveSource}
      AND EXISTS(SELECT 1 FROM agent_recipient_key rk WHERE rk.key_id=? AND rk.state='active')
      AND (SELECT count(*) FROM agent_grant g WHERE g.account_id=ss.account_id AND g.revoked=0 AND g.expires_at>?)<20`,
      )
      .bind(
        ...sourceValues,
        input.grant_id,
        input.delegate,
        input.provider,
        input.resource,
        input.recipient_key_id,
        JSON.stringify(input.operations),
        JSON.stringify(input.document_ids),
        JSON.stringify(input.envelope),
        input.token_hash,
        requestHash,
        time,
        input.expires_at,
        owner.secretHash,
        owner.account,
        time,
        input.recipient_key_id,
        time,
      ),
    session
      .prepare(
        `INSERT INTO agent_audit SELECT ?,grant_id,'grant','created',NULL,? FROM agent_grant
      WHERE grant_id=? AND request_hash=?`,
      )
      .bind(randomId(), time, input.grant_id, requestHash),
  ]);
  if (!result[0].meta.changes) throw new Error('Access denied');
}

export async function auditAccess(
  db: D1Database,
  grant: Grant,
  op: Operation,
  documentId?: string,
) {
  const result = await db
    .withSession('first-primary')
    .prepare(
      `INSERT INTO agent_audit SELECT ?,g.grant_id,?,'authorized',?,? ${activeJoin}
     AND g.grant_id=? AND g.revision=? AND ${accessCondition}`,
    )
    .bind(
      randomId(),
      op,
      documentId ?? null,
      now(),
      now(),
      grant.recipient_key_id,
      grant.resource,
      grant.grant_id,
      grant.revision,
      ...accessValues(grant),
    )
    .run();
  if (!result.meta.changes) throw new Error('Access denied');
}

export async function denied(db: D1Database, grant: Grant, op: Operation) {
  await db
    .prepare(`INSERT INTO agent_audit VALUES(?,?,?,'denied',NULL,?)`)
    .bind(randomId(), grant.grant_id, op, now())
    .run();
}

export async function ownerStatus(
  db: D1Database,
  owner: Owner,
  keyId: string,
  resource: string,
  storageVersion: 1 | 2 = 1,
) {
  if (!(await ownerActive(db, owner))) throw new Error('Access denied');
  const session = db.withSession('first-primary');
  const grants = await session
    .prepare(
      `SELECT g.grant_id,g.delegate,g.provider,g.resource,g.source_revision,
    g.operations,g.document_ids,g.created_at,g.expires_at,g.revoked,g.revision,g.recipient_key_id,
    g.storage_version,g.source_origin,g.source_vault_id,g.source_collection_id,g.source_record_id,
    g.source_kind,g.source_ciphertext_sha256,g.source_key_generation,g.source_owner_key_revision,
    CASE WHEN g.revoked=0 AND g.expires_at>? AND g.recipient_key_id=? AND g.resource=?
      AND a.active=1 AND a.epoch=g.owner_epoch AND c.active=1 AND g.expires_at>unixepoch()
      AND g.encrypted_snapshot IS NOT NULL
      AND EXISTS(SELECT 1 FROM agent_recipient_key rk WHERE rk.key_id=g.recipient_key_id AND rk.state='active')
      AND ${liveSource} THEN 1 ELSE 0 END AS active
    FROM agent_grant g JOIN account_security a ON a.account_id=g.account_id
    JOIN credential c ON c.credential_id=g.credential_id AND c.account_id=g.account_id
    WHERE g.account_id=? AND g.storage_version=? ORDER BY g.created_at DESC LIMIT 100`,
    )
    .bind(now(), keyId, resource, owner.account, storageVersion)
    .all();
  const audit = await session
    .prepare(
      `SELECT au.* FROM agent_audit au JOIN agent_grant g ON g.grant_id=au.grant_id
    WHERE g.account_id=? AND g.storage_version=? ORDER BY au.created_at DESC,au.event_id DESC LIMIT 100`,
    )
    .bind(owner.account, storageVersion)
    .all();
  const proposals = await session
    .prepare(
      `SELECT p.* FROM agent_proposal p JOIN agent_grant g ON g.grant_id=p.grant_id
    WHERE g.account_id=? AND g.storage_version=? ORDER BY p.created_at DESC LIMIT 20`,
    )
    .bind(owner.account, storageVersion)
    .all();
  const drafts = await session
    .prepare(
      `SELECT d.* FROM agent_draft d JOIN agent_proposal p ON p.proposal_id=d.proposal_id
      JOIN agent_grant g ON g.grant_id=p.grant_id WHERE d.account_id=? AND g.storage_version=? ORDER BY d.created_at DESC LIMIT 20`,
    )
    .bind(owner.account, storageVersion)
    .all();
  if (!(await ownerActive(db, owner))) throw new Error('Access denied');
  return {
    grants: grants.results,
    audit: audit.results,
    proposals: proposals.results,
    drafts: drafts.results,
  };
}

// No v2 target may enter the legacy owner-note capability/commit state machine.
export async function requireLegacyAttributeGrant(
  db: D1Database,
  owner: Owner,
  raw: unknown,
  capability: boolean,
) {
  const input = raw as { grant_id?: unknown; proposal_id?: unknown } | null;
  const id = capability ? input?.grant_id : input?.proposal_id;
  if (typeof id !== 'string') throw new Error('Access denied');
  const row = await db
    .withSession('first-primary')
    .prepare(
      capability
        ? 'SELECT 1 FROM agent_grant WHERE grant_id=? AND account_id=? AND storage_version=1'
        : `SELECT 1 FROM agent_attribute_proposal p JOIN agent_grant g ON g.grant_id=p.grant_id
       WHERE p.proposal_id=? AND g.account_id=? AND g.storage_version=1`,
    )
    .bind(id, owner.account)
    .first();
  if (!row) throw new Error('Access denied');
}

export async function revoke(db: D1Database, owner: Owner, grantId: string | null) {
  const time = now();
  const session = db.withSession('first-primary');
  await session.batch([
    session
      .prepare(
        `INSERT INTO agent_audit SELECT ? || g.grant_id,g.grant_id,'revoke','revoked',NULL,?
      FROM agent_grant g WHERE g.account_id=? AND (? IS NULL OR g.grant_id=?) AND g.revoked=0
      AND EXISTS(SELECT 1 ${ownerJoin})`,
      )
      // One event ID per row is required for revoke-all.
      .bind(
        randomId(),
        time,
        owner.account,
        grantId,
        grantId,
        owner.secretHash,
        owner.account,
        time,
      ),
    session
      .prepare(
        `UPDATE agent_grant SET revoked=1,revision=revision+1,encrypted_snapshot=NULL
      WHERE account_id=? AND (? IS NULL OR grant_id=?) AND revoked=0 AND EXISTS(SELECT 1 ${ownerJoin})`,
      )
      .bind(owner.account, grantId, grantId, owner.secretHash, owner.account, time),
    session
      .prepare(
        `UPDATE agent_proposal SET text=NULL,state='rejected' WHERE state!='executed'
      AND grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=? AND revoked=1)`,
      )
      .bind(owner.account),
  ]);
  if (!(await ownerActive(db, owner))) throw new Error('Access denied');
}

export async function propose(
  db: D1Database,
  grant: Grant,
  input: {
    proposal_id: string;
    document_id: string;
    title: string;
    text: string;
  },
) {
  if (!JSON.parse(grant.document_ids).includes(input.document_id)) throw new Error('Access denied');
  const requestHash = await digest(JSON.stringify(input));
  const session = db.withSession('first-primary');
  const existing = await session
    .prepare('SELECT * FROM agent_proposal WHERE proposal_id=? AND grant_id=?')
    .bind(input.proposal_id, grant.grant_id)
    .first<Proposal>();
  if (existing) {
    if (existing.request_hash !== requestHash) throw new Error('Conflict');
    return {
      proposal_id: existing.proposal_id,
      state: existing.state,
      request_hash: existing.request_hash,
    };
  }
  const result = await session.batch([
    session
      .prepare(
        `INSERT INTO agent_proposal(proposal_id,grant_id,request_hash,document_id,title,text,expires_at,created_at)
      SELECT ?,g.grant_id,?,?,?,?,MIN(g.expires_at,?),? ${activeJoin} AND g.grant_id=? AND g.revision=?
      AND ${accessCondition}
      AND (SELECT count(*) FROM agent_proposal p WHERE p.grant_id=g.grant_id AND p.state IN('pending','approved'))<20`,
      )
      .bind(
        input.proposal_id,
        requestHash,
        input.document_id,
        input.title,
        input.text,
        now() + 3600,
        now(),
        now(),
        grant.recipient_key_id,
        grant.resource,
        grant.grant_id,
        grant.revision,
        ...accessValues(grant),
      ),
    session
      .prepare(
        `INSERT INTO agent_audit SELECT ?,grant_id,'propose','pending',document_id,?
      FROM agent_proposal WHERE proposal_id=? AND request_hash=?`,
      )
      .bind(randomId(), now(), input.proposal_id, requestHash),
  ]);
  if (!result[0].meta.changes) throw new Error('Access denied');
  return { proposal_id: input.proposal_id, state: 'pending', request_hash: requestHash };
}

export async function decide(
  db: D1Database,
  owner: Owner,
  proposalId: string,
  requestHash: string,
  approve: boolean,
  keyId: string,
  resource: string,
) {
  const session = db.withSession('first-primary');
  const result = await session.batch([
    session
      .prepare(
        `UPDATE agent_proposal SET state=?,approved_revision=(SELECT revision FROM agent_grant WHERE grant_id=agent_proposal.grant_id)
      WHERE proposal_id=? AND request_hash=? AND state='pending' AND expires_at>?
      AND grant_id IN(SELECT g.grant_id ${activeJoin} AND g.account_id=?) AND EXISTS(SELECT 1 ${ownerJoin})`,
      )
      .bind(
        approve ? 'approved' : 'rejected',
        proposalId,
        requestHash,
        now(),
        now(),
        keyId,
        resource,
        owner.account,
        owner.secretHash,
        owner.account,
        now(),
      ),
    session
      .prepare(
        `INSERT INTO agent_audit SELECT ?,grant_id,'decision',state,document_id,?
      FROM agent_proposal WHERE proposal_id=? AND request_hash=? AND state=?
      AND grant_id IN(SELECT grant_id FROM agent_grant WHERE account_id=?) AND changes()=1`,
      )
      .bind(
        randomId(),
        now(),
        proposalId,
        requestHash,
        approve ? 'approved' : 'rejected',
        owner.account,
      ),
  ]);
  if (!result[0].meta.changes) {
    const prior = await session
      .prepare(
        `SELECT p.state FROM agent_proposal p JOIN agent_grant g ON g.grant_id=p.grant_id
      WHERE p.proposal_id=? AND p.request_hash=? AND g.account_id=?`,
      )
      .bind(proposalId, requestHash, owner.account)
      .first<{ state: string }>();
    if (
      !prior ||
      !(await ownerActive(db, owner)) ||
      !(approve ? ['approved', 'executed'].includes(prior.state) : prior.state === 'rejected')
    )
      throw new Error('Access denied');
  }
}

export async function execute(
  db: D1Database,
  grant: Grant,
  proposalId: string,
  requestHash: string,
) {
  const session = db.withSession('first-primary');
  const draftId = randomId();
  await session.batch([
    session
      .prepare(
        `INSERT INTO agent_draft SELECT ?,g.account_id,p.proposal_id,p.title,p.text,?
      FROM agent_proposal p JOIN agent_grant g ON g.grant_id=p.grant_id
      WHERE p.proposal_id=? AND p.request_hash=? AND p.grant_id=? AND p.state='approved'
      AND p.text IS NOT NULL AND p.expires_at>? AND p.approved_revision=g.revision
      AND g.grant_id IN(SELECT g.grant_id ${activeJoin} AND ${accessCondition})`,
      )
      .bind(
        draftId,
        now(),
        proposalId,
        requestHash,
        grant.grant_id,
        now(),
        now(),
        grant.recipient_key_id,
        grant.resource,
        ...accessValues(grant),
      ),
    session
      .prepare(
        `UPDATE agent_proposal SET state='executed',result_id=(SELECT draft_id FROM agent_draft d WHERE d.proposal_id=agent_proposal.proposal_id)
      WHERE proposal_id=? AND grant_id=? AND request_hash=? AND state='approved'
      AND EXISTS(SELECT 1 FROM agent_draft d WHERE d.proposal_id=agent_proposal.proposal_id)`,
      )
      .bind(proposalId, grant.grant_id, requestHash),
    session
      .prepare(
        `INSERT INTO agent_audit SELECT ?,grant_id,'execute','executed',document_id,?
      FROM agent_proposal WHERE proposal_id=? AND result_id=?`,
      )
      .bind(randomId(), now(), proposalId, draftId),
  ]);
  const result = await session
    .prepare(
      "SELECT result_id FROM agent_proposal WHERE proposal_id=? AND grant_id=? AND request_hash=? AND state='executed'",
    )
    .bind(proposalId, grant.grant_id, requestHash)
    .first<{ result_id: string }>();
  if (!result) throw new Error('Access denied');
  return { draft_id: result.result_id, state: 'executed' };
}

export async function cleanup(db: D1Database) {
  await db.batch([
    db
      .prepare('UPDATE agent_grant SET encrypted_snapshot=NULL WHERE expires_at<=? OR revoked=1')
      .bind(now()),
    db
      .prepare(
        "UPDATE agent_proposal SET text=NULL,state='rejected' WHERE expires_at<=? AND state IN('pending','approved')",
      )
      .bind(now()),
    db.prepare('DELETE FROM agent_audit WHERE created_at<?').bind(now() - 30 * 86400),
    db.prepare('DELETE FROM agent_draft WHERE created_at<?').bind(now() - 30 * 86400),
    db.prepare('UPDATE agent_proposal SET text=NULL WHERE expires_at<=?').bind(now()),
    db
      .prepare(
        `DELETE FROM agent_proposal WHERE created_at<?
      AND NOT EXISTS(SELECT 1 FROM agent_draft d WHERE d.proposal_id=agent_proposal.proposal_id)`,
      )
      .bind(now() - 30 * 86400),
    db
      .prepare(
        `DELETE FROM agent_grant WHERE expires_at<?
      AND NOT EXISTS(SELECT 1 FROM agent_proposal p WHERE p.grant_id=agent_grant.grant_id)
      AND NOT EXISTS(SELECT 1 FROM agent_attribute_proposal p WHERE p.grant_id=agent_grant.grant_id)
      AND NOT EXISTS(SELECT 1 FROM agent_oauth_request r WHERE r.grant_id=agent_grant.grant_id)
      AND NOT EXISTS(SELECT 1 FROM agent_audit a WHERE a.grant_id=agent_grant.grant_id)`,
      )
      .bind(now() - 30 * 86400),
  ]);
}
