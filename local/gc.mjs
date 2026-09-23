import { p, now, query } from './shared.mjs';

// Store this bound when the record is created; never recompute old retention
// using a newly shortened policy. Expiry and retention have separate meanings.
export const retained = (expiry) =>
  expiry + p('oidc.validation.clock_skew') + p('retention.gc_grace');

// Parent expiry bounds every code/token in this local profile. Keep all issuance
// evidence until that bound, its saved grace/audit retention, and notification GC.
const expiredParent = (reference) => `EXISTS(SELECT 1 FROM sso_session ss
  WHERE ss.sso_id=${reference} AND ss.expires_at<=?1 AND ss.gc_after<=?1
  AND NOT EXISTS(SELECT 1 FROM sso_logout_event e WHERE e.sso_id=ss.sso_id)
  AND NOT EXISTS(SELECT 1 FROM revocation_event r WHERE r.account_id=ss.account_id
    AND r.through_epoch>=ss.epoch AND r.expanded=0))`;
const expiredCode = (reference) => `EXISTS(SELECT 1 FROM authorization_code ac
  JOIN client_session cs ON cs.client_id=ac.client_id AND cs.sid=ac.sid
  WHERE ac.code_hash=${reference} AND ${expiredParent('cs.sso_id')})`;

const targets = {
  op: [
    ['ceremony', 'gc_after<=?1 AND expires_at<=?1'],
    [
      'op_login',
      'gc_after<=?1 AND expires_at<=?1 AND NOT EXISTS(SELECT 1 FROM ceremony WHERE login_id=op_login.id)',
    ],
    ['logout_transaction', 'gc_after<=?1 AND expires_at<=?1'],
    ['assertion_use', 'gc_after<=?1 AND retain_until<=?1'],
    ['rate_window', 'gc_after<=?1'],
    [
      'revocation_event',
      `gc_after<=?1 AND expanded=1 AND NOT EXISTS(SELECT 1 FROM sso_session ss WHERE ss.account_id=revocation_event.account_id AND ss.epoch<=revocation_event.through_epoch)`,
    ],
    [
      'logout_retry_audit',
      'gc_after<=?1 AND NOT EXISTS(SELECT 1 FROM sso_logout_event e WHERE e.id=logout_retry_audit.event_id)',
    ],
    [
      'logout_delivery',
      `gc_after<=?1 AND deadline<=?1 AND finished_at IS NOT NULL
      AND state IN ('delivered','failed','expired') AND lease IS NULL AND lease_until IS NULL
      AND EXISTS(SELECT 1 FROM sso_logout_event e WHERE e.id=logout_delivery.event_id
        AND e.expanded=1 AND e.deadline<=?1 AND e.gc_after<=?1) AND NOT EXISTS(SELECT 1 FROM sso_logout_event e JOIN sso_session ss ON ss.sso_id=e.sso_id JOIN revocation_event r ON r.account_id=ss.account_id AND r.through_epoch>=ss.epoch WHERE e.id=logout_delivery.event_id AND r.expanded=0)`,
    ],
    [
      'sso_logout_event',
      `gc_after<=?1 AND deadline<=?1 AND expanded=1
      AND NOT EXISTS(SELECT 1 FROM sso_session ss JOIN revocation_event r ON r.account_id=ss.account_id AND r.through_epoch>=ss.epoch WHERE ss.sso_id=sso_logout_event.sso_id AND r.expanded=0)
      AND NOT EXISTS(SELECT 1 FROM logout_delivery d WHERE d.event_id=sso_logout_event.id)`,
    ],
    ['token_issue', expiredCode('token_issue.code_hash')],
    ['code_context', expiredCode('code_context.code_hash')],
    [
      'authorization_code',
      `EXISTS(SELECT 1 FROM client_session cs
      WHERE cs.client_id=authorization_code.client_id AND cs.sid=authorization_code.sid
      AND ${expiredParent('cs.sso_id')})
      AND NOT EXISTS(SELECT 1 FROM token_issue ti WHERE ti.code_hash=authorization_code.code_hash)
      AND NOT EXISTS(SELECT 1 FROM code_context cc WHERE cc.code_hash=authorization_code.code_hash)`,
    ],
    [
      'client_session',
      `${expiredParent('client_session.sso_id')}
      AND NOT EXISTS(SELECT 1 FROM authorization_code ac WHERE ac.client_id=client_session.client_id AND ac.sid=client_session.sid)`,
    ],
    ['sso_context', expiredParent('sso_context.sso_id')],
    [
      'sso_session',
      `${expiredParent('sso_session.sso_id')}
      AND NOT EXISTS(SELECT 1 FROM client_session cs WHERE cs.sso_id=sso_session.sso_id)
      AND NOT EXISTS(SELECT 1 FROM sso_context x WHERE x.sso_id=sso_session.sso_id)
      AND NOT EXISTS(SELECT 1 FROM logout_transaction tx WHERE tx.sso_id=sso_session.sso_id)`,
    ],
  ],
  rp: [
    ['login', 'gc_after<=?1 AND expires_at<=?1'],
    ['logout_transaction', 'gc_after<=?1 AND expires_at<=?1'],
    ['app_session', 'gc_after<=?1 AND parent_expires_at<=?1'],
    ['logout_use', 'expires_at<=?1'],
    [
      'tombstone',
      'expires_at<=?1 AND NOT EXISTS(SELECT 1 FROM app_session WHERE sid=tombstone.sid)',
    ],
  ],
};

export async function collect(db, role, at = now()) {
  if (!Object.hasOwn(targets, role)) throw new Error('invalid_gc_role');
  let remaining = p('retention.gc_batch_size');
  const deleted = {};
  // Names/predicates are a static allowlist, never request input. Each DELETE
  // chooses and checks its candidates in one atomic statement, so a concurrent
  // retention extension cannot be overwritten by an earlier candidate read.
  for (const [table, predicate] of targets[role]) {
    if (!remaining) break;
    const result = await query(
      db,
      `DELETE FROM ${table} WHERE rowid IN (
      SELECT rowid FROM ${table} WHERE ${predicate} ORDER BY rowid LIMIT ?2)`,
      [at, remaining],
    ).run();
    deleted[table] = result.meta.changes;
    remaining -= result.meta.changes;
  }
  const count = p('retention.gc_batch_size') - remaining;
  if (count) console.info(JSON.stringify({ event: 'gc_complete', role, count, deleted }));
  return { count, deleted };
}
