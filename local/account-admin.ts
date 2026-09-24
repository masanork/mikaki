// Trusted local operator functions; no public management endpoint.
import { p, now, uuid, query, guard } from './shared.ts';
import { retained } from './gc.ts';

export async function revokeAccountSessions(
  db: any,
  {
    account,
    epoch,
    actor,
    reason,
  }: { account: string; epoch: number; actor: string; reason: string },
) {
  if (
    typeof account !== 'string' ||
    !account ||
    account.length > 128 ||
    !Number.isSafeInteger(epoch) ||
    epoch < 0 ||
    epoch >= Number.MAX_SAFE_INTEGER ||
    typeof actor !== 'string' ||
    !actor ||
    actor.length > 128 ||
    !['session_reset', 'security_incident'].includes(reason)
  )
    throw new Error('invalid_revocation_parameters');
  const operation = uuid(),
    at = now(),
    deadline = at + p('logout_delivery.retry_deadline');
  await db.batch([
    query(
      db,
      'UPDATE account_security SET epoch=epoch+1 WHERE account_id=? AND epoch=? AND active=1',
      [account, epoch],
    ),
    ...guard(db, 'changes()=1'),
    query(
      db,
      `INSERT INTO revocation_event(operation_id,account_id,through_epoch,created_at,actor,reason,deadline,gc_after)
      VALUES(?,?,?,?,?,?,?,?)`,
      [
        operation,
        account,
        epoch,
        at,
        actor,
        reason,
        deadline,
        retained(Math.max(deadline, at + p('retention.audit_ttl'))),
      ],
    ),
  ]);
  return { operation, account, epoch: epoch + 1 };
}

export async function expandAccountRevocations(db: any) {
  await db.batch([
    // There is at most one logout event per SSO. Its SSO UUID is also a stable
    // event ID here; browser logout may already have created that event.
    query(
      db,
      `INSERT INTO sso_logout_event(id,sso_id,created_at,deadline,gc_after)
      SELECT ss.sso_id,ss.sso_id,MIN(r.created_at),MIN(r.deadline),
        MAX(MAX(COALESCE(ss.gc_after,0),ss.expires_at+?,r.gc_after))
      FROM revocation_event r JOIN sso_session ss ON ss.account_id=r.account_id AND ss.epoch<=r.through_epoch
      WHERE r.expanded=0 AND r.deadline IS NOT NULL AND r.gc_after IS NOT NULL
        AND NOT EXISTS(SELECT 1 FROM sso_logout_event e WHERE e.sso_id=ss.sso_id)
      GROUP BY ss.sso_id
      ORDER BY MIN(r.created_at),ss.sso_id LIMIT ?`,
      [retained(0), p('logout_delivery.fanout_batch_size')],
    ),
    query(
      db,
      `UPDATE revocation_event SET expanded=1 WHERE expanded=0 AND deadline IS NOT NULL AND gc_after IS NOT NULL
      AND NOT EXISTS(SELECT 1 FROM sso_session ss WHERE ss.account_id=revocation_event.account_id
        AND ss.epoch<=revocation_event.through_epoch AND NOT EXISTS(SELECT 1 FROM sso_logout_event e WHERE e.sso_id=ss.sso_id))`,
    ),
  ]);
}
