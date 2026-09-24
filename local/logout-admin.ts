import { revokeAccountSessions } from './account-admin.ts';
// Trusted local runner API. Never mount this on an unauthenticated HTTP route.
import { p, now, uuid, query, guard } from './shared.ts';
import { retained } from './gc.ts';

export async function listLogoutEvents(db: any) {
  return (
    await query(
      db,
      `SELECT e.id,e.revision,e.deadline,e.gc_after,e.expanded,
    COUNT(d.id) AS deliveries,
    SUM(CASE WHEN d.state IN ('failed','expired') THEN 1 ELSE 0 END) AS retryable
    FROM sso_logout_event e LEFT JOIN logout_delivery d ON d.event_id=e.id
    GROUP BY e.id ORDER BY e.created_at,e.id LIMIT 100`,
    ).all()
  ).results;
}

export async function retryLogout(
  db: any,
  {
    event,
    revision,
    deadline,
    retainUntil,
    actor,
    reason,
  }: {
    event: string;
    revision: number;
    deadline: number;
    retainUntil: number;
    actor: string;
    reason: string;
  },
) {
  const at = now();
  if (
    typeof event !== 'string' ||
    !event ||
    event.length > 128 ||
    !Number.isSafeInteger(revision) ||
    revision < 0 ||
    !Number.isSafeInteger(deadline) ||
    deadline <= at ||
    !Number.isSafeInteger(retainUntil) ||
    retainUntil < retained(deadline + p('retention.delivery_result_ttl')) ||
    typeof actor !== 'string' ||
    !actor ||
    actor.length > 128 ||
    !['network_recovered', 'configuration_fixed', 'operator_retry'].includes(reason)
  )
    throw new Error('invalid_retry_parameters');
  const operation = uuid();
  await db.batch([
    // Completeness is checked inside the write transaction, against the original
    // session membership. A partially GC'd event cannot silently retry a subset.
    ...guard(
      db,
      `EXISTS(SELECT 1 FROM sso_logout_event e WHERE e.id=? AND e.revision=?
      AND e.expanded=1 AND e.deadline<? AND ?>CAST(strftime('%s','now') AS INTEGER)
      AND EXISTS(SELECT 1 FROM logout_delivery d WHERE d.event_id=e.id AND d.state IN ('failed','expired'))
      AND NOT EXISTS(SELECT 1 FROM logout_delivery d WHERE d.event_id=e.id AND d.state IN ('pending','leased'))
      AND NOT EXISTS(SELECT 1 FROM client_session cs WHERE cs.sso_id=e.sso_id AND NOT EXISTS(
        SELECT 1 FROM logout_delivery d WHERE d.event_id=e.id AND d.client_id=cs.client_id AND d.sid=cs.sid)))`,
      [event, revision, deadline, deadline],
    ),
    query(
      db,
      `INSERT INTO logout_retry_audit(operation_id,event_id,revision,actor,reason,created_at,
      old_deadline,new_deadline,retain_until,targets,gc_after)
      SELECT ?,e.id,e.revision,?,?,?,e.deadline,?,?,
        (SELECT json_group_array(json_object('client_id',d.client_id,'sid',d.sid,'attempts',d.attempts,
          'state',d.state,'last_status',d.last_status,'reason',d.reason)) FROM logout_delivery d
          WHERE d.event_id=e.id AND d.state IN ('failed','expired')),?
      FROM sso_logout_event e WHERE e.id=?`,
      [
        operation,
        actor,
        reason,
        at,
        deadline,
        retainUntil,
        Math.max(retainUntil, retained(at + p('retention.audit_ttl'))),
        event,
      ],
    ),
    query(
      db,
      `UPDATE sso_logout_event SET revision=revision+1,deadline=?,gc_after=MAX(gc_after,?) WHERE id=?`,
      [deadline, retainUntil, event],
    ),
    query(
      db,
      `UPDATE logout_delivery SET state='pending',attempts=0,next_at=?,deadline=?,
      gc_after=MAX(COALESCE(gc_after,0),?),lease=NULL,lease_until=NULL,finished_at=NULL,
      last_status=NULL,reason=NULL WHERE event_id=? AND state IN ('failed','expired')`,
      [at, deadline, retainUntil, event],
    ),
  ]);
  return { operation, event, revision: revision + 1 };
}

export async function adminCommand(db: any, line: string, actor: string) {
  const parts = line.trim().split(/\s+/);
  if (parts.length === 1 && parts[0] === 'logout-list') return listLogoutEvents(db);
  if (parts.length === 1 && parts[0] === 'account-list')
    return (
      await query(
        db,
        'SELECT account_id,epoch,active FROM account_security ORDER BY account_id LIMIT 100',
      ).all()
    ).results;
  if (parts.length === 4 && parts[0] === 'account-revoke' && /^\d+$/.test(parts[2]))
    return revokeAccountSessions(db, {
      account: parts[1],
      epoch: Number(parts[2]),
      actor,
      reason: parts[3],
    });
  if (parts.length !== 6 || parts[0] !== 'logout-retry' || !/^\d+$/.test(parts[2]))
    throw new Error(
      'usage: logout-list | logout-retry EVENT REVISION DEADLINE_UTC RETAIN_UNTIL_UTC REASON',
    );
  function time(value: string) {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) throw new Error('invalid_utc_time');
    const millis = Date.parse(value);
    if (!Number.isFinite(millis) || new Date(millis).toISOString().replace('.000Z', 'Z') !== value)
      throw new Error('invalid_utc_time');
    return millis / 1000;
  }
  return retryLogout(db, {
    event: parts[1],
    revision: Number(parts[2]),
    deadline: time(parts[3]),
    retainUntil: time(parts[4]),
    actor,
    reason: parts[5],
  });
}
