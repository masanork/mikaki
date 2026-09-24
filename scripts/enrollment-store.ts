import { createHash, randomBytes, randomUUID } from 'node:crypto';

export async function issueBootstrapInvite(db: any, actor: string, reason: string) {
  if (
    typeof actor !== 'string' ||
    actor.length < 1 ||
    actor.length > 128 ||
    typeof reason !== 'string' ||
    reason.length < 1 ||
    reason.length > 512
  ) {
    throw new Error('actor and reason are required');
  }
  const secret = randomBytes(32).toString('base64url');
  const inviteHash = createHash('sha256').update(secret).digest('base64url');
  const operationId = randomUUID();
  await db.batch([
    db.prepare(
      "UPDATE enrollment_invite SET revoked=1 WHERE kind='bootstrap' AND consumed_at IS NULL AND revoked=0 AND expires_at<=CAST(strftime('%s','now') AS INTEGER)",
    ),
    db
      .prepare(
        "INSERT INTO enrollment_invite(invite_hash,kind,issued_at,expires_at) SELECT ?,'bootstrap',CAST(strftime('%s','now') AS INTEGER),CAST(strftime('%s','now') AS INTEGER)+p.bootstrap_ttl_seconds FROM enrollment_policy p JOIN bootstrap_state b ON b.id=1 AND b.closed=0 WHERE p.id=1 AND NOT EXISTS(SELECT 1 FROM enrollment_invite WHERE kind='bootstrap' AND consumed_at IS NULL AND revoked=0)",
      )
      .bind(inviteHash),
    db
      .prepare(
        'INSERT INTO atomic_guard(operation_id,passed) VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
      )
      .bind(operationId),
    db
      .prepare(
        "INSERT INTO enrollment_invite_audit(operation_id,invite_hash,action,actor,reason,occurred_at) VALUES(?1,?2,'issue-bootstrap',?3,?4,CAST(strftime('%s','now') AS INTEGER))",
      )
      .bind(operationId, inviteHash, actor, reason),
    db.prepare('DELETE FROM atomic_guard WHERE operation_id=?').bind(operationId),
  ]);
  const row = await db
    .prepare('SELECT expires_at FROM enrollment_invite WHERE invite_hash=?')
    .bind(inviteHash)
    .first();
  if (!row) throw new Error('bootstrap invite was not issued');
  return { invitation: secret, expiresAt: row.expires_at };
}
