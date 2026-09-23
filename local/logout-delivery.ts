import { expandAccountRevocations } from './account-admin.ts';
import { retained } from './gc.ts';
import { CLIENT, RP, p, now, uuid, query, row, signed } from './shared.ts';

const policy = (name) => p(`logout_delivery.${name}`);

// The epoch-wide event in the design model has a different scope: this event
// revokes one SSO session. Insert it in the same batch as the revocation.
export function logoutEvent(db, ssoId) {
  const at = now();
  return query(
    db,
    `INSERT INTO sso_logout_event(id,sso_id,created_at,deadline,gc_after)
    SELECT ?,sso_id,?,?,MAX(expires_at+?,?,COALESCE(gc_after,0)) FROM sso_session WHERE sso_id=?`,
    [
      uuid(),
      at,
      at + policy('retry_deadline'),
      retained(0),
      retained(at + Math.max(policy('retry_deadline'), p('retention.audit_ttl'))),
      ssoId,
    ],
  );
}

export async function fanout(db) {
  // A single bounded batch across all events; NOT EXISTS makes restart safe.
  await db.batch([
    query(
      db,
      `INSERT INTO logout_delivery(event_id,client_id,sid,created_at,deadline,next_at)
      SELECT e.id,c.client_id,c.sid,e.created_at,e.deadline,e.created_at
      FROM sso_logout_event e JOIN client_session c USING(sso_id)
      WHERE e.expanded=0 AND NOT EXISTS (
        SELECT 1 FROM logout_delivery d WHERE d.event_id=e.id AND d.client_id=c.client_id AND d.sid=c.sid)
      ORDER BY e.created_at,e.id,c.client_id,c.sid LIMIT ?`,
      [policy('fanout_batch_size')],
    ),
    query(
      db,
      `UPDATE sso_logout_event SET expanded=1 WHERE expanded=0 AND NOT EXISTS (
      SELECT 1 FROM client_session c WHERE c.sso_id=sso_logout_event.sso_id AND NOT EXISTS (
        SELECT 1 FROM logout_delivery d WHERE d.event_id=sso_logout_event.id AND d.client_id=c.client_id AND d.sid=c.sid))`,
    ),
  ]);
}

export async function claim(db, at = now()) {
  // Claim only when ready to execute. SQLite serializes this entire predicate
  // and update, including the client-wide concurrency limit across invocations.
  const lease = uuid();
  return row(
    db,
    `UPDATE logout_delivery SET state='leased',lease=?,lease_until=?,attempts=attempts+1
    WHERE id=(SELECT d.id FROM logout_delivery d
      WHERE d.state IN ('pending','leased') AND d.next_at<=? AND COALESCE(d.lease_until,0)<=?
        AND d.deadline>? AND d.attempts<? AND
        (SELECT COUNT(*) FROM logout_delivery busy WHERE busy.client_id=d.client_id
          AND busy.state='leased' AND busy.lease_until>?)<?
      ORDER BY d.next_at,d.id LIMIT 1) RETURNING *`,
    [
      lease,
      at + policy('lease_ttl'),
      at,
      at,
      at,
      policy('max_attempts'),
      at,
      policy('max_inflight_per_client'),
    ],
  );
}

export function outcome(task, status, retryAfter, at = now(), random = Math.random) {
  if (status >= 200 && status < 300) return { state: 'delivered', reason: 'success', next: at };
  if (status !== 0 && status !== 408 && status !== 429 && !(status >= 500 && status <= 599))
    return { state: 'failed', reason: 'http_permanent', next: at };
  if (at >= task.deadline) return { state: 'expired', reason: 'deadline', next: at };
  if (task.attempts >= policy('max_attempts'))
    return { state: 'failed', reason: 'attempt_limit', next: at };
  const base = policy('base_delay');
  const cap = Math.min(policy('max_delay'), base * 2 ** Math.min(task.attempts - 1, 52));
  let next = at + Math.ceil(base + random() * (cap - base));
  if (retryAfter) {
    const value = retryAfter.trim();
    // Accept delta-seconds or IMF-fixdate, not Date.parse's permissive numeric dates.
    const retryAt = /^\d+$/.test(value)
      ? at + Number(value)
      : /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(
            value,
          )
        ? Date.parse(value) / 1000
        : NaN;
    if (!Number.isNaN(retryAt)) next = Math.max(next, retryAt);
  }
  return next >= task.deadline
    ? { state: 'expired', reason: 'deadline', next: at }
    : { state: 'pending', reason: status ? 'http_retry' : 'transport', next };
}

export async function settle(db, task, result, status, at = now()) {
  return query(
    db,
    `UPDATE logout_delivery SET state=?,reason=?,next_at=?,last_status=?,
      lease=NULL,lease_until=NULL,finished_at=?,gc_after=MAX(COALESCE(gc_after,0),?)
    WHERE id=? AND state='leased' AND lease=? AND lease_until>?`,
    [
      result.state,
      result.reason,
      result.next,
      status || null,
      result.state === 'pending' ? null : at,
      retained(at + p('retention.delivery_result_ttl')),
      task.id,
      task.lease,
      at,
    ],
  ).run();
}

export async function expire(db, at = now()) {
  await query(
    db,
    `UPDATE logout_delivery SET
    state=CASE WHEN deadline<=? THEN 'expired' ELSE 'failed' END,
    reason=CASE WHEN deadline<=? THEN 'deadline' ELSE 'attempt_limit' END,
    lease=NULL,lease_until=NULL,finished_at=?,gc_after=MAX(COALESCE(gc_after,0),?)
    WHERE state IN ('pending','leased') AND COALESCE(lease_until,0)<=?
      AND (deadline<=? OR attempts>=?)`,
    [at, at, at, retained(at + p('retention.delivery_result_ttl')), at, at, policy('max_attempts')],
  ).run();
}

export async function sendLogout(env, task, transport = fetch) {
  // Only the registered local RP is supported. Never derive a destination from
  // a token or event payload; dynamic client registration is a separate feature.
  if (task.client_id !== CLIENT) return { status: 400, retryAfter: null };
  const jwt = await signed(
    env,
    'op',
    {
      sid: task.sid,
      jti: uuid(),
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
    },
    task.client_id,
    p('oidc_logout.token_ttl'),
    'logout+jwt',
  );
  const result = await transport(`${RP}/backchannel`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ logout_token: jwt }),
    redirect: 'manual',
    signal: AbortSignal.timeout(p('oidc.backchannel.request_timeout') * 1000),
  });
  // Response content is never interpreted or logged. Cancel at the configured
  // byte ceiling; do not buffer an untrusted arbitrarily large response.
  const reader = result.body?.getReader();
  if (reader) {
    try {
      let bytes = 0;
      while (bytes < policy('max_response_bytes')) {
        const chunk = await reader.read();
        if (chunk.done) break;
        bytes += chunk.value.byteLength;
      }
    } finally {
      await reader.cancel();
    }
  }
  return { status: result.status, retryAfter: result.headers.get('retry-after') };
}

export async function deliveryHealth(db, at = now()) {
  const health = await row(
    db,
    `SELECT
    COUNT(CASE WHEN state IN ('pending','leased') THEN 1 END) AS pending,
    MIN(CASE WHEN state IN ('pending','leased') THEN created_at END) AS oldest,
    COUNT(CASE WHEN state='failed' THEN 1 END) AS failed,
    COUNT(CASE WHEN state='expired' THEN 1 END) AS expired FROM logout_delivery`,
  );
  const events = await row(
    db,
    `SELECT COUNT(*) AS unexpanded,MIN(created_at) AS oldest FROM (SELECT created_at FROM sso_logout_event WHERE expanded=0 UNION ALL SELECT created_at FROM revocation_event WHERE expanded=0)`,
  );
  const oldest = [health.oldest, events.oldest].filter((v) => v !== null);
  const oldestAge = oldest.length ? Math.max(0, at - Math.min(...oldest)) : 0;
  return {
    pending: health.pending,
    unexpanded: events.unexpanded,
    failed: health.failed,
    expired: health.expired,
    oldest_age_seconds: oldestAge,
    alert: !!(
      health.failed ||
      health.expired ||
      health.pending >= policy('backlog_alert_count') ||
      oldestAge >= policy('oldest_pending_alert_age')
    ),
  };
}

export async function deliver(db, env) {
  await expandAccountRevocations(db);
  await fanout(db);
  await expire(db);
  for (let i = 0; i < policy('claim_batch_size'); i++) {
    const task = await claim(db);
    if (!task) break;
    let response;
    try {
      response = await sendLogout(env, task);
    } catch {
      response = { status: 0, retryAfter: null };
    }
    await settle(db, task, outcome(task, response.status, response.retryAfter), response.status);
  }
  const health = await deliveryHealth(db);
  if (health.alert) console.warn(JSON.stringify({ event: 'logout_delivery_health', ...health }));
  return health;
}
