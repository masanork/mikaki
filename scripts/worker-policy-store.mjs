import { createHash, randomUUID } from 'node:crypto';

const REVISION = /^[0-9a-f]{64}$/;
const NUMERIC_FIELDS = [
  'assertion_ttl_seconds',
  'clock_skew_seconds',
  'authorization_code_ttl_seconds',
  'request_target_bytes',
  'parameter_count',
  'state_bytes',
  'nonce_bytes',
  'access_token_ttl_seconds',
  'id_token_ttl_seconds',
  'response_bytes',
  'jwt_bytes',
  'form_body_bytes',
  'token_rate_window_seconds',
  'token_attempts_per_client',
];
const FIELDS = new Set([
  ...NUMERIC_FIELDS,
  'schema_version',
  'policy_revision',
  'projection_revision',
]);

export function validateWorkerPolicyProjection(policy) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error('worker policy must be an object');
  }
  if (
    Object.keys(policy).length !== FIELDS.size ||
    Object.keys(policy).some((key) => !FIELDS.has(key))
  ) {
    throw new Error('worker policy fields do not match schema');
  }
  const { projection_revision: projectionRevision, ...contents } = policy;
  if (!REVISION.test(projectionRevision) || !REVISION.test(contents.policy_revision)) {
    throw new Error('invalid worker policy revision');
  }
  if (
    policy.schema_version !== 4 ||
    NUMERIC_FIELDS.some((field) => !Number.isSafeInteger(policy[field]) || policy[field] <= 0) ||
    policy.jwt_bytes > 1_048_576 ||
    policy.form_body_bytes > 1_048_576 ||
    policy.jwt_bytes + 4096 > policy.form_body_bytes ||
    policy.request_target_bytes > 1_048_576 ||
    policy.parameter_count > 128 ||
    policy.state_bytes > policy.request_target_bytes ||
    policy.nonce_bytes > policy.request_target_bytes ||
    policy.response_bytes > 1_048_576 ||
    ![10, 60].includes(policy.token_rate_window_seconds) ||
    policy.token_attempts_per_client > 1000 ||
    [
      'assertion_ttl_seconds',
      'clock_skew_seconds',
      'authorization_code_ttl_seconds',
      'access_token_ttl_seconds',
      'id_token_ttl_seconds',
    ].some((field) => policy[field] > 2_147_483_647)
  ) {
    throw new Error('worker policy values are outside the supported range');
  }
  const canonical = Object.fromEntries(
    Object.entries(contents).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
  const digest = createHash('sha256').update(JSON.stringify(canonical), 'ascii').digest('hex');
  if (digest !== projectionRevision) {
    throw new Error('worker policy projection hash mismatch');
  }
  return JSON.stringify(policy);
}

/** Stage a complete Worker projection and atomically switch the active revision. */
export async function activateWorkerPolicy(db, policy, { expectedRevision = null, actor, reason }) {
  const json = validateWorkerPolicyProjection(policy);
  if (
    typeof actor !== 'string' ||
    actor.length < 1 ||
    actor.length > 128 ||
    typeof reason !== 'string' ||
    reason.length < 1 ||
    reason.length > 512 ||
    (expectedRevision !== null && !REVISION.test(expectedRevision))
  ) {
    throw new Error('invalid worker policy activation metadata');
  }
  const current = await db
    .prepare('SELECT projection_revision,generation FROM runtime_policy_active WHERE id=1')
    .first();
  if ((current?.projection_revision ?? null) !== expectedRevision) {
    throw new Error('active worker policy revision changed');
  }
  const generation = (current?.generation ?? 0) + 1;
  const now = Math.floor(Date.now() / 1000);
  const operationId = randomUUID();
  const activation = current
    ? db
        .prepare(
          'UPDATE runtime_policy_active SET projection_revision=?,generation=? WHERE id=1 AND projection_revision=? AND generation=?',
        )
        .bind(policy.projection_revision, generation, expectedRevision, current.generation)
    : db
        .prepare(
          'INSERT INTO runtime_policy_active(id,projection_revision,generation) SELECT 1,?,1 WHERE NOT EXISTS(SELECT 1 FROM runtime_policy_active WHERE id=1)',
        )
        .bind(policy.projection_revision);
  await db.batch([
    db
      .prepare(
        'INSERT INTO runtime_policy_version(projection_revision,policy_revision,projection_json,created_at) VALUES(?,?,?,?) ON CONFLICT(projection_revision) DO NOTHING',
      )
      .bind(policy.projection_revision, policy.policy_revision, json, now),
    activation,
    db
      .prepare(
        'INSERT INTO atomic_guard(operation_id,passed) VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
      )
      .bind(operationId),
    db
      .prepare(
        'INSERT INTO runtime_policy_audit(generation,previous_revision,projection_revision,changed_at,actor,reason) VALUES(?,?,?,?,?,?)',
      )
      .bind(generation, expectedRevision, policy.projection_revision, now, actor, reason),
    db.prepare('DELETE FROM atomic_guard WHERE operation_id=?').bind(operationId),
  ]);
  return { generation, projectionRevision: policy.projection_revision };
}
