/** Operator separation is a deployment policy; it never disables checkpoint checks. */
import assert from 'node:assert/strict';

export type WorkAdministrationPolicy = {
  format_version: 1;
  operator_separation: 'optional' | 'required';
};
export const PRODUCTION_WORK_ADMINISTRATION: WorkAdministrationPolicy = {
  format_version: 1,
  operator_separation: 'optional',
};
export function assertWorkAdministrationPolicy(
  policy: WorkAdministrationPolicy,
  operators: { primary: string; checkpoint: string },
) {
  assert.deepEqual(Object.keys(operators).sort(), ['checkpoint', 'primary']);
  assert.deepEqual(Object.keys(policy).sort(), ['format_version', 'operator_separation']);
  assert.equal(policy.format_version, 1);
  assert.ok(['optional', 'required'].includes(policy.operator_separation));
  for (const value of Object.values(operators))
    assert.ok(typeof value === 'string' && value.length > 0 && value.length <= 256);
  if (policy.operator_separation === 'required')
    assert.notEqual(operators.primary, operators.checkpoint, 'work_separate_operators_required');
  return {
    operator_separation: policy.operator_separation,
    operators_distinct: operators.primary !== operators.checkpoint,
    checkpoint_required: true as const,
    // Identity comparison is only a policy check, never proof of provider permissions.
    control_plane_separation_verified: false as const,
  };
}
