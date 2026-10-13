/** Exact OP configuration delta for review; no upload, consent or copy transport. */
import assert from 'node:assert/strict';
import { z } from 'zod';
import { disclosureSchema } from '../crates/worker/ui/work-preparation-view.ts';
import { copyBindingTargetSchema, type CopyBindingTarget } from './work-copy-binding-plan.ts';
import {
  assertClosedProductionCopyGraph,
  CLOSED_OP_COPY_VARS,
  PRODUCTION_COPY_PREFIX,
} from './production-work-copy-graph.ts';
import { PRODUCTION_WORK_TARGET } from './production-work-adoption.ts';
import { disclosureProjectionDigest } from './work-disclosure-digest.ts';

type OPConfig = {
  name: string;
  account_id: string;
  vars: Record<string, string>;
  services?: { binding: string; service: string; entrypoint?: string }[];
  secrets: { required: string[] };
  [key: string]: unknown;
};
const recordSchema = z.strictObject({
  kind: z.literal('disclosure'),
  digest: z.string().regex(/^[a-f0-9]{64}$/),
  manifest: disclosureSchema,
  current_sources: z.literal(true),
});

/** The caller must pin the complete baseline/target/record bytes externally.
 * A saved projection is not live authority; Native repeats all owner checks.
 */
export function copyOPActivationConfiguration(
  baseline: OPConfig,
  recordInput: unknown,
  targetInput: CopyBindingTarget,
) {
  const record = recordSchema.parse(recordInput);
  assert.equal(
    disclosureProjectionDigest(record.manifest),
    record.digest,
    'copy_op_disclosure_manifest_changed',
  );
  const target = copyBindingTargetSchema.parse(targetInput);
  assert.equal(target.account_id, PRODUCTION_WORK_TARGET.account, 'copy_op_account_changed');
  assert.equal(target.authority_id, PRODUCTION_WORK_TARGET.authority, 'copy_op_authority_changed');
  assert.equal(
    target.checkpoint.service,
    PRODUCTION_WORK_TARGET.checkpoint,
    'copy_op_checkpoint_changed',
  );
  assert.equal(assertClosedProductionCopyGraph(baseline), true);
  assert.equal(baseline.name, target.op.service, 'copy_op_service_changed');
  assert.equal(baseline.account_id, target.account_id, 'copy_op_account_changed');
  assert.equal(baseline.vars.WORK_ARTIFACTS_ACCOUNT, target.account_id, 'copy_op_account_changed');
  assert.equal(
    baseline.vars.WORK_ARTIFACTS_NAMESPACE,
    target.artifacts_namespace,
    'copy_op_namespace_changed',
  );
  assert.equal(target.worker_prefix, PRODUCTION_COPY_PREFIX, 'copy_op_prefix_changed');
  assert.equal(
    baseline.vars.WORK_CHECKPOINT_NAMESPACE_ID,
    target.checkpoint.namespace_id,
    'copy_op_checkpoint_changed',
  );
  assert.equal(
    baseline.vars.WORK_CREDENTIAL_KEY_FLOOR,
    String(target.wrapping_key.version),
    'copy_op_key_changed',
  );
  assert.ok(
    baseline.secrets.required.includes(`WORK_CREDENTIAL_KEY_V${target.wrapping_key.version}`),
    'copy_op_custody_missing',
  );
  for (const name of [
    'WORK_OWNER_API_ENABLED',
    'WORK_SOURCE_API_ENABLED',
    'WORK_PREPARATION_REVIEW_ENABLED',
    'WORK_COPY_CONSENT_ENABLED',
  ])
    assert.equal(baseline.vars[name], 'true', 'copy_op_owner_gates_missing');
  assert.equal(record.digest, target.host.disclosure_digest, 'copy_op_disclosure_changed');
  assert.equal(
    record.manifest.recipient,
    baseline.vars.WORK_COPY_RECIPIENT,
    'copy_op_recipient_changed',
  );
  assert.equal(
    record.manifest.workload,
    baseline.vars.WORK_COPY_WORKLOAD,
    'copy_op_workload_changed',
  );
  assert.ok(
    record.manifest.expires_at > Math.floor(Date.now() / 1000),
    'copy_op_disclosure_expired',
  );
  const config = structuredClone(baseline);
  for (const name of CLOSED_OP_COPY_VARS) config.vars[name] = 'true';
  config.vars.WORK_COPY_ACTIVATION_PROFILE = 'single-disclosure';
  config.vars.WORK_COPY_ACTIVATION_DISCLOSURE_DIGEST = record.digest;
  return config;
}

export function verifyCopyOPActivationConfiguration(
  candidate: unknown,
  baseline: OPConfig,
  record: unknown,
  target: CopyBindingTarget,
) {
  assert.deepEqual(
    candidate,
    copyOPActivationConfiguration(baseline, record, target),
    'copy_op_configuration_changed',
  );
  return {
    stage: 'offline-single-disclosure-op-review-not-deployed-or-authorized',
    current_owner_session_source_and_consent_verified: false,
    provider_versions_resources_bytes_and_custody_verified: false,
    external_effects: false,
  };
}
