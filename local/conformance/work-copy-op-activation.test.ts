/** Real Native projection; offline OP derivation issues no provider operation. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { copyJobFixture } from './support/work-copy-job-fixture.ts';
import {
  copyOPActivationConfiguration,
  verifyCopyOPActivationConfiguration,
} from '../../scripts/work-copy-op-activation.ts';
import {
  CLOSED_OP_COPY_VARS,
  assertClosedProductionCopyGraph,
} from '../../scripts/production-work-copy-graph.ts';
import { PRODUCTION_WORK_TARGET } from '../../scripts/production-work-adoption.ts';
import type { CopyBindingTarget } from '../../scripts/work-copy-binding-plan.ts';

test('an exact Native disclosure changes only the six OP gates and its activation selector', async () => {
  const f = await copyJobFixture({ LOCAL_COPY_TRIGGER_DISABLED: 'true' });
  try {
    const baseline = JSON.parse(await readFile('crates/worker/wrangler.production.jsonc', 'utf8'));
    baseline.vars.WORK_COPY_RECIPIENT = f.nativeDisclosure.manifest.recipient;
    baseline.vars.WORK_COPY_WORKLOAD = f.nativeDisclosure.manifest.workload;
    const target: CopyBindingTarget = {
      format_version: 1,
      account_id: PRODUCTION_WORK_TARGET.account,
      authority_id: PRODUCTION_WORK_TARGET.authority,
      artifacts_namespace: baseline.vars.WORK_ARTIFACTS_NAMESPACE,
      worker_prefix: 'mikaki-work',
      op: {
        service: baseline.name,
        source_commit: 'a'.repeat(40),
        version_id: '11111111-1111-4111-8111-111111111111',
        attestation_sha256: 'b'.repeat(64),
      },
      checkpoint: {
        service: PRODUCTION_WORK_TARGET.checkpoint,
        version_id: '22222222-2222-4222-8222-222222222222',
        namespace_id: baseline.vars.WORK_CHECKPOINT_NAMESPACE_ID,
        object_id: 'c'.repeat(64),
      },
      host: {
        bucket_name: 'synthetic-git-sources',
        disclosure_digest: f.nativeDisclosure.digest,
        registry_sha256: 'd'.repeat(64),
        image_digest: 'sha256:' + 'e'.repeat(64),
      },
      wrapping_key: {
        version: 1,
        custody_reference: 'synthetic-custody',
        review_sha256: 'f'.repeat(64),
      },
    };
    const before = structuredClone(baseline);
    const candidate = copyOPActivationConfiguration(baseline, f.nativeDisclosure, target);
    assert.deepEqual(baseline, before);
    const expected = structuredClone(baseline);
    for (const name of CLOSED_OP_COPY_VARS) expected.vars[name] = 'true';
    expected.vars.WORK_COPY_ACTIVATION_PROFILE = 'single-disclosure';
    expected.vars.WORK_COPY_ACTIVATION_DISCLOSURE_DIGEST = f.nativeDisclosure.digest;
    assert.deepEqual(candidate, expected);
    assert.throws(() => assertClosedProductionCopyGraph(candidate), /remain closed/);
    const report = verifyCopyOPActivationConfiguration(
      candidate,
      baseline,
      f.nativeDisclosure,
      target,
    );
    assert.equal(report.external_effects, false);
    assert.equal(report.current_owner_session_source_and_consent_verified, false);
    for (const mutate of [
      (c: any) => {
        c.vars.WORK_COPY_ACTIVATION_DISCLOSURE_DIGEST = '0'.repeat(64);
      },
      (c: any) => {
        c.vars.WORK_COPY_ACTIVATION_PROFILE = 'closed';
      },
      (c: any) => {
        c.vars.WORK_COPY_EXECUTION_ENABLED = 'false';
      },
      (c: any) => {
        c.secrets.required = [];
      },
      (c: any) => {
        c.routes = [];
      },
      (c: any) => {
        c.r2_buckets[0].bucket_name = 'substitute';
      },
      (c: any) => {
        c.services.push({
          binding: 'ADMIN',
          service: baseline.name,
          entrypoint: 'OpAuthorityAdmin',
        });
      },
    ]) {
      const changed = structuredClone(candidate);
      mutate(changed);
      assert.throws(
        () => verifyCopyOPActivationConfiguration(changed, baseline, f.nativeDisclosure, target),
        /configuration_changed/,
      );
    }
    for (const altered of [
      { ...f.nativeDisclosure, current_sources: false },
      { ...f.nativeDisclosure, digest: '0'.repeat(64) },
      { ...f.nativeDisclosure, manifest: { ...f.nativeDisclosure.manifest, expires_at: 1 } },
      {
        ...f.nativeDisclosure,
        manifest: { ...f.nativeDisclosure.manifest, recipient: 'substitute' },
      },
    ])
      assert.throws(() => copyOPActivationConfiguration(baseline, altered, target));
    for (const change of [
      { account_id: '0'.repeat(32) },
      { authority_id: 'substitute' },
      { artifacts_namespace: 'substitute' },
      { checkpoint: { ...target.checkpoint, namespace_id: '0'.repeat(32) } },
      { wrapping_key: { ...target.wrapping_key, version: 2 } },
    ])
      assert.throws(() =>
        copyOPActivationConfiguration(baseline, f.nativeDisclosure, { ...target, ...change }),
      );
    for (const table of [
      'work_copy_consent',
      'work_copy_job',
      'work_credential_attempt',
      'work_grant',
      'work_run',
    ])
      assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM ' + table).first('n'), 0);
    assert.equal((await f.remote()).repos.length, 0);
  } finally {
    await f.close();
  }
});
