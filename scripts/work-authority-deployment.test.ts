import assert from 'node:assert/strict';
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import {
  AUTHORITY_ACCOUNT,
  AUTHORITY_INPUTS,
  AUTHORITY_TARGET,
  OP_MEMBERS,
  authorityInventory,
  authorityPlan,
  authorityTemplates,
  digest,
  packetJson,
} from './work-authority-packet.ts';
import { REVIEWED_AUTHORITY_MANIFEST } from './allocate-work-authority.ts';
import {
  REVIEWED_BOOTSTRAP_MANIFEST,
  authorityDeploymentConfigs,
  inspectAuthorityAllocation,
  materializeAuthorityDeployment,
  readAuthorityAllocation,
  verifyAuthorityDeployment,
} from './work-authority-deployment.ts';
import type { AllocationEvidence } from './work-authority-deployment.ts';
import { authorityBootstrapOperatorConfig } from './work-authority-bootstrap.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const date = '2026-10-10T12:00:00.000Z';
const bytes = (v: unknown) => Buffer.from(JSON.stringify(v, null, 2) + '\n');
const source = { commit: 'a'.repeat(40), clean: true as const };
const kinds = ['database', 'vault', 'logout_dlq', 'logout_queue'] as const;
const resources = kinds.map((resource, index) => ({
  resource,
  name: AUTHORITY_TARGET[resource],
  id:
    resource === 'database'
      ? '11111111-1111-4111-8111-111111111111'
      : resource === 'vault'
        ? AUTHORITY_TARGET.vault
        : String(index).repeat(32),
  created_at: date,
}));
function evidenceFixture(): AllocationEvidence {
  const journal = 'local/generated/work-authority-allocation/allocate-AAAAAA';
  const reservation = {
    account_id: AUTHORITY_ACCOUNT,
    target: AUTHORITY_TARGET,
    packet: 'local/generated/work-authority-qualification/authority-nMECMX',
    manifest_sha256: REVIEWED_AUTHORITY_MANIFEST,
    source_commit: source.commit,
    journal,
  };
  const records: object[] = [
    {
      event: 'selected',
      mode: 'allocate',
      source_commit: source.commit,
      allocator_sha256: 'b'.repeat(64),
      packet: reservation.packet,
      manifest_sha256: REVIEWED_AUTHORITY_MANIFEST,
      packet_source: source,
      account_id: AUTHORITY_ACCOUNT,
    },
    { event: 'reserved', account_id: AUTHORITY_ACCOUNT, target: AUTHORITY_TARGET },
  ];
  for (const v of resources) {
    const base = `/accounts/${AUTHORITY_ACCOUNT}`;
    records.push(
      {
        event: 'create_intent',
        resource: v.resource,
        method: 'POST',
        path:
          v.resource === 'database'
            ? `${base}/d1/database`
            : v.resource === 'vault'
              ? `${base}/r2/buckets`
              : `${base}/queues`,
        body: v.resource.startsWith('logout_') ? { queue_name: v.name } : { name: v.name },
      },
      { event: 'create_observed', identity: v },
      { event: 'identity_verified', identity: v },
    );
  }
  records.push(
    { event: 'allocation_complete', resources },
    {
      event: 'report',
      mode: 'allocate',
      report: {
        stage: 'resources-allocated-workers-not-deployed-authority-not-enrolled',
        account_id: AUTHORITY_ACCOUNT,
        resources,
        workers: [AUTHORITY_TARGET.op, AUTHORITY_TARGET.checkpoint].map((name) => ({
          name,
          present: false,
        })),
        checkpoint_namespace_id: null,
        bootstrap_invoked: false,
        owner_enrolled: false,
        production_mutations: 0,
        artifacts_calls: 0,
        provider_creates: 4,
      },
    },
  );
  return {
    format_version: 1,
    reservation: bytes(reservation).toString(),
    records: records.map((r) => JSON.stringify({ recorded_at: date, ...r }) + '\n'),
  };
}
function reviewFixture(evidence: AllocationEvidence, parentSha = REVIEWED_BOOTSTRAP_MANIFEST) {
  const observation = inspectAuthorityAllocation(evidence);
  return {
    format_version: 1,
    account_id: AUTHORITY_ACCOUNT,
    packet_sha256: parentSha,
    allocation_sha256: observation.allocation_sha256,
    reservation_sha256: observation.reservation_sha256,
    browser_origin: 'https://authority.example.test',
    ownership: {
      op_operator: 'test-op',
      checkpoint_operator: 'test-checkpoint',
      op_recovery: 'test-op-recovery',
      checkpoint_recovery: 'test-checkpoint-recovery',
      review_sha256: 'c'.repeat(64),
      same_account_control_plane: true,
    },
    signing: { custody_id: 'test-key-custodian', review_sha256: 'd'.repeat(64) },
  };
}
function alter(evidence: AllocationEvidence, index: number, change: (r: any) => void) {
  const copy = structuredClone(evidence);
  const r = JSON.parse(copy.records[index]!);
  change(r);
  copy.records[index] = JSON.stringify(r) + '\n';
  return copy;
}

test('complete acknowledged identities produce closed configs with a separate private bootstrap connection', () => {
  const evidence = evidenceFixture(),
    review = reviewFixture(evidence);
  const observed = inspectAuthorityAllocation(evidence);
  assert.equal(observed.complete, true);
  assert.deepEqual(observed.verified, resources);
  assert.deepEqual(observed.unknown, []);
  const configs = authorityDeploymentConfigs(review, evidence);
  assert.equal(configs.op.d1_databases[0]!.database_id, resources[0]!.id);
  assert.equal(configs.op.vars.MIKAKI_ISSUER, review.browser_origin);
  assert.deepEqual(
    configs.op.services.map((s) => s.entrypoint),
    ['WorkCheckpointService'],
  );
  assert.deepEqual(
    configs.operator.services.map((s) => s.entrypoint),
    ['WorkCheckpointBootstrap'],
  );
  assert.equal(configs.checkpoint.vars.WORK_BOOTSTRAP_PACKET_SHA256, REVIEWED_BOOTSTRAP_MANIFEST);
  for (const config of [configs.op, configs.checkpoint]) {
    assert.deepEqual(config.routes, []);
    assert.equal(config.workers_dev, false);
    assert.equal(config.preview_urls, false);
  }
  assert.deepEqual(configs.op.triggers.crons, []);
  for (const k of [
    'WORK_PREPARATION_COMPOSE_ENABLED',
    'WORK_COPY_EXECUTION_ENABLED',
    'WORK_EFFECT_STORE_ENABLED',
    'WORK_MINT_STORE_ENABLED',
    'WORK_GIT_STORE_ENABLED',
  ] as const)
    assert.equal(configs.op.vars[k], 'false');
  assert.deepEqual(configs.op.secrets.required, ['OP_PRIVATE_JWK', 'MIKAKI_READY_TOKEN']);
  assert.equal('artifacts' in configs.op, false);
  assert.equal('services' in configs.checkpoint, false);
  assert.equal('OP_PRIVATE_JWK' in configs.op.vars, false);
});

test('lost or missing acknowledgment cannot be promoted by readback, a report or another create', () => {
  const evidence = evidenceFixture();
  const unknown = structuredClone(evidence);
  unknown.records = unknown.records.slice(0, 9); // two verified resources, then DLQ intent
  unknown.records.push(
    JSON.stringify({ recorded_at: date, event: 'create_outcome_unknown', resource: 'logout_dlq' }) +
      '\n',
  );
  const observation = inspectAuthorityAllocation(unknown);
  assert.equal(observation.complete, false);
  assert.deepEqual(observation.unknown, ['logout_dlq']);
  assert.deepEqual(observation.unattempted, ['logout_queue']);
  assert.throws(
    () => authorityDeploymentConfigs(reviewFixture(unknown), unknown),
    /requires_reconciliation/,
  );
  for (const extra of [
    evidence.records[9]!,
    evidence.records[11]!,
    evidence.records[14]!,
    evidence.records[15]!,
  ]) {
    const forged = structuredClone(unknown);
    forged.records.push(extra);
    assert.throws(() => inspectAuthorityAllocation(forged));
  }
  const crashed = structuredClone(evidence);
  crashed.records = crashed.records.slice(0, 9);
  assert.deepEqual(inspectAuthorityAllocation(crashed).unknown, ['logout_dlq']);
  const lostRead = structuredClone(evidence);
  lostRead.records = lostRead.records.slice(0, 10);
  const readObservation = inspectAuthorityAllocation(lostRead);
  assert.deepEqual(readObservation.unknown, []);
  assert.deepEqual(readObservation.unverified, ['logout_dlq']);
  assert.equal(readObservation.complete, false);
  const noFinalReport = structuredClone(evidence);
  noFinalReport.records.pop();
  assert.equal(inspectAuthorityAllocation(noFinalReport).complete, false);
});

test('substituted identities, scope, ledger order, secrets and resource aliases refuse materialization', () => {
  const e = evidenceFixture();
  for (const changed of [
    alter(e, 3, (r) => {
      r.identity.id = 'd0258938-0d27-4110-8aa9-c82e20f3885b';
    }),
    alter(e, 4, (r) => {
      r.identity.created_at = '2026-10-10T12:00:01Z';
    }),
    alter(e, 2, (r) => {
      r.resource = 'vault';
    }),
    alter(e, 0, (r) => {
      r.source_commit = 'f'.repeat(40);
    }),
    alter(e, 0, (r) => {
      r.token = 'must-never-be-copied';
    }),
    alter(e, 9, (r) => {
      r.identity.id = '0'.repeat(32);
    }),
    alter(e, 15, (r) => {
      r.report.workers[0].present = true;
    }),
  ])
    assert.throws(() => inspectAuthorityAllocation(changed));
  const reversed = structuredClone(e);
  [reversed.records[3], reversed.records[4]] = [reversed.records[4]!, reversed.records[3]!];
  assert.throws(() => inspectAuthorityAllocation(reversed));
  const wrong = structuredClone(e);
  const reservation = JSON.parse(wrong.reservation);
  reservation.target.op = 'mikaki-auth';
  wrong.reservation = JSON.stringify(reservation);
  assert.throws(() => inspectAuthorityAllocation(wrong));
  assert.throws(() => authorityBootstrapOperatorConfig('d0258938-0d27-4110-8aa9-c82e20f3885b'));
});

test('review pins, origin and cross-boundary operator/recovery claims are closed inputs', () => {
  const e = evidenceFixture(),
    good = reviewFixture(e);
  for (const origin of [
    'http://authority.example.test',
    'https://auth.mikaki.org',
    'https://mikaki-native.tossa.app',
    'https://user:secret@authority.example.test',
    'https://authority.example.test/',
    'https://authority.example.test/path',
    'https://authority.example.test:8443',
    'https://127.0.0.1',
    'https://-bad.example.test',
    'https://bad..example.test',
  ]) {
    assert.throws(() => authorityDeploymentConfigs({ ...good, browser_origin: origin }, e));
  }
  assert.throws(
    () => authorityDeploymentConfigs({ ...good, allocation_sha256: 'e'.repeat(64) }, e),
    /review_changed/,
  );
  assert.throws(
    () => authorityDeploymentConfigs({ ...good, packet_sha256: 'e'.repeat(64) }, e),
    /parent_review_changed/,
  );
  for (const owner of [good.ownership.op_operator, good.ownership.op_recovery])
    assert.throws(
      () =>
        authorityDeploymentConfigs(
          { ...good, ownership: { ...good.ownership, checkpoint_recovery: owner } },
          e,
        ),
      /separation_denied/,
    );
  assert.throws(() =>
    authorityDeploymentConfigs({ ...good, signing: { ...good.signing, private_jwk: 'secret' } }, e),
  );
});

/** Inventory fixtures are synthetic, never provider receipts or product qualification. */
async function packetFixture() {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'mikaki-authority-child-test-')));
  const parent = join(directory, 'parent');
  await mkdir(parent);
  const write = async (path: string, value: string | Buffer) => {
    await mkdir(dirname(join(parent, path)), { recursive: true });
    await writeFile(join(parent, path), value);
  };
  for (const name of OP_MEMBERS) await write(`op/build/${name}`, 'synthetic member');
  await write(
    'op/build/index_bg.wasm',
    Buffer.concat([
      Buffer.from([0, 97, 115, 109, 1, 0, 0, 0, 0, 41, 0]),
      Buffer.from(source.commit),
    ]),
  );
  await write('checkpoint/worker.mjs', 'synthetic checkpoint');
  for (const name of ['build.json', 'build-1.log', 'build-2.log', 'build-3.log'])
    await write(name, 'synthetic evidence');
  for (const name of AUTHORITY_INPUTS) await write(`inputs/${name.replaceAll('/', '__')}`, 'input');
  for (const location of ['migrations', 'work-migrations'])
    for (const name of (await readdir(join(root, 'crates/worker', location))).filter((n) =>
      n.endsWith('.sql'),
    ))
      await write(
        `migrations/${name}`,
        await readFile(join(root, 'crates/worker', location, name)),
      );
  for (const [name, config] of Object.entries(authorityTemplates(AUTHORITY_ACCOUNT)))
    await packetJson(join(parent, name, 'wrangler.template.json'), config);
  await packetJson(join(parent, 'plan.json'), authorityPlan(AUTHORITY_ACCOUNT));
  const manifest = await authorityInventory(parent, source);
  await packetJson(join(parent, 'manifest.json'), manifest);
  return {
    directory,
    parent,
    manifest,
    parentSha: digest(await readFile(join(parent, 'manifest.json'))).sha256,
    close: () => rm(directory, { recursive: true, force: true }),
  };
}
test('exclusive child copies frozen bytes and verifies from its own files after the parent is unavailable', async () => {
  const f = await packetFixture();
  try {
    const e = evidenceFixture(),
      review = bytes(reviewFixture(e, f.parentSha));
    const child = join(f.directory, 'child');
    const result = await materializeAuthorityDeployment(
      f.parent,
      child,
      review,
      digest(review).sha256,
      e,
      f.parentSha,
    );
    assert.equal((await stat(join(child, 'deployment-review.json'))).mode & 0o777, 0o600);
    for (const m of f.manifest.members)
      assert.deepEqual(await readFile(join(child, m.path)), await readFile(join(f.parent, m.path)));
    await assert.rejects(
      materializeAuthorityDeployment(
        f.parent,
        child,
        review,
        digest(review).sha256,
        e,
        f.parentSha,
      ),
      { code: 'EEXIST' },
    );
    await rm(f.parent, { recursive: true });
    assert.equal(
      (await verifyAuthorityDeployment(child, result.child_manifest_sha256, f.parentSha)).members,
      43,
    );
    await assert.rejects(
      verifyAuthorityDeployment(child, 'f'.repeat(64), f.parentSha),
      /child_review_changed/,
    );
    // A self-consistent rewritten child inventory still cannot alter frozen parent bytes/configs.
    const original = await readFile(join(child, 'op/build/worker/service.mjs'));
    await writeFile(join(child, 'op/build/worker/service.mjs'), 'replacement facade');
    const originalChild = await readFile(join(child, 'child-manifest.json'));
    const forgedChild = JSON.parse(originalChild.toString());
    forgedChild.members.find(
      (m: { path: string }) => m.path === 'op/build/worker/service.mjs',
    ).digest = digest(Buffer.from('replacement facade'));
    const forgedBytes = bytes(forgedChild);
    await writeFile(join(child, 'child-manifest.json'), forgedBytes);
    await assert.rejects(
      verifyAuthorityDeployment(child, digest(forgedBytes).sha256, f.parentSha),
      /frozen_bytes_changed/,
    );
    await writeFile(join(child, 'child-manifest.json'), originalChild);
    await writeFile(join(child, 'op/build/worker/service.mjs'), original);
    const configPath = join(child, 'op/wrangler.json');
    const configBytes = await readFile(configPath);
    const config = JSON.parse(configBytes.toString());
    config.services.push({
      binding: 'ADMIN',
      service: AUTHORITY_TARGET.checkpoint,
      entrypoint: 'WorkCheckpointBootstrap',
    });
    await writeFile(configPath, bytes(config));
    await assert.rejects(
      verifyAuthorityDeployment(child, result.child_manifest_sha256, f.parentSha),
      /config_changed/,
    );
    await writeFile(configPath, configBytes);
    await writeFile(join(child, 'extra.json'), '{}');
    await assert.rejects(
      verifyAuthorityDeployment(child, result.child_manifest_sha256, f.parentSha),
      /members_changed/,
    );
  } finally {
    await f.close();
  }
});

test('refusal before child creation preserves parent and allocation; symlink outputs and journal gaps are denied', async () => {
  const f = await packetFixture();
  try {
    const e = evidenceFixture(),
      review = bytes(reviewFixture(e, f.parentSha));
    const child = join(f.directory, 'child');
    await assert.rejects(
      materializeAuthorityDeployment(f.parent, child, review, 'f'.repeat(64), e, f.parentSha),
      /review_changed/,
    );
    await assert.rejects(stat(child), { code: 'ENOENT' });
    const partial = structuredClone(e);
    partial.records = partial.records.slice(0, 9);
    const partialReview = bytes(reviewFixture(partial, f.parentSha));
    await assert.rejects(
      materializeAuthorityDeployment(
        f.parent,
        child,
        partialReview,
        digest(partialReview).sha256,
        partial,
        f.parentSha,
      ),
      /requires_reconciliation/,
    );
    await assert.rejects(stat(child), { code: 'ENOENT' });
    const linked = join(f.directory, 'linked');
    await symlink(f.directory, linked);
    await assert.rejects(
      materializeAuthorityDeployment(
        f.parent,
        join(linked, 'child'),
        review,
        digest(review).sha256,
        e,
        f.parentSha,
      ),
      /symlink_denied/,
    );
    const reservation = JSON.parse(e.reservation),
      journal = join(f.directory, reservation.journal);
    await mkdir(journal, { recursive: true });
    await writeFile(
      join(f.directory, 'local/generated/work-authority-allocation/reservation.json'),
      e.reservation,
    );
    for (const [i, r] of e.records.entries())
      await writeFile(join(journal, `${String(i).padStart(4, '0')}.json`), r);
    assert.deepEqual(await readAuthorityAllocation(f.directory), e);
    await writeFile(join(journal, 'extra.json'), '{}');
    await assert.rejects(readAuthorityAllocation(f.directory), /gap_or_extra/);
    const copy = join(f.directory, 'parent-copy');
    await cp(f.parent, copy, { recursive: true });
    await rm(join(copy, 'checkpoint/worker.mjs'));
    await symlink(join(f.parent, 'checkpoint/worker.mjs'), join(copy, 'checkpoint/worker.mjs'));
    await assert.rejects(
      materializeAuthorityDeployment(copy, child, review, digest(review).sha256, e, f.parentSha),
    );
    await assert.rejects(stat(child), { code: 'ENOENT' });
  } finally {
    await f.close();
  }
});
