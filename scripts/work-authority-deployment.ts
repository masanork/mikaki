/** Offline child materialization. No provider calls, deployment, migration or enrollment. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readdir, realpath, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import {
  AUTHORITY_ACCOUNT,
  AUTHORITY_TARGET,
  authorityTemplates,
  digest,
  packetFile,
  packetJson,
  verifyAuthorityPacket,
} from './work-authority-packet.ts';
import { REVIEWED_AUTHORITY_MANIFEST } from './allocate-work-authority.ts';
import { authorityBootstrapOperatorConfig } from './work-authority-bootstrap.ts';

export const REVIEWED_BOOTSTRAP_MANIFEST =
  '101e4405e6eb3dfd40e50e46a1bdeaf6d8b886ec294f735b913864a943d53849';
const root = fileURLToPath(new URL('../', import.meta.url));
const parentPacket = 'local/generated/work-authority-bootstrap-qualification/authority-zFCHDp';
const allocationRoot = 'local/generated/work-authority-allocation';
const oldPacket = 'local/generated/work-authority-qualification/authority-nMECMX';
const hex = z.string().regex(/^[a-f0-9]{64}$/);
const commit = z.string().regex(/^[a-f0-9]{40}$/);
const timestamp = z
  .string()
  .max(40)
  .refine((s) => Number.isFinite(Date.parse(s)));
const kinds = ['database', 'vault', 'logout_dlq', 'logout_queue'] as const;
const kind = z.enum(kinds);
const identitySchema = z.strictObject({
  resource: kind,
  name: z.string().max(128),
  id: z.string().max(128),
  created_at: timestamp,
});
type Identity = z.infer<typeof identitySchema>;
const reservationSchema = z.strictObject({
  account_id: z.literal(AUTHORITY_ACCOUNT),
  target: z.unknown(),
  packet: z.literal(oldPacket),
  manifest_sha256: z.literal(REVIEWED_AUTHORITY_MANIFEST),
  source_commit: commit,
  journal: z
    .string()
    .regex(/^local\/generated\/work-authority-allocation\/allocate-[A-Za-z0-9]{6}$/),
});
const evidenceSchema = z.strictObject({
  format_version: z.literal(1),
  reservation: z.string().max(4096),
  records: z.array(z.string().max(65536)).min(1).max(1024),
});
export type AllocationEvidence = z.infer<typeof evidenceSchema>;
const recordBase = { recorded_at: timestamp };
const request = { method: z.enum(['GET', 'POST']), path: z.string().max(4096) };
const recordSchemas = {
  selected: z.strictObject({
    ...recordBase,
    event: z.literal('selected'),
    mode: z.literal('allocate'),
    source_commit: commit,
    allocator_sha256: hex,
    packet: z.literal(oldPacket),
    manifest_sha256: z.literal(REVIEWED_AUTHORITY_MANIFEST),
    packet_source: z.strictObject({ commit, clean: z.literal(true) }),
    account_id: z.literal(AUTHORITY_ACCOUNT),
  }),
  reserved: z.strictObject({
    ...recordBase,
    event: z.literal('reserved'),
    account_id: z.literal(AUTHORITY_ACCOUNT),
    target: z.unknown(),
  }),
  create_intent: z.strictObject({
    ...recordBase,
    event: z.literal('create_intent'),
    resource: kind,
    ...request,
    body: z.unknown(),
  }),
  create_observed: z.strictObject({
    ...recordBase,
    event: z.literal('create_observed'),
    identity: identitySchema,
  }),
  identity_verified: z.strictObject({
    ...recordBase,
    event: z.literal('identity_verified'),
    identity: identitySchema,
  }),
  create_outcome_unknown: z.strictObject({
    ...recordBase,
    event: z.literal('create_outcome_unknown'),
    resource: kind,
  }),
  allocation_complete: z.strictObject({
    ...recordBase,
    event: z.literal('allocation_complete'),
    resources: z.array(identitySchema).length(4),
  }),
  report: z.strictObject({
    ...recordBase,
    event: z.literal('report'),
    mode: z.literal('allocate'),
    report: z.unknown(),
  }),
  stopped: z.strictObject({
    ...recordBase,
    event: z.literal('stopped'),
    action: z.literal('inspect-same-identities-without-retry-or-reset'),
  }),
  request_intent: z.strictObject({ ...recordBase, event: z.literal('request_intent'), ...request }),
  http_status: z.strictObject({
    ...recordBase,
    event: z.literal('http_status'),
    ...request,
    status: z.number().int().min(100).max(599),
  }),
  api_status: z.strictObject({
    ...recordBase,
    event: z.literal('api_status'),
    ...request,
    success: z.boolean().nullable(),
    error_codes: z.array(z.number().int()).max(16),
  }),
  api_shape_invalid: z.strictObject({
    ...recordBase,
    event: z.literal('api_shape_invalid'),
    ...request,
    fields: z
      .array(
        z.strictObject({
          code: z.string().max(64),
          path: z.array(z.union([z.string().max(128), z.number().int()])).max(16),
        }),
      )
      .max(64),
  }),
};
function identity(value: unknown): Identity {
  const v = identitySchema.parse(value);
  assert.equal(v.name, AUTHORITY_TARGET[v.resource], 'deployment_allocation_name_denied');
  if (v.resource === 'database') authorityBootstrapOperatorConfig(v.id);
  else if (v.resource === 'vault') assert.equal(v.id, v.name);
  else {
    assert.match(v.id, /^[a-f0-9]{32}$/, 'deployment_queue_id_denied');
    assert.notEqual(v.id, '0'.repeat(32), 'deployment_queue_id_denied');
  }
  return v;
}
const workers = [AUTHORITY_TARGET.op, AUTHORITY_TARGET.checkpoint].map((name) => ({
  name,
  present: false,
}));
function finalReport(resources: Identity[]) {
  return {
    stage: 'resources-allocated-workers-not-deployed-authority-not-enrolled',
    account_id: AUTHORITY_ACCOUNT,
    resources,
    workers,
    checkpoint_namespace_id: null,
    bootstrap_invoked: false,
    owner_enrolled: false,
    production_mutations: 0,
    artifacts_calls: 0,
    provider_creates: 4,
  };
}
const jsonBytes = (v: unknown) => Buffer.from(JSON.stringify(v, null, 2) + '\n');

/** A later list or report can never upgrade a lost acknowledgment in this protocol. */
export function inspectAuthorityAllocation(value: unknown) {
  const evidence = evidenceSchema.parse(value);
  assert.ok(
    Buffer.byteLength(JSON.stringify(evidence)) <= 2 * 1024 * 1024,
    'deployment_evidence_too_large',
  );
  const reservation = reservationSchema.parse(JSON.parse(evidence.reservation));
  assert.deepEqual(reservation.target, AUTHORITY_TARGET, 'deployment_reservation_scope_denied');
  const acknowledged: Identity[] = [],
    verified: Identity[] = [];
  const attempted: string[] = [],
    unknown: string[] = [];
  let reserved = false,
    complete = false,
    reported = false,
    stopped = false;
  let active: string | null = null;
  for (const [index, bytes] of evidence.records.entries()) {
    const raw = JSON.parse(bytes) as Record<string, unknown>;
    const event = raw.event;
    assert.ok(
      typeof event === 'string' && Object.hasOwn(recordSchemas, event),
      'deployment_record_denied',
    );
    const r = recordSchemas[event as keyof typeof recordSchemas].parse(raw);
    assert.ok(!stopped && !reported, 'deployment_record_after_terminal');
    if (index === 0) assert.equal(event, 'selected', 'deployment_selection_missing');
    if (r.event === 'selected') {
      assert.equal(index, 0, 'deployment_selection_repeated');
      assert.equal(r.source_commit, reservation.source_commit, 'deployment_source_changed');
    } else if (r.event === 'reserved') {
      assert.ok(!reserved && attempted.length === 0, 'deployment_reservation_repeated');
      assert.deepEqual(r.target, AUTHORITY_TARGET);
      reserved = true;
    } else if (r.event === 'create_intent') {
      assert.ok(
        reserved && !active && !complete && unknown.length === 0,
        'deployment_create_replayed',
      );
      assert.equal(r.resource, kinds[attempted.length], 'deployment_create_order_denied');
      const base = `/accounts/${AUTHORITY_ACCOUNT}`;
      const path =
        r.resource === 'database'
          ? `${base}/d1/database`
          : r.resource === 'vault'
            ? `${base}/r2/buckets`
            : `${base}/queues`;
      const body = r.resource.startsWith('logout_')
        ? { queue_name: AUTHORITY_TARGET[r.resource] }
        : { name: AUTHORITY_TARGET[r.resource] };
      assert.equal(r.method, 'POST');
      assert.equal(r.path, path);
      assert.deepEqual(r.body, body);
      attempted.push(r.resource);
      active = r.resource;
    } else if (r.event === 'create_observed') {
      const v = identity(r.identity);
      assert.equal(v.resource, active, 'deployment_ack_without_intent');
      assert.ok(!acknowledged.some((a) => a.resource === v.resource), 'deployment_ack_repeated');
      acknowledged.push(v);
    } else if (r.event === 'identity_verified') {
      const v = identity(r.identity);
      assert.equal(v.resource, active, 'deployment_read_without_ack');
      assert.deepEqual(v, acknowledged.at(-1), 'deployment_identity_changed');
      verified.push(v);
      active = null;
    } else if (r.event === 'create_outcome_unknown') {
      assert.equal(r.resource, active, 'deployment_unknown_without_intent');
      assert.ok(
        !acknowledged.some((a) => a.resource === r.resource),
        'deployment_ack_reclassified',
      );
      unknown.push(r.resource);
      active = null;
    } else if (r.event === 'allocation_complete') {
      assert.ok(
        reserved && !active && unknown.length === 0 && !complete && verified.length === 4,
        'deployment_allocation_incomplete',
      );
      assert.deepEqual(r.resources, verified, 'deployment_allocation_substituted');
      assert.equal(new Set(verified.map((v) => v.id)).size, 4, 'deployment_resource_alias_denied');
      complete = true;
    } else if (r.event === 'report') {
      assert.ok(complete, 'deployment_report_without_completion');
      assert.deepEqual(r.report, finalReport(verified), 'deployment_report_changed');
      reported = true;
    } else if (r.event === 'stopped') stopped = true;
    else {
      // Diagnostic receipts may contain paths and safe codes, never provider bodies or bearers.
      assert.ok(
        r.path.startsWith(`/accounts/${AUTHORITY_ACCOUNT}/`) && !/[\r\n#]/.test(r.path),
        'deployment_diagnostic_scope_denied',
      );
    }
  }
  // A crash after intent still consumes the slot, whether any read can see the resource.
  if (active && !acknowledged.some((v) => v.resource === active) && !unknown.includes(active))
    unknown.push(active);
  return {
    format_version: 1,
    account_id: AUTHORITY_ACCOUNT,
    allocation_packet_sha256: REVIEWED_AUTHORITY_MANIFEST,
    reservation_sha256: digest(Buffer.from(evidence.reservation)).sha256,
    allocation_sha256: digest(jsonBytes(evidence)).sha256,
    original_journal: reservation.journal,
    records: evidence.records.length,
    complete: complete && reported && !stopped && unknown.length === 0,
    acknowledged,
    verified,
    unknown,
    unverified: acknowledged
      .filter((a) => !verified.some((v) => v.resource === a.resource))
      .map((a) => a.resource),
    unattempted: kinds.filter((k) => !attempted.includes(k)),
  };
}

const reviewerId = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$/);
export const deploymentReviewSchema = z.strictObject({
  format_version: z.literal(1),
  account_id: z.literal(AUTHORITY_ACCOUNT),
  packet_sha256: hex,
  allocation_sha256: hex,
  reservation_sha256: hex,
  browser_origin: z.string().max(253),
  ownership: z.strictObject({
    op_operator: reviewerId,
    checkpoint_operator: reviewerId,
    op_recovery: reviewerId,
    checkpoint_recovery: reviewerId,
    review_sha256: hex,
    same_account_control_plane: z.literal(true),
  }),
  signing: z.strictObject({ custody_id: reviewerId, review_sha256: hex }),
});
export type DeploymentReview = z.infer<typeof deploymentReviewSchema>;
function reviewedOrigin(origin: string) {
  const u = new URL(origin);
  assert.ok(
    u.protocol === 'https:' && u.origin === origin && !u.username && !u.password && !u.port,
    'deployment_origin_denied',
  );
  assert.ok(
    !isIP(u.hostname) &&
      /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(u.hostname) &&
      u.hostname.includes('.') &&
      u.hostname
        .split('.')
        .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) &&
      !u.hostname.endsWith('.'),
    'deployment_origin_denied',
  );
  assert.ok(
    !['auth.mikaki.org', 'mikaki.org', 'mikaki.tossa.app', 'mikaki-native.tossa.app'].includes(
      u.hostname,
    ),
    'deployment_production_origin_denied',
  );
  return origin;
}
export function authorityDeploymentConfigs(
  reviewValue: unknown,
  evidence: unknown,
  reviewedParentSha = REVIEWED_BOOTSTRAP_MANIFEST,
) {
  const review = deploymentReviewSchema.parse(reviewValue);
  assert.equal(
    review.packet_sha256,
    hex.parse(reviewedParentSha),
    'deployment_parent_review_changed',
  );
  const allocation = inspectAuthorityAllocation(evidence);
  assert.ok(allocation.complete, 'deployment_allocation_requires_reconciliation');
  assert.equal(
    review.allocation_sha256,
    allocation.allocation_sha256,
    'deployment_allocation_review_changed',
  );
  assert.equal(
    review.reservation_sha256,
    allocation.reservation_sha256,
    'deployment_reservation_review_changed',
  );
  const opOwners = [review.ownership.op_operator, review.ownership.op_recovery];
  const cpOwners = [review.ownership.checkpoint_operator, review.ownership.checkpoint_recovery];
  assert.ok(
    opOwners.every((owner) => !cpOwners.includes(owner)),
    'deployment_operator_separation_denied',
  );
  const templates = authorityTemplates(AUTHORITY_ACCOUNT);
  const databaseId = allocation.verified.find((v) => v.resource === 'database')!.id;
  templates.op.vars.MIKAKI_ISSUER = reviewedOrigin(review.browser_origin);
  templates.op.d1_databases[0]!.database_id = databaseId;
  return {
    op: { ...templates.op, routes: [] },
    checkpoint: {
      ...templates.checkpoint,
      routes: [],
      vars: { ...templates.checkpoint.vars, WORK_BOOTSTRAP_PACKET_SHA256: review.packet_sha256 },
    },
    operator: authorityBootstrapOperatorConfig(databaseId),
  };
}

async function retainedRoot() {
  const common = execFileSync('git', ['rev-parse', '--git-common-dir'], {
    cwd: root,
    encoding: 'utf8',
  }).trim();
  return dirname(await realpath(resolve(root, common)));
}
export async function readAuthorityAllocation(retained: string) {
  const reservationPath = join(retained, allocationRoot, 'reservation.json');
  assert.equal(await realpath(reservationPath), reservationPath, 'deployment_symlink_denied');
  const reservation = (await packetFile(reservationPath, 4096)).toString('utf8');
  const selected = reservationSchema.parse(JSON.parse(reservation));
  const directory = join(retained, selected.journal);
  assert.equal(await realpath(directory), directory, 'deployment_symlink_denied');
  const names = (await readdir(directory)).sort();
  assert.ok(names.length > 0 && names.length <= 1024, 'deployment_journal_count_denied');
  const records: string[] = [];
  let size = Buffer.byteLength(reservation);
  for (const [index, name] of names.entries()) {
    assert.equal(name, `${String(index).padStart(4, '0')}.json`, 'deployment_journal_gap_or_extra');
    const bytes = await packetFile(join(directory, name), 65536);
    size += bytes.length;
    assert.ok(size <= 2 * 1024 * 1024, 'deployment_evidence_too_large');
    records.push(bytes.toString('utf8'));
  }
  assert.deepEqual((await readdir(directory)).sort(), names, 'deployment_journal_changed');
  assert.equal(
    (await packetFile(reservationPath, 4096)).toString('utf8'),
    reservation,
    'deployment_reservation_changed',
  );
  const evidence: AllocationEvidence = { format_version: 1, reservation, records };
  inspectAuthorityAllocation(evidence);
  return evidence;
}
async function pinnedParent(retained: string) {
  const directory = join(retained, parentPacket);
  assert.equal(await realpath(directory), directory, 'deployment_symlink_denied');
  assert.equal(
    digest(await packetFile(join(directory, 'manifest.json'), 65536)).sha256,
    REVIEWED_BOOTSTRAP_MANIFEST,
    'deployment_parent_review_changed',
  );
  return { directory, manifest: await verifyAuthorityPacket(directory) };
}
const extraMembers = [
  'deployment-review.json',
  'allocation-evidence.json',
  'deployment.json',
  'op/wrangler.json',
  'checkpoint/wrangler.json',
  'operator/wrangler.json',
];
async function inventory(
  directory: string,
  prefix = '',
): Promise<{ path: string; digest: ReturnType<typeof digest> }[]> {
  const out = [];
  assert.ok(prefix.split('/').length <= 8, 'deployment_directory_depth_denied');
  const entries = await readdir(join(directory, prefix), { withFileTypes: true });
  assert.ok(entries.length > 0 && entries.length <= 64, 'deployment_directory_count_denied');
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
    const path = prefix ? `${prefix}/${e.name}` : e.name;
    if (!prefix && path === 'child-manifest.json') continue;
    assert.ok(e.isDirectory() || e.isFile(), 'deployment_member_denied');
    if (e.isDirectory()) out.push(...(await inventory(directory, path)));
    else out.push({ path, digest: digest(await packetFile(join(directory, path))) });
    assert.ok(out.length <= 64, 'deployment_member_count_denied');
  }
  return out;
}
function deploymentMetadata(
  source: unknown,
  review: DeploymentReview,
  allocation: ReturnType<typeof inspectAuthorityAllocation>,
  reviewSha: string,
) {
  return {
    format_version: 1,
    stage: 'child-prepared-workers-not-deployed-authority-not-enrolled',
    source,
    account_id: AUTHORITY_ACCOUNT,
    target: AUTHORITY_TARGET,
    parent_manifest_sha256: review.packet_sha256,
    review_sha256: reviewSha,
    allocation_sha256: allocation.allocation_sha256,
    reservation_sha256: allocation.reservation_sha256,
    browser_origin: review.browser_origin,
    resources: allocation.verified,
    checkpoint_namespace_id: null,
    checkpoint_version_id: null,
    checkpoint_object_id: null,
    bootstrap_plan: null,
    owner_enrolled: false,
    ingress_enabled: false,
    external_effects: false,
    ownership: 'reviewed-claims-not-independent-control-plane-proof',
  };
}

/** Only validated members are copied; any failure leaves the partial child for inspection. */
export async function materializeAuthorityDeployment(
  parent: string,
  output: string,
  reviewBytes: Buffer,
  reviewSha: string,
  evidence: AllocationEvidence,
  reviewedParentSha = REVIEWED_BOOTSTRAP_MANIFEST,
) {
  hex.parse(reviewSha);
  assert.equal(digest(reviewBytes).sha256, reviewSha, 'deployment_review_changed');
  const review = deploymentReviewSchema.parse(JSON.parse(reviewBytes.toString('utf8')));
  const configs = authorityDeploymentConfigs(review, evidence, reviewedParentSha);
  assert.equal(await realpath(parent), parent, 'deployment_symlink_denied');
  const manifestBytes = await packetFile(join(parent, 'manifest.json'), 65536);
  assert.equal(digest(manifestBytes).sha256, reviewedParentSha, 'deployment_parent_review_changed');
  const manifest = await verifyAuthorityPacket(parent);
  assert.equal(await realpath(dirname(output)), dirname(output), 'deployment_symlink_denied');
  await mkdir(output, { mode: 0o700 }); // exclusive, never amend a completed or partial child
  for (const member of [
    ...manifest.members,
    { path: 'manifest.json', digest: digest(manifestBytes) },
  ]) {
    const bytes = await packetFile(join(parent, member.path));
    assert.deepEqual(digest(bytes), member.digest, 'deployment_parent_changed_during_copy');
    await mkdir(dirname(join(output, member.path)), { recursive: true, mode: 0o700 });
    await writeFile(join(output, member.path), bytes, { flag: 'wx', mode: 0o600 });
  }
  await writeFile(join(output, 'deployment-review.json'), reviewBytes, { flag: 'wx', mode: 0o600 });
  await packetJson(join(output, 'allocation-evidence.json'), evidence);
  for (const [name, config] of Object.entries(configs)) {
    await mkdir(join(output, name), { recursive: true, mode: 0o700 });
    await packetJson(join(output, name, 'wrangler.json'), config);
  }
  const metadata = deploymentMetadata(
    manifest.source,
    review,
    inspectAuthorityAllocation(evidence),
    reviewSha,
  );
  await packetJson(join(output, 'deployment.json'), metadata);
  await packetJson(join(output, 'child-manifest.json'), {
    ...metadata,
    members: await inventory(output),
  });
  const childSha = digest(await packetFile(join(output, 'child-manifest.json'), 65536)).sha256;
  await verifyAuthorityDeployment(output, childSha, reviewedParentSha);
  return { directory: output, child_manifest_sha256: childSha, stage: metadata.stage };
}

export async function verifyAuthorityDeployment(
  directory: string,
  reviewedChildSha: string,
  reviewedParentSha = REVIEWED_BOOTSTRAP_MANIFEST,
) {
  hex.parse(reviewedChildSha);
  assert.equal(await realpath(directory), directory, 'deployment_symlink_denied');
  const childBytes = await packetFile(join(directory, 'child-manifest.json'), 65536);
  assert.equal(digest(childBytes).sha256, reviewedChildSha, 'deployment_child_review_changed');
  const child = JSON.parse(childBytes.toString('utf8'));
  const parentBytes = await packetFile(join(directory, 'manifest.json'), 65536);
  assert.equal(
    digest(parentBytes).sha256,
    hex.parse(reviewedParentSha),
    'deployment_parent_review_changed',
  );
  const parent = JSON.parse(parentBytes.toString('utf8'));
  const reviewBytes = await packetFile(join(directory, 'deployment-review.json'), 8192);
  const review = deploymentReviewSchema.parse(JSON.parse(reviewBytes.toString('utf8')));
  const evidence = evidenceSchema.parse(
    JSON.parse(
      (await packetFile(join(directory, 'allocation-evidence.json'), 4 * 1024 * 1024)).toString(
        'utf8',
      ),
    ),
  );
  const allocation = inspectAuthorityAllocation(evidence);
  const configs = authorityDeploymentConfigs(review, evidence, reviewedParentSha);
  const metadata = deploymentMetadata(
    parent.source,
    review,
    allocation,
    digest(reviewBytes).sha256,
  );
  const members = await inventory(directory);
  assert.deepEqual(
    members.map((m) => m.path).sort(),
    [
      ...parent.members.map((m: { path: string }) => m.path),
      'manifest.json',
      ...extraMembers,
    ].sort(),
    'deployment_members_changed',
  );
  for (const m of parent.members)
    assert.deepEqual(
      members.find((c) => c.path === m.path)?.digest,
      m.digest,
      'deployment_frozen_bytes_changed',
    );
  assert.deepEqual(
    JSON.parse((await packetFile(join(directory, 'deployment.json'))).toString('utf8')),
    metadata,
    'deployment_metadata_changed',
  );
  for (const [name, config] of Object.entries(configs))
    assert.deepEqual(
      JSON.parse((await packetFile(join(directory, name, 'wrangler.json'))).toString('utf8')),
      config,
      'deployment_config_changed',
    );
  assert.deepEqual(child, { ...metadata, members }, 'deployment_inventory_changed');
  return {
    stage: metadata.stage,
    child_manifest_sha256: reviewedChildSha,
    members: members.length,
    external_effects: false,
  };
}

async function run(args: string[]) {
  if (args[0] === 'verify' && args.length === 3)
    return verifyAuthorityDeployment(resolve(args[1]!), args[2]!);
  const retained = await retainedRoot();
  const parent = await pinnedParent(retained);
  const evidence = await readAuthorityAllocation(retained);
  const allocation = inspectAuthorityAllocation(evidence);
  if (args[0] === 'inspect' && (args.length === 1 || args.length === 2)) {
    const report = {
      stage: 'offline-deployment-gate-inspection',
      provenance: 'local-retained-journal-observation-not-fresh-provider-inventory',
      inspector_sha256: digest(await packetFile(fileURLToPath(import.meta.url))).sha256,
      parent_manifest_sha256: REVIEWED_BOOTSTRAP_MANIFEST,
      parent_source: parent.manifest.source,
      allocation,
      child_materialized: false,
      remote_calls: 0,
      remaining: allocation.complete
        ? ['review-origin-ownership-and-signing-custody']
        : [
            'reconcile-same-allocation-with-positive-evidence',
            'complete-unattempted-resource-under-retained-reservation',
            'review-origin-ownership-and-signing-custody',
          ],
    };
    if (args[1]) {
      const receipt = resolve(args[1]);
      const local = join(retained, 'local/generated');
      assert.ok(
        relative(local, receipt) && !relative(local, receipt).startsWith('..'),
        'deployment_receipt_denied',
      );
      execFileSync('git', ['check-ignore', '--quiet', receipt], { cwd: retained, stdio: 'pipe' });
      await mkdir(dirname(receipt), { recursive: true, mode: 0o700 });
      assert.equal(await realpath(dirname(receipt)), dirname(receipt), 'deployment_symlink_denied');
      await packetJson(receipt, report);
    }
    return report;
  }
  assert.ok(
    args[0] === 'prepare' && args.length === 4,
    'usage: work-authority-deployment.ts inspect [NEW_RECEIPT] | prepare REVIEW REVIEW_SHA256 OUTPUT_PARENT | verify CHILD CHILD_SHA256',
  );
  const review = await packetFile(resolve(args[1]!), 8192);
  // Check every gate before even reserving a child directory.
  assert.equal(digest(review).sha256, hex.parse(args[2]), 'deployment_review_changed');
  authorityDeploymentConfigs(JSON.parse(review.toString('utf8')), evidence);
  const output = resolve(args[3]!);
  const local = join(retained, 'local/generated');
  assert.ok(
    relative(local, output) && !relative(local, output).startsWith('..'),
    'deployment_output_denied',
  );
  execFileSync('git', ['check-ignore', '--quiet', output], { cwd: retained, stdio: 'pipe' });
  await mkdir(output, { recursive: true, mode: 0o700 });
  assert.equal(await realpath(output), output, 'deployment_symlink_denied');
  const reservation = await mkdtemp(join(output, 'child-'));
  return materializeAuthorityDeployment(
    parent.directory,
    join(reservation, 'packet'),
    review,
    args[2]!,
    evidence,
  );
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run(process.argv.slice(2))
    .then((value) => process.stdout.write(JSON.stringify(value, null, 2) + '\n'))
    .catch(() => {
      process.stderr.write(
        'authority_deployment_refused; retain existing packet/allocation; inspect without replay or replacement\n',
      );
      process.exitCode = 1;
    });
}
