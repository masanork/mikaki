/** One fixed reconciliation and one unattempted create; never rewrites or retries. */
import assert from 'node:assert/strict';
import { z } from 'zod';
import { AUTHORITY_ACCOUNT, AUTHORITY_TARGET } from './work-authority-packet.ts';

export const ORIGINAL_ALLOCATION_SHA =
  'e23cdb9bc1be812f11d7c5200ba6f9f56ef6feebadd49a002ed369487fb8f0dd';
export const ORIGINAL_RESERVATION_SHA =
  '5da004865d86681838b5935c3fb26b07466bbfa3f3c65cd6fbe2c777a9ca673a';
export const DLQ_AUDIT_ID = 'bee80ee1-8440-46c3-b762-eff0a6d5f0e1';
export const DLQ_RECEIPT_SHA = 'ef7bad9ee257da2641587a5f7e9b7d4da1b73ff3b2e4e8fdf93110d74df22c52';
export const COMPLETION_DIRECTORY = 'local/generated/work-authority-allocation/completion-v1';
const time = z
  .string()
  .max(40)
  .refine((s) => Number.isFinite(Date.parse(s)));
const sha = z.string().regex(/^[a-f0-9]{64}$/);
export const completionIdentitySchema = z.strictObject({
  resource: z.enum(['database', 'vault', 'logout_dlq', 'logout_queue']),
  name: z.string().max(128),
  id: z.string().max(128),
  created_at: time,
});
export type CompletionIdentity = z.infer<typeof completionIdentitySchema>;
export const RETAINED_IDENTITIES: CompletionIdentity[] = [
  {
    resource: 'database',
    name: AUTHORITY_TARGET.database,
    id: 'b2d340cd-bcc2-4a96-94a2-83edb93ff627',
    created_at: '2026-10-10T21:57:41.197Z',
  },
  {
    resource: 'vault',
    name: AUTHORITY_TARGET.vault,
    id: AUTHORITY_TARGET.vault,
    created_at: '2026-10-10T21:57:45.642Z',
  },
  {
    resource: 'logout_dlq',
    name: AUTHORITY_TARGET.logout_dlq,
    id: '4f95485d3880458b9a14a8168b836498',
    created_at: '2026-10-10T21:57:49.42237Z',
  },
];
export const auditProofSchema = z.strictObject({
  provider: z.literal('cloudflare-audit-v1'),
  audit_id: z.literal(DLQ_AUDIT_ID),
  account_id: z.literal(AUTHORITY_ACCOUNT),
  resource_id: z.literal(RETAINED_IDENTITIES[2]!.id),
  resource_type: z.literal('queue'),
  queue_name: z.literal(AUTHORITY_TARGET.logout_dlq),
  action: z.literal('create_queue'),
  success: z.literal(true),
  occurred_at: z.literal('2026-10-10T21:57:50.458616Z'),
  original_intent_at: z.literal('2026-10-10T21:57:49.291Z'),
  original_http_status_at: z.literal('2026-10-10T21:57:50.515Z'),
  original_http_status: z.literal(200),
  original_request_matches: z.literal(true),
  created_within_original_request: z.literal(true),
});
export type DlqAuditProof = z.infer<typeof auditProofSchema>;
export type OriginalAllocation = {
  allocation_sha256: string;
  reservation_sha256: string;
  original_journal: string;
  complete: boolean;
  acknowledged: CompletionIdentity[];
  verified: CompletionIdentity[];
  unknown: string[];
  unverified: string[];
  unattempted: string[];
};
export function requireOriginalCompletionLane(original: OriginalAllocation) {
  assert.equal(original.allocation_sha256, ORIGINAL_ALLOCATION_SHA, 'completion_original_changed');
  assert.equal(
    original.reservation_sha256,
    ORIGINAL_RESERVATION_SHA,
    'completion_reservation_changed',
  );
  assert.equal(
    original.original_journal,
    'local/generated/work-authority-allocation/allocate-kHIGYa',
  );
  assert.equal(original.complete, false);
  assert.deepEqual(original.acknowledged, RETAINED_IDENTITIES.slice(0, 2));
  assert.deepEqual(original.verified, original.acknowledged);
  assert.deepEqual(original.unknown, ['logout_dlq']);
  assert.deepEqual(original.unverified, []);
  assert.deepEqual(original.unattempted, ['logout_queue']);
}
export function completionIdentity(value: unknown) {
  const v = completionIdentitySchema.parse(value);
  assert.equal(v.name, AUTHORITY_TARGET[v.resource], 'completion_name_changed');
  if (v.resource === 'logout_queue') {
    assert.match(v.id, /^[a-f0-9]{32}$/);
    assert.ok(
      v.id !== '0'.repeat(32) && !RETAINED_IDENTITIES.some((r) => r.id === v.id),
      'completion_identity_alias',
    );
  } else
    assert.deepEqual(
      v,
      RETAINED_IDENTITIES.find((r) => r.resource === v.resource),
      'completion_retained_identity_changed',
    );
  return v;
}
const base = `/accounts/${AUTHORITY_ACCOUNT}`;
const request = {
  method: 'POST' as const,
  path: `${base}/queues`,
  body: { queue_name: AUTHORITY_TARGET.logout_queue },
};
const recorded = { recorded_at: time };
const selectedSchema = z.strictObject({
  ...recorded,
  event: z.literal('selected'),
  source_commit: z.string().regex(/^[a-f0-9]{40}$/),
  completer_sha256: sha,
  original_allocation_sha256: z.literal(ORIGINAL_ALLOCATION_SHA),
  reservation_sha256: z.literal(ORIGINAL_RESERVATION_SHA),
  audit_receipt_sha256: z.literal(DLQ_RECEIPT_SHA),
});
const schemas = {
  selected: selectedSchema,
  recovered: z.strictObject({
    ...recorded,
    event: z.literal('recovered'),
    identity: completionIdentitySchema,
    proof: auditProofSchema,
  }),
  create_intent: z.strictObject({
    ...recorded,
    event: z.literal('create_intent'),
    resource: z.literal('logout_queue'),
    method: z.literal('POST'),
    path: z.literal(request.path),
    body: z.strictObject({ queue_name: z.literal(AUTHORITY_TARGET.logout_queue) }),
  }),
  create_observed: z.strictObject({
    ...recorded,
    event: z.literal('create_observed'),
    identity: completionIdentitySchema,
  }),
  identity_verified: z.strictObject({
    ...recorded,
    event: z.literal('identity_verified'),
    identity: completionIdentitySchema,
  }),
  complete: z.strictObject({
    ...recorded,
    event: z.literal('complete'),
    resources: z.array(completionIdentitySchema).length(4),
    workers_enabled: z.literal(false),
    bootstrap_invoked: z.literal(false),
  }),
  stopped: z.strictObject({
    ...recorded,
    event: z.literal('stopped'),
    phase: z.enum([
      'preflight',
      'recovered',
      'create-outcome-unknown',
      'acknowledged-unverified',
      'verification-incomplete',
    ]),
    recovery: z.literal('inspect-same-identities-no-replay'),
  }),
};
export const completionEvidenceSchema = z.strictObject({
  format_version: z.literal(1),
  records: z.array(z.string().max(65536)).max(128),
});
export type CompletionEvidence = z.infer<typeof completionEvidenceSchema>;
/** Reconciliation is separate evidence; the original unknown admission is retained. */
export function inspectAuthorityCompletion(original: OriginalAllocation, value: unknown) {
  requireOriginalCompletionLane(original);
  const evidence = completionEvidenceSchema.parse(value);
  let recovered = false,
    attempted = false,
    verified = false,
    complete = false,
    stopped = false;
  let acknowledgment: CompletionIdentity | null = null;
  for (const [index, bytes] of evidence.records.entries()) {
    const raw = JSON.parse(bytes) as Record<string, unknown>;
    assert.ok(
      typeof raw.event === 'string' && Object.hasOwn(schemas, raw.event),
      'completion_record_denied',
    );
    assert.ok(!stopped && !complete, 'completion_record_after_terminal');
    const r = schemas[raw.event as keyof typeof schemas].parse(raw);
    if (index === 0) assert.equal(r.event, 'selected', 'completion_selection_missing');
    if (r.event === 'selected') assert.equal(index, 0, 'completion_selection_repeated');
    else if (r.event === 'recovered') {
      assert.ok(!recovered && !attempted, 'completion_recovery_repeated');
      assert.deepEqual(completionIdentity(r.identity), RETAINED_IDENTITIES[2]);
      recovered = true;
    } else if (r.event === 'create_intent') {
      assert.ok(recovered && !attempted, 'completion_create_replayed');
      attempted = true;
    } else if (r.event === 'create_observed') {
      assert.ok(attempted && !acknowledgment, 'completion_ack_without_intent');
      acknowledgment = completionIdentity(r.identity);
      assert.equal(acknowledgment.resource, 'logout_queue');
    } else if (r.event === 'identity_verified') {
      assert.ok(acknowledgment && !verified, 'completion_read_without_ack');
      assert.deepEqual(completionIdentity(r.identity), acknowledgment);
      verified = true;
    } else if (r.event === 'complete') {
      assert.ok(recovered && verified && acknowledgment, 'completion_not_verified');
      assert.deepEqual(r.resources, [...RETAINED_IDENTITIES, acknowledgment]);
      complete = true;
    } else if (r.event === 'stopped') {
      const expected: string = verified
        ? 'verification-incomplete'
        : acknowledgment
          ? 'acknowledged-unverified'
          : attempted
            ? 'create-outcome-unknown'
            : recovered
              ? 'recovered'
              : 'preflight';
      assert.equal(r.phase, expected, 'completion_stop_phase_changed');
      stopped = true;
    }
  }
  return {
    complete: complete && !stopped,
    acknowledged: [
      ...original.acknowledged,
      ...(recovered ? [RETAINED_IDENTITIES[2]!] : []),
      ...(acknowledgment ? [acknowledgment] : []),
    ],
    verified: [
      ...original.verified,
      ...(recovered ? [RETAINED_IDENTITIES[2]!] : []),
      ...(verified && acknowledgment ? [acknowledgment] : []),
    ],
    unknown: [
      ...(!recovered ? ['logout_dlq'] : []),
      ...(attempted && !acknowledgment ? ['logout_queue'] : []),
    ],
    unverified: acknowledgment && !verified ? ['logout_queue'] : [],
    unattempted: attempted ? [] : ['logout_queue'],
    reconciliation: {
      original_unknown: ['logout_dlq'],
      recovered: recovered ? ['logout_dlq'] : [],
      records: evidence.records.length,
    },
  };
}
type Snapshot = { resources: CompletionIdentity[]; workers: { name: string; present: boolean }[] };
export type CompletionIO = {
  original(): Promise<OriginalAllocation>;
  snapshot(): Promise<Snapshot>;
  audit(): Promise<DlqAuditProof>;
  read(identity: CompletionIdentity): Promise<CompletionIdentity>;
  create(): Promise<CompletionIdentity>;
  /** Exclusively reserves the one canonical shared directory, never removed. */
  reserve(): Promise<void>;
  record(value: Record<string, unknown>): Promise<void>;
};
const sorted = (rows: CompletionIdentity[]) =>
  [...rows].sort((a, b) => a.resource.localeCompare(b.resource));
async function preflight(io: CompletionIO, expected: CompletionIdentity[]) {
  requireOriginalCompletionLane(await io.original());
  const inventory = await io.snapshot();
  assert.deepEqual(inventory.resources, sorted(expected), 'completion_inventory_changed');
  assert.deepEqual(
    inventory.workers,
    [AUTHORITY_TARGET.op, AUTHORITY_TARGET.checkpoint].map((name) => ({ name, present: false })),
    'completion_worker_exists',
  );
  const proof = auditProofSchema.parse(await io.audit());
  for (const identity of expected)
    assert.deepEqual(await io.read(identity), identity, 'completion_read_changed');
  return proof;
}
/** Exactly one new create, after recovery evidence and reservation are durable. */
export async function completeAuthorityAllocation(
  io: CompletionIO,
  provenance: { source_commit: string; completer_sha256: string },
) {
  const proof = await preflight(io, RETAINED_IDENTITIES);
  await io.reserve();
  let phase:
    | 'preflight'
    | 'recovered'
    | 'create-outcome-unknown'
    | 'acknowledged-unverified'
    | 'verification-incomplete' = 'preflight';
  await io.record(
    selectedSchema.omit({ recorded_at: true }).parse({
      event: 'selected',
      ...provenance,
      original_allocation_sha256: ORIGINAL_ALLOCATION_SHA,
      reservation_sha256: ORIGINAL_RESERVATION_SHA,
      audit_receipt_sha256: DLQ_RECEIPT_SHA,
    }),
  );
  try {
    assert.deepEqual(await preflight(io, RETAINED_IDENTITIES), proof, 'completion_audit_changed');
    await io.record({ event: 'recovered', identity: RETAINED_IDENTITIES[2], proof });
    phase = 'recovered';
    await io.record({ event: 'create_intent', resource: 'logout_queue', ...request });
    phase = 'create-outcome-unknown';
    const identity = completionIdentity(await io.create());
    assert.equal(identity.resource, 'logout_queue');
    await io.record({ event: 'create_observed', identity });
    phase = 'acknowledged-unverified';
    assert.deepEqual(await io.read(identity), identity, 'completion_read_changed');
    await io.record({ event: 'identity_verified', identity });
    phase = 'verification-incomplete';
    const resources = [...RETAINED_IDENTITIES, identity];
    assert.deepEqual(await preflight(io, resources), proof, 'completion_audit_changed');
    await io.record({
      event: 'complete',
      resources,
      workers_enabled: false,
      bootstrap_invoked: false,
    });
    return {
      resources,
      provider_creates: 1,
      dlq_recreated: false,
      bootstrap_invoked: false,
      owner_enrolled: false,
    };
  } catch {
    await io.record({ event: 'stopped', phase, recovery: 'inspect-same-identities-no-replay' });
    throw new Error(`authority_completion_${phase}`);
  }
}
