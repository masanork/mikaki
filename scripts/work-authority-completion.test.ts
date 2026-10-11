import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ORIGINAL_ALLOCATION_SHA,
  ORIGINAL_RESERVATION_SHA,
  DLQ_AUDIT_ID,
  RETAINED_IDENTITIES,
  auditProofSchema,
  completeAuthorityAllocation,
  inspectAuthorityCompletion,
} from './work-authority-completion.ts';
import type {
  CompletionIO,
  CompletionIdentity,
  OriginalAllocation,
  DlqAuditProof,
} from './work-authority-completion.ts';
import { AUTHORITY_ACCOUNT, AUTHORITY_TARGET } from './work-authority-packet.ts';

const original: OriginalAllocation = {
  allocation_sha256: ORIGINAL_ALLOCATION_SHA,
  reservation_sha256: ORIGINAL_RESERVATION_SHA,
  original_journal: 'local/generated/work-authority-allocation/allocate-kHIGYa',
  complete: false,
  acknowledged: structuredClone(RETAINED_IDENTITIES.slice(0, 2)),
  verified: structuredClone(RETAINED_IDENTITIES.slice(0, 2)),
  unknown: ['logout_dlq'],
  unverified: [],
  unattempted: ['logout_queue'],
};
const proof = auditProofSchema.parse({
  provider: 'cloudflare-audit-v1',
  audit_id: DLQ_AUDIT_ID,
  account_id: AUTHORITY_ACCOUNT,
  resource_id: RETAINED_IDENTITIES[2]!.id,
  resource_type: 'queue',
  queue_name: AUTHORITY_TARGET.logout_dlq,
  action: 'create_queue',
  success: true,
  occurred_at: '2026-10-10T21:57:50.458616Z',
  original_intent_at: '2026-10-10T21:57:49.291Z',
  original_http_status_at: '2026-10-10T21:57:50.515Z',
  original_http_status: 200,
  original_request_matches: true,
  created_within_original_request: true,
});
const remaining: CompletionIdentity = {
  resource: 'logout_queue',
  name: AUTHORITY_TARGET.logout_queue,
  id: '6'.repeat(32),
  created_at: '2026-10-12T00:00:00.000Z',
};
const provenance = { source_commit: 'a'.repeat(40), completer_sha256: 'b'.repeat(64) };
function fixture() {
  const resources = structuredClone(RETAINED_IDENTITIES);
  const events: Record<string, unknown>[] = [];
  const counts = { creates: 0, reservations: 0 };
  const state = { failRecord: '', loseReply: false, invisible: false, substitute: false };
  const io: CompletionIO = {
    original: async () => structuredClone(original),
    snapshot: async () => ({
      resources: [...resources].sort((a, b) => a.resource.localeCompare(b.resource)),
      workers: [AUTHORITY_TARGET.op, AUTHORITY_TARGET.checkpoint].map((name) => ({
        name,
        present: false,
      })),
    }),
    audit: async () => structuredClone(proof),
    read: async (identity) => {
      assert.deepEqual(
        resources.find((r) => r.resource === identity.resource),
        identity,
      );
      return identity;
    },
    reserve: async () => {
      assert.equal(counts.reservations++, 0, 'reservation_exists');
    },
    record: async (value) => {
      if (value.event === state.failRecord) throw new Error('disk_full');
      events.push({ recorded_at: '2026-10-12T00:00:00.000Z', ...value });
    },
    create: async () => {
      assert.equal(counts.reservations, 1);
      assert.equal(events.at(-1)!.event, 'create_intent');
      counts.creates++;
      if (!state.invisible) resources.push(remaining);
      if (state.loseReply) throw new Error('reply_lost');
      return state.substitute ? { ...remaining, id: RETAINED_IDENTITIES[2]!.id } : remaining;
    },
  };
  return {
    io,
    events,
    counts,
    state,
    resources,
    evidence: () => ({ format_version: 1, records: events.map((e) => JSON.stringify(e) + '\n') }),
  };
}
test('audit recovery preserves original history and admits only the one unattempted Queue', async () => {
  const f = fixture();
  const retained = JSON.stringify(original);
  const result = await completeAuthorityAllocation(f.io, provenance);
  assert.equal(result.provider_creates, 1);
  assert.equal(result.dlq_recreated, false);
  assert.equal(result.bootstrap_invoked, false);
  assert.equal(result.owner_enrolled, false);
  assert.equal(f.counts.creates, 1);
  assert.equal(JSON.stringify(original), retained);
  const inspection = inspectAuthorityCompletion(original, f.evidence());
  assert.equal(inspection.complete, true);
  assert.deepEqual(inspection.verified, [...RETAINED_IDENTITIES, remaining]);
  assert.deepEqual(inspection.reconciliation.original_unknown, ['logout_dlq']);
  assert.deepEqual(inspection.unknown, []);
});
test('a later Queue listing without successful original audit proof cannot grant recovery', async () => {
  const f = fixture();
  f.io.audit = async () => ({ ...proof, success: false }) as unknown as DlqAuditProof;
  await assert.rejects(completeAuthorityAllocation(f.io, provenance));
  assert.equal(f.counts.creates, 0);
  assert.equal(f.counts.reservations, 0);
});
test('scope, time, original packet and reservation substitution refuse before any create', async () => {
  for (const changed of [
    { ...proof, resource_id: '9'.repeat(32) },
    { ...proof, occurred_at: '2026-10-12T00:00:00.000Z' },
    { ...proof, account_id: '0'.repeat(32) },
    { ...proof, queue_name: 'production-queue' },
  ]) {
    const f = fixture();
    f.io.audit = async () => changed as DlqAuditProof;
    await assert.rejects(completeAuthorityAllocation(f.io, provenance));
    assert.equal(f.counts.creates, 0);
  }
  for (const changed of [
    { ...original, allocation_sha256: '0'.repeat(64) },
    { ...original, reservation_sha256: '0'.repeat(64) },
  ]) {
    const f = fixture();
    f.io.original = async () => changed;
    await assert.rejects(completeAuthorityAllocation(f.io, provenance));
    assert.equal(f.counts.creates, 0);
  }
});
test('an existing unattempted Queue is a collision, never adopted', async () => {
  const f = fixture();
  f.resources.push(remaining);
  await assert.rejects(completeAuthorityAllocation(f.io, provenance), /inventory_changed/);
  assert.equal(f.counts.creates, 0);
  assert.equal(f.counts.reservations, 0);
});
test('journal failure before create leaves its reservation consumed and dispatches no request', async () => {
  const f = fixture();
  f.state.failRecord = 'create_intent';
  await assert.rejects(
    completeAuthorityAllocation(f.io, provenance),
    /authority_completion_recovered/,
  );
  assert.equal(f.counts.creates, 0);
  const observed = inspectAuthorityCompletion(original, f.evidence());
  assert.equal(observed.complete, false);
  assert.deepEqual(observed.unattempted, ['logout_queue']);
  f.state.failRecord = '';
  await assert.rejects(completeAuthorityAllocation(f.io, provenance), /reservation_exists/);
  assert.equal(f.counts.creates, 0);
});
test('lost create reply remains unknown even when a later read can see the Queue', async () => {
  const f = fixture();
  f.state.loseReply = true;
  await assert.rejects(completeAuthorityAllocation(f.io, provenance), /create-outcome-unknown/);
  const observed = inspectAuthorityCompletion(original, f.evidence());
  assert.deepEqual(observed.unknown, ['logout_queue']);
  assert.equal(observed.complete, false);
  await assert.rejects(completeAuthorityAllocation(f.io, provenance), /inventory_changed/);
  assert.equal(f.counts.creates, 1);
});
test('an invisible lost reply cannot reopen a canonical reservation', async () => {
  const f = fixture();
  f.state.loseReply = true;
  f.state.invisible = true;
  await assert.rejects(completeAuthorityAllocation(f.io, provenance), /create-outcome-unknown/);
  await assert.rejects(completeAuthorityAllocation(f.io, provenance), /reservation_exists/);
  assert.equal(f.counts.creates, 1);
});
test('resource alias and lost readback retain their failed admission instead of completing', async () => {
  const alias = fixture();
  alias.state.substitute = true;
  await assert.rejects(completeAuthorityAllocation(alias.io, provenance), /create-outcome-unknown/);
  assert.equal(inspectAuthorityCompletion(original, alias.evidence()).complete, false);
  const read = fixture();
  const before = read.io.read;
  read.io.read = async (identity) => {
    if (identity.resource === 'logout_queue') throw new Error('unreachable');
    return before(identity);
  };
  await assert.rejects(completeAuthorityAllocation(read.io, provenance), /acknowledged-unverified/);
  const inspected = inspectAuthorityCompletion(original, read.evidence());
  assert.deepEqual(inspected.unverified, ['logout_queue']);
  assert.deepEqual(inspected.unknown, []);
  assert.equal(inspected.complete, false);
});
test('completion reader refuses report forgery, identity substitution, duplicate creates and terminal additions', async () => {
  const f = fixture();
  await completeAuthorityAllocation(f.io, provenance);
  for (const change of [
    (events: Record<string, unknown>[]) => {
      events[1]!.proof = { ...proof, success: false };
    },
    (events: Record<string, unknown>[]) => {
      events[3]!.identity = { ...remaining, id: '7'.repeat(32) };
    },
    (events: Record<string, unknown>[]) => {
      events.splice(3, 0, events[2]!);
    },
    (events: Record<string, unknown>[]) => {
      events.splice(3, 2);
    },
    (events: Record<string, unknown>[]) => {
      events.push(events[2]!);
    },
  ]) {
    const events = structuredClone(f.events);
    change(events);
    assert.throws(() =>
      inspectAuthorityCompletion(original, {
        format_version: 1,
        records: events.map((e) => JSON.stringify(e)),
      }),
    );
  }
});
