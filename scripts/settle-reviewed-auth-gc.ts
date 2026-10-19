/** Privileged, incident-specific GC settlement. Never called by the product. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { open, readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { parse } from 'jsonc-parser';
import { getPlatformProxy } from 'wrangler';

type Checkpoint = { authority: string; epoch: string; sequence: number; tip: string };
export type GcPermit = { operation: string; previous: Checkpoint; next: Checkpoint };
type Inspection = {
  authority: string;
  object_id: string;
  state: {
    checkpoint: Checkpoint;
    pending: GcPermit | null;
    last: GcPermit | null;
    release_floor: number;
    frozen: boolean;
  } | null;
};
export type GcReview = {
  authority: string;
  object_id: string;
  permit_sha256: string;
  previous_sequence: number;
};
interface Statement {
  bind(...values: (string | number)[]): Statement;
  first<T>(): Promise<T | null>;
  run(): Promise<unknown>;
}
export interface GcDatabase {
  prepare(sql: string): Statement;
}
export interface GcRecoveryIO {
  DB: GcDatabase;
  inspect(): Promise<string>;
  commit(permit: GcPermit, observed: Checkpoint): Promise<unknown>;
  journal(event: Record<string, unknown>): Promise<void>;
}

// Reviewed trace: scheduled auth GC, 2026-10-17 11:12:30 UTC, source ff24024d.
// This pin prevents the CLI from retiring any other pending operation.
export const incidentReview: GcReview = {
  authority: 'mikaki-auth-work-v1',
  object_id: '1d06c242fcae199a9308facb664bdf3544d6a31cf9b96ef21d9a59f5a9ae46c3',
  permit_sha256: '161de12cf0c21595367f6caa59d22d3c679f72df5704fd2869546732664fd026',
  previous_sequence: 8829,
};
function marker(c: Checkpoint) {
  assert.match(c.authority, /^[a-zA-Z0-9_.:-]{1,128}$/);
  assert.match(c.epoch, /^[a-f0-9]{64}$/);
  assert.match(c.tip, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(c.sequence) && c.sequence >= 0);
  return { authority: c.authority, epoch: c.epoch, sequence: c.sequence, tip: c.tip };
}
export function gcPermitHash(p: GcPermit) {
  assert.match(p.operation, /^[a-zA-Z0-9_.:-]{1,128}$/);
  const previous = marker(p.previous);
  const next = marker(p.next);
  assert.equal(next.authority, previous.authority);
  assert.equal(next.epoch, previous.epoch);
  assert.equal(next.sequence, previous.sequence + 1);
  assert.notEqual(next.tip, previous.tip);
  return createHash('sha256')
    .update(JSON.stringify({ operation: p.operation, previous, next }))
    .digest('hex');
}
const equal = (a: Checkpoint, b: Checkpoint) =>
  JSON.stringify(marker(a)) === JSON.stringify(marker(b));
async function primary(DB: GcDatabase) {
  const row = await DB.prepare(
    'SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1',
  ).first<Checkpoint>();
  assert.ok(row, 'primary_marker_missing');
  return marker(row);
}

/**
 * Explicit operator exception for reviewed expired-state deletion only.
 * A read-only plan is the default. No business SQL, reset, replay, or new permit.
 * Unknown outcomes remain resumable through the same exact existing permit.
 */
export async function settleReviewedAuthGc(io: GcRecoveryIO, review: GcReview, execute = false) {
  const inspection = JSON.parse(await io.inspect()) as Inspection;
  assert.equal(inspection.authority, review.authority, 'authority_mismatch');
  assert.equal(inspection.object_id, review.object_id, 'object_mismatch');
  const state = inspection.state;
  assert.ok(state, 'checkpoint_uninitialized');
  assert.equal(state.frozen, false, 'checkpoint_frozen');
  assert.equal(state.release_floor, 1, 'release_floor_mismatch');
  const p = state.pending ?? state.last;
  assert.ok(p, 'reviewed_permit_missing');
  assert.equal(gcPermitHash(p), review.permit_sha256, 'unreviewed_permit');
  assert.equal(p.previous.authority, review.authority);
  assert.equal(p.previous.sequence, review.previous_sequence);
  const current = await primary(io.DB);
  if (!state.pending) {
    assert.ok(equal(state.checkpoint, p.next) && equal(current, p.next), 'marker_mismatch');
    return { status: 'already-settled', sequence: p.next.sequence };
  }
  assert.ok(equal(state.checkpoint, p.previous), 'independent_marker_mismatch');
  assert.ok(equal(current, p.previous) || equal(current, p.next), 'primary_marker_mismatch');
  const openFrames = await io.DB.prepare(
    'SELECT (SELECT count(*) FROM work_authority_frame)+(SELECT count(*) FROM work_transition_guard) AS n',
  ).first<{ n: number }>();
  assert.equal(openFrames?.n, 0, 'open_authority_transaction');
  const plan = {
    status: 'ready',
    permit_sha256: review.permit_sha256,
    previous_sequence: p.previous.sequence,
    next_sequence: p.next.sequence,
    fence_required: equal(current, p.previous),
  };
  if (!execute) return plan;
  // Persist intent before any production mutation. Journal contains no row data.
  await io.journal({ phase: 'reviewed-gc-settlement-started', ...plan });
  if (equal(current, p.previous)) {
    // Serialized at D1 primary. The original batch's leading CAS+guard cannot
    // subsequently succeed. If that batch wins, only its exact next is accepted.
    await io.DB.prepare(
      'UPDATE work_authority_checkpoint SET sequence=?,tip=? WHERE id=1 AND authority=? AND epoch=? AND sequence=? AND tip=?',
    )
      .bind(
        p.next.sequence,
        p.next.tip,
        p.previous.authority,
        p.previous.epoch,
        p.previous.sequence,
        p.previous.tip,
      )
      .run();
  }
  const observed = await primary(io.DB);
  assert.ok(equal(observed, p.next), 'fence_not_observed');
  await io.journal({ phase: 'exact-next-marker-observed', sequence: observed.sequence });
  const committed = (await io.commit(p, observed)) as Checkpoint;
  assert.ok(equal(committed, p.next), 'commit_response_mismatch');
  await io.journal({ phase: 'reviewed-gc-settled', sequence: committed.sequence });
  return { status: 'settled', sequence: committed.sequence };
}

async function main() {
  const args = process.argv.slice(2);
  assert.ok(args.length === 1 || (args.length === 3 && args[1] === '--execute'));
  const [config, , journalPath] = args;
  const execute = args[1] === '--execute';
  const target = parse(await readFile(config!, 'utf8'));
  assert.equal(target.account_id, '4b749427a0c80c547e726a42aff4b6fc');
  assert.equal(target.workers_dev, false);
  assert.equal(target.preview_urls, false);
  assert.equal(target.env, undefined);
  assert.equal(target.d1_databases?.length, 1);
  assert.deepEqual(target.d1_databases[0], {
    binding: 'DB',
    database_name: 'mikaki-auth-owner',
    database_id: 'd0258938-0d27-4110-8aa9-c82e20f3885b',
    remote: true,
  });
  assert.deepEqual(target.services, [
    {
      binding: 'CHECKPOINT_BOOTSTRAP',
      service: 'mikaki-auth-work-checkpoint',
      entrypoint: 'WorkCheckpointBootstrap',
      remote: true,
    },
    {
      binding: 'CHECKPOINT_SERVICE',
      service: 'mikaki-auth-work-checkpoint',
      entrypoint: 'WorkCheckpointService',
      remote: true,
    },
  ]);
  // Supply an existing private config with only DB, CHECKPOINT_BOOTSTRAP and
  // CHECKPOINT_SERVICE remote bindings; this command deploys no Worker.
  const platform = await getPlatformProxy<{
    DB: GcDatabase;
    CHECKPOINT_BOOTSTRAP: { inspect(): Promise<string> };
    CHECKPOINT_SERVICE: {
      fetch(url: string, init: RequestInit): Promise<Response>;
    };
  }>({ configPath: config, remoteBindings: true, persist: false });
  let journal: Awaited<ReturnType<typeof open>> | null = null;
  try {
    journal = execute ? await open(journalPath!, 'wx', 0o600) : null;
    const result = await settleReviewedAuthGc(
      {
        DB: platform.env.DB,
        inspect: () => platform.env.CHECKPOINT_BOOTSTRAP.inspect(),
        async commit(permit, observed) {
          const response = await platform.env.CHECKPOINT_SERVICE.fetch(
            'https://private.invalid/checkpoint',
            {
              method: 'POST',
              body: JSON.stringify({ action: 'commit', release: 1, permit, observed }),
            },
          );
          assert.equal(response.status, 200, 'commit_refused');
          return response.json();
        },
        async journal(event) {
          assert.ok(journal);
          await journal.writeFile(
            JSON.stringify({ time: new Date().toISOString(), ...event }) + '\n',
          );
          await journal.sync();
        },
      },
      incidentReview,
      execute,
    );
    console.log(JSON.stringify(result));
  } finally {
    await journal?.close();
    await platform.dispose();
  }
}
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch(() => {
    // The private RPC/SQL exception may include provider details. Do not print it.
    console.error('reviewed_gc_settlement_failed; inspect private journal and current markers');
    process.exitCode = 1;
  });
}
