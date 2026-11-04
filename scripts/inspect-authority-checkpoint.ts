/** Read-only production authority diagnosis; this capability cannot settle a permit. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { parse } from 'jsonc-parser';
import { getPlatformProxy } from 'wrangler';
import type { D1Database } from '@cloudflare/workers-types';
import { gcPermitHash, type GcPermit } from './settle-reviewed-auth-gc.ts';

type Marker = GcPermit['previous'];
type State = {
  checkpoint: Marker;
  pending: GcPermit | null;
  last: GcPermit | null;
  release_floor: number;
  frozen: boolean;
};
type Inspection = { authority: string; object_id: string; state: State | null };
type Primary = Marker & { open_frames: number; open_guards: number };
export interface DiagnosticIO {
  inspect(): Promise<string>;
  primary(): Promise<Primary | null>;
}
const authority = 'mikaki-auth-work-v1';
const objectId = '1d06c242fcae199a9308facb664bdf3544d6a31cf9b96ef21d9a59f5a9ae46c3';
const equal = (a: Marker, b: Marker) =>
  a.authority === b.authority &&
  a.epoch === b.epoch &&
  a.sequence === b.sequence &&
  a.tip === b.tip;

function validateMarker(marker: Marker) {
  assert.equal(marker.authority, authority);
  assert.match(marker.epoch, /^[a-f0-9]{64}$/);
  assert.match(marker.tip, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(marker.sequence) && marker.sequence >= 0);
}

async function sample(io: DiagnosticIO) {
  const before = JSON.parse(await io.inspect()) as Inspection;
  const primary = await io.primary();
  const after = JSON.parse(await io.inspect()) as Inspection;
  for (const observation of [before, after]) {
    assert.equal(observation.authority, authority, 'authority_mismatch');
    assert.equal(observation.object_id, objectId, 'object_mismatch');
    assert.ok(Object.hasOwn(observation, 'state'));
    assert.ok(observation.state === null || typeof observation.state === 'object');
  }
  if (JSON.stringify(before.state) !== JSON.stringify(after.state)) return null;
  assert.ok(primary, 'primary_missing');
  validateMarker(primary);
  assert.ok(Number.isSafeInteger(primary.open_frames) && primary.open_frames >= 0);
  assert.ok(Number.isSafeInteger(primary.open_guards) && primary.open_guards >= 0);
  const state = after.state;
  if (state) {
    assert.ok(Object.hasOwn(state, 'pending') && Object.hasOwn(state, 'last'));
    assert.ok(state.pending === null || typeof state.pending === 'object');
    assert.ok(state.last === null || typeof state.last === 'object');
    validateMarker(state.checkpoint);
    assert.ok(Number.isSafeInteger(state.release_floor) && state.release_floor >= 0);
    assert.equal(typeof state.frozen, 'boolean');
    if (state.last) gcPermitHash(state.last);
    if (state.pending) {
      gcPermitHash(state.pending);
      assert.ok(equal(state.checkpoint, state.pending.previous), 'pending_previous_mismatch');
    }
  }
  return { state, primary };
}

/** Two equal observations reduce transient false alarms; they do not prove continuous stability. */
export async function inspectAuthorityCheckpoint(io: DiagnosticIO, wait: () => Promise<void>) {
  const first = await sample(io);
  await wait();
  const second = await sample(io);
  if (!first || !second || JSON.stringify(first) !== JSON.stringify(second))
    return { status: 'changing' as const };
  const { state, primary } = second;
  const result = {
    primary_sequence: primary.sequence,
    checkpoint_sequence: state?.checkpoint.sequence,
  };
  if (!state) return { status: 'uninitialized' as const, ...result };
  if (state.frozen) return { status: 'frozen' as const, ...result };
  if (state.release_floor !== 1) return { status: 'unsupported_floor' as const, ...result };
  if (primary.open_frames || primary.open_guards)
    return { status: 'open_transaction_state' as const, ...result };
  if (!state.pending)
    return {
      status: equal(primary, state.checkpoint) ? ('healthy' as const) : ('mismatch' as const),
      ...result,
    };
  const pending = {
    permit_sha256: gcPermitHash(state.pending),
    next_sequence: state.pending.next.sequence,
  };
  if (equal(primary, state.pending.previous))
    return { status: 'pending_quarantined' as const, ...result, ...pending };
  if (equal(primary, state.pending.next))
    return { status: 'pending_committed' as const, ...result, ...pending };
  return { status: 'mismatch' as const, ...result, ...pending };
}

export function validateDiagnosticConfig(target: Record<string, unknown>) {
  assert.deepEqual(Object.keys(target).sort(), [
    'account_id',
    'compatibility_date',
    'd1_databases',
    'name',
    'preview_urls',
    'services',
    'workers_dev',
  ]);
  assert.match(String(target.name), /^[a-z0-9-]{1,63}$/);
  assert.match(String(target.compatibility_date), /^\d{4}-\d{2}-\d{2}$/);
  assert.equal(target.account_id, '4b749427a0c80c547e726a42aff4b6fc');
  assert.equal(target.workers_dev, false);
  assert.equal(target.preview_urls, false);
  assert.equal(target.env, undefined);
  assert.deepEqual(target.d1_databases, [
    {
      binding: 'DB',
      database_name: 'mikaki-auth-owner',
      database_id: 'd0258938-0d27-4110-8aa9-c82e20f3885b',
      remote: true,
    },
  ]);
  assert.deepEqual(target.services, [
    {
      binding: 'CHECKPOINT_BOOTSTRAP',
      service: 'mikaki-auth-work-checkpoint',
      entrypoint: 'WorkCheckpointBootstrap',
      remote: true,
    },
  ]);
}

async function main() {
  assert.equal(process.argv.length, 3, 'expected_private_remote_binding_config');
  const target = parse(await readFile(process.argv[2]!, 'utf8')) as Record<string, unknown>;
  validateDiagnosticConfig(target);
  const platform = await getPlatformProxy<{
    DB: D1Database;
    CHECKPOINT_BOOTSTRAP: { inspect(): Promise<string> };
  }>({ configPath: process.argv[2], remoteBindings: true, persist: false });
  try {
    const result = await inspectAuthorityCheckpoint(
      {
        inspect: () => platform.env.CHECKPOINT_BOOTSTRAP.inspect(),
        primary: () =>
          platform.env.DB.prepare(
            'SELECT authority,epoch,sequence,tip,(SELECT count(*) FROM work_authority_frame) AS open_frames,(SELECT count(*) FROM work_transition_guard) AS open_guards FROM work_authority_checkpoint WHERE id=1',
          ).first<Primary>(),
      },
      () => new Promise((resolve) => setTimeout(resolve, 5000)),
    );
    console.log(JSON.stringify(result));
    if (result.status !== 'healthy') process.exitCode = result.status === 'changing' ? 2 : 1;
  } finally {
    await platform.dispose();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch(() => {
    console.error('checkpoint_diagnostic_failed');
    process.exitCode = 1;
  });
