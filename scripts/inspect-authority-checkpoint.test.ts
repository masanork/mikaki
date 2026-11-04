import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import {
  inspectAuthorityCheckpoint,
  diagnosticConfig,
  type DiagnosticIO,
} from './inspect-authority-checkpoint.ts';

const marker = {
  authority: 'mikaki-auth-work-v1',
  epoch: 'a'.repeat(64),
  sequence: 42,
  tip: 'b'.repeat(64),
};
const next = { ...marker, sequence: 43, tip: 'c'.repeat(64) };
const permit = { operation: 'lost-write', previous: marker, next };
const state = { checkpoint: marker, pending: null, last: null, frozen: false, release_floor: 1 };
const inspection = (s: unknown) =>
  JSON.stringify({
    authority: marker.authority,
    object_id: '1d06c242fcae199a9308facb664bdf3544d6a31cf9b96ef21d9a59f5a9ae46c3',
    state: s,
  });
const primary = (m = marker, open_frames = 0, open_guards = 0) => ({
  ...m,
  open_frames,
  open_guards,
});
const wait = async () => {};
const fixture = (s: unknown, p = primary()): DiagnosticIO => ({
  inspect: async () => inspection(s),
  primary: async () => p,
});

test('stable matching checkpoints are healthy', async () => {
  assert.deepEqual(await inspectAuthorityCheckpoint(fixture(state), wait), {
    status: 'healthy',
    primary_sequence: 42,
    checkpoint_sequence: 42,
  });
});

test('unknown old marker is quarantined; exact committed marker is separately classified', async () => {
  const pending = { ...state, pending: permit };
  const old = await inspectAuthorityCheckpoint(fixture(pending), wait);
  assert.equal(old.status, 'pending_quarantined');
  assert.match('permit_sha256' in old ? old.permit_sha256 : '', /^[a-f0-9]{64}$/);
  assert.equal(
    (await inspectAuthorityCheckpoint(fixture(pending, primary(next)), wait)).status,
    'pending_committed',
  );
  assert.equal(
    (
      await inspectAuthorityCheckpoint(
        fixture(pending, primary({ ...next, tip: 'd'.repeat(64) })),
        wait,
      )
    ).status,
    'mismatch',
  );
  assert.doesNotMatch(JSON.stringify(old), /lost-write|bbbbbbbb|cccccccc/);
});

test('frozen, unsupported floor, open frame, missing state and marker mismatch fail closed', async () => {
  assert.equal(
    (await inspectAuthorityCheckpoint(fixture({ ...state, frozen: true }), wait)).status,
    'frozen',
  );
  assert.equal(
    (await inspectAuthorityCheckpoint(fixture({ ...state, release_floor: 2 }), wait)).status,
    'unsupported_floor',
  );
  assert.equal(
    (await inspectAuthorityCheckpoint(fixture(state, primary(marker, 1)), wait)).status,
    'open_transaction_state',
  );
  assert.equal((await inspectAuthorityCheckpoint(fixture(null), wait)).status, 'uninitialized');
  assert.equal(
    (await inspectAuthorityCheckpoint(fixture(state, primary(next)), wait)).status,
    'mismatch',
  );
});

test('a changing independent state or primary cannot be reported as a stable incident', async () => {
  let n = 0;
  const duringRead: DiagnosticIO = {
    inspect: async () => inspection(n++ ? { ...state, pending: permit } : state),
    primary: async () => primary(),
  };
  assert.equal((await inspectAuthorityCheckpoint(duringRead, wait)).status, 'changing');
  n = 0;
  const betweenSamples: DiagnosticIO = {
    inspect: async () => inspection(state),
    primary: async () => primary(n++ ? next : marker),
  };
  assert.equal((await inspectAuthorityCheckpoint(betweenSamples, wait)).status, 'changing');
});

test('foreign or malformed permit, object and marker are rejected', async () => {
  await assert.rejects(
    inspectAuthorityCheckpoint(
      fixture({ ...state, pending: { ...permit, next: { ...next, epoch: 'e'.repeat(64) } } }),
      wait,
    ),
  );
  await assert.rejects(
    inspectAuthorityCheckpoint(fixture(state, primary({ ...marker, authority: 'foreign' })), wait),
  );
  const foreign: DiagnosticIO = {
    ...fixture(state),
    inspect: async () =>
      JSON.stringify({ authority: marker.authority, object_id: 'foreign', state }),
  };
  await assert.rejects(inspectAuthorityCheckpoint(foreign, wait));
  const { pending: _pending, ...missingPending } = state;
  await assert.rejects(inspectAuthorityCheckpoint(fixture(missingPending), wait));
  await assert.rejects(
    inspectAuthorityCheckpoint(
      fixture({ ...state, last: { ...permit, next: { ...next, epoch: 'e'.repeat(64) } } }),
      wait,
    ),
  );
});

test('diagnostic config fixes the production targets and exposes no extra bindings', () => {
  const config = diagnosticConfig();
  assert.deepEqual(
    Object.keys(config).sort((a, b) => a.localeCompare(b)),
    [
      'account_id',
      'compatibility_date',
      'd1_databases',
      'name',
      'preview_urls',
      'services',
      'workers_dev',
    ],
  );
  assert.equal(config.account_id, '4b749427a0c80c547e726a42aff4b6fc');
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.deepEqual(config.d1_databases, [
    {
      binding: 'DB',
      database_name: 'mikaki-auth-owner',
      database_id: 'd0258938-0d27-4110-8aa9-c82e20f3885b',
      remote: true,
    },
  ]);
  assert.deepEqual(config.services, [
    {
      binding: 'CHECKPOINT_BOOTSTRAP',
      service: 'mikaki-auth-work-checkpoint',
      entrypoint: 'WorkCheckpointBootstrap',
      remote: true,
    },
  ]);
});

test('the CLI rejects arguments without opening a remote connection', () => {
  const result = spawnSync(
    process.execPath,
    ['scripts/inspect-authority-checkpoint.ts', '/tmp/other-config.json'],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /checkpoint_diagnostic_failed/);
  assert.doesNotMatch(result.stdout + result.stderr, /Establishing remote connection/);
});
