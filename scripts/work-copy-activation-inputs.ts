/** Offline review candidate. Never uploads, activates, approves or dispatches a copy. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, realpath, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { packetFile } from './work-authority-packet.ts';
import { copyBindingPlan } from './work-copy-binding-plan.ts';
import { copyRuntimeInventory, type CopyRuntimeReceipt } from './work-copy-runtime-packet.ts';
import {
  closedCopyWorkerConfigurations,
  verifyClosedCopyConfigurations,
} from './work-copy-worker-configs.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const hex = z.string().regex(/^[a-f0-9]{64}$/);
const kind = 'mikaki-work-copy-activation-inputs-v1';
const stage = 'offline-activation-review-not-deployed-or-authorized';
const hash = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const json = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
const decode = (bytes: Buffer): unknown =>
  JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));

async function inputs(closed: string, expected: string) {
  await verifyClosedCopyConfigurations(closed, expected);
  const binding = join(closed, 'binding');
  const manifest = decode(await packetFile(join(binding, 'manifest.json'), 256 * 1024)) as {
    runtime: CopyRuntimeReceipt;
  };
  const plan = await copyBindingPlan(
    join(binding, 'runtime'),
    manifest.runtime,
    decode(await packetFile(join(binding, 'target.json'), 16384)),
  );
  const configurations = closedCopyWorkerConfigurations(plan);
  const changes = [];
  for (const worker of plan.workers.filter(({ id }) => id !== 'checkpoint')) {
    const config = configurations[worker.id]!;
    const vars: Record<string, string> = config.vars;
    const gate = Object.keys(worker.disabled_vars);
    assert.equal(gate.length, 1, 'Exactly one reviewed companion gate is required');
    assert.equal(vars[gate[0]!], 'false');
    vars[gate[0]!] = 'true';
    // Retain the parent bytes inside the candidate instead of referencing its original path.
    config.main = `../../closed/binding/runtime/workers/${worker.id}.mjs`;
    changes.push({
      worker: worker.id,
      service: worker.service,
      gate: gate[0],
      before: 'false',
      after: 'true',
    });
  }
  await verifyClosedCopyConfigurations(closed, expected);
  return {
    configurations,
    details: {
      kind,
      stage,
      closed_manifest_sha256: expected,
      source_commit: plan.runtime.source_commit,
      target: plan.target,
      companion_changes: changes,
      op: {
        expected_existing: plan.target.op,
        required_copy_services: plan.op.services,
        requested_gate_values: Object.fromEntries(
          Object.keys(plan.op.disabled_vars).map((name) => [name, 'true']),
        ),
        full_configuration_emitted: false,
        ordinary_closed_production_promotion_accepts_activation: false,
        existing_services_routes_resources_and_secrets_must_be_preserved: true,
      },
      checkpoint: {
        ...plan.target.checkpoint,
        configuration_emitted: false,
        bootstrap_authorized: false,
      },
      prerequisites: plan.prerequisites,
      current_provider_observations_verified: false,
      current_owner_session_source_expiry_and_consent_verified: false,
      sealed_source_supply_included: false,
      provider_transport_included: false,
      external_effects: false,
    },
  };
}

async function write(path: string, bytes: Buffer) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
}
async function outputDirectory(parentInput: string) {
  const parent = resolve(parentInput);
  const inside = relative(join(root, 'local/generated'), parent);
  assert.ok(inside && !inside.startsWith('..') && !inside.startsWith('/'));
  let ancestor = root;
  for (const part of relative(root, parent).split('/')) {
    ancestor = join(ancestor, part);
    const info = await lstat(ancestor).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error;
      return null;
    });
    if (info) assert.ok(info.isDirectory() && !info.isSymbolicLink());
    else await mkdir(ancestor, { mode: 0o700 });
  }
  assert.equal(await realpath(parent), parent);
  execFileSync('git', ['check-ignore', '--quiet', parent], { cwd: root, stdio: 'pipe' });
  return mkdtemp(join(parent, 'activation-review-'));
}

export async function prepareCopyActivationInputs(
  closedInput: string,
  closedSha: string,
  outputParent: string,
) {
  hex.parse(closedSha);
  const closed = resolve(closedInput);
  const { configurations, details } = await inputs(closed, closedSha);
  const members = await copyRuntimeInventory(closed);
  const directory = await outputDirectory(outputParent);
  for (const path of ['manifest.json', ...members.map(({ path }) => path)])
    await write(join(directory, 'closed', path), await packetFile(join(closed, path)));
  for (const [id, config] of Object.entries(configurations))
    await write(join(directory, 'configs', id, 'wrangler.json'), json(config));
  await write(join(directory, 'activation-review.json'), json(details));
  const manifest = json({ ...details, members: await copyRuntimeInventory(directory) });
  await write(join(directory, 'manifest.json'), manifest);
  return { directory, ...(await verifyCopyActivationInputs(directory, hash(manifest))) };
}

export async function verifyCopyActivationInputs(directoryInput: string, expected: string) {
  const directory = resolve(directoryInput);
  assert.equal(await realpath(directory), directory);
  const stat = await lstat(join(directory, 'manifest.json'));
  assert.ok(stat.isFile() && stat.nlink === 1);
  const bytes = await packetFile(join(directory, 'manifest.json'), 256 * 1024);
  assert.equal(hash(bytes), hex.parse(expected), 'copy_activation_manifest_changed');
  const manifest = z
    .object({ closed_manifest_sha256: hex, members: z.array(z.unknown()).max(768) })
    .parse(decode(bytes));
  const members = await copyRuntimeInventory(directory);
  assert.deepEqual(members, manifest.members, 'copy_activation_members_changed');
  const { configurations, details } = await inputs(
    join(directory, 'closed'),
    manifest.closed_manifest_sha256,
  );
  assert.deepEqual(decode(bytes), { ...details, members }, 'copy_activation_metadata_changed');
  assert.deepEqual(
    decode(await packetFile(join(directory, 'activation-review.json'), 65536)),
    details,
    'copy_activation_metadata_changed',
  );
  for (const [id, config] of Object.entries(configurations))
    assert.deepEqual(
      decode(await packetFile(join(directory, 'configs', id, 'wrangler.json'), 16384)),
      config,
      'copy_activation_capabilities_changed',
    );
  const parentMembers = await copyRuntimeInventory(join(directory, 'closed'));
  assert.deepEqual(
    members.map(({ path }) => path).sort(),
    [
      'activation-review.json',
      'closed/manifest.json',
      ...parentMembers.map(({ path }) => 'closed/' + path),
      ...Object.keys(configurations).map((id) => `configs/${id}/wrangler.json`),
    ].sort(),
    'copy_activation_extra_member',
  );
  return {
    manifest_sha256: expected,
    source_commit: details.source_commit,
    stage,
    workers: Object.keys(configurations).length,
    external_effects: false,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [action, ...args] = process.argv.slice(2);
    let result;
    if (action === 'create' && args.length === 3)
      result = await prepareCopyActivationInputs(args[0]!, args[1]!, args[2]!);
    else {
      assert.ok(action === 'verify' && args.length === 2);
      result = await verifyCopyActivationInputs(args[0]!, args[1]!);
    }
    console.log(JSON.stringify(result, null, 2));
  } catch {
    console.error(
      'Copy activation review refused. No provider operation or owner approval is issued.',
    );
    process.exitCode = 1;
  }
}
