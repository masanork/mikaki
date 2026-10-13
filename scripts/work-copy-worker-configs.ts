/** Closed companion upload inputs. No allocation, upload, ingress, bootstrap or copy execution. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, realpath, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { packetFile } from './work-authority-packet.ts';
import { copyBindingPlan, verifyCopyBindingPlan } from './work-copy-binding-plan.ts';
import { copyRuntimeInventory, type CopyRuntimeReceipt } from './work-copy-runtime-packet.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const hex = z.string().regex(/^[a-f0-9]{64}$/);
const kind = 'mikaki-work-copy-worker-configs-v1';
const stage = 'closed-companion-inputs-not-deployed-or-authorized';
const hash = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const decode = (bytes: Buffer): unknown =>
  JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
const json = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
type Plan = Awaited<ReturnType<typeof copyBindingPlan>>;

export function closedCopyWorkerConfigurations(plan: Plan) {
  return Object.fromEntries(
    plan.workers
      .filter((worker) => worker.id !== 'checkpoint')
      .map((worker) => [
        worker.id,
        {
          name: worker.service,
          account_id: plan.target.account_id,
          main: `../../binding/runtime/workers/${worker.id}.mjs`,
          no_bundle: true,
          find_additional_modules: false,
          compatibility_date: '2026-10-13',
          workers_dev: false,
          preview_urls: false,
          routes: [],
          triggers: { crons: [] },
          observability: { enabled: true, traces: { enabled: true } },
          vars: {
            ...plan.scope,
            ...worker.disabled_vars,
            ...(worker.id === 'git-host'
              ? {
                  WORK_GIT_DISCLOSURE_DIGEST: plan.target.host.disclosure_digest,
                  WORK_GIT_REGISTRY_SHA256: plan.target.host.registry_sha256,
                }
              : {}),
          },
          services: worker.services,
          ...(worker.resources.artifacts
            ? { artifacts: [{ ...worker.resources.artifacts, remote: false }] }
            : {}),
          ...(worker.resources.workflow ? { workflows: [worker.resources.workflow] } : {}),
          ...(worker.id === 'git-host'
            ? {
                r2_buckets: [
                  {
                    binding: 'GIT_SOURCES',
                    bucket_name: plan.target.host.bucket_name,
                    remote: false,
                  },
                ],
                durable_objects: {
                  bindings: [{ name: 'GIT_HOST', class_name: 'GitHostContainer' }],
                },
                exports: {
                  GitHostContainer: {
                    type: 'durable-object',
                    storage: 'sqlite',
                    container: worker.service,
                  },
                },
                containers: [
                  {
                    name: worker.service,
                    scheduling_policy: 'durable_object',
                    images: {
                      host: {
                        image: `registry.cloudflare.com/${plan.target.account_id}/${worker.service}@${plan.target.host.image_digest}`,
                      },
                    },
                    ssh: { enabled: false },
                    observability: { enabled: true, logs: { enabled: true } },
                  },
                ],
              }
            : {}),
        },
      ]),
  );
}

function metadata(plan: Plan, bindingSha: string) {
  return {
    kind,
    stage,
    binding_manifest_sha256: bindingSha,
    source_commit: plan.runtime.source_commit,
    compatibility_date: '2026-10-13',
    checkpoint: {
      ...plan.target.checkpoint,
      configuration_emitted: false,
      bootstrap_authorized: false,
    },
    op: {
      expected_existing: plan.target.op,
      required_copy_services: plan.op.services,
      disabled_copy_vars: plan.op.disabled_vars,
      required_secret_binding: plan.op.required_secret_binding,
      full_configuration_emitted: false,
      existing_services_routes_resources_and_secrets_must_be_preserved: true,
    },
    prerequisites: plan.prerequisites,
    image: {
      repository: plan.workers.find((worker) => worker.id === 'git-host')!.service,
      digest: plan.target.host.image_digest,
      registry_observation_verified: false,
      sealed_source_supply_included: false,
    },
    external_effects: false,
  };
}
async function readPlan(directory: string, expected: string) {
  await verifyCopyBindingPlan(directory, expected);
  const manifest = decode(await packetFile(join(directory, 'manifest.json'), 256 * 1024)) as {
    runtime: CopyRuntimeReceipt;
  };
  const plan = await copyBindingPlan(
    join(directory, 'runtime'),
    manifest.runtime,
    decode(await packetFile(join(directory, 'target.json'), 16384)),
  );
  // Recheck the retained pin after reading the bytes used for derivation.
  await verifyCopyBindingPlan(directory, expected);
  return plan;
}
async function write(path: string, bytes: Buffer) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
}
async function outputDirectory(parentInput: string) {
  const parent = resolve(parentInput);
  const inside = relative(join(root, 'local/generated'), parent);
  assert.ok(
    inside && !inside.startsWith('..') && !inside.startsWith('/'),
    'copy_config_output_denied',
  );
  let ancestor = root;
  for (const part of relative(root, parent).split('/')) {
    ancestor = join(ancestor, part);
    const info = await lstat(ancestor).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error;
      return null;
    });
    if (info)
      assert.ok(info.isDirectory() && !info.isSymbolicLink(), 'copy_config_output_link_denied');
    else await mkdir(ancestor, { mode: 0o700 });
  }
  assert.equal(await realpath(parent), parent, 'copy_config_output_link_denied');
  execFileSync('git', ['check-ignore', '--quiet', parent], { cwd: root, stdio: 'pipe' });
  return mkdtemp(join(parent, 'closed-'));
}

export async function prepareClosedCopyConfigurations(
  bindingInput: string,
  bindingSha: string,
  outputParent: string,
) {
  hex.parse(bindingSha);
  const binding = resolve(bindingInput);
  const plan = await readPlan(binding, bindingSha);
  const configs = closedCopyWorkerConfigurations(plan);
  const members = await copyRuntimeInventory(binding);
  const directory = await outputDirectory(outputParent);
  for (const path of ['manifest.json', ...members.map((member) => member.path)])
    await write(join(directory, 'binding', path), await packetFile(join(binding, path)));
  for (const [id, config] of Object.entries(configs))
    await write(join(directory, 'configs', id, 'wrangler.json'), json(config));
  const details = metadata(plan, bindingSha);
  await write(join(directory, 'deployment-inputs.json'), json(details));
  const manifest = json({ ...details, members: await copyRuntimeInventory(directory) });
  await write(join(directory, 'manifest.json'), manifest);
  return { directory, ...(await verifyClosedCopyConfigurations(directory, hash(manifest))) };
}

export async function verifyClosedCopyConfigurations(directoryInput: string, expected: string) {
  const directory = resolve(directoryInput);
  assert.equal(await realpath(directory), directory, 'copy_config_directory_link_denied');
  const stat = await lstat(join(directory, 'manifest.json'));
  assert.ok(stat.isFile() && stat.nlink === 1, 'copy_config_manifest_denied');
  const manifestBytes = await packetFile(join(directory, 'manifest.json'), 256 * 1024);
  assert.equal(hash(manifestBytes), hex.parse(expected), 'copy_config_manifest_changed');
  const manifest = z
    .object({ binding_manifest_sha256: hex, members: z.array(z.unknown()).max(768) })
    .parse(decode(manifestBytes));
  const members = await copyRuntimeInventory(directory);
  assert.deepEqual(members, manifest.members, 'copy_config_members_changed');
  const plan = await readPlan(join(directory, 'binding'), manifest.binding_manifest_sha256);
  const configs = closedCopyWorkerConfigurations(plan);
  const details = metadata(plan, manifest.binding_manifest_sha256);
  assert.deepEqual(decode(manifestBytes), { ...details, members }, 'copy_config_metadata_changed');
  assert.deepEqual(
    decode(await packetFile(join(directory, 'deployment-inputs.json'), 65536)),
    details,
    'copy_config_metadata_changed',
  );
  for (const [id, config] of Object.entries(configs))
    assert.deepEqual(
      decode(await packetFile(join(directory, 'configs', id, 'wrangler.json'), 16384)),
      config,
      'copy_config_capabilities_changed',
    );
  const parentMembers = await copyRuntimeInventory(join(directory, 'binding'));
  assert.deepEqual(
    members.map((member) => member.path).sort(),
    [
      'deployment-inputs.json',
      'binding/manifest.json',
      ...parentMembers.map((member) => 'binding/' + member.path),
      ...Object.keys(configs).map((id) => `configs/${id}/wrangler.json`),
    ].sort(),
    'copy_config_extra_member',
  );
  return {
    manifest_sha256: expected,
    source_commit: plan.runtime.source_commit,
    stage,
    workers: Object.keys(configs).length,
    external_effects: false,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [action, ...args] = process.argv.slice(2);
    let result;
    if (action === 'create' && args.length === 3)
      result = await prepareClosedCopyConfigurations(args[0]!, args[1]!, args[2]!);
    else {
      assert.ok(action === 'verify' && args.length === 2);
      result = await verifyClosedCopyConfigurations(args[0]!, args[1]!);
    }
    console.log(JSON.stringify(result, null, 2));
  } catch {
    console.error(
      'Closed copy configuration refused. Retain the exact binding packet and external digests. No provider operation is issued.',
    );
    process.exitCode = 1;
  }
}
