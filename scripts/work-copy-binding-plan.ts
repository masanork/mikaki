/** Offline private graph bound to retained runtime bytes. No provider or deployment transport. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, realpath, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { packetFile } from './work-authority-packet.ts';
import {
  COPY_RUNTIME_MODULES,
  copyRuntimeInventory,
  verifyCopyRuntimePacket,
  type CopyRuntimeReceipt,
} from './work-copy-runtime-packet.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const hex = z.string().regex(/^[a-f0-9]{64}$/);
const service = z.string().regex(/^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/);
const identifier = z.string().regex(/^[A-Za-z0-9_.:@/-]{1,128}$/);
export const copyBindingTargetSchema = z.strictObject({
  format_version: z.literal(1),
  account_id: z.string().regex(/^[a-f0-9]{32}$/),
  authority_id: z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/),
  artifacts_namespace: z.string().regex(/^[a-z0-9-]{1,63}$/),
  worker_prefix: z.string().regex(/^[a-z0-9][a-z0-9-]{0,35}[a-z0-9]$/),
  op: z.strictObject({
    service,
    source_commit: z.string().regex(/^[a-f0-9]{40}$/),
    version_id: z.uuid(),
    attestation_sha256: hex,
  }),
  checkpoint: z.strictObject({
    service,
    version_id: z.uuid(),
    namespace_id: z.string().regex(/^[a-f0-9]{32}$/),
    object_id: hex,
  }),
  host: z.strictObject({
    bucket_name: z.string().regex(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/),
    disclosure_digest: hex,
    registry_sha256: hex,
    image_digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  }),
  wrapping_key: z.strictObject({
    version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    custody_reference: identifier,
    review_sha256: hex,
  }),
});
export type CopyBindingTarget = z.infer<typeof copyBindingTargetSchema>;
type ModuleId = (typeof COPY_RUNTIME_MODULES)[number][0];
type NodeId = ModuleId | 'op';
type Edge = readonly [NodeId, string, NodeId, string];

// The OP owns data/session checks. Companions receive only their named capabilities.
export const COPY_BINDING_EDGES: readonly Edge[] = [
  ['op', 'WORK_AUTHORITY_CHECKPOINT', 'checkpoint', 'WorkCheckpointService'],
  ['op', 'WORK_COPY_STARTER', 'copy', 'WorkCopyStarter'],
  ['op', 'WORK_COPY_INITIAL', 'initial', 'WorkEffectGate'],
  ['op', 'WORK_COPY_INITIAL_RECONCILER', 'initial-reconcile', 'WorkEffectReconciler'],
  ['op', 'WORK_COPY_MINT', 'mint', 'WorkMintGate'],
  ['op', 'WORK_COPY_GIT', 'git', 'WorkGitGate'],
  ['op', 'WORK_COPY_RECONCILER', 'mint-reconcile', 'WorkMintReconciler'],
  ['op', 'WORK_COPY_CLOSER', 'mint-close', 'WorkMintCloser'],
  ['op', 'WORK_COPY_VERIFIER', 'preparation', 'WorkPreparationGate'],
  ['op', 'WORK_PREPARATION_EVIDENCE', 'checkpoint', 'WorkPreparationEvidence'],
  ['op', 'WORK_GIT_EXECUTION_CHECKPOINT', 'checkpoint', 'WorkGitExecutionCheckpoint'],
  ['op', 'WORK_GIT_TRANSPORT', 'git-transport', 'WorkGitTransport'],
  ['op', 'WORK_MINT_REFUSAL_TRANSPORT', 'mint-refusal', 'WorkMintRefusalTransport'],
  ['copy', 'OP_COPY_STORE', 'op', 'WorkCopyStore'],
  ['initial', 'OP_EFFECT_STORE', 'op', 'WorkEffectStore'],
  ['initial', 'EFFECT_CHECKPOINT', 'checkpoint', 'WorkEffectCheckpoint'],
  ['initial-reconcile', 'OP_EFFECT_STORE', 'op', 'WorkEffectStore'],
  ['initial-reconcile', 'EFFECT_MAINTENANCE', 'checkpoint', 'WorkEffectMaintenance'],
  ['initial-reconcile', 'ARTIFACTS_MAINTENANCE', 'initial-maintenance', 'WorkArtifactsMaintenance'],
  ['initial-maintenance', 'EFFECT_LOOKUP', 'checkpoint', 'WorkEffectLookup'],
  ['mint', 'OP_MINT_STORE', 'op', 'WorkMintStore'],
  ['mint', 'MINT_CHECKPOINT', 'checkpoint', 'WorkMintCheckpoint'],
  ['mint-maintenance', 'MINT_LOOKUP', 'checkpoint', 'WorkMintLookup'],
  ['mint-reconcile', 'OP_MINT_STORE', 'op', 'WorkMintStore'],
  ['mint-reconcile', 'MINT_MAINTENANCE', 'checkpoint', 'WorkMintMaintenance'],
  [
    'mint-reconcile',
    'MINT_ARTIFACTS_MAINTENANCE',
    'mint-maintenance',
    'WorkMintArtifactsMaintenance',
  ],
  ['mint-close', 'OP_MINT_STORE', 'op', 'WorkMintStore'],
  ['mint-close', 'MINT_REFUSAL_CHECKPOINT', 'checkpoint', 'WorkMintRefusalCheckpoint'],
  ['mint-refusal', 'MINT_LOOKUP', 'checkpoint', 'WorkMintLookup'],
  ['git', 'OP_GIT_STORE', 'op', 'WorkGitStore'],
  ['git', 'OP_MINT_STORE', 'op', 'WorkMintStore'],
  ['git', 'GIT_CHECKPOINT', 'checkpoint', 'WorkGitCheckpoint'],
  ['git-transport', 'MINT_LOOKUP', 'checkpoint', 'WorkMintLookup'],
  ['git-transport', 'GIT_DISPATCH', 'checkpoint', 'WorkGitDispatch'],
  ['git-transport', 'GIT_EXECUTOR', 'git-host', 'WorkGitHost'],
  ['preparation', 'OP_GIT_STORE', 'op', 'WorkGitStore'],
];
const flags: Record<ModuleId, string | null> = {
  copy: 'WORK_COPY_WORKFLOW_ENABLED',
  initial: 'WORK_EFFECT_GATE_ENABLED',
  'initial-reconcile': 'WORK_EFFECT_RECONCILE_ENABLED',
  'initial-maintenance': 'WORK_ARTIFACTS_MAINTENANCE_ENABLED',
  mint: 'WORK_MINT_GATE_ENABLED',
  'mint-maintenance': 'WORK_MINT_MAINTENANCE_ENABLED',
  'mint-reconcile': 'WORK_MINT_RECONCILE_ENABLED',
  'mint-close': 'WORK_MINT_CLOSURE_ENABLED',
  'mint-refusal': 'WORK_MINT_REFUSAL_TRANSPORT_ENABLED',
  git: 'WORK_GIT_GATE_ENABLED',
  'git-transport': 'WORK_GIT_TRANSPORT_ENABLED',
  preparation: 'WORK_PREPARATION_GATE_ENABLED',
  'git-host': 'WORK_GIT_HOST_ENABLED',
  checkpoint: null,
};
const artifacts: ModuleId[] = [
  'initial',
  'initial-maintenance',
  'mint',
  'mint-maintenance',
  'mint-refusal',
  'git-transport',
];
const prerequisites = {
  provenance: 'reviewed-target-claims-not-provider-observations',
  op_attestation_verification: 'required',
  deployed_resource_version_module_and_binding_comparison: 'required',
  current_native_disclosure_source_packet_and_sealed_host_supply: 'required',
  private_r2_and_container_image_verification: 'required',
  active_wrapping_key_custody_verification: 'required',
  current_owner_copy_consent: 'required',
  provider_readback_and_credential_closure: 'required',
  execution_authorized: false,
  ai_delegation_authorized: false,
} as const;
const digest = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const decode = (b: Buffer): unknown =>
  JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(b));

export async function copyBindingPlan(
  runtime: string,
  receipt: CopyRuntimeReceipt,
  targetInput: unknown,
) {
  await verifyCopyRuntimePacket(runtime, receipt);
  const target = copyBindingTargetSchema.parse(targetInput);
  assert.equal(target.op.source_commit, receipt.source_commit, 'copy_binding_op_source_changed');
  const names = Object.fromEntries(
    COPY_RUNTIME_MODULES.map(([id]) => [
      id,
      id === 'checkpoint' ? target.checkpoint.service : `${target.worker_prefix}-${id}`,
    ]),
  ) as Record<ModuleId, string>;
  const allNames = [target.op.service, ...Object.values(names)];
  allNames.forEach((name) => service.parse(name));
  assert.equal(new Set(allNames).size, allNames.length, 'copy_binding_service_collision');
  const serviceName = (id: NodeId) => (id === 'op' ? target.op.service : names[id]);
  const bindings = (id: NodeId) =>
    COPY_BINDING_EDGES.filter(([from]) => from === id).map(([, binding, to, entrypoint]) => ({
      binding,
      service: serviceName(to),
      entrypoint,
    }));
  const inventory = await copyRuntimeInventory(runtime);
  return {
    format_version: 1,
    kind: 'mikaki-work-copy-binding-plan-v1',
    stage: 'offline-binding-plan-not-deployed-or-authorized',
    runtime: receipt,
    target,
    op: {
      service: target.op.service,
      services: bindings('op'),
      disabled_vars: Object.fromEntries(
        [
          'WORK_COPY_EXECUTION_ENABLED',
          'WORK_EFFECT_STORE_ENABLED',
          'WORK_MINT_STORE_ENABLED',
          'WORK_GIT_STORE_ENABLED',
          'WORK_GIT_EXECUTION_ENABLED',
          'WORK_PREPARATION_VERIFY_ENABLED',
        ].map((name) => [name, 'false']),
      ),
      required_secret_binding: `WORK_CREDENTIAL_KEY_V${target.wrapping_key.version}`,
      custody_verified: false,
      full_op_configuration_included: false,
    },
    workers: COPY_RUNTIME_MODULES.map(([id, , entrypoint]) => ({
      id,
      service: names[id],
      entrypoint,
      runtime_bundle: `runtime/workers/${id}.mjs`,
      bundle_digest: inventory.find((m) => m.path === `workers/${id}.mjs`)!.digest,
      services: bindings(id),
      disabled_vars: flags[id] ? { [flags[id]]: 'false' } : {},
      public_routes: [],
      workers_dev: false,
      preview_urls: false,
      cron_triggers: [],
      resources: {
        ...(artifacts.includes(id)
          ? { artifacts: { binding: 'ARTIFACTS', namespace: target.artifacts_namespace } }
          : {}),
        ...(id === 'copy'
          ? {
              workflow: {
                binding: 'COPY_WORKFLOW',
                name: names.copy,
                class_name: 'WorkCopyWorkflow',
              },
            }
          : {}),
        ...(id === 'git-host'
          ? {
              r2: { binding: 'GIT_SOURCES', bucket_name: target.host.bucket_name },
              container: {
                binding: 'GIT_HOST',
                class_name: 'GitHostContainer',
                image_digest: target.host.image_digest,
              },
              disclosure_digest: target.host.disclosure_digest,
              registry_sha256: target.host.registry_sha256,
            }
          : {}),
        ...(id === 'checkpoint'
          ? { existing_checkpoint: target.checkpoint, redeployment_authorized: false }
          : {}),
      },
    })),
    scope: {
      WORK_AUTHORITY_ID: target.authority_id,
      WORK_ARTIFACTS_ACCOUNT: target.account_id,
      WORK_ARTIFACTS_NAMESPACE: target.artifacts_namespace,
    },
    prerequisites,
  };
}

async function writeExclusive(path: string, bytes: Buffer) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
}
const jsonBytes = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
async function ignoredOutput(parentInput: string) {
  const parent = resolve(parentInput);
  const inside = relative(join(root, 'local/generated'), parent);
  assert.ok(
    inside && !inside.startsWith('..') && !inside.startsWith('/'),
    'copy_binding_output_denied',
  );
  let ancestor = root;
  for (const part of relative(root, parent).split('/')) {
    ancestor = join(ancestor, part);
    const info = await lstat(ancestor).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error;
      return null;
    });
    if (info)
      assert.ok(info.isDirectory() && !info.isSymbolicLink(), 'copy_binding_output_link_denied');
    else await mkdir(ancestor, { mode: 0o700 });
  }
  assert.equal(await realpath(parent), parent, 'copy_binding_output_link_denied');
  execFileSync('git', ['check-ignore', '--quiet', parent], { cwd: root, stdio: 'pipe' });
  return parent;
}

export async function prepareCopyBindingPlan(
  runtimeInput: string,
  receipt: CopyRuntimeReceipt,
  targetBytes: Buffer,
  targetSha256: string,
  outputParent: string,
) {
  assert.equal(digest(targetBytes), hex.parse(targetSha256), 'copy_binding_target_changed');
  assert.ok(targetBytes.length <= 16384, 'copy_binding_target_too_large');
  const runtime = resolve(runtimeInput);
  const plan = await copyBindingPlan(runtime, receipt, decode(targetBytes));
  const members = await copyRuntimeInventory(runtime);
  const directory = await mkdtemp(join(await ignoredOutput(outputParent), 'bindings-'));
  for (const path of ['manifest.json', ...members.map((m) => m.path)])
    await writeExclusive(join(directory, 'runtime', path), await packetFile(join(runtime, path)));
  await writeExclusive(join(directory, 'target.json'), targetBytes);
  await writeExclusive(join(directory, 'binding-plan.json'), jsonBytes(plan));
  const manifest = {
    format_version: 1,
    kind: 'mikaki-work-copy-binding-packet-v1',
    runtime: receipt,
    target_sha256: targetSha256,
    members: await copyRuntimeInventory(directory),
  };
  const manifestBytes = jsonBytes(manifest);
  await writeExclusive(join(directory, 'manifest.json'), manifestBytes);
  const checked = await verifyCopyBindingPlan(directory, digest(manifestBytes));
  return { directory, ...checked };
}

export async function verifyCopyBindingPlan(directoryInput: string, expectedSha256: string) {
  const directory = resolve(directoryInput);
  assert.equal(await realpath(directory), directory, 'copy_binding_directory_link_denied');
  const manifestStat = await lstat(join(directory, 'manifest.json'));
  assert.ok(manifestStat.isFile() && manifestStat.nlink === 1, 'copy_binding_manifest_denied');
  const manifestBytes = await packetFile(join(directory, 'manifest.json'), 256 * 1024);
  assert.equal(digest(manifestBytes), hex.parse(expectedSha256), 'copy_binding_manifest_changed');
  const manifest = z
    .strictObject({
      format_version: z.literal(1),
      kind: z.literal('mikaki-work-copy-binding-packet-v1'),
      runtime: z.strictObject({
        source_commit: z.string().regex(/^[a-f0-9]{40}$/),
        manifest_sha256: hex,
      }),
      target_sha256: hex,
      members: z
        .array(
          z.strictObject({
            path: z.string(),
            digest: z.strictObject({ bytes: z.number().int().nonnegative(), sha256: hex }),
          }),
        )
        .max(768),
    })
    .parse(decode(manifestBytes));
  const members = await copyRuntimeInventory(directory);
  assert.deepEqual(manifest.members, members, 'copy_binding_members_changed');
  const targetBytes = await packetFile(join(directory, 'target.json'), 16384);
  assert.equal(digest(targetBytes), manifest.target_sha256, 'copy_binding_target_changed');
  const plan = await copyBindingPlan(
    join(directory, 'runtime'),
    manifest.runtime,
    decode(targetBytes),
  );
  assert.deepEqual(
    decode(await packetFile(join(directory, 'binding-plan.json'), 65536)),
    plan,
    'copy_binding_graph_changed',
  );
  const runtimeMembers = await copyRuntimeInventory(join(directory, 'runtime'));
  assert.deepEqual(
    members.map((m) => m.path).sort(),
    [
      'target.json',
      'binding-plan.json',
      'runtime/manifest.json',
      ...runtimeMembers.map((m) => `runtime/${m.path}`),
    ].sort(),
    'copy_binding_extra_member',
  );
  return {
    manifest_sha256: expectedSha256,
    source_commit: manifest.runtime.source_commit,
    stage: plan.stage,
    workers: plan.workers.length,
    service_bindings: COPY_BINDING_EDGES.length,
    members: members.length,
    external_effects: false,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [mode, ...args] = process.argv.slice(2);
    let result;
    if (mode === 'create' && args.length === 6)
      result = await prepareCopyBindingPlan(
        args[0]!,
        { manifest_sha256: args[1]!, source_commit: args[2]! },
        await packetFile(resolve(args[3]!), 16384),
        args[4]!,
        args[5]!,
      );
    else {
      assert.ok(mode === 'verify' && args.length === 2);
      result = await verifyCopyBindingPlan(args[0]!, args[1]!);
    }
    console.log(JSON.stringify(result, null, 2));
  } catch {
    console.error(
      'Copy binding plan refused. Retain the exact runtime/source, target review and external manifest digests. No provider operation is issued.',
    );
    process.exitCode = 1;
  }
}
