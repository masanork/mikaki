/** Frozen graph portability, privilege substitution and real companion cold admission. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import {
  COPY_BINDING_EDGES,
  copyBindingPlan,
  prepareCopyBindingPlan,
  verifyCopyBindingPlan,
  type CopyBindingTarget,
} from './work-copy-binding-plan.ts';
import { copyRuntimeInventory, prepareCopyRuntimePacket } from './work-copy-runtime-packet.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const parent = join(root, 'local/generated/copy-binding-tests');
const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
function syntheticTarget(source: string): CopyBindingTarget {
  return {
    format_version: 1,
    account_id: 'a'.repeat(32),
    authority_id: 'synthetic-binding-authority',
    artifacts_namespace: 'synthetic-bindings',
    worker_prefix: 'synthetic-copy',
    op: {
      service: 'synthetic-op',
      source_commit: source,
      version_id: '11111111-1111-4111-8111-111111111111',
      attestation_sha256: 'b'.repeat(64),
    },
    checkpoint: {
      service: 'synthetic-checkpoint',
      version_id: '22222222-2222-4222-8222-222222222222',
      namespace_id: 'c'.repeat(32),
      object_id: 'd'.repeat(64),
    },
    host: {
      bucket_name: 'synthetic-git-sources',
      disclosure_digest: 'e'.repeat(64),
      registry_sha256: 'f'.repeat(64),
      image_digest: 'sha256:' + '1'.repeat(64),
    },
    wrapping_key: {
      version: 1,
      custody_reference: 'synthetic-custody',
      review_sha256: '2'.repeat(64),
    },
  };
}

test('retained private binding plan qualifies real companion bytes and refuses privilege substitution', async (t) => {
  const runtime = await prepareCopyRuntimePacket(parent);
  const receipt = {
    source_commit: runtime.source_commit,
    manifest_sha256: runtime.manifest_sha256,
  };
  const target = syntheticTarget(runtime.source_commit);
  const targetBytes = bytes(target);
  const packet = await prepareCopyBindingPlan(
    runtime.directory,
    receipt,
    targetBytes,
    sha(targetBytes),
    parent,
  );
  try {
    await t.test(
      'portable child preserves exact parent bytes, declared scope and closed execution',
      async () => {
        const moved = runtime.directory + '-held';
        await rename(runtime.directory, moved);
        try {
          const verified = await verifyCopyBindingPlan(packet.directory, packet.manifest_sha256);
          assert.equal(verified.workers, 14);
          assert.equal(verified.service_bindings, 36);
          assert.equal(verified.external_effects, false);
          const plan = await copyBindingPlan(join(packet.directory, 'runtime'), receipt, target);
          assert.equal(plan.prerequisites.execution_authorized, false);
          assert.equal(plan.op.custody_verified, false);
          assert.equal(
            plan.workers.find((w) => w.id === 'checkpoint')!.resources.redeployment_authorized,
            false,
          );
          for (const worker of plan.workers) {
            assert.deepEqual(
              Object.values(worker.disabled_vars),
              worker.id === 'checkpoint' ? [] : ['false'],
            );
            assert.deepEqual(worker.public_routes, []);
            assert.deepEqual(worker.cron_triggers, []);
            assert.equal(worker.workers_dev, false);
            assert.equal(worker.preview_urls, false);
          }
        } finally {
          await rename(moved, runtime.directory);
        }
      },
    );
    await t.test(
      'all companion destinations and named capabilities load in real workerd with closed gates',
      async () => {
        const plan = await copyBindingPlan(runtime.directory, receipt, target);
        const selected = COPY_BINDING_EDGES.filter(([, , to]) => to !== 'op');
        const serviceName = (id: string) =>
          id === 'op' ? target.op.service : plan.workers.find((w) => w.id === id)!.service;
        // The OP is a closed transport fixture. This does not qualify its Wasm or attestation.
        const opExports = [
          ...new Set(
            COPY_BINDING_EDGES.filter(([, , to]) => to === 'op').map(([, , , name]) => name),
          ),
        ];
        const mf = new Miniflare(
          convertV4MiniflareOptions({
            workers: [
              {
                name: 'probe',
                modules: true,
                compatibilityDate: '2026-10-10',
                script: `export default { fetch(request, env) { return env['B' + new URL(request.url).pathname.slice(1)].fetch('https://private.invalid/'); } };`,
                serviceBindings: Object.fromEntries(
                  selected.map(([, , to, entrypoint], n) => [
                    `B${n}`,
                    { name: serviceName(to), entrypoint },
                  ]),
                ),
              },
              {
                name: target.op.service,
                modules: true,
                compatibilityDate: '2026-10-10',
                script: `import { WorkerEntrypoint } from 'cloudflare:workers'; class Closed extends WorkerEntrypoint { fetch() { return new Response(null, {status:404}); } } ${opExports.map((name) => `export class ${name} extends Closed {}`).join(' ')} export default {fetch(){return new Response(null,{status:404});}};`,
              },
              ...(await Promise.all(
                plan.workers.map(async (worker) => ({
                  name: worker.service,
                  modules: true,
                  compatibilityDate: '2026-10-10',
                  script: await readFile(join(packet.directory, worker.runtime_bundle), 'utf8'),
                  bindings: { ...plan.scope, ...worker.disabled_vars },
                  serviceBindings: Object.fromEntries(
                    worker.services.map((s) => [
                      s.binding,
                      { name: s.service, entrypoint: s.entrypoint },
                    ]),
                  ),
                })),
              )),
            ],
          }),
        );
        try {
          for (const worker of plan.workers) {
            const response = await (
              await mf.getWorker(worker.service)
            ).fetch('https://public.invalid/');
            assert.equal(response.status, 404, worker.id);
            assert.equal(await response.text(), '');
          }
          for (const [n, edge] of selected.entries()) {
            const response = await mf.dispatchFetch(`https://probe.invalid/${n}`);
            assert.ok(
              [404, 409, 503].includes(response.status),
              `${edge.join('/')}: ${response.status}`,
            );
            assert.ok((await response.text()).length <= 4096);
          }
        } finally {
          await mf.dispose();
        }
      },
    );
    await t.test(
      'rewritten inventory cannot add admin authority, execution or extra credential members',
      async () => {
        const manifestPath = join(packet.directory, 'manifest.json');
        const planPath = join(packet.directory, 'binding-plan.json');
        const originalManifest = await readFile(manifestPath);
        const originalPlan = await readFile(planPath);
        async function rewrittenReceipt() {
          const manifest = JSON.parse(originalManifest.toString());
          manifest.members = await copyRuntimeInventory(packet.directory);
          const changed = bytes(manifest);
          await writeFile(manifestPath, changed);
          return sha(changed);
        }
        for (const mutate of [
          (p: any) => {
            p.op.services[0].entrypoint = 'WorkCheckpointAdmin';
          },
          (p: any) => {
            p.workers.find((w: any) => w.id === 'mint').services[1].entrypoint =
              'WorkMintMaintenance';
          },
          (p: any) => {
            p.op.disabled_vars.WORK_COPY_EXECUTION_ENABLED = 'true';
          },
          (p: any) => {
            p.prerequisites.execution_authorized = true;
          },
          (p: any) => {
            p.workers[0].services[0].service = 'different-op';
          },
        ]) {
          const changed = JSON.parse(originalPlan.toString());
          mutate(changed);
          await writeFile(planPath, bytes(changed));
          await assert.rejects(
            verifyCopyBindingPlan(packet.directory, packet.manifest_sha256),
            /members_changed/,
          );
          await assert.rejects(
            verifyCopyBindingPlan(packet.directory, await rewrittenReceipt()),
            /graph_changed/,
          );
          await writeFile(manifestPath, originalManifest);
          await writeFile(planPath, originalPlan);
        }
        const credentialPath = join(packet.directory, 'credentials.json');
        await writeFile(credentialPath, '{}');
        await assert.rejects(
          verifyCopyBindingPlan(packet.directory, await rewrittenReceipt()),
          /extra_member/,
        );
        await unlink(credentialPath);
        await writeFile(manifestPath, originalManifest);
        await verifyCopyBindingPlan(packet.directory, packet.manifest_sha256);
      },
    );
    await t.test(
      'target digest, source, service collisions and secret-bearing input refuse before materialization',
      async () => {
        await assert.rejects(
          prepareCopyBindingPlan(runtime.directory, receipt, targetBytes, '0'.repeat(64), parent),
          /target_changed/,
        );
        for (const changed of [
          { ...target, op: { ...target.op, source_commit: '0'.repeat(40) } },
          { ...target, checkpoint: { ...target.checkpoint, service: target.op.service } },
          { ...target, op: { ...target.op, service: target.worker_prefix + '-copy' } },
          { ...target, wrapping_key: { ...target.wrapping_key, private_key: 'forbidden' } },
          { ...target, WORK_COPY_EXECUTION_ENABLED: true },
          { ...target, host: { ...target.host, image_digest: 'latest' } },
        ])
          await assert.rejects(copyBindingPlan(runtime.directory, receipt, changed));
      },
    );
    await t.test('linked output ancestor and linked packet members refuse', async () => {
      const link = join(parent, 'linked-output');
      const scratch = join(parent, 'empty-output');
      await mkdir(scratch);
      await symlink(scratch, link);
      try {
        await assert.rejects(
          prepareCopyBindingPlan(
            runtime.directory,
            receipt,
            targetBytes,
            sha(targetBytes),
            join(link, 'nested'),
          ),
          /output_link_denied/,
        );
        assert.deepEqual(await import('node:fs/promises').then((fs) => fs.readdir(scratch)), []);
      } finally {
        await unlink(link);
        await rm(scratch, { recursive: true });
      }
      const planPath = join(packet.directory, 'binding-plan.json');
      const saved = await readFile(planPath);
      await unlink(planPath);
      await symlink('target.json', planPath);
      await assert.rejects(
        verifyCopyBindingPlan(packet.directory, packet.manifest_sha256),
        /link_denied/,
      );
      await unlink(planPath);
      await writeFile(planPath, saved);
    });
  } finally {
    await rm(runtime.directory, { recursive: true, force: true });
    await rm(packet.directory, { recursive: true, force: true });
  }
});
