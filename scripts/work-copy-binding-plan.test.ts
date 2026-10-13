/** Frozen graph portability, privilege substitution and real companion cold admission. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import {
  COPY_BINDING_EDGES,
  copyBindingPlan,
  prepareCopyBindingPlan,
  verifyCopyBindingPlan,
  type CopyBindingTarget,
} from './work-copy-binding-plan.ts';
import { copyRuntimeInventory, prepareCopyRuntimePacket } from './work-copy-runtime-packet.ts';
import {
  prepareClosedCopyConfigurations,
  verifyClosedCopyConfigurations,
} from './work-copy-worker-configs.ts';

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
  let closed: Awaited<ReturnType<typeof prepareClosedCopyConfigurations>> | undefined;
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
      'portable closed configurations keep checkpoint and OP out of deployment and pass pinned Wrangler dry runs',
      async () => {
        closed = await prepareClosedCopyConfigurations(
          packet.directory,
          packet.manifest_sha256,
          parent,
        );
        assert.equal(closed.workers, 13);
        const moved = packet.directory + '-held';
        await rename(packet.directory, moved);
        try {
          await verifyClosedCopyConfigurations(closed.directory, closed.manifest_sha256);
        } finally {
          await rename(moved, packet.directory);
        }
        const ids = await readdir(join(closed.directory, 'configs'));
        assert.equal(ids.length, 13);
        assert.ok(!ids.includes('checkpoint') && !ids.includes('op'));
        const dry = await mkdtemp(join(parent, 'dry-'));
        const run = promisify(execFile);
        try {
          for (const id of ids) {
            const configPath = join(closed.directory, 'configs', id, 'wrangler.json');
            const config = JSON.parse(await readFile(configPath, 'utf8'));
            assert.equal(config.no_bundle, true);
            assert.equal(config.account_id, target.account_id);
            assert.equal(config.compatibility_date, '2026-10-13');
            assert.deepEqual(config.routes, []);
            assert.deepEqual(config.triggers.crons, []);
            assert.equal(config.workers_dev, false);
            assert.equal(config.preview_urls, false);
            assert.equal(config.observability.traces.enabled, true);
            if (id === 'git-host') {
              assert.equal(
                config.containers[0].images.host.image,
                `registry.cloudflare.com/${target.account_id}/${target.worker_prefix}-git-host@${target.host.image_digest}`,
              );
              assert.equal(config.containers[0].ssh.enabled, false);
              assert.equal(config.vars.WORK_GIT_DISCLOSURE_DIGEST, target.host.disclosure_digest);
              assert.equal(config.r2_buckets[0].remote, false);
            }
            const output = join(dry, id);
            await run(
              process.execPath,
              [
                join(root, 'node_modules/wrangler/bin/wrangler.js'),
                'deploy',
                '--dry-run',
                '--containers-rollout',
                'none',
                '--config',
                configPath,
                '--outdir',
                output,
              ],
              {
                cwd: root,
                timeout: 30000,
                maxBuffer: 1024 * 1024,
                env: {
                  ...process.env,
                  CI: 'true',
                  CLOUDFLARE_API_TOKEN: '',
                  CLOUDFLARE_API_BASE_URL: 'http://127.0.0.1:1',
                  WRANGLER_SEND_METRICS: 'false',
                },
              },
            );
            const modulePaths = (await readdir(output)).filter((name) =>
              /\.(?:js|mjs)$/.test(name),
            );
            assert.equal(modulePaths.length, 1);
            assert.deepEqual(
              await readFile(join(output, modulePaths[0]!)),
              await readFile(join(closed.directory, 'binding/runtime/workers', id + '.mjs')),
            );
          }
          await run(
            process.execPath,
            [
              join(root, 'node_modules/wrangler/bin/wrangler.js'),
              'types',
              '--config',
              join(closed.directory, 'configs/git-host/wrangler.json'),
              '--include-runtime=false',
              '--strict-vars=false',
              join(dry, 'git-host-env.d.ts'),
            ],
            {
              cwd: root,
              timeout: 30000,
              maxBuffer: 1024 * 1024,
              env: {
                ...process.env,
                CI: 'true',
                CLOUDFLARE_API_TOKEN: '',
                CLOUDFLARE_API_BASE_URL: 'http://127.0.0.1:1',
                WRANGLER_SEND_METRICS: 'false',
              },
            },
          );
          const types = await readFile(join(dry, 'git-host-env.d.ts'), 'utf8');
          assert.match(types, /GIT_SOURCES: R2Bucket/);
          assert.match(types, /GIT_HOST: DurableObjectNamespace/);
        } finally {
          await rm(dry, { recursive: true, force: true });
        }
      },
    );
    await t.test(
      'rewritten configuration inventory cannot grant bootstrap, open ingress or substitute image bytes',
      async () => {
        assert.ok(closed);
        const manifestPath = join(closed.directory, 'manifest.json');
        const configPath = join(closed.directory, 'configs/git-host/wrangler.json');
        const savedManifest = await readFile(manifestPath);
        const savedConfig = await readFile(configPath);
        for (const mutate of [
          (config: any) => {
            config.services.push({
              binding: 'ADMIN',
              service: target.checkpoint.service,
              entrypoint: 'WorkCheckpointBootstrap',
            });
          },
          (config: any) => {
            config.vars.WORK_GIT_HOST_ENABLED = 'true';
          },
          (config: any) => {
            config.workers_dev = true;
          },
          (config: any) => {
            config.containers[0].images.host.image =
              'registry.cloudflare.com/' + target.account_id + '/unreviewed:latest';
          },
          (config: any) => {
            config.main = '/tmp/unreviewed.mjs';
          },
        ]) {
          const config = JSON.parse(savedConfig.toString());
          mutate(config);
          await writeFile(configPath, bytes(config));
          await assert.rejects(
            verifyClosedCopyConfigurations(closed.directory, closed.manifest_sha256),
            /members_changed/,
          );
          const manifest = JSON.parse(savedManifest.toString());
          manifest.members = await copyRuntimeInventory(closed.directory);
          const updated = bytes(manifest);
          await writeFile(manifestPath, updated);
          await assert.rejects(
            verifyClosedCopyConfigurations(closed.directory, sha(updated)),
            /capabilities_changed/,
          );
          await writeFile(configPath, savedConfig);
          await writeFile(manifestPath, savedManifest);
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
    if (closed) await rm(closed.directory, { recursive: true, force: true });
    await rm(runtime.directory, { recursive: true, force: true });
    await rm(packet.directory, { recursive: true, force: true });
  }
});
