/** Append a frozen Worker revision to the retained packet; no new source/resource identity. */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { build } from 'esbuild';
import { z } from 'zod';
import { boundedHostFile } from './work-git-registry.ts';
import {
  qualificationTargetSchema,
  qualificationImage,
  restartTargetSchema,
} from './work-git-host-qualification.ts';
const exec = promisify(execFile);
const root = fileURLToPath(new URL('../', import.meta.url));
const hash = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const resourcesSchema = z.object({
  account_id: z.string(),
  worker: z.string(),
  bucket: z.string(),
  registry_sha256: z.string(),
  namespace_id: z.string().regex(/^[a-f0-9]{32}$/),
  container_application_id: z.string().regex(/^[a-f0-9]{32}$/),
  worker_version: z.string().uuid(),
  image: z.string(),
  bindings_verified: z.literal(true),
  workers_dev: z.literal(false),
  preview_urls: z.literal(false),
});
async function jsonFile(path: string, value: unknown) {
  await writeFile(path, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
export async function prepareGitHostRestart(packet: string) {
  await exec('git', ['check-ignore', '--quiet', packet], { cwd: root });
  if ((await exec('git', ['status', '--porcelain'], { cwd: root })).stdout.trim())
    throw new Error('qualification_source_dirty');
  const source = (await exec('git', ['rev-parse', 'HEAD'], { cwd: root })).stdout.trim();
  const original = qualificationTargetSchema.parse(
    JSON.parse((await boundedHostFile(join(packet, 'target.json'), 4096)).toString()),
  );
  const selected = resourcesSchema.parse(
    JSON.parse((await boundedHostFile(join(packet, 'remote-resources.json'), 8192)).toString()),
  );
  if (
    selected.account_id !== original.account_id ||
    selected.worker !== original.worker ||
    selected.bucket !== original.bucket ||
    selected.registry_sha256 !== original.registry_sha256
  )
    throw new Error('qualification_resource_denied');
  const image = qualificationImage(original.account_id, selected.image);
  for (const [file, digest] of [
    ['worker.mjs', original.worker_sha256],
    ['image/host.mjs', original.host_sha256],
    ['image/Dockerfile', original.dockerfile_sha256],
    ['registry.json', original.registry_sha256],
  ]) {
    if (hash(await boundedHostFile(join(packet, file!), 2 * 1024 * 1024)) !== digest)
      throw new Error('qualification_packet_changed');
  }
  await exec(
    'git',
    [
      'diff',
      '--exit-code',
      original.source_commit,
      '--',
      'crates/work-git-host-worker/worker.ts',
      'crates/work-git-host-worker/container.ts',
      'scripts/work-git-host-bootstrap.ts',
      'scripts/work-git-registry.ts',
    ],
    { cwd: root },
  );
  const directory = join(packet, 'restart-qualification');
  await mkdir(directory, { mode: 0o700 });
  const workerFile = join(directory, 'worker.mjs');
  await build({
    entryPoints: [join(root, 'crates/work-git-host-worker/qualification.ts')],
    outfile: workerFile,
    bundle: true,
    platform: 'browser',
    format: 'esm',
    target: 'es2022',
    external: ['cloudflare:workers'],
    logLevel: 'silent',
  });
  const target = restartTargetSchema.parse({
    format_version: 1,
    experiment: 'inactive_restart_v1',
    original,
    image,
    namespace_id: selected.namespace_id,
    container_application_id: selected.container_application_id,
    previous_worker_version: selected.worker_version,
    source_commit: source,
    source_clean: true,
    worker_sha256: hash(await readFile(workerFile)),
  });
  await jsonFile(join(directory, 'target.json'), target);
  await jsonFile(join(directory, 'wrangler.json'), {
    $schema: join(root, 'node_modules/wrangler/config-schema.json'),
    name: original.worker,
    account_id: original.account_id,
    main: workerFile,
    compatibility_date: '2026-10-10',
    workers_dev: false,
    preview_urls: false,
    vars: {
      WORK_GIT_HOST_ENABLED: 'false',
      WORK_GIT_PROVISION_ENABLED: 'true',
      WORK_ARTIFACTS_ACCOUNT: original.account_id,
      WORK_ARTIFACTS_NAMESPACE: original.namespace,
      WORK_AUTHORITY_ID: original.authority,
      WORK_GIT_DISCLOSURE_DIGEST: original.disclosure_digest,
      WORK_GIT_REGISTRY_SHA256: original.registry_sha256,
    },
    containers: [
      {
        name: original.worker,
        scheduling_policy: 'durable_object',
        images: { host: { image } },
        observability: { enabled: true, logs: { enabled: true } },
      },
    ],
    durable_objects: {
      bindings: [{ name: 'GIT_HOST', class_name: 'GitHostQualificationContainer' }],
    },
    r2_buckets: [{ binding: 'GIT_SOURCES', bucket_name: original.bucket }],
    exports: {
      GitHostQualificationContainer: {
        type: 'durable-object',
        storage: 'sqlite',
        container: original.worker,
      },
    },
    observability: { enabled: true, traces: { enabled: true } },
  });
  return { directory, target };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [packet, ...rest] = process.argv.slice(2);
    if (!packet || rest.length) throw new Error('usage');
    console.log(JSON.stringify(await prepareGitHostRestart(resolve(packet)), null, 2));
  } catch {
    console.error(
      'Restart revision refused. Retain the original packet and use its verified resource receipt from a clean committed checkout.',
    );
    process.exitCode = 1;
  }
}
