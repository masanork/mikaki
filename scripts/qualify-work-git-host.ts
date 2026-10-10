/** Authenticated private service-binding probe. No deploy, mint or Git request. */
import { writeFile, open } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { getPlatformProxy } from 'wrangler';
import { boundedHostFile } from './work-git-registry.ts';
import {
  qualificationTargetSchema,
  qualificationImage,
  qualificationObservation,
} from './work-git-host-qualification.ts';
export async function qualifyGitHost(directory: string, imageRef: string) {
  const target = qualificationTargetSchema.parse(
    JSON.parse((await boundedHostFile(join(directory, 'target.json'), 4096)).toString('utf8')),
  );
  const image = qualificationImage(target.account_id, imageRef);
  for (const [file, digest] of [
    ['worker.mjs', target.worker_sha256],
    ['image/host.mjs', target.host_sha256],
    ['image/Dockerfile', target.dockerfile_sha256],
    ['registry.json', target.registry_sha256],
  ]) {
    const bytes = await boundedHostFile(join(directory, file!), 2 * 1024 * 1024);
    if (createHash('sha256').update(bytes).digest('hex') !== digest)
      throw new Error('qualification_packet_changed');
  }
  const configFile = join(directory, 'probe.json');
  await writeFile(
    configFile,
    JSON.stringify({
      name: 'mikaki-work-git-host-local-probe',
      account_id: target.account_id,
      compatibility_date: '2026-10-10',
      workers_dev: false,
      preview_urls: false,
      services: [
        {
          binding: 'HOST_PROVISIONER',
          service: target.worker,
          entrypoint: 'WorkGitHostQualification',
          remote: true,
        },
      ],
    }),
    { flag: 'wx', mode: 0o600 },
  );
  const journal = await open(join(directory, 'infrastructure-run.jsonl'), 'wx', 0o600);
  let proxy:
    | Awaited<
        ReturnType<typeof getPlatformProxy<{ HOST_PROVISIONER: { prepare(): Promise<unknown> } }>>
      >
    | undefined;
  const record = async (value: unknown) => {
    await journal.write(JSON.stringify(value) + '\n');
    await journal.sync();
  };
  try {
    await record({ event: 'selected', target, image, scope: 'infrastructure_only' });
    proxy = await getPlatformProxy({
      configPath: configFile,
      envFiles: [],
      persist: false,
      remoteBindings: true,
    });
    for (const [ordinal, started] of [
      [1, true],
      [2, false],
      [3, true],
    ] as const) {
      if (ordinal === 3) {
        await record({ event: 'cooling', wait_ms: 75000 });
        await new Promise<void>((r) => setTimeout(r, 75000));
      }
      await record({ event: 'intent', ordinal });
      // No RPC retries. A missing/mismatching response stops the remaining steps.
      let timer: ReturnType<typeof setTimeout> | undefined;
      let reply: unknown;
      try {
        reply = await Promise.race([
          proxy.env.HOST_PROVISIONER.prepare(),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error('qualification_timeout')), 300000);
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
      const value = qualificationObservation(target, image, ordinal, started, reply);
      await record({ event: 'observed', ...value });
    }
    await record({ event: 'complete', git_dispatches: 0 });
    return {
      qualified: true,
      source_commit: target.source_commit,
      registry_sha256: target.registry_sha256,
      image,
    };
  } catch {
    await record({ event: 'stopped', outcome: 'unqualified' });
    throw new Error('qualification_unqualified');
  } finally {
    try {
      await proxy?.dispose();
    } finally {
      await journal.close();
    }
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [directory, image, ...rest] = process.argv.slice(2);
    if (!directory || !image || rest.length) throw new Error('usage');
    console.log(JSON.stringify(await qualifyGitHost(resolve(directory), image), null, 2));
  } catch {
    console.error(
      'Infrastructure qualification stopped. Inspect the retained journal; do not reset slots or retry unknown calls.',
    );
    process.exitCode = 1;
  }
}
