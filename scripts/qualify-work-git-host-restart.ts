/** Inspect retained outcomes or measure the single stopped-state experiment over private RPC. */
import { open, readFile, writeFile, lstat } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getPlatformProxy } from 'wrangler';
import { boundedHostFile } from './work-git-registry.ts';
import {
  restartTargetSchema,
  qualificationImage,
  qualificationStatus,
  runRestartQualification,
  type RestartConnection,
} from './work-git-host-qualification.ts';
export async function qualifyGitHostRestart(directory: string, mode: 'inspect' | 'restart') {
  if (mode !== 'inspect' && mode !== 'restart') throw new Error('qualification_mode_denied');
  const target = restartTargetSchema.parse(
    JSON.parse((await boundedHostFile(join(directory, 'target.json'), 8192)).toString()),
  );
  qualificationImage(target.original.account_id, target.image);
  if (
    createHash('sha256')
      .update(await boundedHostFile(join(directory, 'worker.mjs'), 2 * 1024 * 1024))
      .digest('hex') !== target.worker_sha256
  )
    throw new Error('qualification_packet_changed');
  const configPath = join(directory, 'probe.json');
  const configBytes = JSON.stringify({
    name: 'mikaki-work-git-host-restart-probe',
    account_id: target.original.account_id,
    compatibility_date: '2026-10-10',
    workers_dev: false,
    preview_urls: false,
    services: [
      {
        binding: 'HOST_PROVISIONER',
        service: target.original.worker,
        entrypoint: 'WorkGitHostQualification',
        remote: true,
      },
    ],
  });
  try {
    await writeFile(configPath, configBytes, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
  }
  const metadata = await lstat(configPath);
  if (
    !metadata.isFile() ||
    metadata.size > 4096 ||
    (await readFile(configPath, 'utf8')) !== configBytes
  )
    throw new Error('qualification_probe_changed');
  const journal =
    mode === 'restart' ? await open(join(directory, 'restart-run.jsonl'), 'wx', 0o600) : undefined;
  const record = async (value: unknown) => {
    if (journal) {
      await journal.write(JSON.stringify(value) + '\n');
      await journal.sync();
    }
  };
  let proxy:
    | Awaited<ReturnType<typeof getPlatformProxy<{ HOST_PROVISIONER: RestartConnection }>>>
    | undefined;
  try {
    await record({ event: 'selected', target, scope: 'infrastructure_only' });
    proxy = await getPlatformProxy({
      configPath,
      envFiles: [],
      persist: false,
      remoteBindings: true,
    });
    if (mode === 'inspect') {
      const status = qualificationStatus(
        target.original,
        target.image,
        await proxy.env.HOST_PROVISIONER.status(),
      );
      await writeFile(
        join(directory, `inspection-${randomUUID()}.json`),
        JSON.stringify(status, null, 2) + '\n',
        { flag: 'wx', mode: 0o600 },
      );
      return status;
    }
    const result = await runRestartQualification(
      target.original,
      target.image,
      proxy.env.HOST_PROVISIONER,
      record,
    );
    await record({ event: 'complete', ...result, git_dispatches: 0 });
    return result;
  } catch {
    await record({ event: 'stopped', outcome: 'unqualified' });
    throw new Error('qualification_restart_unqualified');
  } finally {
    try {
      await proxy?.dispose();
    } finally {
      await journal?.close();
    }
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [mode, directory, ...rest] = process.argv.slice(2);
    if ((mode !== 'inspect' && mode !== 'restart') || !directory || rest.length)
      throw new Error('usage');
    console.log(JSON.stringify(await qualifyGitHostRestart(resolve(directory), mode), null, 2));
  } catch {
    console.error(
      'Restart qualification refused or stopped. Inspect the retained outcome; never reset records or resend the experiment.',
    );
    process.exitCode = 1;
  }
}
