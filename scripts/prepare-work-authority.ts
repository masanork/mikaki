/** Build fresh product Wasm and seal an offline isolated-authority preparation packet. */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { build } from 'esbuild';
import { releaseSource } from './release-inventory.ts';
import {
  AUTHORITY_INPUTS,
  OP_MEMBERS,
  authorityInventory,
  authorityPlan,
  authorityTemplates,
  digest,
  packetFile,
  packetJson,
  verifyAuthorityPacket,
} from './work-authority-packet.ts';

const exec = promisify(execFile);
const root = fileURLToPath(new URL('../', import.meta.url));
export async function prepareWorkAuthority(account: string, outputParent: string) {
  const templates = authorityTemplates(account);
  const source = releaseSource(root);
  assert.equal(source.clean, true, 'authority_packet_source_dirty');
  const parent = resolve(outputParent);
  const local = join(root, 'local/generated');
  assert.ok(relative(local, parent) && !relative(local, parent).startsWith('..'));
  await mkdir(parent, { recursive: true, mode: 0o700 });
  assert.equal(await realpath(parent), parent, 'authority_packet_symlink_output_denied');
  await exec('git', ['check-ignore', '--quiet', parent], { cwd: root });
  const directory = await mkdtemp(join(parent, 'authority-'));
  await packetJson(join(directory, 'plan.json'), authorityPlan(account));
  for (const name of ['op/build/worker', 'checkpoint', 'migrations', 'inputs'])
    await mkdir(join(directory, name), { recursive: true, mode: 0o700 });
  const env = { ...process.env, GITHUB_SHA: source.commit, CARGO_NET_OFFLINE: 'true' };
  const commands = [
    { executable: 'worker-build', args: ['--release', 'crates/worker', '--locked'] },
    { executable: process.execPath, args: ['scripts/build-service-catalog.ts', '--check'] },
    { executable: process.execPath, args: ['scripts/build-op-authority.ts'] },
  ];
  for (const [index, command] of commands.entries()) {
    const result = await exec(command.executable, command.args, {
      cwd: root,
      env,
      maxBuffer: 4 * 1024 * 1024,
    }).catch(async (error: { stdout?: string; stderr?: string }) => {
      await writeFile(
        join(directory, `build-${index + 1}.log`),
        `${error.stdout ?? ''}${error.stderr ?? ''}`,
        {
          flag: 'wx',
          mode: 0o600,
        },
      );
      throw new Error(`authority_packet_build_${index + 1}_failed`);
    });
    await writeFile(join(directory, `build-${index + 1}.log`), result.stdout + result.stderr, {
      flag: 'wx',
      mode: 0o600,
    });
  }
  for (const name of OP_MEMBERS)
    await writeFile(
      join(directory, 'op/build', name),
      await packetFile(join(root, 'crates/worker/build', name)),
      { flag: 'wx', mode: 0o600 },
    );
  await build({
    entryPoints: [join(root, 'crates/work-checkpoint-worker/worker.ts')],
    outfile: join(directory, 'checkpoint/worker.mjs'),
    bundle: true,
    platform: 'browser',
    format: 'esm',
    target: 'es2022',
    external: ['cloudflare:workers'],
    logLevel: 'silent',
  });
  for (const location of ['migrations', 'work-migrations']) {
    const path = join(root, 'crates/worker', location);
    for (const name of (await readdir(path)).filter((n) => n.endsWith('.sql')).sort())
      await writeFile(join(directory, 'migrations', name), await packetFile(join(path, name)), {
        flag: 'wx',
        mode: 0o600,
      });
  }
  for (const name of AUTHORITY_INPUTS)
    await writeFile(
      join(directory, 'inputs', name.replaceAll('/', '__')),
      await packetFile(join(root, name)),
      {
        flag: 'wx',
        mode: 0o600,
      },
    );
  for (const [name, config] of Object.entries(templates))
    await packetJson(join(directory, name, 'wrangler.template.json'), config);
  const workerBuild = (await exec('which', ['worker-build'])).stdout.trim();
  await packetJson(join(directory, 'build.json'), {
    source,
    commands,
    features: ['worker-entry'],
    qualification_feature: false,
    tools: {
      node: process.version,
      rustc: (await exec('rustc', ['--version'])).stdout.trim(),
      worker_build: {
        executable: workerBuild,
        ...digest(await packetFile(workerBuild, 64 * 1024 * 1024)),
      },
      wrangler: JSON.parse(await readFile(join(root, 'node_modules/wrangler/package.json'), 'utf8'))
        .version,
      esbuild: JSON.parse(await readFile(join(root, 'node_modules/esbuild/package.json'), 'utf8'))
        .version,
    },
    provenance: 'local-build-byte-inventory-not-signed-attestation',
  });
  assert.deepEqual(releaseSource(root), source, 'authority_packet_source_changed');
  await packetJson(
    join(directory, 'manifest.json'),
    await authorityInventory(directory, { ...source, clean: true }),
  );
  await verifyAuthorityPacket(directory);
  assert.deepEqual(releaseSource(root), source, 'authority_packet_source_changed');
  return { directory, source, stage: 'prepared-not-allocated-or-enrolled' };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [action, ...args] = process.argv.slice(2);
    if (action === 'prepare' && args.length === 2)
      console.log(JSON.stringify(await prepareWorkAuthority(args[0]!, args[1]!), null, 2));
    else if (action === 'verify' && args.length === 1) {
      const manifest = await verifyAuthorityPacket(resolve(args[0]!));
      console.log(
        JSON.stringify({
          source: manifest.source,
          members: manifest.members.length,
          stage: manifest.stage,
        }),
      );
    } else throw new Error('usage');
  } catch {
    console.error(
      'Authority preparation refused. Use prepare ACCOUNT local/generated/OUTPUT from a clean commit, or verify PACKET. No remote resource is allocated or enrolled.',
    );
    process.exitCode = 1;
  }
}
