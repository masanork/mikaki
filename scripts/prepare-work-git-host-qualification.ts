/** Prepare a frozen, synthetic-data infrastructure packet. No remote mutation. */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { build } from 'esbuild';
import { parse, type ParseError } from 'jsonc-parser';
import { copyJobFixture } from '../local/conformance/support/work-copy-job-fixture.ts';
import { prepareGitHostImage } from './prepare-work-git-host.ts';
import { QUALIFICATION_NAME, qualificationTargetSchema } from './work-git-host-qualification.ts';
const exec = promisify(execFile);
const root = fileURLToPath(new URL('../', import.meta.url));
const hash = (b: Buffer) => createHash('sha256').update(b).digest('hex');
async function file(path: string, value: unknown) {
  await writeFile(path, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
export async function prepareGitHostQualification(account: string, parent: string) {
  if (!/^[a-f0-9]{32}$/.test(account)) throw new Error('qualification_target_denied');
  await exec('git', ['check-ignore', '--quiet', resolve(parent)], { cwd: root });
  if ((await exec('git', ['status', '--porcelain'], { cwd: root })).stdout.trim())
    throw new Error('qualification_source_dirty');
  const source = (await exec('git', ['rev-parse', 'HEAD'], { cwd: root })).stdout.trim();
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const f = await copyJobFixture({ LOCAL_COPY_TRIGGER_DISABLED: 'true' });
  try {
    const packet = await prepareGitHostImage(f.nativeDisclosure, f.sourceBindings, parent);
    const workerFile = join(packet.directory, 'worker.mjs');
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
    const target = qualificationTargetSchema.parse({
      account_id: account,
      worker: QUALIFICATION_NAME,
      bucket: QUALIFICATION_NAME,
      namespace: 'mikaki-dev',
      authority: 'mikaki-git-host-qualification-v1',
      ...packet.receipt,
      source_commit: source,
      source_clean: true,
      worker_sha256: hash(await readFile(workerFile)),
    });
    await file(join(packet.directory, 'native-disclosure.json'), f.nativeDisclosure);
    await file(join(packet.directory, 'target.json'), target);
    const errors: ParseError[] = [];
    const config = parse(
      await readFile(
        join(root, 'crates/work-git-host-worker/wrangler.qualification.example.jsonc'),
        'utf8',
      ),
      errors,
      { allowTrailingComma: true },
    );
    if (errors.length) throw new Error('qualification_config_invalid');
    config.$schema = join(root, 'node_modules/wrangler/config-schema.json');
    config.account_id = account;
    config.main = workerFile;
    Object.assign(config.vars, {
      WORK_GIT_PROVISION_ENABLED: 'true',
      WORK_ARTIFACTS_ACCOUNT: account,
      WORK_GIT_REGISTRY_SHA256: target.registry_sha256,
      WORK_GIT_DISCLOSURE_DIGEST: target.disclosure_digest,
    });
    config.containers[0].images.host = {
      dockerfile: join(packet.image, 'Dockerfile'),
      build_context: packet.image,
    };
    await file(join(packet.directory, 'wrangler.json'), config);
    return { directory: packet.directory, target };
  } finally {
    await f.close();
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [account, parent, ...rest] = process.argv.slice(2);
    if (!account || !parent || rest.length) throw new Error('usage');
    console.log(
      JSON.stringify(await prepareGitHostQualification(account, resolve(parent)), null, 2),
    );
  } catch {
    console.error(
      'Qualification packet refused. Use a clean committed checkout, explicit account and ignored output directory.',
    );
    process.exitCode = 1;
  }
}
