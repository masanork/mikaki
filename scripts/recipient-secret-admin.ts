import { spawn } from 'node:child_process';
import { lstat, readFile, realpath, rename, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validatePublicRecord } from './recipient-key-admin.ts';

const repository = fileURLToPath(new URL('..', import.meta.url));
const wrangler = fileURLToPath(
  new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url),
);

function options(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    if (!key?.startsWith('--') || !args[index + 1] || Object.hasOwn(parsed, key)) {
      throw new Error('invalid arguments');
    }
    parsed[key] = args[index + 1];
  }
  const allowed = ['--seed', '--public', '--store-id', '--config', '--apply'];
  if (
    Object.keys(parsed).some((key) => !allowed.includes(key)) ||
    allowed.some((key) => !parsed[key]) ||
    !/^[0-9a-f]{32}$/i.test(parsed['--store-id']) ||
    !['yes', 'no'].includes(parsed['--apply'])
  ) {
    throw new Error(
      'usage: node scripts/recipient-secret-admin.ts --seed FILE --public FILE --store-id STORE_ID --config CONFIG --apply yes|no',
    );
  }
  return parsed;
}

function outsideRepository(path) {
  const fromRepository = relative(repository, path);
  return fromRepository === '..' || fromRepository.startsWith(`..${sep}`);
}

async function run(program, args, input = undefined) {
  await new Promise<void>((resolveRun, rejectRun) => {
    const child = spawn(program, args, {
      cwd: repository,
      stdio: [input ? 'pipe' : 'ignore', 'inherit', 'inherit'],
    });
    child.once('error', rejectRun);
    child.once('exit', (code) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${program} exited with status ${code}`));
    });
    if (input) {
      child.stdin.end(input);
    }
  });
}

async function main() {
  const args = options(process.argv.slice(2));
  const seedPath = resolve(args['--seed']);
  const publicPath = resolve(args['--public']);
  const configPath = resolve(args['--config']);
  if (!isAbsolute(args['--seed'])) {
    throw new Error('seed path must be absolute');
  }
  const seedInfo = await lstat(seedPath);
  if (
    !seedInfo.isFile() ||
    seedInfo.isSymbolicLink() ||
    seedInfo.nlink !== 1 ||
    (seedInfo.mode & 0o777) !== 0o600 ||
    seedInfo.uid !== process.getuid() ||
    !outsideRepository(await realpath(seedPath))
  ) {
    throw new Error('seed must be an owner-only regular file outside the repository');
  }
  const record = JSON.parse(await readFile(publicPath, 'utf8'));
  validatePublicRecord(record);
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  if (
    config.name !== 'mikaki-userinfo-claim-worker' ||
    config.workers_dev !== false ||
    config.preview_urls !== false ||
    config.secrets_store_secrets?.some((binding) => binding.binding === record.secret_ref)
  ) {
    throw new Error('claim Worker config is incompatible or binding already exists');
  }
  await run('cargo', [
    'run',
    '--locked',
    '--quiet',
    '--manifest-path',
    'design/probes/pqc/Cargo.toml',
    '--bin',
    'recipient_key',
    '--',
    'verify',
    seedPath,
    publicPath,
  ]);
  console.log(
    JSON.stringify({
      key_id: record.key_id,
      generation: record.generation,
      binding: record.secret_ref,
      config: configPath,
      apply: args['--apply'],
    }),
  );
  if (args['--apply'] !== 'yes') return;
  const seed = await readFile(seedPath);
  try {
    if (!/^[A-Za-z0-9_-]{86}\n$/.test(seed.toString('ascii'))) {
      throw new Error('invalid seed file encoding');
    }
    await run(
      process.execPath,
      [
        wrangler,
        'secrets-store',
        'secret',
        'create',
        args['--store-id'],
        '--name',
        record.secret_ref,
        '--scopes',
        'workers',
        '--remote',
        '--config',
        configPath,
      ],
      seed,
    );
  } finally {
    seed.fill(0);
  }
  config.secrets_store_secrets = [
    ...(config.secrets_store_secrets ?? []),
    { binding: record.secret_ref, store_id: args['--store-id'], secret_name: record.secret_ref },
  ];
  const temporary = join(dirname(configPath), `.recipient-binding-${process.pid}.tmp`);
  await writeFile(temporary, `${JSON.stringify(config, null, 2)}\n`, { flag: 'wx' });
  await rename(temporary, configPath);
  console.log(
    'Secret created and claim Worker config updated. Deploy the claim Worker, then stage and activate the public key.',
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
