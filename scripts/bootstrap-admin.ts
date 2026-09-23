import { open, readFile, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
import { getPlatformProxy } from 'wrangler';
import { issueBootstrapInvite } from './enrollment-store.ts';

const options = {};
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  if (!key?.startsWith('--') || index + 1 >= process.argv.length || Object.hasOwn(options, key)) {
    throw new Error('invalid command arguments');
  }
  options[key] = process.argv[index + 1];
}
if (
  Object.keys(options).some(
    (key) => !['--config', '--remote', '--actor', '--reason', '--output', '--apply'].includes(key),
  ) ||
  !options['--config'] ||
  !['yes', 'no'].includes(options['--remote']) ||
  !options['--actor'] ||
  !options['--reason'] ||
  !options['--output'] ||
  !['yes', 'no'].includes(options['--apply'])
) {
  throw new Error(
    'usage: node scripts/bootstrap-admin.ts --config CONFIG --remote yes|no --actor NAME --reason TEXT --output FILE --apply yes|no',
  );
}
const configPath = resolve(options['--config']);
const config = JSON.parse(await readFile(configPath, 'utf8'));
const remote = options['--remote'] === 'yes';
const binding = config.d1_databases?.find((item) => item.binding === 'DB');
if (!binding || Boolean(binding.remote) !== remote || (remote && !binding.database_id)) {
  throw new Error('DB binding and --remote must identify the same configured database');
}
console.log(`Target: ${remote ? 'remote' : 'local'} DB in ${configPath}`);
if (options['--apply'] === 'no') {
  console.log('Dry run; no invitation generated or database write');
  process.exit(0);
}
const outputPath = resolve(options['--output']);
const output = await open(outputPath, 'wx', 0o600);
let written = false;
try {
  const platform = await getPlatformProxy({ configPath, remoteBindings: remote });
  try {
    const result = await issueBootstrapInvite(
      platform.env.DB,
      options['--actor'],
      options['--reason'],
    );
    await output.writeFile(`${JSON.stringify(result)}\n`);
    written = true;
    console.log(
      `Invitation written to ${outputPath}; expires at ${new Date(result.expiresAt * 1000).toISOString()}`,
    );
  } finally {
    await platform.dispose();
  }
} finally {
  await output.close();
  if (!written) await unlink(outputPath);
}
