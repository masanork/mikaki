import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { getPlatformProxy } from 'wrangler';
import { activateWorkerPolicy, validateWorkerPolicyProjection } from './worker-policy-store.ts';

const options: Record<string, string> = {};
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  if (!key?.startsWith('--') || index + 1 >= process.argv.length || Object.hasOwn(options, key)) {
    throw new Error('invalid command arguments');
  }
  options[key] = process.argv[index + 1];
}
const allowed = new Set([
  '--config',
  '--policy',
  '--expected',
  '--actor',
  '--reason',
  '--apply',
  '--remote',
]);
if (
  Object.keys(options).some((key) => !allowed.has(key)) ||
  !options['--config'] ||
  !options['--policy'] ||
  !options['--expected'] ||
  !options['--actor'] ||
  !options['--reason'] ||
  !['yes', 'no'].includes(options['--apply']) ||
  !['yes', 'no'].includes(options['--remote'])
) {
  throw new Error(
    'usage: node scripts/activate-worker-policy.ts --config CONFIG --policy JSON --expected REVISION|none --actor NAME --reason TEXT --remote yes|no --apply yes|no',
  );
}

const configPath = resolve(options['--config']);
const config = JSON.parse(await readFile(configPath, 'utf8'));
const binding = config.d1_databases?.find((entry: { binding: string }) => entry.binding === 'DB');
const remote = options['--remote'] === 'yes';
if (
  !binding ||
  Boolean(binding.remote) !== remote ||
  (remote && (!binding.database_id || /^0+$/.test(binding.database_id.replaceAll('-', ''))))
) {
  throw new Error('DB binding and --remote must identify the same configured database');
}
const policy = JSON.parse(await readFile(resolve(options['--policy']), 'utf8'));
validateWorkerPolicyProjection(policy);
const expectedRevision = options['--expected'] === 'none' ? null : options['--expected'];
console.log(`Policy revision: ${policy.policy_revision}`);
console.log(`Projection revision: ${policy.projection_revision}`);
console.log(`Target: ${remote ? 'remote' : 'local'} DB binding in ${configPath}`);
if (options['--apply'] !== 'yes') {
  console.log('Dry run; no database write');
  process.exit(0);
}

const platform = await getPlatformProxy({
  configPath,
  remoteBindings: remote,
  persist: remote ? false : { path: join(dirname(configPath), '.wrangler', 'state', 'v3') },
});
try {
  const result = await activateWorkerPolicy(platform.env.DB, policy, {
    expectedRevision,
    actor: options['--actor'],
    reason: options['--reason'],
  });
  console.log(`Activated generation ${result.generation}: ${result.projectionRevision}`);
} finally {
  await platform.dispose();
}
