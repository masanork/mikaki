import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { getPlatformProxy } from 'wrangler';
import {
  addRedirect,
  addKey,
  disableClient,
  listClients,
  registerClient,
  retireRedirect,
  retireKey,
  validateRedirect,
  validateKey,
  validateRegistration,
} from './client-admin-store.ts';

const options = {};
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  if (!key?.startsWith('--') || index + 1 >= process.argv.length || Object.hasOwn(options, key)) {
    throw new Error('invalid command arguments');
  }
  options[key] = process.argv[index + 1];
}
const allowed = new Set([
  '--config',
  '--remote',
  '--action',
  '--input',
  '--client',
  '--kid',
  '--actor',
  '--reason',
  '--apply',
]);
if (
  Object.keys(options).some((key) => !allowed.has(key)) ||
  !options['--config'] ||
  !['yes', 'no'].includes(options['--remote']) ||
  ![
    'register',
    'add-key',
    'retire-key',
    'add-redirect',
    'retire-redirect',
    'disable',
    'list',
  ].includes(options['--action']) ||
  !['yes', 'no'].includes(options['--apply'])
) {
  throw new Error(
    'usage: node scripts/client-admin.ts --config CONFIG --remote yes|no --action register|add-key|retire-key|add-redirect|retire-redirect|disable|list --input JSON --client ID --kid KID --actor NAME --reason TEXT --apply yes|no',
  );
}
const remote = options['--remote'] === 'yes';
const configPath = resolve(options['--config']);
const config = JSON.parse(await readFile(configPath, 'utf8'));
const binding = config.d1_databases?.find((item) => item.binding === 'DB');
if (!binding || Boolean(binding.remote) !== remote || (remote && !binding.database_id)) {
  throw new Error('DB binding and --remote must identify the same configured database');
}
const action = options['--action'];
const input = options['--input']
  ? JSON.parse(await readFile(resolve(options['--input']), 'utf8'))
  : null;
if (action === 'register') validateRegistration(input);
if (action === 'add-key') validateKey(input);
if (action === 'add-redirect' || action === 'retire-redirect') validateRedirect(input);
if (action !== 'list' && (!options['--actor'] || !options['--reason'])) {
  throw new Error('actor and reason are required for a change');
}
if (
  ['add-key', 'retire-key', 'add-redirect', 'retire-redirect', 'disable'].includes(action) &&
  !options['--client']
) {
  throw new Error('client ID is required');
}
if (action === 'retire-key' && !options['--kid']) throw new Error('key ID is required');
console.log(`Target: ${remote ? 'remote' : 'local'} DB in ${configPath}`);
console.log(`Action: ${action}`);
if (options['--apply'] !== 'yes' && action !== 'list') {
  console.log('Dry run; no database write');
  process.exit(0);
}
const platform = await getPlatformProxy({ configPath, remoteBindings: remote });
try {
  const db = platform.env.DB;
  let result;
  if (action === 'register')
    result = await registerClient(db, input, options['--actor'], options['--reason']);
  else if (action === 'add-key')
    result = await addKey(db, options['--client'], input, options['--actor'], options['--reason']);
  else if (action === 'retire-key')
    result = await retireKey(
      db,
      options['--client'],
      options['--kid'],
      options['--actor'],
      options['--reason'],
    );
  else if (action === 'add-redirect')
    result = await addRedirect(
      db,
      options['--client'],
      input,
      options['--actor'],
      options['--reason'],
    );
  else if (action === 'retire-redirect')
    result = await retireRedirect(
      db,
      options['--client'],
      input,
      options['--actor'],
      options['--reason'],
    );
  else if (action === 'disable')
    result = await disableClient(db, options['--client'], options['--actor'], options['--reason']);
  else result = await listClients(db);
  console.log(JSON.stringify(result, null, 2));
} finally {
  await platform.dispose();
}
