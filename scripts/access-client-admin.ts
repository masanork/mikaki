import { lstat, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { getPlatformProxy } from 'wrangler';
import {
  bindAccessEmail,
  registerAccessClient,
  rotateAccessSecret,
} from './access-client-admin-store.ts';

const options: Record<string, string> = {};
for (let i = 2; i < process.argv.length; i += 2) {
  const key = process.argv[i];
  if (!key?.startsWith('--') || i + 1 >= process.argv.length || Object.hasOwn(options, key))
    throw new Error('invalid arguments');
  options[key] = process.argv[i + 1];
}
const allowed = new Set([
  '--config',
  '--remote',
  '--action',
  '--input',
  '--actor',
  '--reason',
  '--apply',
]);
const action = options['--action'];
if (
  Object.keys(options).some((key) => !allowed.has(key)) ||
  !options['--config'] ||
  !options['--input'] ||
  !options['--actor'] ||
  !options['--reason'] ||
  !['yes', 'no'].includes(options['--remote']) ||
  !['yes', 'no'].includes(options['--apply']) ||
  !['register', 'rotate', 'revoke-secret', 'bind-email', 'revoke-email'].includes(action)
)
  throw new Error(
    'usage: --config FILE --remote yes|no --action register|rotate|revoke-secret|bind-email|revoke-email --input PRIVATE_JSON --actor NAME --reason TEXT --apply yes|no',
  );
const inputPath = resolve(options['--input']);
const inputStat = await lstat(inputPath);
if (
  !inputStat.isFile() ||
  (inputStat.mode & 0o077) !== 0 ||
  inputStat.uid !== process.getuid?.() ||
  inputStat.size > 16384
)
  throw new Error('input must be an owner-only regular file owned by the current user');
const input: Record<string, unknown> = JSON.parse(await readFile(inputPath, 'utf8'));
const fields: Record<string, string[]> = {
  register: ['client', 'redirect', 'secret', 'method'],
  rotate: ['client', 'expected', 'secret'],
  'revoke-secret': ['client', 'expected'],
  'bind-email': ['client', 'account', 'email', 'expected', 'verified_by_operator'],
  'revoke-email': ['client', 'account', 'expected'],
};
if (
  !input ||
  typeof input !== 'object' ||
  Array.isArray(input) ||
  JSON.stringify(Object.keys(input).sort()) !== JSON.stringify(fields[action].sort())
)
  throw new Error('unexpected input fields');
if (
  typeof input.client !== 'string' ||
  (action !== 'register' &&
    (!Number.isSafeInteger(input.expected) || (input.expected as number) < 0))
)
  throw new Error('invalid input');
if (
  action === 'register' &&
  (typeof input.redirect !== 'string' ||
    typeof input.secret !== 'string' ||
    !['client_secret_basic', 'client_secret_post'].includes(input.method as string))
)
  throw new Error('invalid registration input');
if (action === 'rotate' && typeof input.secret !== 'string')
  throw new Error('invalid secret input');
if (['bind-email', 'revoke-email'].includes(action) && typeof input.account !== 'string')
  throw new Error('invalid account input');
if (
  action === 'bind-email' &&
  (typeof input.email !== 'string' || input.verified_by_operator !== true)
)
  throw new Error('operator must verify the exact email address');
const configPath = resolve(options['--config']);
const config = JSON.parse(await readFile(configPath, 'utf8'));
const remote = options['--remote'] === 'yes';
const binding = config.d1_databases?.find((item: { binding: string }) => item.binding === 'DB');
if (!binding || Boolean(binding.remote) !== remote || (remote && !binding.database_id))
  throw new Error('DB binding does not match target');
console.log(`Target: ${remote ? 'remote' : 'local'} DB in ${configPath}; action: ${action}`);
if (options['--apply'] !== 'yes') {
  console.log(
    'Dry run; input shape and target checked. No database write or ownership verification performed.',
  );
  process.exit(0);
}
const platform = await getPlatformProxy({ configPath, remoteBindings: remote });
try {
  const db = platform.env.DB;
  const actor = options['--actor'],
    reason = options['--reason'],
    client = input.client as string;
  let result;
  if (action === 'register')
    result = await registerAccessClient(
      db,
      client,
      input.redirect as string,
      input.secret as string,
      input.method as 'client_secret_basic' | 'client_secret_post',
      actor,
      reason,
    );
  else if (action === 'rotate' || action === 'revoke-secret')
    result = await rotateAccessSecret(
      db,
      client,
      input.expected as number,
      action === 'rotate' ? (input.secret as string) : null,
      actor,
      reason,
    );
  else
    result = await bindAccessEmail(
      db,
      client,
      input.account as string,
      action === 'bind-email' ? (input.email as string) : null,
      input.expected as number,
      actor,
      reason,
    );
  console.log(JSON.stringify(result));
} finally {
  await platform.dispose();
}
