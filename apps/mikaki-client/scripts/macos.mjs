import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const [command, ...args] = process.argv.slice(2);
if (process.platform !== 'darwin' || !['dev', 'build'].includes(command)) {
  throw new Error('Run dev:macos or build:macos on macOS.');
}
const appDirectory = fileURLToPath(new URL('../', import.meta.url));
const registration = JSON.parse(
  readFileSync(new URL('../desktop-client-registration.json', import.meta.url), 'utf8'),
);
const clientId = process.env.MIKAKI_DESKTOP_CLIENT_ID ?? registration.client_id;
if (!clientId.trim()) throw new Error('MIKAKI_DESKTOP_CLIENT_ID must not be empty.');

const result = spawnSync(
  process.execPath,
  [
    fileURLToPath(new URL('../node_modules/@tauri-apps/cli/tauri.js', import.meta.url)),
    command,
    '--config',
    'src-tauri/tauri.macos-dev.conf.json',
    ...(command === 'build' ? ['--bundles', 'app'] : []),
    ...args,
    '--',
    '--locked',
  ],
  {
    cwd: appDirectory,
    stdio: 'inherit',
    env: {
      ...process.env,
      MIKAKI_DESKTOP_CLIENT_ID: clientId,
      APPLE_SIGNING_IDENTITY: '-',
    },
  },
);
if (result.error) throw result.error;
process.exit(result.status ?? 1);
