import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { preparePasskeySigning } from './macos-passkeys.mjs';

const [command, ...args] = process.argv.slice(2);
const passkeys = args.includes('--passkeys');
if (passkeys && command !== 'build') throw new Error('Passkey signing requires a bundled build.');
if (process.platform !== 'darwin' || !['dev', 'build'].includes(command)) {
  throw new Error('Run dev:macos or build:macos on macOS.');
}
const appDirectory = fileURLToPath(new URL('../', import.meta.url));
const registration = JSON.parse(
  readFileSync(new URL('../desktop-client-registration.json', import.meta.url), 'utf8'),
);
const clientId = process.env.MIKAKI_DESKTOP_CLIENT_ID ?? registration.client_id;
if (!clientId.trim()) throw new Error('MIKAKI_DESKTOP_CLIENT_ID must not be empty.');

const signing = passkeys ? preparePasskeySigning() : undefined;
try {
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL('../node_modules/@tauri-apps/cli/tauri.js', import.meta.url)),
      command,
      '--config',
      'src-tauri/tauri.macos-dev.conf.json',
      ...(signing ? ['--config', JSON.stringify(signing.config)] : []),
      ...(command === 'build' ? ['--bundles', 'app'] : []),
      ...args.filter((arg) => arg !== '--passkeys'),
      '--',
      '--locked',
    ],
    {
      cwd: appDirectory,
      stdio: 'inherit',
      env: {
        ...process.env,
        MIKAKI_DESKTOP_CLIENT_ID: clientId,
        APPLE_SIGNING_IDENTITY: signing?.identity ?? '-',
      },
    },
  );
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally {
  signing?.cleanup();
}
