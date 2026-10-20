/** Build the opt-in product Worker locally. This command never deploys. */
import { execFileSync } from 'node:child_process';
import { buildOpAuthority } from './build-op-authority.ts';
const root = new URL('../', import.meta.url);
const run = (command: string, args: string[]) =>
  execFileSync(command, args, { cwd: root, stdio: 'inherit' });
run(process.execPath, ['scripts/build-service-catalog.ts', '--check']);
run('worker-build', [
  '--release',
  '--out-dir',
  'build-messaging-beta',
  'crates/worker',
  '--features',
  'messaging-beta',
  '--locked',
]);
await buildOpAuthority('messaging-beta');
