/** Build the opt-in product Worker locally. This command never deploys. */
import { execFileSync } from 'node:child_process';
const root = new URL('../', import.meta.url);
const run = (command: string, args: string[]) =>
  execFileSync(command, args, { cwd: root, stdio: 'inherit' });
run('worker-build', [
  '--release',
  '--out-dir',
  'build-messaging-beta',
  'crates/worker',
  '--features',
  'messaging-beta',
  '--locked',
]);
