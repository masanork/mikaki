import { createInterface } from 'node:readline';
import { userInfo } from 'node:os';
import { adminCommand } from './logout-admin.ts';
import { startLocal } from './runtime.ts';
const local = await startLocal();
console.log('Local RP: http://127.0.0.1:18878');
console.log('Bootstrap invitation (15 minutes, one use): ' + local.invitation);
console.log('This local runner discards keys and accounts on exit. Ctrl-C stops both Workers.');
console.log(
  'Operator commands: account-list | account-revoke ACCOUNT EPOCH REASON | logout-list | logout-retry EVENT REVISION DEADLINE_UTC RETAIN_UNTIL_UTC REASON',
);
const input = createInterface({ input: process.stdin });
const actor = userInfo().username;
let commands = Promise.resolve();
input.on('line', (line) => {
  if (!line.trim()) return;
  commands = commands.then(async () => {
    try {
      console.log(JSON.stringify(await adminCommand(local.opDB, line, actor)));
    } catch {
      console.error(
        'operator_command_rejected: check syntax, deadlines, revision and event completeness',
      );
    }
  });
});
let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  input.close();
  await commands;
  await local.close();
  process.exit(0);
}
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
