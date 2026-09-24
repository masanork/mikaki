import { startLocal } from './runtime.ts';

const local = await startLocal({ helpdesk: true });
console.log('Helpdesk RP: http://127.0.0.1:18878');
console.log('Mikaki OP: http://localhost:18877');
console.log('Bootstrap invitation (15 minutes, one use): ' + local.invitation);
console.log('Local keys and databases are discarded on exit.');
let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await local.close();
  process.exit(0);
}
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
