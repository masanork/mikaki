import { DatabaseSync } from 'node:sqlite';
import { parentPort, workerData } from 'node:worker_threads';
import { redeem } from './store.mjs';

const db = new DatabaseSync(workerData.filename);
db.exec('PRAGMA busy_timeout=5000');
const view = new Int32Array(workerData.barrier);
Atomics.add(view, 0, 1);
for (;;) {
  const state = Atomics.load(view, 0);
  if (state >= 3) break;
  Atomics.wait(view, 0, state);
}
try { parentPort.postMessage(redeem(db, 'digest', 'nihos', 'key', 100)?.owner ?? 'no-grant'); }
finally { db.close(); }
