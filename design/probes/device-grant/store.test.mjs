import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { Worker } from 'node:worker_threads';
import { redeem, SCHEMA } from './store.mjs';

function insert(db, code, state = 'approved', expires = 200) {
  db.prepare('INSERT INTO device_grant_probe VALUES (?, ?, ?, ?, ?, ?)')
    .run(code, 'nihos', 'key', expires, state, state === 'approved' ? 'alice' : null);
}

test('only the correct client, verified key, approved state and unexpired grant can consume', () => {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec(SCHEMA);
    insert(db, 'digest');
    assert.equal(redeem(db, 'digest', 'other', 'key', 100), null);
    assert.equal(redeem(db, 'digest', 'nihos', 'other', 100), null);
    assert.equal(redeem(db, 'digest', 'nihos', 'key', 200), null);
    assert.equal(redeem(db, 'absent', 'nihos', 'key', 100), null);
    insert(db, 'pending', 'pending');
    insert(db, 'denied', 'denied');
    assert.equal(redeem(db, 'pending', 'nihos', 'key', 100), null);
    assert.equal(redeem(db, 'denied', 'nihos', 'key', 100), null);
    assert.equal(redeem(db, 'digest', 'nihos', 'key', 100).owner, 'alice');
    assert.equal(redeem(db, 'digest', 'nihos', 'key', 100), null);
  } finally { db.close(); }
});

test('failed token record insert rolls back consumption in one SQLite transaction', () => {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec(`${SCHEMA} CREATE TABLE token_probe (id TEXT PRIMARY KEY) STRICT;`);
    insert(db, 'digest');
    db.prepare('INSERT INTO token_probe VALUES (?)').run('existing');
    db.exec('BEGIN IMMEDIATE');
    assert.equal(redeem(db, 'digest', 'nihos', 'key', 100).owner, 'alice');
    assert.throws(() => db.prepare('INSERT INTO token_probe VALUES (?)').run('existing'));
    db.exec('ROLLBACK');
    assert.equal(redeem(db, 'digest', 'nihos', 'key', 100).owner, 'alice');
  } finally { db.close(); }
});

test('concurrent independent SQLite connections permit one redemption', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-device-grant-'));
  const filename = join(directory, 'grant.sqlite');
  const db = new DatabaseSync(filename);
  db.exec(`${SCHEMA} PRAGMA journal_mode=WAL;`);
  insert(db, 'digest');
  db.close();
  const barrier = new SharedArrayBuffer(4);
  const view = new Int32Array(barrier);
  const start = () => new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./worker.mjs', import.meta.url), { workerData: { filename, barrier } });
    worker.once('message', resolve);
    worker.once('error', reject);
    worker.once('exit', (code) => { if (code !== 0) reject(new Error(`worker exit ${code}`)); });
  });
  try {
    const results = [start(), start()];
    // Each worker announces readiness after opening its own connection.
    const deadline = Date.now() + 5000;
    while (Atomics.load(view, 0) < 2 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
    assert.equal(Atomics.load(view, 0), 2, 'both connections ready');
    Atomics.store(view, 0, 3);
    Atomics.notify(view, 0, 2);
    assert.deepEqual((await Promise.all(results)).sort(), ['alice', 'no-grant']);
  } finally {
    // Unblock workers even when setup fails, then remove the isolated database.
    Atomics.store(view, 0, 3);
    Atomics.notify(view, 0, 2);
    await rm(directory, { recursive: true, force: true });
  }
});
