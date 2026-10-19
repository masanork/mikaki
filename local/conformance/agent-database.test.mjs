import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ServiceDatabase } from '../../crates/agent-worker/database.ts';

test('denied D1 capabilities reject asynchronously without dispatching SQL or exports', async () => {
  let calls = 0;
  const unavailable = () => {
    calls++;
    throw new Error('Unexpected service dispatch');
  };
  const service = { fetch: unavailable, connect: unavailable };
  const database = new ServiceDatabase(service);
  for (const [invoke, message] of [
    [() => database.exec('SELECT 1'), 'Arbitrary SQL denied'],
    [() => database.dump(), 'Database export denied'],
    [() => database.prepare('SELECT 1').raw(), 'Raw query denied'],
    [() => database.prepare('SELECT 1').raw({ columnNames: true }), 'Raw query denied'],
  ]) {
    let result;
    assert.doesNotThrow(() => {
      result = invoke();
    });
    assert.ok(result instanceof Promise);
    await assert.rejects(result, { message });
  }
  assert.equal(calls, 0);
});
