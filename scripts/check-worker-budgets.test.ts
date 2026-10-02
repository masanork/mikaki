import assert from 'node:assert/strict';
import { test } from 'node:test';
import { gzipSync } from 'node:zlib';
import { checkBudgets, measure, resources } from './check-worker-budgets.ts';

const measurements = () => resources.map((resource) => measure(resource, Buffer.from('fixture')));
const budgets = () =>
  Object.fromEntries(
    measurements().map((item) => [
      item.resource,
      {
        raw: item.raw,
        gzip: item.gzip,
      },
    ]),
  );

test('both byte limits accept their boundary and independently reject growth', () => {
  assert.deepEqual(checkBudgets(measurements(), budgets()), []);
  for (const encoding of ['raw', 'gzip'] as const) {
    const items = measurements();
    items[0]![encoding]++;
    const failures = checkBudgets(items, budgets());
    assert.equal(failures.length, 1);
    assert.match(failures[0]!, new RegExp(`${encoding} .* > .* bytes`));
  }
});

test('missing, duplicate and malformed coverage cannot silently disable a budget', () => {
  const absent = budgets();
  delete absent[resources[0]];
  assert.throws(() => checkBudgets(measurements(), absent));
  assert.throws(() => checkBudgets(measurements().slice(1), budgets()));
  assert.throws(() => checkBudgets([...measurements(), measurements()[0]!], budgets()));
  for (const value of [0, -1, 1.5, '100', null, Number.POSITIVE_INFINITY]) {
    const invalid = { ...budgets(), [resources[0]]: { raw: value, gzip: 100 } };
    assert.throws(() => checkBudgets(measurements(), invalid));
  }
  assert.throws(() => checkBudgets(measurements(), []));
  assert.throws(() => checkBudgets(measurements(), null));
});

test('measurement reflects exact bytes and compression rather than file extension', () => {
  const bytes = Buffer.from('repeated content '.repeat(1000));
  const item = measure('/fixture.js', bytes);
  assert.equal(item.raw, bytes.length);
  assert.equal(item.gzip, gzipSync(bytes, { level: 9 }).length);
  assert.ok(item.gzip < item.raw);
  assert.equal(item.sha256, measure('/other.css', bytes).sha256);
  assert.notEqual(item.sha256, measure('/fixture.js', Buffer.from('changed')).sha256);
  assert.throws(() => measure('/empty.js', Buffer.alloc(0)));
});
