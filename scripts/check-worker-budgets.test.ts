import assert from 'node:assert/strict';
import { test } from 'node:test';
import { gzipSync } from 'node:zlib';
import {
  checkBudgets,
  measure,
  resources,
  type BundleMeasurement,
} from './check-worker-budgets.ts';
import {
  checkWorkerBundle,
  measureWorkerUpload,
  workerBundleBytes,
  WORKER_BUNDLE_MAX_BYTES,
} from './worker-bundle-size.ts';

const measurements = () => resources.map((resource) => measure(resource, Buffer.from('fixture')));
const budgets = () =>
  Object.fromEntries(
    measurements().map((item) => [item.resource, { raw: item.raw, gzip: item.gzip }]),
  );
const bundles = (): BundleMeasurement[] =>
  ['op', 'userinfo'].map((worker) => ({ worker, raw: 8 * 1024 * 1024 }));

test('individual raw/gzip growth warns without failing deployment eligibility', () => {
  assert.deepEqual(checkBudgets(measurements(), budgets(), bundles()), {
    warnings: [],
    failures: [],
  });
  for (const encoding of ['raw', 'gzip'] as const) {
    const items = measurements();
    items[0]![encoding]++;
    const result = checkBudgets(items, budgets(), bundles());
    assert.deepEqual(result.failures, []);
    assert.equal(result.warnings.length, 1);
    assert.match(result.warnings[0]!, new RegExp(`${encoding} .* > warning threshold .* bytes`));
  }
  const items = measurements();
  items.find((item) => item.resource === '/vault/vault.js')!.gzip += 35;
  items.find((item) => item.resource === 'crates/worker/build/index_bg.wasm')!.raw =
    9 * 1024 * 1024;
  assert.equal(checkBudgets(items, budgets(), bundles()).warnings.length, 2);
  assert.deepEqual(checkBudgets(items, budgets(), bundles()).failures, []);
});

test('64 MiB applies to each complete uncompressed Worker, not their combined size', () => {
  const items = bundles();
  items.forEach((item) => {
    item.raw = WORKER_BUNDLE_MAX_BYTES;
  });
  assert.deepEqual(checkBudgets(measurements(), budgets(), items).failures, []);
  for (const index of [0, 1]) {
    const changed = structuredClone(items);
    changed[index]!.raw++;
    const failures = checkBudgets(measurements(), budgets(), changed).failures;
    assert.equal(failures.length, 1);
    assert.match(failures[0]!, /uncompressed bundle .* > 67108864 bytes/);
  }
});

test('bundle accounting includes JS and every module and excludes only the generated entry source map', () => {
  const files = [
    { name: 'worker.js', bytes: 10, type: 'application/javascript+module' },
    { name: 'module.wasm', bytes: WORKER_BUNDLE_MAX_BYTES - 12, type: 'application/wasm' },
    { name: 'data.txt', bytes: 1, type: 'text/plain' },
    { name: 'imported.map', bytes: 1, type: 'text/plain' },
    { name: 'worker.js.map', bytes: WORKER_BUNDLE_MAX_BYTES, type: 'application/source-map' },
  ];
  assert.equal(workerBundleBytes(files, 'worker.js'), WORKER_BUNDLE_MAX_BYTES);
  assert.deepEqual(checkWorkerBundle('op', workerBundleBytes(files, 'worker.js')), []);
  files[2]!.bytes++;
  assert.equal(checkWorkerBundle('op', workerBundleBytes(files, 'worker.js')).length, 1);
  assert.throws(() => workerBundleBytes(files.slice(1), 'worker.js'), /Missing/);
  assert.throws(() => workerBundleBytes([...files, files[0]!], 'worker.js'), /Duplicate/);
  assert.throws(() =>
    workerBundleBytes([{ name: 'worker.js', bytes: 0, type: 'text/plain' }], 'worker.js'),
  );
  assert.throws(() =>
    workerBundleBytes([{ name: '../worker.js', bytes: 1, type: 'text/plain' }], '../worker.js'),
  );
  assert.throws(() => checkWorkerBundle('op', Number.POSITIVE_INFINITY));
});

test('multipart upload accounting excludes metadata and debug maps and preserves binary module bytes', async () => {
  const data = new FormData();
  data.set(
    'metadata',
    JSON.stringify({ main_module: 'worker.js', bindings: [{ text: 'x'.repeat(1000) }] }),
  );
  data.set(
    'worker.js',
    new Blob(['export default {};'], { type: 'application/javascript+module' }),
    'worker.js',
  );
  data.set(
    'module.wasm',
    new Blob([new Uint8Array([0, 255, 1])], { type: 'application/wasm' }),
    'module.wasm',
  );
  data.set('data.map', new Blob(['data'], { type: 'text/plain' }), 'data.map');
  data.set('empty.txt', new Blob([], { type: 'text/plain' }), 'empty.txt');
  data.set(
    'worker.js.map',
    new Blob(['map'.repeat(1000)], { type: 'application/source-map' }),
    'worker.js.map',
  );
  const bytes = new Uint8Array(await new Response(data).arrayBuffer());
  const measured = await measureWorkerUpload(bytes);
  assert.equal(measured.raw, Buffer.byteLength('export default {};') + 3 + 4);
  assert.equal(measured.modules.length, 5);
  data.delete('metadata');
  await assert.rejects(
    measureWorkerUpload(new Uint8Array(await new Response(data).arrayBuffer())),
    /metadata/,
  );
  await assert.rejects(
    measureWorkerUpload(new TextEncoder().encode('invalid multipart')),
    /boundary/,
  );
});

test('missing, duplicate and malformed coverage cannot silently disable measurements or bundle gates', () => {
  const absent = budgets();
  delete absent[resources[0]];
  assert.throws(() => checkBudgets(measurements(), absent, bundles()));
  assert.throws(() => checkBudgets(measurements().slice(1), budgets(), bundles()));
  assert.throws(() => checkBudgets([...measurements(), measurements()[0]!], budgets(), bundles()));
  assert.throws(() => checkBudgets(measurements(), budgets(), bundles().slice(1)));
  assert.throws(() => checkBudgets(measurements(), budgets(), [bundles()[0]!, bundles()[0]!]));
  for (const value of [0, -1, 1.5, '100', null, Number.POSITIVE_INFINITY]) {
    const invalid = { ...budgets(), [resources[0]]: { raw: value, gzip: 100 } };
    assert.throws(() => checkBudgets(measurements(), invalid, bundles()));
  }
  assert.throws(() => checkBudgets(measurements(), [], bundles()));
  assert.throws(() => checkBudgets(measurements(), null, bundles()));
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
