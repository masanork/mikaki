import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';

const require = createRequire(import.meta.url);
const probe = require('./pkg/mikaki_pqc_probe.js');
const bytes = await readFile(new URL('./pkg/mikaki_pqc_probe_bg.wasm', import.meta.url));
assert.equal(probe.self_test(), true);
const times = [];
for (let sample = 0; sample < 10; sample++) {
  const start = performance.now();
  assert.equal(probe.self_test(), true);
  times.push(performance.now() - start);
}
times.sort((left, right) => left - right);
console.log(
  JSON.stringify({
    result: 'pass',
    wasm_bytes: bytes.length,
    wasm_gzip_bytes: gzipSync(bytes, { mtime: 0 }).length,
    combined_kem_signature_round_trip_median_ms: (times[4] + times[5]) / 2,
  }),
);
