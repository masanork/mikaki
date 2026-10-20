import assert from 'node:assert/strict';
import { test } from 'node:test';
import { boundLcovHitCounts, MAX_LCOV_HIT_COUNT } from './lcov-for-sonar.mjs';

test('LCOV saturation retains zero, unknown and ordinary hits without changing record identity', () => {
  const report = [
    'SF:crates/worker/ui/messaging/device-store.ts',
    'FN:1,ordinary',
    'FNDA:0,unused,with comma',
    'FNDA:1,ordinary',
    'DA:1,0',
    `DA:2,${MAX_LCOV_HIT_COUNT},checksum`,
    'BRDA:3,0,0,-',
    'BRDA:3,0,1,0',
    'BRDA:3,0,2,1',
    'end_of_record',
    '',
  ].join('\n');
  assert.deepEqual(boundLcovHitCounts(report), {
    lcov: report,
    saturatedHitCounts: 0,
    largestRawHitCount: MAX_LCOV_HIT_COUNT,
  });
});

test('actual large counters remain positive and importable at the signed 32-bit limit', () => {
  const result = boundLcovHitCounts(
    'FNDA:2147483648,called\nDA:308,4885251606\nBRDA:308,2,0,4934056700\n',
  );
  assert.equal(
    result.lcov,
    `FNDA:${MAX_LCOV_HIT_COUNT},called\nDA:308,${MAX_LCOV_HIT_COUNT}\nBRDA:308,2,0,${MAX_LCOV_HIT_COUNT}\n`,
  );
  assert.equal(result.saturatedHitCounts, 3);
  assert.equal(result.largestRawHitCount, 4934056700);
});

test('malformed or numerically unsafe counters fail instead of inventing coverage', () => {
  for (const record of ['DA:1,-1', 'FNDA:NaN,called', 'BRDA:1,0,0,1.5', 'DA:1,9007199254740992'])
    assert.throws(() => boundLcovHitCounts(record));
});
