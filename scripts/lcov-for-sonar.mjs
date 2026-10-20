import assert from 'node:assert/strict';

// Sonar's JavaScript LCOV reader uses a signed 32-bit integer for hit counts.
// Saturation preserves the zero/nonzero coverage decision for real counters.
export const MAX_LCOV_HIT_COUNT = 2 ** 31 - 1;

export function boundLcovHitCounts(report) {
  let saturatedHitCounts = 0;
  let largestRawHitCount = 0;
  const lcov = report
    .split('\n')
    .map((line) => {
      const separator = line.indexOf(':');
      const kind = line.slice(0, separator);
      const index = { DA: 1, FNDA: 0, BRDA: 3 }[kind];
      if (index === undefined) return line;
      const fields = line.slice(separator + 1).split(',');
      const raw = fields[index];
      if (kind === 'BRDA' && raw === '-') return line;
      assert.match(raw ?? '', /^\d+$/, `Invalid ${kind} hit count`);
      const count = Number(raw);
      assert.ok(Number.isSafeInteger(count), `Unsafe ${kind} hit count`);
      largestRawHitCount = Math.max(largestRawHitCount, count);
      if (count <= MAX_LCOV_HIT_COUNT) return line;
      saturatedHitCounts++;
      fields[index] = String(MAX_LCOV_HIT_COUNT);
      return `${kind}:${fields.join(',')}`;
    })
    .join('\n');
  return { lcov, saturatedHitCounts, largestRawHitCount };
}
