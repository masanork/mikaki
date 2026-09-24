// Aggregate timings only; adapter logs do not contain credential or account data.
import { readFileSync } from 'node:fs';
const files = process.argv.slice(2);
if (!files.length) throw new Error('Usage: node summarize-timing.ts <timing.log> ...');
const stats = (values: number[]) => {
  const sorted = [...values].sort((a, b) => a - b);
  const at = (p: number) => sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1)];
  return {
    count: values.length,
    sum_ms: +values.reduce((a, b) => a + b, 0).toFixed(3),
    p50_ms: at(0.5),
    p95_ms: at(0.95),
    p99_ms: at(0.99),
    max_ms: sorted.at(-1),
  };
};
const reports = files.map((file) => {
  const rows = readFileSync(file, 'utf8')
    .split('\n')
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line));
  if (
    !rows.length ||
    rows.some(
      (r) =>
        !Number.isFinite(r.ms) || !Number.isFinite(r.verify_ms) || !Number.isFinite(r.metadata_ms),
    )
  )
    throw new Error('Missing timing fields; use FIDO_TIMING=1');
  return {
    file,
    total: stats(rows.map((r) => r.ms)),
    metadata: stats(rows.map((r) => r.metadata_ms)),
    verification_boundary: stats(rows.map((r) => r.verify_ms)),
    ...(rows.every((r) => Number.isFinite(r.db_ms))
      ? { database: stats(rows.map((r) => r.db_ms)) }
      : {}),
    ...(rows.every((r) => Number.isFinite(r.response_ms))
      ? { response: stats(rows.map((r) => r.response_ms)) }
      : {}),
    routes: Object.fromEntries(
      [...new Set(rows.map((r) => r.path))].map((path) => [
        path,
        stats(rows.filter((r) => r.path === path).map((r) => r.ms)),
      ]),
    ),
  };
});
console.log(JSON.stringify(reports, null, 2));
