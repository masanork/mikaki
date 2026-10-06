// Native Node/V8 baseline for handwritten Worker UI TypeScript, not Svelte DOM coverage.
import { mkdir, readFile, writeFile, appendFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

await mkdir('artifacts', { recursive: true });
const child = spawn(
  process.execPath,
  [
    '--experimental-test-coverage',
    '--test',
    '--test-concurrency=1',
    '--test-coverage-include=**/crates/worker/ui/*.ts',
    '--test-coverage-include-all',
    '--test-coverage-exclude=**/crates/worker/ui/vite.config.ts',
    '--test-reporter=spec',
    '--test-reporter-destination=stdout',
    '--test-reporter=lcov',
    '--test-reporter-destination=artifacts/frontend-coverage.lcov',
    ...[
      'vault-crypto',
      'vault-note',
      'vault-freshness',
      'vault-lifecycle',
      'vault-owner-name-sharing',
      'recipient-directory-browser',
    ].map((name) => `local/conformance/${name}.test.ts`),
  ],
  { stdio: 'inherit' },
);
const exit = await new Promise<number>((resolve, reject) => {
  child.on('error', reject);
  child.on('exit', (code) => resolve(code ?? 1));
});
process.exitCode = exit;
if (exit === 0) {
  const lcov = await readFile('artifacts/frontend-coverage.lcov', 'utf8');
  const files = await Promise.all(
    lcov
      .split('end_of_record')
      .filter((block) => block.includes('SF:'))
      .map(async (block) => {
        const path = /^SF:(.+)$/m.exec(block)![1];
        const count = (key: string) =>
          Number(new RegExp(`^${key}:(\\d+)$`, 'm').exec(block)?.[1] ?? 0);
        const metric = (found: string, hit: string) => {
          const total = count(found),
            covered = count(hit);
          return { count: total, covered, percent: total ? (covered * 100) / total : null };
        };
        return {
          path,
          sha256: createHash('sha256')
            .update(await readFile(path))
            .digest('hex'),
          lines: metric('LF', 'LH'),
          branches: metric('BRF', 'BRH'),
          functions: metric('FNF', 'FNH'),
        };
      }),
  );
  const count = files.reduce((sum, file) => sum + file.lines.count, 0);
  const covered = files.reduce((sum, file) => sum + file.lines.covered, 0);
  const lines = { count, covered, percent: count ? (covered * 100) / count : 0 };
  // These modules are exercised directly by the Node suite. Browser entrypoints and
  // separately qualified recipient-envelope code are reported, but have no Node floor.
  const minimums = {
    'recipient-directory.ts': { lines: 90, branches: 80 },
    'vault-crypto.ts': { lines: 85, branches: 70 },
    'vault-freshness.ts': { lines: 95, branches: 90 },
    'vault-lifecycle.ts': { lines: 90, branches: 75 },
    'vault-note.ts': { lines: 95, branches: 90 },
  } as const;
  const failures: string[] = [];
  for (const [name, minimum] of Object.entries(minimums)) {
    const file = files.find((entry) => entry.path === `crates/worker/ui/${name}`);
    if (!file) {
      failures.push(`${name}: missing from coverage report`);
      continue;
    }
    for (const metric of ['lines', 'branches'] as const) {
      const actual = file[metric];
      if (actual.percent === null || actual.percent < minimum[metric]) {
        failures.push(
          `${name}: ${metric} ${actual.percent?.toFixed(1) ?? 'unmeasured'}% < ${minimum[metric]}%`,
        );
      }
    }
  }
  await writeFile(
    'artifacts/frontend-coverage.json',
    JSON.stringify(
      {
        measuredAt: new Date().toISOString(),
        node: process.version,
        scope:
          'Worker UI flat TypeScript files, including unloaded modules; excluding vite.config.ts, generated files and Svelte components',
        source: 'current working-tree contents identified by per-file SHA-256',
        lines,
        files,
        minimums,
        gate: failures.length ? { passed: false, failures } : { passed: true, failures: [] },
      },
      null,
      2,
    ) + '\n',
  );
  if (process.env['GITHUB_STEP_SUMMARY'])
    await appendFile(
      process.env['GITHUB_STEP_SUMMARY'],
      `\nWorker UI TypeScript: ${lines.percent.toFixed(1)}% lines (${covered}/${count}); selected-module regression gate ${failures.length ? 'failed' : 'passed'}. Includes unloaded modules; excludes Svelte DOM/browser execution. LCOV and JSON are in authentication-measurements.\n`,
    );
  if (failures.length) {
    console.error(`Frontend coverage regression:\n${failures.join('\n')}`);
    process.exitCode = 1;
  } else console.log('Frontend coverage regression gate passed for 5 directly tested modules');
}
