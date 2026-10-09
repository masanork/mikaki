/** Measure served UI bodies and server Wasm; gzip sizes are estimates, not wire timings. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { createTestHarness } from 'wrangler';
import { releaseSource } from './release-inventory.ts';

export const resources = [
  '/login/login.js',
  '/login/login.css',
  '/ui/product.css',
  '/ui/session-events.js',
  '/enroll/complete.js',
  '/admin/admin.js',
  '/waitlist/waitlist.js',
  '/vault/vault.js',
  '/vault/search.js',
  '/vault/sqlite3.wasm',
  'crates/worker/build/index_bg.wasm',
  'crates/userinfo-claim-worker/build/index_bg.wasm',
] as const;
export type Measurement = { resource: string; raw: number; gzip: number; sha256: string };
export function measure(resource: string, bytes: Uint8Array): Measurement {
  assert.ok(bytes.length > 0, `Empty resource: ${resource}`);
  return {
    resource,
    raw: bytes.length,
    gzip: gzipSync(bytes, { level: 9 }).length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}
export function checkBudgets(measurements: Measurement[], budgets: unknown): string[] {
  assert.ok(budgets && typeof budgets === 'object' && !Array.isArray(budgets));
  assert.deepEqual(Object.keys(budgets).sort(), [...resources].sort(), 'Incomplete budgets');
  assert.deepEqual(
    measurements.map((item) => item.resource).sort(),
    [...resources].sort(),
    'Incomplete or duplicate measurements',
  );
  const failures: string[] = [];
  for (const item of measurements) {
    const budget: Record<string, unknown> | undefined = (
      budgets as Record<string, Record<string, unknown>>
    )[item.resource];
    assert.ok(budget && typeof budget === 'object' && !Array.isArray(budget));
    assert.deepEqual(Object.keys(budget).sort(), ['gzip', 'raw']);
    for (const encoding of ['raw', 'gzip'] as const) {
      const maximum: unknown = budget[encoding];
      assert.ok(Number.isSafeInteger(maximum) && (maximum as number) > 0, 'Invalid budget');
      assert.ok(Number.isSafeInteger(item[encoding]) && item[encoding] > 0);
      if (item[encoding] > (maximum as number))
        failures.push(`${item.resource}: ${encoding} ${item[encoding]} > ${maximum} bytes`);
    }
  }
  return failures;
}

async function main(): Promise<void> {
  assert.equal(process.argv.length, 2, 'Usage: node scripts/check-worker-budgets.ts');
  const root = fileURLToPath(new URL('../', import.meta.url));
  const source = releaseSource(root);
  const harness = createTestHarness({
    root,
    workers: [
      { configPath: `${root}/crates/worker/wrangler.recipient-local.jsonc` },
      { configPath: `${root}/crates/userinfo-claim-worker/wrangler.local.jsonc` },
    ],
  });
  const measurements: Measurement[] = [];
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    const version = (await (await worker.fetch('https://mikaki.test/version')).json()) as {
      source_commit: string;
      source_clean: boolean;
    };
    assert.equal(version.source_commit, source.commit, 'Rebuild Worker for this revision');
    for (const resource of resources) {
      let bytes: Uint8Array;
      if (resource.startsWith('/')) {
        const response = await worker.fetch(`https://mikaki.test${resource}`);
        assert.equal(response.status, 200, `Unavailable asset: ${resource}`);
        const mime = resource.endsWith('.wasm')
          ? 'application/wasm'
          : resource.endsWith('.js')
            ? 'text/javascript'
            : 'text/css';
        assert.equal(response.headers.get('Content-Type')?.split(';')[0], mime);
        bytes = new Uint8Array(await response.arrayBuffer());
      } else {
        bytes = await readFile(resolve(root, resource));
        assert.deepEqual([...bytes.subarray(0, 8)], [0, 97, 115, 109, 1, 0, 0, 0]);
      }
      measurements.push(measure(resource, bytes));
    }
    const budgets: unknown = JSON.parse(
      await readFile(`${root}/scripts/worker-budgets.json`, 'utf8'),
    );
    const failures = checkBudgets(measurements, budgets);
    await mkdir(`${root}/artifacts`, { recursive: true });
    await writeFile(
      `${root}/artifacts/worker-budgets.json`,
      JSON.stringify(
        {
          schema_version: 1,
          source,
          worker_source_clean: version.source_clean,
          gzip: 'local level-9 estimate; not observed HTTP Content-Encoding',
          measurements,
          budgets,
          failures,
        },
        null,
        2,
      ) + '\n',
    );
    const summary = `| Resource | Raw bytes | gzip estimate |\n|---|---:|---:|\n${measurements.map((item) => `| ${item.resource} | ${item.raw} | ${item.gzip} |`).join('\n')}\n`;
    await writeFile(`${root}/artifacts/worker-budgets.md`, summary);
    console.log(summary);
    assert.equal(failures.length, 0, failures.join('\n'));
  } finally {
    await harness.close();
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
