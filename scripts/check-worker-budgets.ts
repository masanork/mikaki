/** Gate complete uncompressed Worker bundles; report asset growth as warnings. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { createTestHarness } from 'wrangler';
import { releaseSource } from './release-inventory.ts';
import {
  checkWorkerBundle,
  measureWorkerUpload,
  WORKER_BUNDLE_MAX_BYTES,
} from './worker-bundle-size.ts';

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
export type BundleMeasurement = { worker: string; raw: number };
export function measure(resource: string, bytes: Uint8Array): Measurement {
  assert.ok(bytes.length > 0, `Empty resource: ${resource}`);
  return {
    resource,
    raw: bytes.length,
    gzip: gzipSync(bytes, { level: 9 }).length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}
export function checkBudgets(
  measurements: Measurement[],
  budgets: unknown,
  bundles: BundleMeasurement[],
): { warnings: string[]; failures: string[] } {
  assert.ok(budgets && typeof budgets === 'object' && !Array.isArray(budgets));
  assert.deepEqual(Object.keys(budgets).sort(), [...resources].sort(), 'Incomplete budgets');
  assert.deepEqual(
    measurements.map((item) => item.resource).sort(),
    [...resources].sort(),
    'Incomplete or duplicate measurements',
  );
  assert.deepEqual(
    bundles.map((bundle) => bundle.worker).sort(),
    ['op', 'userinfo'],
    'Incomplete or duplicate Worker bundles',
  );
  const failures = bundles.flatMap((bundle) => checkWorkerBundle(bundle.worker, bundle.raw));
  const warnings: string[] = [];
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
        warnings.push(
          `${item.resource}: ${encoding} ${item[encoding]} > warning threshold ${maximum} bytes`,
        );
    }
  }
  return { warnings, failures };
}

async function measureBundles(root: string): Promise<BundleMeasurement[]> {
  const bundles: BundleMeasurement[] = [];
  for (const spec of [
    {
      worker: 'op',
      config: 'crates/worker/wrangler.recipient-local.jsonc',
    },
    {
      worker: 'userinfo',
      config: 'crates/userinfo-claim-worker/wrangler.local.jsonc',
    },
  ]) {
    const output = join(root, 'artifacts/worker-budget-bundles', spec.worker);
    await rm(output, { recursive: true, force: true });
    await mkdir(output, { recursive: true });
    const upload = `${output}.multipart`;
    const log = execFileSync(
      join(root, 'node_modules/.bin/wrangler'),
      [
        'deploy',
        '--config',
        join(root, spec.config),
        '--dry-run',
        '--outdir',
        output,
        '--outfile',
        upload,
      ],
      {
        cwd: root,
        env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
        encoding: 'utf8',
        timeout: 120_000,
        maxBuffer: 2 * 1024 * 1024,
      },
    );
    await writeFile(`${output}.log`, log);
    bundles.push({
      worker: spec.worker,
      ...(await measureWorkerUpload(new Uint8Array(await readFile(upload)))),
    });
  }
  return bundles;
}

async function main(): Promise<void> {
  assert.equal(process.argv.length, 2, 'Usage: node scripts/check-worker-budgets.ts');
  const root = fileURLToPath(new URL('../', import.meta.url));
  const source = releaseSource(root);
  const bundles = await measureBundles(root);
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
    const { warnings, failures } = checkBudgets(measurements, budgets, bundles);
    await mkdir(`${root}/artifacts`, { recursive: true });
    await writeFile(
      `${root}/artifacts/worker-budgets.json`,
      JSON.stringify(
        {
          schema_version: 2,
          source,
          worker_source_clean: version.source_clean,
          gzip: 'local level-9 estimate; not observed HTTP Content-Encoding',
          measurements,
          warning_thresholds: budgets,
          worker_bundle_raw_limit: WORKER_BUNDLE_MAX_BYTES,
          bundles,
          warnings,
          failures,
        },
        null,
        2,
      ) + '\n',
    );
    const summary = `| Worker bundle | Uncompressed bytes | Limit |\n|---|---:|---:|\n${bundles.map((bundle) => `| ${bundle.worker} | ${bundle.raw} | ${WORKER_BUNDLE_MAX_BYTES} |`).join('\n')}\n\n| Resource | Raw bytes | gzip estimate |\n|---|---:|---:|\n${measurements.map((item) => `| ${item.resource} | ${item.raw} | ${item.gzip} |`).join('\n')}\n\n${warnings.map((warning) => `- Warning: ${warning}`).join('\n')}\n`;
    await writeFile(`${root}/artifacts/worker-budgets.md`, summary);
    console.log(summary);
    for (const warning of warnings) console.warn(`::warning::${warning}`);
    assert.equal(failures.length, 0, failures.join('\n'));
  } finally {
    await harness.close();
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
