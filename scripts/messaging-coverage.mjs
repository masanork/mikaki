/** Merge actual mapped Chromium counters into Sonar's LCOV input. Never fabricate hits. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir, mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import libCoverage from 'istanbul-lib-coverage';
import libReport from 'istanbul-lib-report';
import reports from 'istanbul-reports';

const root = process.cwd();
const directory = join(root, 'artifacts/messaging-coverage');
const coverageMap = libCoverage.createCoverageMap({});
const sources = {};
const inputs = (await readdir(join(directory, 'raw'))).filter((name) => name.endsWith('.json'));
assert.ok(inputs.length, 'No actual messaging browser coverage collected');
for (const name of inputs) {
  const report = JSON.parse(await readFile(join(directory, 'raw', name), 'utf8'));
  assert.equal(report.version, 1);
  for (const [path, hash] of Object.entries(report.sources)) {
    assert.ok(path.startsWith('crates/worker/ui/') && !path.split('/').includes('..'));
    const actual = createHash('sha256')
      .update(await readFile(resolve(root, path)))
      .digest('hex');
    assert.equal(hash, actual, `Stale browser coverage: ${path}`);
    assert.ok(!sources[path] || sources[path] === hash, `Mixed browser coverage sources: ${path}`);
    sources[path] = hash;
  }
  for (const data of report.coverage) {
    for (const [path, file] of Object.entries(data)) {
      assert.ok(sources[path] && file.path === path, 'Unverified coverage source');
    }
    coverageMap.merge(data);
  }
}
for (const name of [
  'client',
  'chat-view',
  'device-store',
  'vault-device',
  'http-witness',
  'peer-review',
  'delivery-types',
  'replacement-types',
  'wallet-presentation',
]) {
  const path = `crates/worker/ui/messaging/${name}.ts`;
  assert.ok(coverageMap.files().includes(path), `Unmeasured messaging module: ${path}`);
  assert.ok(
    coverageMap.fileCoverageFor(path).toSummary().lines.covered > 0,
    `Unexecuted messaging module: ${path}`,
  );
}
await mkdir(directory, { recursive: true });
const context = libReport.createContext({ dir: directory, coverageMap });
reports.create('lcovonly', { file: 'messaging-coverage.lcov' }).execute(context);
reports.create('text-summary').execute(context);
await writeFile(
  join(directory, 'summary.json'),
  JSON.stringify(
    {
      version: 1,
      scope:
        'Actual Chromium V8 ranges remapped with exact TypeScript source maps; includes statement/function/branch counters',
      source: sources,
      summary: coverageMap.getCoverageSummary().toJSON(),
      files: coverageMap
        .files()
        .map((path) => ({ path, ...coverageMap.fileCoverageFor(path).toSummary().toJSON() })),
    },
    null,
    2,
  ) + '\n',
);
