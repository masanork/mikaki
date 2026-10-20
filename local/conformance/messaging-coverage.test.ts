import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';
import { chromium } from '@playwright/test';
import libCoverage from 'istanbul-lib-coverage';
import { mappedMessagingCoverage } from './support/messaging-coverage.ts';

test('real Chromium counters retain unexecuted branches and reject stale mapped TypeScript', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mikaki-mapped-coverage-'));
  const relative = 'crates/worker/ui/messaging/fixture.ts';
  const path = join(root, relative);
  const source = [
    'export function choose(flag: boolean) {',
    '  if (flag) {',
    '    return 1;',
    '  }',
    '  return 2;',
    '}',
    'export function unused() {',
    "  throw new Error('not called');",
    '}',
  ].join('\n');
  const browser = await chromium.launch();
  try {
    await mkdir(join(root, 'crates/worker/ui/messaging'), { recursive: true });
    await writeFile(path, source);
    const built = await build({
      absWorkingDir: root,
      entryPoints: [path],
      write: false,
      bundle: true,
      format: 'esm',
      sourcemap: 'inline',
      target: 'es2022',
    });
    const page = await browser.newPage();
    await page.route('https://coverage.test/**', (route) =>
      route.fulfill({
        status: 200,
        contentType:
          new URL(route.request().url()).pathname === '/custody.js'
            ? 'text/javascript'
            : 'text/html',
        body:
          new URL(route.request().url()).pathname === '/custody.js'
            ? built.outputFiles[0].text
            : '<!doctype html><title>Coverage fixture</title>',
      }),
    );
    await page.coverage.startJSCoverage();
    await page.goto('https://coverage.test/');
    assert.equal(
      await page.evaluate(async () => (await import('/custody.js' as string)).choose(true)),
      1,
    );
    const entries = await page.coverage.stopJSCoverage();
    const report = await mappedMessagingCoverage(entries, { root });
    const map = libCoverage.createCoverageMap({});
    for (const data of report.coverage) map.merge(data);
    const file = map.fileCoverageFor(relative);
    assert.ok(file.getLineCoverage()[3] > 0);
    assert.equal(file.getLineCoverage()[5], 0);
    assert.equal(file.getLineCoverage()[8], 0);
    assert.ok(
      Object.values(file.f).some((hits) => hits === 0),
      'unexecuted functions stay uncovered',
    );
    assert.ok(
      Object.values(file.b)
        .flat()
        .some((hits) => hits === 0),
      'unexecuted branches stay uncovered',
    );
    assert.deepEqual(Object.keys(report.sources), [relative]);
    await writeFile(path, source + '\n// source changed after the bundle was built');
    await assert.rejects(mappedMessagingCoverage(entries, { root }), /Stale coverage source/);
  } finally {
    await browser.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('a known coverage bundle without its source map cannot produce coverage evidence', async () => {
  await assert.rejects(
    mappedMessagingCoverage([
      {
        url: 'https://coverage.test/custody.js',
        scriptId: 'fixture',
        source: 'export const value = 1;',
        functions: [],
      },
    ]),
    /exact inline source map/,
  );
});
