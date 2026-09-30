/** Map Chromium's executed bundle ranges back to repository Svelte/TypeScript lines. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TraceMap, decodedMappings } from '@jridgewell/trace-mapping';
import type { Page } from '@playwright/test';

const root = fileURLToPath(new URL('../../..', import.meta.url));
const outputRoot = join(root, 'target/wasm32-unknown-unknown/release/build');
const uiPrefix = 'crates/worker/ui/';
type Entry = Awaited<ReturnType<Page['coverage']['stopJSCoverage']>>[number];

function generatedLineOffsets(source: string): number[] {
  const offsets = [0];
  for (let index = 0; index < source.length; index++) {
    if (source[index] === '\n') offsets.push(index + 1);
  }
  return offsets;
}

function executedAt(offset: number, entry: Entry): boolean {
  let smallest = Infinity;
  let count = 0;
  for (const fn of entry.functions) {
    for (const range of fn.ranges) {
      if (range.startOffset <= offset && offset < range.endOffset) {
        const length = range.endOffset - range.startOffset;
        if (length < smallest) {
          smallest = length;
          count = range.count;
        }
      }
    }
  }
  return smallest !== Infinity && count > 0;
}

async function exactSourceMap(name: string, source: string): Promise<string> {
  const expected = createHash('sha256').update(source).digest('hex');
  for (const directory of await readdir(outputRoot)) {
    if (!directory.startsWith('mikaki-worker-')) continue;
    const output = join(outputRoot, directory, 'out');
    try {
      const bundle = await readFile(join(output, `${name}.js`));
      if (createHash('sha256').update(bundle).digest('hex') !== expected) continue;
      const map = join(output, `${name}.js.map`);
      await readFile(map);
      return map;
    } catch {
      // Ignore another Cargo profile or an incomplete historical build directory.
    }
  }
  throw new Error(`No exact local source map for served ${name}.js`);
}

export function startBrowserSourceCoverage(page: Page, origin: string) {
  const enabled = process.env['MIKAKI_BROWSER_SOURCE_COVERAGE'] === '1';
  const entries: Entry[] = [];
  let running = false;
  return {
    async goto(url: string) {
      if (enabled) {
        if (running) entries.push(...(await page.coverage.stopJSCoverage()));
        await page.coverage.startJSCoverage();
        running = true;
      }
      return page.goto(url);
    },
    async finish() {
      if (!enabled) return;
      if (running) entries.push(...(await page.coverage.stopJSCoverage()));
      const files = new Map<string, { mapped: Set<number>; executed: Set<number> }>();
      const scripts = new Set<string>();
      for (const entry of entries) {
        if (!entry.url.startsWith(`${origin}/`)) continue;
        const path = new URL(entry.url).pathname;
        const name =
          path === '/enroll/complete.js'
            ? 'complete'
            : /^\/(login|vault|admin)\/\1\.js$/.exec(path)?.[1];
        if (!name) continue;
        assert.ok(entry.source, `Chromium omitted source for ${entry.url}`);
        const mapPath = await exactSourceMap(name, entry.source);
        const map = new TraceMap(JSON.parse(await readFile(mapPath, 'utf8')));
        const offsets = generatedLineOffsets(entry.source);
        scripts.add(name);
        for (const [generatedLine, segments] of decodedMappings(map).entries()) {
          for (const segment of segments) {
            const [column, sourceIndex, originalLine] = segment;
            if (sourceIndex === undefined || originalLine === undefined || column === undefined)
              continue;
            const original = map.sources[sourceIndex];
            if (!original) continue;
            const path = relative(root, resolve(dirname(mapPath), original));
            if (!path.startsWith(uiPrefix) || !/\.(?:svelte|ts)$/.test(path)) continue;
            if (path.startsWith(`${uiPrefix}paraglide/`)) continue;
            const current = files.get(path) ?? {
              mapped: new Set<number>(),
              executed: new Set<number>(),
            };
            const line = originalLine + 1;
            current.mapped.add(line);
            const generatedOffset = offsets[generatedLine];
            assert.notEqual(generatedOffset, undefined);
            const offset = generatedOffset + column;
            if (executedAt(offset, entry)) current.executed.add(line);
            files.set(path, current);
          }
        }
      }
      const reported = await Promise.all(
        [...files.entries()]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(async ([path, lines]) => ({
            path,
            sha256: createHash('sha256')
              .update(await readFile(join(root, path)))
              .digest('hex'),
            mapped_lines: lines.mapped.size,
            executed_mapped_lines: lines.executed.size,
          })),
      );
      assert.ok(
        reported.some(
          (file) => file.path === `${uiPrefix}Vault.svelte` && file.executed_mapped_lines > 0,
        ),
      );
      await mkdir(join(root, 'artifacts'), { recursive: true });
      await writeFile(
        join(root, 'artifacts/browser-source-coverage.json'),
        `${JSON.stringify(
          {
            measured_at: new Date().toISOString(),
            suite: 'product-ui-browser',
            method:
              'Chromium precise JS ranges projected through exact hidden Vite maps; counts are mapped source lines, not Istanbul line or branch coverage',
            scripts: [...scripts].sort(),
            files: reported,
          },
          null,
          2,
        )}\n`,
      );
      console.log(
        `Browser source coverage: ${reported.length} UI files from ${scripts.size} scripts`,
      );
    },
  };
}
