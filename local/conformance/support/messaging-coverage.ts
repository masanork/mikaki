/** Test-only Chromium coverage. Persist mapped counters, never browser state or messages. */
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Browser, BrowserContext, Page } from '@playwright/test';
import v8ToIstanbul from 'v8-to-istanbul';
import type { CoverageMapData } from 'istanbul-lib-coverage';

const repository = fileURLToPath(new URL('../../../', import.meta.url));
type Entry = Awaited<ReturnType<Page['coverage']['stopJSCoverage']>>[number];
type MapData = {
  version: 3;
  sources: string[];
  sourcesContent: (string | null)[];
  names: string[];
  mappings: string;
  sourceRoot?: string;
};
type Options = { root?: string; output?: string };
const digest = (source: string) => createHash('sha256').update(source).digest('hex');
const measured = (path: string) =>
  path.startsWith('crates/worker/ui/') &&
  path.endsWith('.ts') &&
  !path.endsWith('.d.ts') &&
  !path.includes('/paraglide/') &&
  !path.endsWith('/vite.config.ts');

export function messagingCoverageEnabled() {
  return process.env['MIKAKI_MESSAGING_COVERAGE'] === '1';
}

async function sourceMap(
  entry: Entry,
  root: string,
): Promise<{ map: MapData; directory: string } | undefined> {
  const source = entry.source;
  if (!source || (!entry.url.startsWith('https://') && !entry.url.startsWith('http://'))) return;
  const url = new URL(entry.url);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === '127.0.0.1'))
    return;
  const path = url.pathname;
  if (['/custody.js', '/device-store.js', '/http-witness.js'].includes(path)) {
    const prefix = '//# sourceMappingURL=data:application/json;base64,';
    const line = source.split('\n').find((line) => line.startsWith(prefix));
    assert.ok(line, 'Coverage fixture must include its exact inline source map');
    return {
      map: JSON.parse(Buffer.from(line.slice(prefix.length), 'base64').toString('utf8')),
      directory: root,
    };
  }
  const name =
    path === '/messaging/client.js'
      ? 'messaging-client'
      : path === '/vault/vault.js'
        ? 'vault'
        : undefined;
  if (!name) return;
  const build = join(root, 'target/wasm32-unknown-unknown/release/build');
  for (const nameOfDirectory of await readdir(build)) {
    if (!nameOfDirectory.startsWith('mikaki-worker-')) continue;
    const directory = join(build, nameOfDirectory, 'out');
    const bundle = await readFile(join(directory, `${name}.js`), 'utf8').catch(() => undefined);
    if (bundle === undefined || digest(bundle) !== digest(source)) continue;
    const content = await readFile(join(directory, `${name}.js.map`), 'utf8').catch(
      () => undefined,
    );
    if (content !== undefined) return { map: JSON.parse(content), directory };
  }
  throw new Error(`No exact source map for served ${name} coverage`);
}

export async function mappedMessagingCoverage(entries: Entry[], options: Options = {}) {
  const root = options.root ?? repository;
  const coverage: CoverageMapData[] = [];
  const sources: Record<string, string> = {};
  for (const entry of entries) {
    const mapped = await sourceMap(entry, root);
    if (!mapped) continue;
    assert.equal(mapped.map.version, 3);
    assert.equal(mapped.map.sources.length, mapped.map.sourcesContent.length);
    const normalized = { ...mapped.map, sourceRoot: '', sources: [] as string[] };
    for (const [index, source] of mapped.map.sources.entries()) {
      const path = resolve(mapped.directory, mapped.map.sourceRoot ?? '', source);
      normalized.sources.push(path);
      const name = relative(root, path);
      if (!measured(name)) continue;
      const content: string | null | undefined = mapped.map.sourcesContent[index];
      assert.equal(typeof content, 'string', `Missing source content for ${name}`);
      const actual = await readFile(path, 'utf8');
      assert.equal(digest(content!), digest(actual), `Stale coverage source: ${name}`);
      sources[name] = digest(actual);
    }
    const converter = v8ToIstanbul(
      join(mapped.directory, 'coverage-bundle.js'),
      0,
      {
        source: entry.source!,
        originalSource: '',
        sourceMap: { sourcemap: normalized },
      },
      (path) => !measured(relative(root, path)),
    );
    await converter.load();
    converter.applyCoverage(entry.functions);
    const data: CoverageMapData = {};
    for (const [path, value] of Object.entries(converter.toIstanbul())) {
      const name = relative(root, path);
      if (!measured(name)) continue;
      assert.ok(sources[name]);
      data[name] = { ...value, path: name };
    }
    coverage.push(data);
  }
  return { version: 1, sources, coverage };
}

const flushers = new WeakMap<Page, () => Promise<void>>();
const browsers = new WeakSet<Browser>();
const contexts = new WeakSet<BrowserContext>();
async function flushPages(pages: Page[]) {
  await Promise.all(pages.map((page) => flushers.get(page)?.()));
}

/** Capture before navigation/closure: V8 can discard old documents even with resetOnNavigation=false. */
export async function trackMessagingCoverage(page: Page, options: Options = {}) {
  if (flushers.has(page)) return;
  if (!messagingCoverageEnabled() || page.context().browser()?.browserType().name() !== 'chromium')
    return;
  const root = options.root ?? repository;
  const output = options.output ?? join(root, 'artifacts/messaging-coverage/raw');
  let running = false;
  let pending: Promise<void> | undefined;
  const start = async () => {
    await pending;
    await page.coverage.startJSCoverage();
    running = true;
  };
  const flush = async () => {
    if (!running) return pending;
    running = false;
    pending = (async () => {
      const report = await mappedMessagingCoverage(await page.coverage.stopJSCoverage(), { root });
      if (!Object.keys(report.sources).length) return;
      await mkdir(output, { recursive: true });
      await writeFile(join(output, `${process.pid}-${randomUUID()}.json`), JSON.stringify(report), {
        flag: 'wx',
      });
    })();
    await pending;
  };
  flushers.set(page, flush);
  const closePage = page.close.bind(page),
    goto = page.goto.bind(page),
    reload = page.reload.bind(page);
  page.close = async (options) => {
    await flush();
    return closePage(options);
  };
  page.goto = async (...args) => {
    await flush();
    await start();
    return goto(...args);
  };
  page.reload = async (...args) => {
    await flush();
    await start();
    return reload(...args);
  };
  const context = page.context();
  if (!contexts.has(context)) {
    contexts.add(context);
    const close = context.close.bind(context);
    context.close = async (options) => {
      await flushPages(context.pages());
      return close(options);
    };
  }
  const browser = context.browser()!;
  if (!browsers.has(browser)) {
    browsers.add(browser);
    const close = browser.close.bind(browser);
    browser.close = async (options) => {
      await flushPages(browser.contexts().flatMap((context) => context.pages()));
      return close(options);
    };
  }
  await start();
}
