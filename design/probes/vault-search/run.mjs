import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { platform, arch, cpus, totalmem } from 'node:os';
import { chromium, firefox, webkit } from '@playwright/test';

const routes = new Map([
  ['/', ['index.html', 'text/html']],
  ['/client.mjs', ['client.mjs', 'text/javascript']],
  ['/worker.mjs', ['worker.mjs', 'text/javascript']],
  ['/sqlite/index.mjs', ['node_modules/@sqlite.org/sqlite-wasm/dist/index.mjs', 'text/javascript']],
  [
    '/sqlite/sqlite3.wasm',
    ['node_modules/@sqlite.org/sqlite-wasm/dist/sqlite3.wasm', 'application/wasm'],
  ],
]);
const server = createServer(async (req, res) => {
  const route = routes.get(new URL(req.url, 'http://localhost').pathname);
  if (req.method !== 'GET' || !route) {
    res.writeHead(404).end();
    return;
  }
  try {
    res
      .writeHead(200, { 'Content-Type': route[1], 'Cache-Control': 'no-store' })
      .end(await readFile(new URL(route[0], import.meta.url)));
  } catch {
    res.writeHead(500).end();
  }
});
await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const url = `http://127.0.0.1:${server.address().port}`;
const report = {
  date: new Date().toISOString(),
  host: { platform: platform(), arch: arch(), cpu: cpus()[0].model, ramBytes: totalmem() },
  fixture: 'synthetic repeated Japanese messages (~200 characters), not real conversations',
  results: [],
};
try {
  for (const [name, engine] of Object.entries({ chromium, firefox, webkit })) {
    const browser = await engine.launch();
    try {
      for (const mobileViewport of [false, true]) {
        const context = await browser.newContext({
          viewport: mobileViewport ? { width: 390, height: 844 } : { width: 1440, height: 1000 },
        });
        const page = await context.newPage();
        const errors = [];
        const requests = [];
        page.on('pageerror', (e) => errors.push(String(e)));
        page.on('request', (r) => requests.push(r.url()));
        await page.goto(url);
        await page.waitForFunction(() => typeof window.probe === 'function');
        for (const size of [1000, 10000, 100000]) {
          const metrics = await page.evaluate((size) => window.probe(size), size);
          report.results.push({
            browser: name,
            version: browser.version(),
            mobileViewport,
            ...metrics,
          });
          console.log(
            `${name} ${mobileViewport ? '390px' : '1440px'} ${size}: ${(metrics.bytes / 1048576).toFixed(1)} MiB; build ${metrics.buildMs.toFixed(0)}ms; restore ${metrics.restoreMs.toFixed(0)}ms; short p95 ${metrics.queries['住所'].p95Ms.toFixed(1)}ms`,
          );
          await page.evaluate(() => window.lockProbe());
          assert.equal(await page.locator('#result').textContent(), '');
        }
        const restricted = await page.evaluate(() => window.probe(1000, ['human']));
        assert.equal(restricted.indexed, 500);
        assert.deepEqual(restricted.threads, ['human']);
        await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
        assert.equal(await page.locator('#result').textContent(), '');
        // Terminate an active request: its result must neither resolve nor repopulate DOM.
        assert.equal(
          await page.evaluate(async () => {
            const pending = window.probe(100000).then(
              () => 'late result',
              () => 'locked',
            );
            await new Promise((resolve) => setTimeout(resolve, 10));
            window.lockProbe();
            return pending;
          }),
          'locked',
        );
        await page.waitForTimeout(100);
        assert.equal(await page.locator('#result').textContent(), '');
        assert.deepEqual(
          await page.evaluate(async () => ({
            local: localStorage.length,
            session: sessionStorage.length,
            idb: (await indexedDB.databases()).length,
            caches: (await caches.keys()).length,
          })),
          { local: 0, session: 0, idb: 0, caches: 0 },
        );
        const opfs = await page.evaluate(async () => {
          try {
            let entries = 0;
            for await (const _ of (await navigator.storage.getDirectory()).values()) entries++;
            return { status: 'inspected', entries };
          } catch (error) {
            return { status: 'unavailable', reason: error.name };
          }
        });
        if (opfs.status === 'inspected') assert.equal(opfs.entries, 0);
        report.storage ??= [];
        report.storage.push({
          browser: name,
          mobileViewport,
          local: 0,
          session: 0,
          idb: 0,
          caches: 0,
          opfs,
        });
        assert(
          requests.every((r) => r.startsWith(url + '/')),
          'no external content/query request',
        );
        assert.deepEqual(errors, []);
        await context.close();
      }
    } finally {
      await browser.close();
    }
  }
  report.checks = [
    'all Worker assertions',
    'selected-thread projection',
    'terminate pending request/no late DOM result',
    'empty localStorage/sessionStorage/IndexedDB/CacheStorage; OPFS status recorded separately',
    'loopback assets only',
  ];
  await writeFile(new URL('report.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
} finally {
  await new Promise((resolve) => server.close(resolve));
}
