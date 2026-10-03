import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium } from '@playwright/test';

test('SQLite Worker searches bounded archive snapshots and destroys pending work on lock', async () => {
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const bundle = async (contents: string) =>
    (
      await build({
        stdin: { contents, resolveDir: root, loader: 'ts' },
        bundle: true,
        write: false,
        format: 'esm',
        platform: 'browser',
        external: ['/sqlite/index.mjs'],
      })
    ).outputFiles![0]!.contents;
  const routes = new Map<string, { type: string; body: Uint8Array | string }>([
    ['/', { type: 'text/html', body: '<!doctype html><title>Search regression</title>' }],
    [
      '/client.js',
      {
        type: 'text/javascript',
        body: await bundle(
          "export { ThreadSearchClient } from './crates/worker/ui/vault-thread-search-client.ts';",
        ),
      },
    ],
    [
      '/worker.js',
      {
        type: 'text/javascript',
        body: await bundle(`
          import init from '/sqlite/index.mjs';
          import { installThreadSearchWorker } from './crates/worker/ui/vault-thread-search-worker.ts';
          installThreadSearchWorker(self, init({ print:()=>{}, printErr:()=>{} })
            .then(sqlite => () => new sqlite.oo1.DB(':memory:')));
        `),
      },
    ],
    ['/silent.js', { type: 'text/javascript', body: 'self.onmessage = () => {};' }],
    [
      '/failed.js',
      {
        type: 'text/javascript',
        body: await bundle(`
          import { installThreadSearchWorker } from './crates/worker/ui/vault-thread-search-worker.ts';
          installThreadSearchWorker(self, Promise.reject(new Error('private runtime details')));
        `),
      },
    ],
  ]);
  for (const [file, type] of [
    ['index.mjs', 'text/javascript'],
    ['sqlite3.wasm', 'application/wasm'],
  ])
    routes.set(`/sqlite/${file}`, {
      type: type!,
      body: await readFile(
        `${root}/design/probes/vault-search/node_modules/@sqlite.org/sqlite-wasm/dist/${file}`,
      ),
    });
  const server = createServer((req, res) => {
    const route = routes.get(new URL(req.url!, 'http://localhost').pathname);
    if (!route || req.method !== 'GET') return void res.writeHead(404).end();
    res
      .writeHead(200, {
        'Content-Type': route.type,
        'Cache-Control': 'no-store',
        'Content-Security-Policy':
          "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'",
      })
      .end(route.body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert(address && typeof address === 'object');
  const url = `http://127.0.0.1:${address.port}`;
  let browser;
  try {
    browser = await chromium.launch();
    const page = await browser.newPage();
    const errors: string[] = [];
    const requests: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('request', (request) => requests.push(request.url()));
    await page.goto(url);
    await page.clock.install();
    const results = await page.evaluate(`(async () => {
      const { ThreadSearchClient } = await import('/client.js');
      const abort = new AbortController();
      const client = new ThreadSearchClient(new Worker('/worker.js', {type:'module'}), abort.signal);
      const message = text => ({speaker:'架空の利用者', actor:'human', text, timestamp:'2026-10-03T00:00:00.000Z'});
      const record = (id, revision, texts, title='架空の会話') => ({id, revision, archive:{format_version:1,title,messages:texts.map(message)}});
      const check = (condition, label) => {if(!condition) throw new Error(label);};
      const rejected = promise => promise.then(()=>false,()=>true);
      const snapshot = [record('human', 4, ['住所変更の申請。ＡＢＣ 100% _ "引用" 🐈 カフェ', '別の発言']), record('ai', 1, ['住所変更の申請'])];
      const coverage = await client.replace(snapshot);
      check(coverage.threads===2 && coverage.messages===3, 'coverage');
      for(const query of ['住所','住','住所変更 申請','abc','100%','_','"引用"','🐈','ｶﾌｪ']) {
        const result = await client.search(query, ['human']);
        check(result.hits.length===1 && result.hits[0].thread==='human' && result.hits[0].revision===4 && result.hits[0].message===0, 'literal/anchor '+query);
      }
      check((await client.search('住所 不在語', ['human'])).hits.length===0, 'AND');
      check((await client.search('OR', ['human'])).hits.length===0, 'literal operator');
      check((await client.search('架空の会話', ['human'])).hits[0].message===-1, 'title anchor');
      check((await client.search('', ['human'])).hits.length===0, 'empty query');
      check((await client.search('住所', [])).hits.length===0, 'empty scope');
      check(await rejected(client.search('住所', ['forbidden'])), 'scope denied');
      check(await rejected(client.search('a '.repeat(9), ['human'])), 'terms bounded');
      check(await rejected(client.search('a'.repeat(257), ['human'])), 'query bounded');
      await client.replace([record('human', 5, ['撤回後の説明'])]);
      check((await client.search('住所', ['human'])).hits.length===0, 'replace invalidates');
      check((await client.search('説明', ['human'])).hits[0].revision===5, 'current revision');
      await client.replace([]);
      check(await rejected(client.search('説明', ['human'])), 'delete invalidates scope');
      await client.replace([record('human', 6, Array.from({length:60},()=> '一致する説明'))]);
      const limited = await client.search('一致', ['human']);
      check(limited.hits.length===50 && limited.truncated, 'coverage limit explicit');
      check(await rejected(client.replace([snapshot[0], snapshot[0]])), 'duplicate denied');
      check(await rejected(client.search('住所', ['human'])), 'failed replace locks projection');
      check(await rejected(client.replace([record('human', 1, ['x'.repeat(24001)])])), 'byte limit');
      check(await rejected(client.replace(Array.from({length:257},(_,i)=>record('t'+i,1,['x'])))), 'record limit');
      await client.replace(snapshot);
      const pending = rejected(client.search('住所', ['human']));
      abort.abort();
      check(await pending, 'pending rejected on abort');
      check(await rejected(client.replace(snapshot)), 'closed cannot rebuild');
      const slow = new ThreadSearchClient(new Worker('/silent.js'), new AbortController().signal);
      const waiting = rejected(slow.replace(snapshot));
      check(await rejected(slow.search('住所', ['human'])), 'no queued clone');
      window.dispatchEvent(new PageTransitionEvent('pagehide'));
      check(await waiting, 'pagehide rejects pending');
      check(await rejected(slow.search('住所',['human'])), 'pagehide terminates');
      const hidden = new ThreadSearchClient(new Worker('/silent.js'), new AbortController().signal);
      const hiding = rejected(hidden.replace(snapshot));
      Object.defineProperty(document, 'visibilityState', {configurable:true, value:'hidden'});
      document.dispatchEvent(new Event('visibilitychange'));
      check(await hiding, 'hidden rejects pending');
      check(await rejected(hidden.search('住所',['human'])), 'hidden terminates');
      delete document.visibilityState;
      const failed = new ThreadSearchClient(new Worker('/failed.js',{type:'module'}), new AbortController().signal);
      check(await rejected(failed.replace(snapshot)), 'runtime failure distinct from empty results');
      failed.dispose();
      const timeout = new ThreadSearchClient(new Worker('/silent.js'), new AbortController().signal);
      window.pendingTimeout = rejected(timeout.replace(snapshot));
      const storage = {local:localStorage.length, session:sessionStorage.length,
        idb:(await indexedDB.databases()).length, caches:(await caches.keys()).length};
      const entries = [];
      for await (const [name] of (await navigator.storage.getDirectory()).entries()) entries.push(name);
      return {storage, opfs:entries};
    })()`);
    assert.deepEqual(results, {
      storage: { local: 0, session: 0, idb: 0, caches: 0 },
      opfs: [],
    });
    await page.clock.fastForward(15001);
    assert.equal(await page.evaluate('window.pendingTimeout'), true);
    assert.deepEqual(errors, []);
    assert(requests.every((request) => request.startsWith(url + '/')));
  } finally {
    await browser?.close();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});
