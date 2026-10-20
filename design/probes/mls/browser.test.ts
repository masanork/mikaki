import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFile } from 'node:fs/promises';
import { after, before, test } from 'node:test';
import { gzipSync } from 'node:zlib';
import { chromium, firefox, webkit, type Browser, type Page } from '@playwright/test';

interface ProbeClient {
  public_key(): Uint8Array;
  key_package(): Uint8Array;
  create_group(id: Uint8Array): void;
  invite(keyPackage: Uint8Array): string;
  join(welcome: Uint8Array, group: Uint8Array): void;
  send(text: string): Uint8Array;
  receive(message: Uint8Array): string;
  update(): Uint8Array;
  remove_peer(): Uint8Array;
  merge_pending(): void;
  epoch(): bigint;
  active(): boolean;
  checkpoint(): Uint8Array;
  free(): void;
}
interface ProbeModule {
  default(): Promise<unknown>;
  MlsProbeClient: {
    new (identity: string): ProbeClient;
    restore(state: Uint8Array): ProbeClient;
  };
}
declare global {
  var mlsProbeModule: ProbeModule;
  var mlsProbeClient: ProbeClient;
}

const group = Array<number>(16).fill(1);
const assets = new Map([
  ['/probe.js', ['mikaki_mls_probe.js', 'text/javascript']],
  ['/mikaki_mls_probe_bg.wasm', ['mikaki_mls_probe_bg.wasm', 'application/wasm']],
]);
const server = createServer(async (request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  if (request.url === '/') {
    response
      .writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      .end('<!doctype html><title>Synthetic MLS qualification</title>');
    return;
  }
  const asset = assets.get(request.url ?? '');
  if (!asset) {
    response.writeHead(404).end();
    return;
  }
  try {
    const bytes = await readFile(new URL(`./pkg-web/${asset[0]}`, import.meta.url));
    response.writeHead(200, { 'Content-Type': asset[1] }).end(bytes);
  } catch {
    response.writeHead(500).end();
  }
});
let origin: string;
before(async () => {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
});

async function device(browser: Browser, identity: string): Promise<Page> {
  // browser.newPage creates an isolated browser context for each device.
  const page = await browser.newPage();
  await page.goto(origin);
  await page.evaluate(async (identity) => {
    globalThis.mlsProbeModule = (await import('/probe.js' as string)) as ProbeModule;
    await mlsProbeModule.default();
    globalThis.mlsProbeClient = new mlsProbeModule.MlsProbeClient(identity);
  }, identity);
  return page;
}

async function restart(page: Page): Promise<void> {
  // Synthetic private state stays in harness memory, never in a file or API.
  const state = await page.evaluate(() => {
    const state = mlsProbeClient.checkpoint();
    try {
      return Array.from(state);
    } finally {
      state.fill(0);
      mlsProbeClient.free();
    }
  });
  try {
    await page.reload();
    await page.evaluate(async (state) => {
      globalThis.mlsProbeModule = (await import('/probe.js' as string)) as ProbeModule;
      await mlsProbeModule.default();
      const bytes = Uint8Array.from(state);
      try {
        globalThis.mlsProbeClient = mlsProbeModule.MlsProbeClient.restore(bytes);
      } finally {
        bytes.fill(0);
        state.fill(0);
      }
    }, state);
  } finally {
    state.fill(0);
  }
}

async function send(page: Page, text: string): Promise<number[]> {
  return page.evaluate((text) => Array.from(mlsProbeClient.send(text)), text);
}
async function receive(page: Page, message: number[]): Promise<unknown> {
  return page.evaluate(
    (message) => JSON.parse(mlsProbeClient.receive(Uint8Array.from(message))) as unknown,
    message,
  );
}
async function rejects(page: Page, message: number[]): Promise<void> {
  assert.equal(
    await page.evaluate((message) => {
      try {
        mlsProbeClient.receive(Uint8Array.from(message));
        return false;
      } catch {
        return true;
      }
    }, message),
    true,
  );
}
async function pair(browser: Browser): Promise<[Page, Page]> {
  const alice = await device(browser, 'alice/device-1');
  const bob = await device(browser, 'bob/device-1');
  const keyPackage = await bob.evaluate(() => Array.from(mlsProbeClient.key_package()));
  await restart(bob);
  const invitation = await alice.evaluate(
    ({ group, keyPackage }) => {
      mlsProbeClient.create_group(Uint8Array.from(group));
      return JSON.parse(mlsProbeClient.invite(Uint8Array.from(keyPackage))) as {
        commit: number[];
        welcome: number[];
      };
    },
    { group, keyPackage },
  );
  await restart(alice);
  await alice.evaluate(() => mlsProbeClient.merge_pending());
  // A wrong conversation must not burn the one-use joining secret.
  assert.equal(
    await bob.evaluate((welcome) => {
      try {
        mlsProbeClient.join(Uint8Array.from(welcome), new Uint8Array(16).fill(2));
        return false;
      } catch {
        return true;
      }
    }, invitation.welcome),
    true,
  );
  await bob.evaluate(
    ({ welcome, group }) => mlsProbeClient.join(Uint8Array.from(welcome), Uint8Array.from(group)),
    { welcome: invitation.welcome, group },
  );
  return [alice, bob];
}

const names = (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',');
const browserTypes = { chromium, firefox, webkit };
for (const name of names) {
  if (!(name in browserTypes)) throw new Error(`Unknown browser: ${name}`);
  const browserType = browserTypes[name as keyof typeof browserTypes];
  test(`${name}: independent Wasm devices restore, exchange, update and remove`, async () => {
    const browser = await browserType.launch({ headless: true });
    try {
      const [alice, bob] = await pair(browser);
      const hello = '端末を再起動しても会話を続ける 🕊️';
      const first = await send(alice, hello);
      await restart(alice);
      assert.deepEqual(await receive(bob, first), {
        kind: 'application',
        sender: 'alice/device-1',
        text: hello,
      });
      await restart(bob);
      await rejects(bob, first);
      assert.deepEqual(await receive(alice, await send(bob, '返信')), {
        kind: 'application',
        sender: 'bob/device-1',
        text: '返信',
      });
      const commit = await alice.evaluate(() => Array.from(mlsProbeClient.update()));
      assert.equal(
        await alice.evaluate(() => {
          try {
            mlsProbeClient.send('must wait');
            return false;
          } catch {
            return true;
          }
        }),
        true,
      );
      await restart(alice);
      await alice.evaluate(() => mlsProbeClient.merge_pending());
      assert.deepEqual(await receive(bob, commit), { kind: 'commit', active: true });
      assert.equal(
        await alice.evaluate(() => mlsProbeClient.epoch()),
        await bob.evaluate(() => mlsProbeClient.epoch()),
      );
      assert.deepEqual(await receive(bob, await send(alice, '更新後')), {
        kind: 'application',
        sender: 'alice/device-1',
        text: '更新後',
      });
      const removal = await alice.evaluate(() => Array.from(mlsProbeClient.remove_peer()));
      await alice.evaluate(() => mlsProbeClient.merge_pending());
      const future = await send(alice, 'removed peer cannot decrypt');
      await rejects(bob, future);
      assert.deepEqual(await receive(bob, removal), { kind: 'commit', active: false });
      await restart(bob);
      assert.equal(await bob.evaluate(() => mlsProbeClient.active()), false);
      await rejects(bob, future);
    } finally {
      await browser.close();
    }
  });

  test(`${name}: tampering cannot consume valid messages; replay and wrong groups fail`, async () => {
    const browser = await browserType.launch({ headless: true });
    try {
      const [alice, bob] = await pair(browser);
      const unrelated = await device(browser, 'unrelated/device-1');
      await unrelated.evaluate(() => mlsProbeClient.create_group(new Uint8Array(16).fill(3)));
      const first = await send(alice, 'first');
      const second = await send(alice, 'second');
      const modified = first.slice();
      modified[modified.length - 1] ^= 1;
      await rejects(bob, modified);
      await rejects(bob, first.slice(0, -1));
      await rejects(bob, [...first, 0]);
      await rejects(unrelated, first);
      assert.deepEqual(await receive(bob, second), {
        kind: 'application',
        sender: 'alice/device-1',
        text: 'second',
      });
      await restart(bob);
      assert.deepEqual(await receive(bob, first), {
        kind: 'application',
        sender: 'alice/device-1',
        text: 'first',
      });
      await rejects(bob, first);
      await rejects(bob, second);
    } finally {
      await browser.close();
    }
  });
}

test('report isolated optimized Wasm size without private state', async (t) => {
  const wasm = await readFile(new URL('./pkg-web/mikaki_mls_probe_bg.wasm', import.meta.url));
  t.diagnostic(JSON.stringify({ wasm_bytes: wasm.length, wasm_gzip_bytes: gzipSync(wasm).length }));
});
