import { qualificationTimeout } from './test-timeout.ts';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, test } from 'node:test';
import {
  chromium,
  firefox,
  webkit,
  type Browser,
  type BrowserContext,
  type Page,
} from '@playwright/test';
import { build } from 'esbuild';
import type {
  Command,
  DeviceEngine,
  DeviceIdentity,
  DeviceModule,
  DeviceScope,
  Head,
  PersistentMlsDevice,
  Phase,
} from './device-store.js';

type Module = DeviceModule & {
  default(): Promise<unknown>;
  BoundMlsClient: {
    new (identity: string, authorities: string): DeviceEngine & { public_key(): Uint8Array };
  };
};
declare global {
  var journalModule: Module;
  var journalClass: typeof PersistentMlsDevice;
  var journalStore: PersistentMlsDevice;
  var journalRaw: DeviceEngine & { public_key(): Uint8Array };
  var journalPhase: ((phase: Phase) => Promise<void>) | undefined;
  var journalReached: (phase: Phase) => Promise<void>;
  var journalRead: (scope: string) => Promise<Head>;
  var journalCas: (scope: string, expected: Head, next: Head) => Promise<Head>;
}
const NOW = 1000;
const GROUP = Array<number>(16).fill(7);
let bundle: Uint8Array;
const server = createServer(async (request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  if (request.url === '/') {
    response
      .writeHead(200, { 'Content-Type': 'text/html' })
      .end('<!doctype html><title>Encrypted device journal qualification</title>');
    return;
  }
  if (request.url === '/device-store.js') {
    response.writeHead(200, { 'Content-Type': 'text/javascript' }).end(bundle);
    return;
  }
  const file =
    request.url === '/probe.js'
      ? 'mikaki_mls_probe.js'
      : request.url === '/mikaki_mls_probe_bg.wasm'
        ? 'mikaki_mls_probe_bg.wasm'
        : null;
  if (!file) {
    response.writeHead(404).end();
    return;
  }
  try {
    response
      .writeHead(200, {
        'Content-Type': file.endsWith('.wasm') ? 'application/wasm' : 'text/javascript',
      })
      .end(await readFile(new URL(`./pkg-web/${file}`, import.meta.url)));
  } catch {
    response.writeHead(500).end();
  }
});
let origin: string;
before(async () => {
  const result = await build({
    entryPoints: [new URL('./device-store.ts', import.meta.url).pathname],
    bundle: true,
    write: false,
    format: 'esm',
    target: 'es2022',
  });
  bundle = result.outputFiles[0].contents;
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
});

// Independent of all browser storage and contexts. Synthetic authenticated
// witness fixture only: a real service must bind this CAS to the signed-in device.
class Witness {
  heads = new Map<string, Head>();
  loseResponse = false;
  read(scope: string) {
    return structuredClone(this.heads.get(scope) ?? { revision: 0, hash: null });
  }
  cas(scope: string, expected: Head, next: Head) {
    const current = this.read(scope);
    if (current.revision === expected.revision && current.hash === expected.hash) {
      assert.equal(next.revision, expected.revision + 1);
      this.heads.set(scope, structuredClone(next));
      if (this.loseResponse) {
        this.loseResponse = false;
        throw new Error('synthetic_response_lost');
      }
      return next;
    }
    return current;
  }
}
class Issuer {
  keys = generateKeyPairSync('ed25519');
  readonly issuer: string;
  constructor(issuer: string) {
    this.issuer = issuer;
  }
  authority() {
    return { issuer: this.issuer, public_key: this.keys.publicKey.export({ format: 'jwk' }).x! };
  }
  binding(device: DeviceIdentity, public_key: string, status = 'active', revision = 1) {
    const header = {
      typ: 'mikaki-device-binding+jwt',
      alg: 'EdDSA',
      kid: createHash('sha256')
        .update(Buffer.from(this.authority().public_key, 'base64url'))
        .digest('base64url'),
    };
    const payload = {
      iss: this.issuer,
      aud: 'mikaki-mls-device-v1',
      device,
      public_key,
      revision,
      status,
      iat: NOW,
      exp: NOW + 300,
    };
    const input = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
    return `${input}.${sign(null, Buffer.from(input), this.keys.privateKey).toString('base64url')}`;
  }
}
class Device {
  page!: Page;
  scope!: DeviceScope;
  publicKey!: string;
  // Qualification custody only. Never persisted in IndexedDB or sent to server.
  key = [...randomBytes(32)];
  reached: ((phase: Phase) => void) | undefined;
  readonly context: BrowserContext;
  readonly id: DeviceIdentity;
  readonly authorities: string;
  readonly witness: Witness;
  constructor(context: BrowserContext, id: DeviceIdentity, authorities: string, witness: Witness) {
    this.context = context;
    this.id = id;
    this.authorities = authorities;
    this.witness = witness;
  }
  async pageModule() {
    const page = await this.context.newPage();
    await page.exposeFunction('journalRead', (scope: string) => this.witness.read(scope));
    await page.exposeFunction('journalCas', (scope: string, expected: Head, next: Head) =>
      this.witness.cas(scope, expected, next),
    );
    await page.exposeFunction('journalReached', (phase: Phase) => this.reached?.(phase));
    await page.goto(origin);
    await page.evaluate(async () => {
      globalThis.journalModule = (await import('/probe.js' as string)) as Module;
      await journalModule.default();
      globalThis.journalClass = (
        (await import('/device-store.js' as string)) as {
          PersistentMlsDevice: typeof PersistentMlsDevice;
        }
      ).PersistentMlsDevice;
    });
    return page;
  }
  async create() {
    this.page = await this.pageModule();
    const info = await this.page.evaluate(
      ({ id, authorities }) => {
        globalThis.journalRaw = new journalModule.BoundMlsClient(JSON.stringify(id), authorities);
        return {
          fingerprint: journalRaw.fingerprint(),
          publicKey: Array.from(journalRaw.public_key()),
        };
      },
      { id: this.id, authorities: this.authorities },
    );
    this.publicKey = Buffer.from(info.publicKey).toString('base64url');
    this.scope = {
      device: this.id,
      storage_id: randomUUID(),
      key_id: randomUUID(),
      fingerprint: info.fingerprint,
    };
  }
  async mount(page = this.page, key = this.key, scope = this.scope) {
    await page.evaluate(
      async ({ key, scope, authorities }) => {
        const raw = Uint8Array.from(key);
        try {
          const custody = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [
            'encrypt',
            'decrypt',
          ]);
          globalThis.journalStore = new journalClass(
            scope,
            custody,
            journalModule,
            authorities,
            { read: journalRead, compareAndSet: journalCas },
            { onPhase: (phase) => globalThis.journalPhase?.(phase) },
          );
        } finally {
          raw.fill(0);
          key.fill(0);
        }
      },
      { key: [...key], scope, authorities: this.authorities },
    );
  }
  async bootstrap() {
    await this.mount();
    await this.page.evaluate(async () => {
      const raw = journalRaw.checkpoint();
      try {
        await journalStore.bootstrap(raw);
      } finally {
        raw.fill(0);
        journalRaw.free();
      }
    });
  }
  async restart() {
    await this.page.close();
    this.page = await this.pageModule();
    await this.mount();
  }
  async tab() {
    const page = await this.pageModule();
    await this.mount(page);
    return page;
  }
  async request(command: Command, operationId = randomUUID(), now = NOW, page = this.page) {
    return page.evaluate(
      ({ command, operationId, now }) => journalStore.request(operationId, command, now),
      { command, operationId, now },
    );
  }
  async ok(command: Command, operationId = randomUUID(), now = NOW) {
    const result = await this.request(command, operationId, now);
    assert.equal(result.ok, true, result.error ?? 'request failed');
    return result;
  }
  box(now = NOW) {
    return this.page.evaluate((now) => journalStore.outbox(now), now);
  }
  inbox() {
    return this.page.evaluate(() => journalStore.inbox());
  }
  ack(message: { id: string; digest: string }) {
    return this.ok({ kind: 'acknowledge', message_id: message.id, digest: message.digest });
  }
}
async function pair(browser: Browser, establish = true) {
  const witness = new Witness();
  const issuer = new Issuer('https://journal.example');
  const authorities = JSON.stringify([issuer.authority()]);
  const id = (): DeviceIdentity => ({
    issuer: issuer.issuer,
    account_id: randomUUID(),
    device_id: randomUUID(),
    generation: 1,
  });
  const a = new Device(await browser.newContext(), id(), authorities, witness);
  const b = new Device(await browser.newContext(), id(), authorities, witness);
  await a.create();
  await b.create();
  const aToken = issuer.binding(a.id, a.publicKey),
    bToken = issuer.binding(b.id, b.publicKey);
  for (const [own, self, peer, fingerprint] of [
    [a, aToken, bToken, b.scope.fingerprint],
    [b, bToken, aToken, a.scope.fingerprint],
  ] as const) {
    await own.page.evaluate(
      ({ self, peer, fingerprint }) => {
        journalRaw.bind_self(self, 1000n);
        journalRaw.confirm_peer(peer, fingerprint, 1000n);
      },
      { self, peer, fingerprint },
    );
    await own.bootstrap();
  }
  if (!establish) return { a, b, witness, issuer };
  const packageResult = await b.ok({ kind: 'key_package' });
  const kp = (await b.box()).ready.find((m) => m.id === packageResult.message_ids[0])!;
  await a.ok({ kind: 'create_group', group: GROUP });
  const invitation = await a.ok({ kind: 'invite', key_package: kp.wire });
  const out = await a.box();
  assert.equal(out.ready.length, 1);
  assert.equal(out.waiting.length, 1, 'Welcome cannot leave before Commit acceptance and merge');
  const commit = out.ready[0];
  assert.equal(
    (await a.request({ kind: 'merge_pending', commit_id: commit.id })).error,
    'commit_not_accepted',
  );
  await a.ack(commit);
  assert.equal((await a.box()).waiting.length, 1);
  await a.ok({ kind: 'merge_pending', commit_id: commit.id });
  const welcome = (await a.box()).ready.find((m) => m.id === invitation.message_ids[1])!;
  await b.ok({ kind: 'join', welcome: welcome.wire, group: GROUP });
  await a.ack(welcome);
  await b.ack(kp);
  return { a, b, witness, issuer };
}
// Test-only whole-record inspection/corruption, never plaintext or a debug export
// on the production adapter. All connections/transactions complete before use.
async function record(page: Page, replacement?: unknown, remove = false): Promise<unknown> {
  return page.evaluate(
    async ({ replacement, remove }) => {
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const r = indexedDB.open('mikaki-mls-device-v1', 1);
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      });
      try {
        return await new Promise((resolve, reject) => {
          const tx = db.transaction(
            'devices',
            replacement !== undefined || remove ? 'readwrite' : 'readonly',
          );
          const store = tx.objectStore('devices'),
            keys = store.getAllKeys();
          let result: unknown;
          keys.onsuccess = () => {
            if (keys.result.length !== 1) {
              tx.abort();
              return;
            }
            if (remove) store.delete(keys.result[0]);
            else if (replacement !== undefined) store.put(replacement, keys.result[0]);
            else {
              const r = store.get(keys.result[0]);
              r.onsuccess = () => {
                result = r.result;
              };
            }
          };
          tx.oncomplete = () => resolve(result);
          tx.onabort = () => reject(new Error('test_record_failed'));
        });
      } finally {
        db.close();
      }
    },
    { replacement, remove },
  );
}
async function abortNextWrite(page: Page) {
  await page.evaluate(() => {
    const original = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (...args: Parameters<typeof original>) {
      IDBObjectStore.prototype.put = original;
      const request = original.apply(this, args);
      this.transaction.abort();
      return request;
    };
  });
}
const browserTypes = { chromium, firefox, webkit };
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const browserType = browserTypes[name as keyof typeof browserTypes];
  if (!browserType) throw new Error(`Unsupported browser: ${name}`);
  test(
    `${name}: witnessed encrypted device state`,
    { timeout: qualificationTimeout(180_000) },
    async (t) => {
      const browser = await browserType.launch();
      try {
        await t.test(
          'exact retry, durable inbox deduplication and explicit Commit ordering',
          async () => {
            const { a, b } = await pair(browser);
            const id = randomUUID(),
              command: Command = { kind: 'send', text: '保存してから送信する秘密の本文' };
            const receipt = await a.ok(command, id);
            const message = (await a.box()).ready[0];
            assert.deepEqual(receipt.message_ids, [message.id]);
            const dump = JSON.stringify(await record(a.page));
            for (const secret of [
              '保存してから送信する秘密の本文',
              'checkpoint',
              'private_key',
              'outbox',
              'operations',
            ])
              assert.equal(dump.includes(secret), false);
            assert.deepEqual(Object.keys(JSON.parse(dump)).sort(), ['head', 'pending', 'version']);
            await a.restart();
            assert.deepEqual(await a.ok(command, id), receipt);
            assert.deepEqual(
              (await a.box()).ready,
              [message],
              'retry never reseals an MLS message',
            );
            await assert.rejects(
              a.request({ kind: 'send', text: 'different' }, id),
              /operation_id_conflict/,
            );
            const incoming: Command = {
              kind: 'receive',
              message_id: message.id,
              wire: message.wire,
            };
            const received = await b.ok(incoming);
            await b.restart();
            assert.deepEqual((await b.ok(incoming)).event_id, received.event_id);
            assert.equal((await b.inbox()).length, 1);
            assert.equal(JSON.stringify(await b.inbox()).includes(command.text), true);
            const changed = message.wire.slice();
            changed[changed.length - 1] ^= 1;
            assert.equal(
              (await b.request({ ...incoming, wire: changed })).error,
              'message_id_conflict',
            );
            assert.equal(
              (
                await a.request({
                  kind: 'acknowledge',
                  message_id: message.id,
                  digest: 'A'.repeat(43),
                })
              ).error,
              'receipt_digest_mismatch',
            );
            await a.ack(message);
            await a.restart();
            assert.equal((await a.box()).ready.length, 0);
            const update = await a.ok({ kind: 'update' });
            const commit = (await a.box()).ready.find((m) => m.id === update.message_ids[0])!;
            const fromBob = await b.ok({ kind: 'send', text: 'pending commit' });
            const queued = (await b.box()).ready.find((m) => m.id === fromBob.message_ids[0])!;
            const denied = await a.request({
              kind: 'receive',
              message_id: queued.id,
              wire: queued.wire,
            });
            assert.equal(denied.ok, false);
            await a.restart();
            await b.ok({ kind: 'receive', message_id: commit.id, wire: commit.wire });
            await a.ack(commit);
            await a.ok({ kind: 'merge_pending', commit_id: commit.id });
            // The existing probe deliberately retains no past-epoch secrets.
            // Pending input stays rejected; reconciliation does not invent a
            // successful receive or silently reset/rejoin the conversation.
            assert.equal(
              (await a.request({ kind: 'receive', message_id: queued.id, wire: queued.wire })).ok,
              false,
            );
            await b.ok({ kind: 'send', text: 'after explicit epoch reconciliation' });
            const currentEpoch = (await b.box()).ready.at(-1)!;
            await a.ok({ kind: 'receive', message_id: currentEpoch.id, wire: currentEpoch.wire });
            assert.equal(
              (await a.inbox()).length,
              1,
              'only current-epoch input is published after explicit reconciliation',
            );
            await a.context.close();
            await b.context.close();
          },
        );
        await t.test(
          'page termination at every durable send boundary recovers the same candidate',
          async () => {
            const { a, b } = await pair(browser);
            for (const phase of ['after_prepare', 'after_witness', 'after_publish'] as const) {
              const id = randomUUID(),
                command: Command = { kind: 'send', text: `crash-${phase}` };
              const reached = new Promise<void>((resolve) => {
                a.reached = (p) => {
                  if (p === phase) resolve();
                };
              });
              await a.page.evaluate((phase) => {
                globalThis.journalPhase = async (p) => {
                  if (p === phase) {
                    await journalReached(p);
                    await new Promise(() => {});
                  }
                };
              }, phase);
              const interrupted = a.request(command, id).catch(() => null);
              await reached;
              const candidate = (await record(a.page)) as {
                head: { hash: string };
                pending: { hash: string } | null;
              };
              const expected = candidate.pending?.hash ?? candidate.head.hash;
              await a.restart();
              await interrupted;
              assert.equal((await a.ok(command, id)).ok, true);
              const recovered = (await record(a.page)) as {
                head: { hash: string };
                pending: unknown;
              };
              assert.equal(
                recovered.head.hash,
                expected,
                'recovery publishes the exact sealed candidate',
              );
              assert.equal(recovered.pending, null);
              const messages = (await a.box()).ready;
              assert.equal(messages.length, 1);
              await b.ok({ kind: 'receive', message_id: messages[0].id, wire: messages[0].wire });
              await a.ack(messages[0]);
            }
            assert.equal((await b.inbox()).length, 3);
            // Received plaintext also remains unavailable until the prepared receive
            // and deduplication/event records have committed together.
            await b.ok({ kind: 'send', text: 'receive crash' });
            const message = (await b.box()).ready[0];
            const reached = new Promise<void>((resolve) => {
              a.reached = (p) => {
                if (p === 'after_prepare') resolve();
              };
            });
            await a.page.evaluate(() => {
              globalThis.journalPhase = async (p) => {
                if (p === 'after_prepare') {
                  await journalReached(p);
                  await new Promise(() => {});
                }
              };
            });
            const command: Command = {
                kind: 'receive',
                message_id: message.id,
                wire: message.wire,
              },
              id = randomUUID();
            const interrupted = a.request(command, id).catch(() => null);
            await reached;
            await a.restart();
            await interrupted;
            const first = await a.ok(command, id);
            assert.equal((await a.ok(command)).event_id, first.event_id);
            assert.equal((await a.inbox()).length, 1);
            await a.context.close();
            await b.context.close();
          },
        );
        await t.test(
          'aborted IDB transactions, lost witness replies and lock revoke fail closed',
          async () => {
            const { a, b, witness } = await pair(browser);
            const prior = structuredClone([...witness.heads]);
            const id = randomUUID(),
              command: Command = { kind: 'send', text: 'durability failure' };
            await abortNextWrite(a.page);
            await assert.rejects(a.request(command, id), /storage_commit_failed/);
            assert.deepEqual([...witness.heads], prior);
            assert.equal((await a.box()).ready.length, 0);
            // CAS commits remotely but the response is lost. Recovery must publish
            // the pending record, never rerun send or invent a second ciphertext.
            witness.loseResponse = true;
            await assert.rejects(a.request(command, id), /synthetic_response_lost/);
            const candidate = (await record(a.page)) as { pending: { hash: string } };
            await a.restart();
            const receipt = await a.ok(command, id);
            assert.equal(
              ((await record(a.page)) as { head: { hash: string } }).head.hash,
              candidate.pending.hash,
            );
            const message = (await a.box()).ready[0];
            assert.deepEqual(receipt.message_ids, [message.id]);
            await b.ok({ kind: 'receive', message_id: message.id, wire: message.wire });
            await a.ack(message);
            // Abort the publish transaction after witness advancement.
            await a.page.evaluate(() => {
              globalThis.journalPhase = async (p) => {
                if (p !== 'after_witness') return;
                globalThis.journalPhase = undefined;
                const original = IDBObjectStore.prototype.put;
                IDBObjectStore.prototype.put = function (...args: Parameters<typeof original>) {
                  IDBObjectStore.prototype.put = original;
                  const request = original.apply(this, args);
                  this.transaction.abort();
                  return request;
                };
              };
            });
            const secondId = randomUUID();
            await assert.rejects(
              a.request({ kind: 'send', text: 'publish aborted' }, secondId),
              /storage_commit_failed/,
            );
            await a.restart();
            await a.ok({ kind: 'send', text: 'publish aborted' }, secondId);
            assert.equal((await a.box()).ready.length, 1);
            await a.page.evaluate(() => {
              globalThis.journalPhase = async (p) => {
                if (p === 'after_prepare') journalStore.close();
              };
            });
            const lockedId = randomUUID();
            await assert.rejects(
              a.request({ kind: 'send', text: 'locked before release' }, lockedId),
              /device_locked/,
            );
            await assert.rejects(a.box(), /device_locked/);
            await a.restart();
            await a.ok({ kind: 'send', text: 'locked before release' }, lockedId);
            assert.equal((await a.box()).ready.length, 2);
            await a.context.close();
            await b.context.close();
          },
        );
        await t.test(
          'tabs serialize state changes and duplicate requests without forking the ratchet',
          async () => {
            const { a, b } = await pair(browser),
              tab = await a.tab();
            const id = randomUUID(),
              duplicate: Command = { kind: 'send', text: 'same operation across tabs' };
            const receipts = await Promise.all([
              a.request(duplicate, id),
              a.request(duplicate, id, NOW, tab),
              ...Array.from({ length: 6 }, (_, n) =>
                a.request(
                  { kind: 'send', text: `tab-${n}` },
                  randomUUID(),
                  NOW,
                  n % 2 ? tab : a.page,
                ),
              ),
            ]);
            assert.deepEqual(receipts[0], receipts[1]);
            assert.equal(
              receipts.every((r) => r.ok),
              true,
            );
            const messages = (await a.box()).ready;
            assert.equal(messages.length, 7);
            assert.equal(new Set(messages.map((m) => m.digest)).size, 7);
            // Reorder adjacent messages within the existing bounded MLS window.
            [messages[0], messages[1]] = [messages[1], messages[0]];
            for (const message of messages)
              await b.ok({ kind: 'receive', message_id: message.id, wire: message.wire });
            assert.equal((await b.inbox()).length, 7);
            await a.restart();
            assert.equal((await a.box()).ready.length, 7);
            await a.context.close();
            await b.context.close();
          },
        );
        await t.test('outbox exhaustion rolls back the entire two-message invitation', async () => {
          const { a, b } = await pair(browser, false);
          await b.ok({ kind: 'key_package' });
          const kp = (await b.box()).ready[0];
          // Only one slot remains, whereas an invitation needs both Commit and
          // Welcome. A failed second admission must undo the first and the MLS
          // pending commit, while retaining the durable rejection receipt.
          for (let i = 0; i < 63; i++) await a.ok({ kind: 'key_package' });
          await a.ok({ kind: 'create_group', group: GROUP });
          const command: Command = { kind: 'invite', key_package: kp.wire },
            id = randomUUID();
          const rejected = await a.request(command, id);
          assert.equal(rejected.error, 'outbox_full');
          await a.restart();
          assert.deepEqual(await a.request(command, id), rejected);
          const full = await a.box();
          assert.equal(full.ready.length, 63);
          assert.equal(full.waiting.length, 0);
          assert.equal(
            full.ready.every((m) => m.kind === 'key_package'),
            true,
          );
          await a.ack(full.ready[0]);
          const retry = await a.ok(command);
          assert.equal(retry.message_ids.length, 2, 'no partial pending Commit survived rejection');
          const next = await a.box();
          assert.equal(next.ready.length, 63);
          assert.equal(next.waiting.length, 1);
          const commit = next.ready.find((m) => m.id === retry.message_ids[0])!;
          await a.ack(commit);
          await a.ok({ kind: 'merge_pending', commit_id: commit.id });
          const welcome = (await a.box()).ready.find((m) => m.id === retry.message_ids[1])!;
          await b.ok({ kind: 'join', welcome: welcome.wire, group: GROUP });
          await b.ok({ kind: 'send', text: 'only the complete invitation was committed' });
          const message = (await b.box()).ready.find((m) => m.kind === 'application')!;
          await a.ok({ kind: 'receive', message_id: message.id, wire: message.wire });
          await a.context.close();
          await b.context.close();
        });
        await t.test(
          'reviewed replacement cannot release ciphertext prepared for the previous key',
          async () => {
            const { a, b, issuer, witness } = await pair(browser);
            await a.ok({ kind: 'send', text: 'sealed to the original peer key' });
            const replacement = new Device(
              await browser.newContext(),
              { ...b.id, generation: 2 },
              a.authorities,
              witness,
            );
            await replacement.create();
            const token = issuer.binding(replacement.id, replacement.publicKey, 'active', 2);
            assert.equal(
              (await a.ok({ kind: 'observe_binding', token })).observation,
              'key_changed',
            );
            assert.equal((await a.box()).ready.length, 0);
            await a.ok({
              kind: 'accept_key_change',
              token,
              previous: b.scope.fingerprint,
              replacement: replacement.scope.fingerprint,
            });
            await a.restart();
            const out = await a.box();
            assert.equal(out.ready.length, 0);
            assert.equal(out.blocked[0].error, 'outgoing_key_changed');
            await a.context.close();
            await b.context.close();
            await replacement.context.close();
          },
        );
        await t.test(
          'whole-database rollback, missing state, tampering and wrong custody keys are rejected',
          async () => {
            const { a, b } = await pair(browser);
            const old = await record(a.page);
            await a.ok({ kind: 'send', text: 'newer witnessed state' });
            const current = await record(a.page);
            await record(a.page, old);
            await a.restart();
            await assert.rejects(a.box(), /rollback_or_state_loss/);
            await record(a.page, current);
            await a.restart();
            assert.equal((await a.box()).ready.length, 1);
            await a.mount(a.page, [...randomBytes(32)]);
            await assert.rejects(a.box(), /state_authentication_failed/);
            await a.restart();
            const corrupt = structuredClone(current) as { head: { ciphertext: string } };
            corrupt.head.ciphertext = `${corrupt.head.ciphertext[0] === 'A' ? 'B' : 'A'}${corrupt.head.ciphertext.slice(1)}`;
            await record(a.page, corrupt);
            await assert.rejects(a.box(), /ciphertext_digest_mismatch/);
            await record(a.page, current);
            await a.mount(a.page, a.key, { ...a.scope, key_id: randomUUID() });
            await assert.rejects(a.box(), /device_not_initialized/);
            await a.restart();
            await record(a.page, undefined, true);
            await assert.rejects(a.box(), /rollback_or_state_loss/);
            // Missing state cannot silently bootstrap a new device under an old witness.
            await a.page.evaluate(
              ({ id, authorities }) => {
                globalThis.journalRaw = new journalModule.BoundMlsClient(
                  JSON.stringify(id),
                  authorities,
                );
              },
              { id: a.id, authorities: a.authorities },
            );
            await assert.rejects(
              a.page.evaluate(() => journalStore.bootstrap(journalRaw.checkpoint())),
              /rollback_or_state_loss/,
            );
            await a.context.close();
            await b.context.close();
          },
        );
        await t.test(
          'persisted revocation and time watermark block already queued ciphertext',
          async () => {
            const { a, b, issuer } = await pair(browser);
            await a.ok({ kind: 'send', text: 'queued before revocation' });
            const revoked = issuer.binding(b.id, b.publicKey, 'revoked', 2);
            assert.equal(
              (await a.ok({ kind: 'observe_binding', token: revoked })).observation,
              'revoked',
            );
            await a.restart();
            const revokedBox = await a.box();
            assert.equal(revokedBox.ready.length, 0);
            assert.equal(revokedBox.blocked.length, 1);
            const removal = await a.ok({ kind: 'remove_peer' });
            assert.equal(
              (await a.box()).ready[0].id,
              removal.message_ids[0],
              'revoked peer cannot stop its removal',
            );
            await b.ok({ kind: 'send', text: 'expires while queued' });
            assert.equal((await b.box(NOW + 301)).ready.length, 0);
            await b.restart();
            await assert.rejects(b.box(NOW), /clock_rollback/);
            await assert.rejects(
              b.request({ kind: 'send', text: 'clock rollback' }, randomUUID(), NOW),
              /clock_rollback/,
            );
            await a.context.close();
            await b.context.close();
          },
        );
      } finally {
        await browser.close();
      }
    },
  );
}
