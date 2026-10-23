import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { before } from 'node:test';
import type { Browser, BrowserContext, Page } from '@playwright/test';
import { build } from 'esbuild';
import type { OwnerVaultController } from '../../../crates/worker/ui/vault-owner-controller.ts';
import type { VaultScope } from '../../../crates/worker/ui/vault-lifecycle.ts';
import type { VaultMlsDevice, EnrollmentModule, EnrollmentPhase } from './vault-device.js';
import type { MlsChatView } from './chat-view.js';
import type { Command, PersistentMlsDevice } from './device-store.js';
import { type DeliveryChannel, type InvitationOffer, type CloseReason } from './delivery-types.ts';
import { fixture, ORIGIN, pub } from './server-support.ts';
import {
  messagingCoverageEnabled,
  trackMessagingCoverage,
} from '../../../local/conformance/support/messaging-coverage.ts';

declare global {
  var custodyModule: {
    VaultScope: typeof VaultScope;
    OwnerVaultController: typeof OwnerVaultController;
    VaultMlsDevice: typeof VaultMlsDevice;
    PersistentMlsDevice: typeof PersistentMlsDevice;
    MlsChatView: typeof MlsChatView;
  };
  var custodyWasm: EnrollmentModule & { default(): Promise<unknown> };
  var custodyOwner: OwnerVaultController;
  var custodyScope: VaultScope;
  var custodyDevice: VaultMlsDevice;
  var custodyRoot: string;
  var custodyCalls: number;
  var custodyOutputs: Uint8Array[];
  var custodyReached: (phase: EnrollmentPhase) => Promise<void>;
  var custodyChat: MlsChatView;
}
let bundle: string, script: Buffer, wasm: Buffer, chatStyle: string;
before(async () => {
  bundle = (
    await build({
      stdin: {
        resolveDir: new URL('../../../', import.meta.url).pathname,
        contents: `export {OwnerVaultController} from './crates/worker/ui/vault-owner-controller.ts';export {VaultScope} from './crates/worker/ui/vault-lifecycle.ts';export {VaultMlsDevice} from './design/probes/mls/vault-device.ts';export {PersistentMlsDevice} from './design/probes/mls/device-store.ts';export {MlsChatView} from './design/probes/mls/chat-view.ts';`,
      },
      bundle: true,
      write: false,
      format: 'esm',
      target: 'es2022',
      sourcemap: messagingCoverageEnabled() ? 'inline' : false,
    })
  ).outputFiles[0].text;
  [script, wasm] = await Promise.all(
    ['mikaki_mls_probe.js', 'mikaki_mls_probe_bg.wasm'].map((file) =>
      readFile(new URL(`./pkg-web/${file}`, import.meta.url)),
    ),
  );
  chatStyle = await readFile(new URL('./chat.css', import.meta.url), 'utf8');
});
type Server = Awaited<ReturnType<typeof fixture>>;
export class Client {
  context!: BrowserContext;
  page!: Page;
  readonly id: string;
  readonly prf: number[] = [...randomBytes(32)];
  reached: ((phase: EnrollmentPhase) => void) | undefined;
  loss: { path: string; method: string; skip?: number } | undefined;
  dropRequest: { path: string; method: string } | undefined;
  forgedReceipt = false;
  forgedStopReceipt = false;
  pauseHead: { reached: () => void; release: Promise<void> } | undefined;
  requests: { path: string; method: string; body: string | null }[] = [];
  constructor(server: Server, browser: Browser, who: Server['a'], id: string = randomUUID()) {
    this.server = server;
    this.browser = browser;
    this.who = who;
    this.id = id;
  }
  readonly server: Server;
  readonly browser: Browser;
  who: Server['a'];
  async init() {
    this.context = await this.browser.newContext();
    await this.cookies();
    await this.context.route(`${ORIGIN}/**`, async (route) => {
      const req = route.request(),
        path = new URL(req.url()).pathname;
      if (path.startsWith('/messaging/') || path.startsWith('/vault/')) {
        const headers = await req.allHeaders();
        if (!headers.cookie)
          headers.cookie = (await this.context.cookies(req.url()))
            .map((c) => `${c.name}=${c.value}`)
            .join('; ');
        this.requests.push({ path, method: req.method(), body: req.postData() });
        if (this.dropRequest?.path === path && this.dropRequest.method === req.method()) {
          this.dropRequest = undefined;
          await route.abort('failed');
          return;
        }
        const response = await this.server.worker.fetch(req.url(), {
          method: req.method(),
          headers,
          ...(req.postData() === null ? {} : { body: req.postData()! }),
        });
        // Materialize the committed service response before withholding or
        // discarding delivery. A Vault lock may cancel the browser request
        // while delivery is paused; never defer reading the worker's stream
        // until after that cancellation (or leave lost replies undrained).
        let body = Buffer.from(await response.arrayBuffer());
        if (this.loss?.path === path && this.loss.method === req.method()) {
          if (this.loss.skip) this.loss.skip--;
          else {
            this.loss = undefined;
            assert.equal(response.status, 200);
            await route.abort('failed');
            return;
          }
        }
        if (this.pauseHead && req.method() === 'PUT' && path.startsWith('/messaging/heads/')) {
          const pause = this.pauseHead;
          this.pauseHead = undefined;
          pause.reached();
          await pause.release;
        }
        try {
          if (this.forgedStopReceipt && path.endsWith('/replace/stop') && response.status === 200) {
            this.forgedStopReceipt = false;
            const value = JSON.parse(body.toString());
            value.operation_id = randomUUID();
            body = Buffer.from(JSON.stringify(value));
          }
          if (this.forgedReceipt && path.endsWith('/messages') && response.status === 200) {
            this.forgedReceipt = false;
            const value = JSON.parse(body.toString());
            value.receipt.recipient_scope = 'A'.repeat(43);
            body = Buffer.from(JSON.stringify(value));
          }
          await route.fulfill({
            status: response.status,
            headers: Object.fromEntries(response.headers),
            body,
          });
        } catch (error) {
          if (!req.failure()) throw error;
        }
        return;
      }
      const asset =
        path === '/'
          ? {
              body: '<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vault device custody qualification</title><body></body></html>',
              contentType: 'text/html',
            }
          : path === '/custody.js'
            ? { body: bundle, contentType: 'text/javascript' }
            : path === '/chat.css'
              ? { body: chatStyle, contentType: 'text/css' }
              : path === '/probe.js'
                ? { body: script, contentType: 'text/javascript' }
                : path === '/mikaki_mls_probe_bg.wasm'
                  ? { body: wasm, contentType: 'application/wasm' }
                  : null;
      await route.fulfill(asset ? { status: 200, ...asset } : { status: 404, body: '' });
    });
    this.page = await this.newPage();
  }
  async cookies() {
    await this.context.clearCookies();
    await this.context.addCookies([
      {
        name: '__Host-op-sso',
        value: this.who.secret,
        url: ORIGIN,
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
      },
    ]);
  }
  async newPage() {
    const page = await this.context.newPage();
    await trackMessagingCoverage(page);
    await page.exposeFunction('custodyReached', (phase: EnrollmentPhase) => this.reached?.(phase));
    await page.goto(ORIGIN);
    await page.evaluate(
      async ({ prf, credential, root }) => {
        globalThis.custodyModule = (await import('/custody.js' as string)) as typeof custodyModule;
        globalThis.custodyWasm = (await import('/probe.js' as string)) as typeof custodyWasm;
        await custodyWasm.default();
        globalThis.custodyRoot = root;
        globalThis.custodyCalls = 0;
        globalThis.custodyOutputs = [];
        let pending: Uint8Array<ArrayBuffer> | undefined = Uint8Array.from(prf);
        prf.fill(0);
        const id = Uint8Array.from(
          atob(
            credential.replaceAll('-', '+').replaceAll('_', '/') +
              '='.repeat((4 - (credential.length % 4)) % 4),
          ),
          (c) => c.charCodeAt(0),
        );
        globalThis.custodyScope = new custodyModule.VaultScope(() => {});
        globalThis.custodyOwner = new custodyModule.OwnerVaultController(
          custodyScope,
          location.origin,
          async () => {
            if (!pending) throw new Error('synthetic_prf_already_consumed');
            custodyCalls++;
            const output = pending;
            pending = undefined;
            custodyOutputs.push(output);
            return { credentialId: id, output };
          },
        );
        await custodyOwner.open();
        if (custodyOutputs.some((p) => p.some((b) => b !== 0))) throw new Error('PRF_not_consumed');
      },
      {
        prf: [...this.prf],
        credential: this.who.credential,
        root: JSON.stringify([{ issuer: ORIGIN, public_key: pub(this.server.issuer.publicKey) }]),
      },
    );
    return page;
  }
  async manager(page = this.page, phase?: EnrollmentPhase) {
    await page.evaluate(
      ({ id, phase }) => {
        globalThis.custodyDevice = new custodyModule.VaultMlsDevice(
          custodyOwner,
          custodyWasm,
          custodyRoot,
          id,
          {
            onPhase: async (p) => {
              if (p === phase) {
                await custodyReached(p);
                await new Promise(() => {});
              }
            },
          },
        );
      },
      { id: this.id, phase },
    );
  }
  async create() {
    await this.manager();
    await this.page.evaluate(() => custodyDevice.create());
  }
  async chat(offer?: InvitationOffer, limited = false) {
    await this.page.evaluate(
      async ({ offer, limited }) => {
        const style = document.createElement('link');
        style.rel = 'stylesheet';
        style.href = '/chat.css';
        document.head.append(style);
        const root = document.createElement('main');
        document.body.replaceChildren(root);
        globalThis.custodyChat = new custodyModule.MlsChatView(
          root,
          custodyDevice,
          offer,
          false,
          undefined,
          limited,
        );
        await custodyChat.open();
      },
      { offer, limited },
    );
  }
  async open() {
    await this.manager();
    await this.page.evaluate(() => custodyDevice.open());
  }
  async restart() {
    await this.page.close();
    this.page = await this.newPage();
  }
  phase(phase: EnrollmentPhase) {
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`phase_timeout_${phase}`)), 15_000);
      this.reached = (p) => {
        if (p === phase) {
          clearTimeout(timer);
          this.reached = undefined;
          resolve();
        }
      };
    });
  }
  async run(command: Command, page = this.page, id: string = randomUUID()) {
    const receipt = await page.evaluate(({ command, id }) => custodyDevice.request(id, command), {
      command,
      id,
    });
    assert.equal(receipt.ok, true, receipt.error ?? 'device command failed');
    return receipt;
  }
  box(page = this.page) {
    return page.evaluate(() => custodyDevice.outbox());
  }
  approve(route: DeliveryChannel) {
    return this.page.evaluate((route) => custodyDevice.approveDelivery(route), route);
  }
  sync(route: DeliveryChannel) {
    return this.page.evaluate((route) => custodyDevice.syncDelivery(route), route);
  }
  approveInvite(offer: InvitationOffer) {
    return this.page.evaluate((o) => custodyDevice.approveInvitation(o), offer);
  }
  syncInvite(offer: InvitationOffer) {
    return this.page.evaluate((o) => custodyDevice.syncInvitation(o), offer);
  }
  stop(offer: InvitationOffer, reason: CloseReason) {
    return this.page.evaluate(
      ({ offer, reason }) => custodyDevice.closeConversation(offer, reason),
      { offer, reason },
    );
  }
  recovery(offer: InvitationOffer) {
    return this.page.evaluate((offer) => custodyDevice.recoveryStatus(offer), offer);
  }
  approveRejoin(previous: InvitationOffer, next: InvitationOffer) {
    return this.page.evaluate(({ previous, next }) => custodyDevice.approveRejoin(previous, next), {
      previous,
      next,
    });
  }
  syncRejoin(previous: InvitationOffer, next: InvitationOffer) {
    return this.page.evaluate(({ previous, next }) => custodyDevice.syncRejoin(previous, next), {
      previous,
      next,
    });
  }
  async abortCommand(kind: Command['kind']) {
    await this.page.evaluate((kind) => {
      const original = custodyModule.PersistentMlsDevice.prototype.request;
      let armed = false,
        used = false;
      custodyModule.PersistentMlsDevice.prototype.request = function (
        ...args: Parameters<typeof original>
      ) {
        if (!used && args[1].kind === kind) {
          armed = true;
          used = true;
        }
        return original.apply(this, args);
      };
      const transaction = IDBDatabase.prototype.transaction;
      IDBDatabase.prototype.transaction = function (...args: Parameters<typeof transaction>) {
        const tx = transaction.apply(this, args);
        if (armed && this.name === 'mikaki-mls-device-v1' && args[1] === 'readwrite') {
          armed = false;
          queueMicrotask(() => tx.abort());
        }
        return tx;
      };
    }, kind);
  }
  async close() {
    await this.context.close();
    this.prf.fill(0);
  }
}
// Whole-record inspection/corruption stays in the test harness; the manager has
// no public raw key, engine, checkpoint or diagnostic database export.
export async function stored(
  page: Page,
  replacement?: unknown,
  dropJournal = false,
): Promise<unknown> {
  return page.evaluate(
    async ({ replacement, dropJournal }) => {
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const r = indexedDB.open('mikaki-mls-custody-v1');
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      });
      try {
        return await new Promise((resolve, reject) => {
          const tx = db.transaction(
              'devices',
              replacement === undefined ? 'readonly' : 'readwrite',
            ),
            s = tx.objectStore('devices'),
            keys = s.getAllKeys();
          let value: unknown;
          keys.onsuccess = () => {
            if (keys.result.length !== 1) {
              tx.abort();
              return;
            }
            if (replacement !== undefined) s.put(replacement, keys.result[0]);
            else {
              const r = s.get(keys.result[0]);
              r.onsuccess = () => {
                value = r.result;
              };
            }
          };
          tx.onabort = () => reject(new Error('fixture_storage_failed'));
          tx.oncomplete = () => resolve(value);
        });
      } finally {
        db.close();
        if (dropJournal)
          await new Promise<void>((resolve, reject) => {
            const r = indexedDB.deleteDatabase('mikaki-mls-device-v1');
            r.onsuccess = () => resolve();
            r.onerror = () => reject(r.error);
            r.onblocked = () => reject(new Error('fixture_delete_blocked'));
          });
      }
    },
    { replacement, dropJournal },
  );
}
export async function trust(a: Client, b: Client) {
  const ownA = await a.server.response<{ binding: string }>(
      await a.server.request(`/messaging/devices/${a.id}/binding`, 'GET', undefined, a.who),
    ),
    ownB = await b.server.response<{ binding: string }>(
      await b.server.request(`/messaging/devices/${b.id}/binding`, 'GET', undefined, b.who),
    );
  const ar = (await stored(a.page)) as { scope: { fingerprint: string } },
    br = (await stored(b.page)) as { scope: { fingerprint: string } };
  await a.run({ kind: 'confirm_peer', token: ownB.binding, fingerprint: br.scope.fingerprint });
  await b.run({ kind: 'confirm_peer', token: ownA.binding, fingerprint: ar.scope.fingerprint });
}
export async function join(a: Client, b: Client) {
  await trust(a, b);
  await b.run({ kind: 'key_package' });
  const kp = (await b.box()).ready[0],
    group = Array<number>(16).fill(8);
  await a.run({ kind: 'create_group', group });
  await a.run({ kind: 'invite', key_package: kp.wire });
  const commit = (await a.box()).ready[0];
  await a.run({ kind: 'acknowledge', message_id: commit.id, digest: commit.digest });
  await a.run({ kind: 'merge_pending', commit_id: commit.id });
  const welcome = (await a.box()).ready[0];
  await b.run({ kind: 'join', welcome: welcome.wire, group });
  await a.run({ kind: 'acknowledge', message_id: welcome.id, digest: welcome.digest });
  await b.run({ kind: 'acknowledge', message_id: kp.id, digest: kp.digest });
}
export async function descriptor(a: Client, b: Client): Promise<DeliveryChannel> {
  const endpoints = await Promise.all(
    [a, b].map(async (c) => {
      const row = await c.server.env.DB.prepare(
        "SELECT scope_hash AS scope,fingerprint FROM messaging_generation WHERE device_id=? AND status='active'",
      )
        .bind(c.id)
        .first<{ scope: string; fingerprint: string }>();
      assert.ok(row);
      return row;
    }),
  );
  endpoints.sort((a, b) => (a.scope < b.scope ? -1 : 1));
  const route: DeliveryChannel = {
    id: randomUUID(),
    group: Buffer.alloc(16, 8).toString('base64url'),
    a: endpoints[0],
    b: endpoints[1],
  };
  return route;
}
export async function delivery(a: Client, b: Client): Promise<DeliveryChannel> {
  const route = await descriptor(a, b);
  assert.equal(await a.approve(route), false);
  assert.equal(await b.approve(route), true);
  return route;
}
export async function invitation(a: Client, b: Client): Promise<InvitationOffer> {
  const route = await descriptor(a, b);
  const own = await a.server.env.DB.prepare(
    "SELECT scope_hash FROM messaging_generation WHERE device_id=? AND status='active'",
  )
    .bind(a.id)
    .first<{ scope_hash: string }>();
  assert.ok(own);
  const offer = { channel: route, inviter_scope: own.scope_hash };
  assert.equal(await a.approveInvite(offer), false);
  assert.equal(await b.approveInvite(offer), true);
  return offer;
}
export function successor(offer: InvitationOffer, flip = false): InvitationOffer {
  return {
    channel: { ...offer.channel, id: randomUUID(), group: randomBytes(16).toString('base64url') },
    inviter_scope: flip
      ? offer.inviter_scope === offer.channel.a.scope
        ? offer.channel.b.scope
        : offer.channel.a.scope
      : offer.inviter_scope,
  };
}
export async function admit(a: Client, b: Client): Promise<InvitationOffer> {
  await trust(a, b);
  const offer = await invitation(a, b);
  await b.syncInvite(offer);
  await a.syncInvite(offer);
  assert.equal((await b.syncInvite(offer)).phase, 'active');
  assert.equal((await a.syncInvite(offer)).phase, 'active');
  return offer;
}
