import { qualificationTimeout } from './test-timeout.ts';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { before, test } from 'node:test';
import { chromium, firefox, webkit, type Page } from '@playwright/test';
import { build } from 'esbuild';
import type {
  Command,
  DeviceEngine,
  DeviceModule,
  DeviceScope,
  PersistentMlsDevice,
} from './device-store.js';
import type { AuthenticatedHeadWitness } from './http-witness.js';
import { fixture, ORIGIN, pub, type Challenge } from './server-support.ts';

type Module = DeviceModule & {
  default(): Promise<unknown>;
  BoundMlsClient: {
    new (
      identity: string,
      authorities: string,
    ): DeviceEngine & {
      public_key(): Uint8Array;
      registration_proof(nonce: string, now: bigint): string;
    };
  };
};
declare global {
  var enrollmentModule: Module;
  var enrollmentRaw: InstanceType<Module['BoundMlsClient']>;
  var enrollmentJournal: PersistentMlsDevice;
  var enrollmentScope: DeviceScope;
  var enrollmentBinding: string;
  var enrollmentRoot: string;
}
let store: string, witness: string;
before(async () => {
  [store, witness] = await Promise.all(
    ['device-store', 'http-witness'].map(
      async (name) =>
        (
          await build({
            entryPoints: [new URL(`./${name}.ts`, import.meta.url).pathname],
            write: false,
            bundle: true,
            format: 'esm',
            target: 'es2022',
          })
        ).outputFiles[0].text,
    ),
  );
});
async function modules(page: Page) {
  await page.goto(ORIGIN);
  await page.evaluate(async () => {
    globalThis.enrollmentModule = (await import('/probe.js' as string)) as Module;
    await enrollmentModule.default();
  });
}
async function attach(page: Page, scope: DeviceScope, key: number[], root: string) {
  await page.evaluate(
    async ({ scope, key, root }) => {
      const { PersistentMlsDevice } = (await import('/device-store.js' as string)) as {
        PersistentMlsDevice: typeof import('./device-store.js').PersistentMlsDevice;
      };
      const { AuthenticatedHeadWitness } = (await import('/http-witness.js' as string)) as {
        AuthenticatedHeadWitness: typeof import('./http-witness.js').AuthenticatedHeadWitness;
      };
      const raw = Uint8Array.from(key);
      try {
        const custody = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [
          'encrypt',
          'decrypt',
        ]);
        globalThis.enrollmentScope = scope;
        globalThis.enrollmentRoot = root;
        globalThis.enrollmentJournal = new PersistentMlsDevice(
          scope,
          custody,
          enrollmentModule,
          root,
          new AuthenticatedHeadWitness(),
        );
      } finally {
        raw.fill(0);
        key.fill(0);
      }
    },
    { scope, key: [...key], root },
  );
}
async function register(page: Page, key: number[], root: string) {
  const challenge = await page.evaluate(async (root) => {
    const send = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
      const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
      });
      if (response.status !== 200) throw new Error(`registration_http_${response.status}`);
      return response.json();
    };
    const account = (await send('/messaging/account', {})) as {
      issuer: string;
      account_id: string;
    };
    const identity = { ...account, device_id: crypto.randomUUID(), generation: 1 };
    globalThis.enrollmentRaw = new enrollmentModule.BoundMlsClient(JSON.stringify(identity), root);
    const bytes = enrollmentRaw.public_key();
    const publicKey = btoa(String.fromCharCode(...bytes))
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replaceAll('=', '');
    const c = (await send(
      '/messaging/enrollments',
      {
        device_id: identity.device_id,
        public_key: publicKey,
        storage_id: crypto.randomUUID(),
        key_id: crypto.randomUUID(),
        expected_revision: 0,
      },
      { 'X-Operation-ID': crypto.randomUUID() },
    )) as Challenge;
    if (JSON.stringify(c.device) !== JSON.stringify(identity)) {
      for (const name of ['issuer', 'account_id', 'device_id', 'generation'] as const)
        if (c.device[name] !== identity[name]) throw new Error('registered_identity_mismatch');
    }
    if (c.scope.fingerprint !== enrollmentRaw.fingerprint())
      throw new Error('registration_fingerprint_mismatch');
    const proof = enrollmentRaw.registration_proof(c.nonce, BigInt(Math.floor(Date.now() / 1000)));
    const result = (await send(`/messaging/enrollments/${c.enrollment_id}/complete`, {
      proof,
    })) as { binding: string };
    enrollmentRaw.bind_self(result.binding, BigInt(Math.floor(Date.now() / 1000)));
    globalThis.enrollmentBinding = result.binding;
    return c;
  }, root);
  await attach(page, challenge.scope, key, root);
  await page.evaluate(async () => {
    const raw = enrollmentRaw.checkpoint();
    try {
      await enrollmentJournal.bootstrap(raw);
    } finally {
      raw.fill(0);
      enrollmentRaw.free();
    }
  });
  return { scope: challenge.scope, token: await page.evaluate(() => enrollmentBinding) };
}
async function run(page: Page, command: Command, id: string = randomUUID()) {
  const receipt = await page.evaluate(
    ({ command, id }) => enrollmentJournal.request(id, command, Math.floor(Date.now() / 1000)),
    { command, id },
  );
  assert.equal(receipt.ok, true, receipt.error ?? 'journal command failed');
  return receipt;
}
const box = (page: Page) =>
  page.evaluate(() => enrollmentJournal.outbox(Math.floor(Date.now() / 1000)));
async function ack(page: Page, message: { id: string; digest: string }) {
  await run(page, { kind: 'acknowledge', message_id: message.id, digest: message.digest });
}
const browserTypes = { chromium, firefox, webkit };
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const browserType = browserTypes[name as keyof typeof browserTypes];
  if (!browserType) throw new Error(`Unsupported browser ${name}`);
  test(
    `${name}: real Wasm device proofs and encrypted journal use authenticated Rust/workerd registry and witness`,
    { timeout: qualificationTimeout(90_000) },
    async () => {
      const f = await fixture(),
        browser = await browserType.launch();
      try {
        const root = JSON.stringify([{ issuer: ORIGIN, public_key: pub(f.issuer.publicKey) }]);
        const script = await readFile(new URL('./pkg-web/mikaki_mls_probe.js', import.meta.url)),
          wasm = await readFile(new URL('./pkg-web/mikaki_mls_probe_bg.wasm', import.meta.url));
        let loseNextCas = false;
        async function context(who: typeof f.a) {
          const context = await browser.newContext();
          await context.addCookies([
            {
              name: '__Host-op-sso',
              value: who.secret,
              url: ORIGIN,
              httpOnly: true,
              secure: true,
              sameSite: 'Strict',
            },
          ]);
          await context.route(`${ORIGIN}/**`, async (route) => {
            const request = route.request(),
              path = new URL(request.url()).pathname;
            if (path.startsWith('/messaging/')) {
              // Browser cookies/Origin reach the actual Rust handler. The bridge
              // serves a test origin; it supplies no actor or authorization facts.
              const headers = await request.allHeaders();
              // WebKit's interception hook can precede Cookie header attachment.
              // Forward only cookies actually present in this browser's jar.
              if (!headers.cookie) {
                const cookies = await context.cookies(request.url());
                assert.equal(
                  cookies.some((c) => c.name === '__Host-op-sso'),
                  true,
                );
                headers.cookie = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
              }
              const response = await f.worker.fetch(request.url(), {
                method: request.method(),
                headers,
                ...(request.postData() === null ? {} : { body: request.postData()! }),
              });
              if (
                loseNextCas &&
                request.method() === 'PUT' &&
                path.startsWith('/messaging/heads/')
              ) {
                loseNextCas = false;
                assert.equal(response.status, 200);
                await route.abort('failed');
                return;
              }
              await route.fulfill({
                status: response.status,
                headers: Object.fromEntries(response.headers),
                body: Buffer.from(await response.arrayBuffer()),
              });
              return;
            }
            const asset =
              path === '/'
                ? {
                    body: '<!doctype html><title>Authenticated MLS storage qualification</title>',
                    contentType: 'text/html',
                  }
                : path === '/probe.js'
                  ? { body: script, contentType: 'text/javascript' }
                  : path === '/mikaki_mls_probe_bg.wasm'
                    ? { body: wasm, contentType: 'application/wasm' }
                    : path === '/device-store.js'
                      ? { body: store, contentType: 'text/javascript' }
                      : path === '/http-witness.js'
                        ? { body: witness, contentType: 'text/javascript' }
                        : null;
            if (asset) await route.fulfill({ status: 200, ...asset });
            else await route.fulfill({ status: 404, body: '' });
          });
          return context;
        }
        const ac = await context(f.a),
          bc = await context(f.b),
          a = await ac.newPage(),
          b = await bc.newPage();
        const aKey = [...randomBytes(32)],
          bKey = [...randomBytes(32)];
        await modules(a);
        await modules(b);
        const ai = await register(a, aKey, root),
          bi = await register(b, bKey, root);
        assert.notEqual(ai.scope.device.account_id, bi.scope.device.account_id);
        await run(a, { kind: 'confirm_peer', token: bi.token, fingerprint: bi.scope.fingerprint });
        await run(b, { kind: 'confirm_peer', token: ai.token, fingerprint: ai.scope.fingerprint });
        await run(b, { kind: 'key_package' });
        const kp = (await box(b)).ready[0];
        const group = Array<number>(16).fill(3);
        await run(a, { kind: 'create_group', group });
        await run(a, { kind: 'invite', key_package: kp.wire });
        const pending = await box(a);
        assert.equal(pending.waiting.length, 1);
        const commit = pending.ready[0];
        await ack(a, commit);
        await run(a, { kind: 'merge_pending', commit_id: commit.id });
        const welcome = (await box(a)).ready[0];
        await run(b, { kind: 'join', welcome: welcome.wire, group });
        await ack(a, welcome);
        await ack(b, kp);
        // CAS response loss after the actual D1 commit. No journal receipt/wire
        // escapes; restart restores only the encrypted IDB record plus test custody.
        const operation = randomUUID(),
          command: Command = { kind: 'send', text: '認証付きの保存境界を越える秘密の本文' };
        loseNextCas = true;
        await assert.rejects(run(a, command, operation), /fetch|network|Network|Failed|Load/i);
        const before = await f.env.DB.prepare(
          'SELECT head_revision,head_hash FROM messaging_generation WHERE device_id=?',
        )
          .bind(ai.scope.device.device_id)
          .first();
        await modules(a);
        await attach(a, ai.scope, aKey, root);
        await run(a, command, operation);
        const after = await f.env.DB.prepare(
          'SELECT head_revision,head_hash FROM messaging_generation WHERE device_id=?',
        )
          .bind(ai.scope.device.device_id)
          .first();
        assert.deepEqual(after, before);
        const message = (await box(a)).ready[0];
        await run(b, { kind: 'receive', message_id: message.id, wire: message.wire });
        await run(b, { kind: 'receive', message_id: message.id, wire: message.wire });
        const inbox = await b.evaluate(() => enrollmentJournal.inbox());
        assert.equal(inbox.length, 1);
        assert.ok(JSON.stringify(inbox).includes(command.text));
        assert.equal(
          JSON.stringify(
            await f.env.DB.prepare('SELECT * FROM messaging_generation').all(),
          ).includes(command.text),
          false,
        );
        await assert.rejects(
          a.evaluate(async () => {
            const { AuthenticatedHeadWitness } = (await import('/http-witness.js' as string)) as {
              AuthenticatedHeadWitness: new (origin?: string) => AuthenticatedHeadWitness;
            };
            new AuthenticatedHeadWitness('https://other.test');
          }),
          /witness_origin_mismatch/,
        );
        // Owner revocation closes the old witness scope and fresh registry leases
        // stop release of already queued ciphertext on the other device.
        const revoked = await f.response<{ binding: string }>(
          await f.request(
            `/messaging/devices/${bi.scope.device.device_id}/revoke`,
            'POST',
            { expected_revision: 1 },
            f.b,
          ),
        );
        await run(a, { kind: 'observe_binding', token: revoked.binding });
        assert.equal((await box(a)).ready.length, 0);
        assert.equal((await box(a)).blocked[0].id, message.id);
        await assert.rejects(box(b), /witness_scope_missing/);
        await b.evaluate(() => enrollmentJournal.close());
        await assert.rejects(box(b), /device_locked/);
        await ac.close();
        await bc.close();
      } finally {
        await browser.close();
        await f.close();
      }
    },
  );
}
