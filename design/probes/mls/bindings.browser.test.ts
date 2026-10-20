import assert from 'node:assert/strict';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, test } from 'node:test';
import { chromium, firefox, webkit, type Browser, type Page } from '@playwright/test';

type Identity = { issuer: string; account_id: string; device_id: string; generation: number };
interface BoundClient {
  public_key(): Uint8Array;
  fingerprint(): string;
  registration_proof(nonce: string, now: bigint): string;
  bind_self(token: string, now: bigint): void;
  confirm_peer(token: string, fingerprint: string, now: bigint): void;
  observe_binding(token: string, now: bigint): string;
  accept_key_change(token: string, old: string, replacement: string, now: bigint): void;
  key_package(now: bigint): Uint8Array;
  create_group(id: Uint8Array, now: bigint): void;
  invite(packageBytes: Uint8Array, now: bigint): string;
  join(welcome: Uint8Array, id: Uint8Array, now: bigint): void;
  send(text: string, now: bigint): Uint8Array;
  receive(message: Uint8Array, now: bigint): string;
  remove_peer(now: bigint): Uint8Array;
  merge_pending(now: bigint): void;
  checkpoint(): Uint8Array;
  free(): void;
}
interface BoundModule {
  default(): Promise<unknown>;
  BoundMlsClient: {
    new (identity: string, authorities: string): BoundClient;
    restore(bytes: Uint8Array, authorities: string): BoundClient;
  };
  MlsProbeClient: {
    new (identity: string): {
      key_package(): Uint8Array;
      create_group(id: Uint8Array): void;
      invite(bytes: Uint8Array): string;
      free(): void;
    };
  };
}
declare global {
  var boundMlsModule: BoundModule;
  var boundMlsClient: BoundClient;
}

const NOW = 1_000;
const group = Array<number>(16).fill(1);
const server = createServer(async (request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  if (request.url === '/') {
    response
      .writeHead(200, { 'Content-Type': 'text/html' })
      .end('<!doctype html><title>Device trust qualification</title>');
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
    const bytes = await readFile(new URL(`./pkg-web/${file}`, import.meta.url));
    response
      .writeHead(200, {
        'Content-Type': file.endsWith('.wasm') ? 'application/wasm' : 'text/javascript',
      })
      .end(bytes);
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

const identity = (issuer: string, n: number, generation = 1): Identity => ({
  issuer,
  account_id: `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`,
  device_id: `10000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`,
  generation,
});

// This independent Node issuer is a qualification fixture. Its predetermined
// owner/challenge context stands in for the future authenticated SSO adapter.
// Neither authority private keys nor enrollment requests enter the static server.
class Issuer {
  readonly issuer: string;
  readonly keys = generateKeyPairSync('ed25519');
  constructor(issuer: string) {
    this.issuer = issuer;
  }
  authority() {
    return { issuer: this.issuer, public_key: this.keys.publicKey.export({ format: 'jwk' }).x! };
  }
  binding(device: Identity, publicKey: string, revision = 1, status = 'active') {
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
      public_key: publicKey,
      revision,
      status,
      iat: NOW,
      exp: NOW + 300,
    };
    const input = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
    return `${input}.${sign(null, Buffer.from(input), this.keys.privateKey).toString('base64url')}`;
  }
  async enroll(page: Page, expected: Identity) {
    const nonce = randomBytes(32).toString('base64url');
    const proof = await page.evaluate(
      ({ nonce, now }) => boundMlsClient.registration_proof(nonce, BigInt(now)),
      { nonce, now: NOW },
    );
    const parts = proof.split('.');
    assert.equal(parts.length, 3);
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    assert.deepEqual(header, {
      typ: 'mikaki-device-registration+jwt',
      alg: 'EdDSA',
      kid: createHash('sha256')
        .update(Buffer.from(claims.public_key, 'base64url'))
        .digest('base64url'),
    });
    assert.deepEqual(claims.device, expected);
    assert.equal(expected.issuer, this.issuer);
    assert.equal(claims.aud, this.issuer);
    assert.equal(claims.nonce, nonce);
    assert.equal(claims.iat, NOW);
    assert.equal(claims.exp, NOW + 60);
    const publicKey = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: claims.public_key },
      format: 'jwk',
    });
    assert.equal(
      verify(
        null,
        Buffer.from(`${parts[0]}.${parts[1]}`),
        publicKey,
        Buffer.from(parts[2], 'base64url'),
      ),
      true,
    );
    return this.binding(expected, claims.public_key);
  }
}

async function device(browser: Browser, id: Identity, authorities: string) {
  const page = await browser.newPage();
  await page.goto(origin);
  await page.evaluate(
    async ({ id, authorities }) => {
      globalThis.boundMlsModule = (await import('/probe.js' as string)) as BoundModule;
      await boundMlsModule.default();
      globalThis.boundMlsClient = new boundMlsModule.BoundMlsClient(
        JSON.stringify(id),
        authorities,
      );
    },
    { id, authorities },
  );
  return page;
}
async function restart(page: Page, authorities: string) {
  const state = await page.evaluate(() => {
    const bytes = boundMlsClient.checkpoint();
    try {
      return Array.from(bytes);
    } finally {
      bytes.fill(0);
      boundMlsClient.free();
    }
  });
  try {
    await page.reload();
    await page.evaluate(
      async ({ state, authorities }) => {
        globalThis.boundMlsModule = (await import('/probe.js' as string)) as BoundModule;
        await boundMlsModule.default();
        const bytes = Uint8Array.from(state);
        try {
          globalThis.boundMlsClient = boundMlsModule.BoundMlsClient.restore(bytes, authorities);
        } finally {
          bytes.fill(0);
          state.fill(0);
        }
      },
      { state, authorities },
    );
  } finally {
    state.fill(0);
  }
}
async function exchange(alice: Page, bob: Page) {
  const message = await alice.evaluate(() =>
    Array.from(boundMlsClient.send('確認済みの端末', 1000n)),
  );
  return bob.evaluate(
    (message) => JSON.parse(boundMlsClient.receive(Uint8Array.from(message), 1000n)) as unknown,
    message,
  );
}
async function pair(browser: Browser) {
  const a = new Issuer('https://alice.example');
  const b = new Issuer('https://bob.example');
  const aId = identity(a.issuer, 1);
  const bId = identity(b.issuer, 2);
  const authorities = JSON.stringify([a.authority(), b.authority()]);
  const alice = await device(browser, aId, authorities);
  const bob = await device(browser, bId, authorities);
  const aToken = await a.enroll(alice, aId);
  const bToken = await b.enroll(bob, bId);
  await alice.evaluate((token) => boundMlsClient.bind_self(token, 1000n), aToken);
  await bob.evaluate((token) => boundMlsClient.bind_self(token, 1000n), bToken);
  // Read each device's fingerprint independently of its issuer's token.
  const aFingerprint = await alice.evaluate(() => boundMlsClient.fingerprint());
  const bFingerprint = await bob.evaluate(() => boundMlsClient.fingerprint());
  for (const [id, token, fingerprint] of [
    [aId, aToken, aFingerprint],
    [bId, bToken, bFingerprint],
  ] as const) {
    const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    const expected = createHash('sha256')
      .update(JSON.stringify(['mikaki-device-fingerprint-v1', id, 'Ed25519', claims.public_key]))
      .digest('base64url');
    assert.equal(fingerprint, expected, 'Node and Wasm agree on the invitation fingerprint');
  }
  await alice.evaluate(
    ({ token, fingerprint }) => boundMlsClient.confirm_peer(token, fingerprint, 1000n),
    { token: bToken, fingerprint: bFingerprint },
  );
  await bob.evaluate(
    ({ token, fingerprint }) => boundMlsClient.confirm_peer(token, fingerprint, 1000n),
    { token: aToken, fingerprint: aFingerprint },
  );
  return { a, b, aId, bId, alice, bob, aToken, bToken, aFingerprint, bFingerprint, authorities };
}
async function join(alice: Page, bob: Page) {
  const packageBytes = await bob.evaluate(() => Array.from(boundMlsClient.key_package(1000n)));
  const welcome = await alice.evaluate(
    ({ packageBytes, group }) => {
      boundMlsClient.create_group(Uint8Array.from(group), 1000n);
      const invitation = JSON.parse(
        boundMlsClient.invite(Uint8Array.from(packageBytes), 1000n),
      ) as { welcome: number[] };
      boundMlsClient.merge_pending(1000n);
      return invitation.welcome;
    },
    { packageBytes, group },
  );
  await bob.evaluate(
    ({ welcome, group }) =>
      boundMlsClient.join(Uint8Array.from(welcome), Uint8Array.from(group), 1000n),
    { welcome, group },
  );
}

const browserTypes = { chromium, firefox, webkit };
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  if (!(name in browserTypes)) throw new Error(`Unknown browser: ${name}`);
  const type = browserTypes[name as keyof typeof browserTypes];
  test(`${name}: issuer proof, pinned identity, substituted package/Welcome and revocation`, async () => {
    const browser = await type.launch({ headless: true });
    try {
      const p = await pair(browser);
      const packageBytes = await p.bob.evaluate(() =>
        Array.from(boundMlsClient.key_package(1000n)),
      );
      const rogue = await p.alice.evaluate(
        ({ aId, bId, group, packageBytes }) => {
          const impostor = new boundMlsModule.MlsProbeClient(JSON.stringify(bId));
          const packageBytesImpostor = Array.from(impostor.key_package());
          impostor.free();
          const creator = new boundMlsModule.MlsProbeClient(JSON.stringify(aId));
          creator.create_group(Uint8Array.from(group));
          const invitation = JSON.parse(creator.invite(Uint8Array.from(packageBytes))) as {
            welcome: number[];
          };
          creator.free();
          return { packageBytesImpostor, welcome: invitation.welcome };
        },
        { aId: p.aId, bId: p.bId, group, packageBytes },
      );
      await p.alice.evaluate(
        (group) => boundMlsClient.create_group(Uint8Array.from(group), 1000n),
        group,
      );
      assert.equal(
        await p.alice.evaluate((bytes) => {
          try {
            boundMlsClient.invite(Uint8Array.from(bytes), 1000n);
            return false;
          } catch {
            return true;
          }
        }, rogue.packageBytesImpostor),
        true,
      );
      assert.equal(
        await p.bob.evaluate(
          ({ welcome, group }) => {
            try {
              boundMlsClient.join(Uint8Array.from(welcome), Uint8Array.from(group), 1000n);
              return false;
            } catch {
              return true;
            }
          },
          { welcome: rogue.welcome, group },
        ),
        true,
      );
      const welcome = await p.alice.evaluate((bytes) => {
        const invitation = JSON.parse(boundMlsClient.invite(Uint8Array.from(bytes), 1000n)) as {
          welcome: number[];
        };
        boundMlsClient.merge_pending(1000n);
        return invitation.welcome;
      }, packageBytes);
      await p.bob.evaluate(
        ({ welcome, group }) =>
          boundMlsClient.join(Uint8Array.from(welcome), Uint8Array.from(group), 1000n),
        { welcome, group },
      );
      await restart(p.alice, p.authorities);
      assert.deepEqual(await exchange(p.alice, p.bob), {
        kind: 'application',
        sender: p.aId,
        text: '確認済みの端末',
      });
      const aKey = await p.alice.evaluate(() => Array.from(boundMlsClient.public_key()));
      const revoked = p.a.binding(p.aId, Buffer.from(aKey).toString('base64url'), 2, 'revoked');
      assert.equal(
        await p.bob.evaluate((token) => boundMlsClient.observe_binding(token, 1000n), revoked),
        'revoked',
      );
      await restart(p.bob, p.authorities);
      const message = await p.alice.evaluate(() =>
        Array.from(boundMlsClient.send('revoked sender', 1000n)),
      );
      assert.equal(
        await p.bob.evaluate((bytes) => {
          try {
            boundMlsClient.receive(Uint8Array.from(bytes), 1000n);
            return false;
          } catch {
            return true;
          }
        }, message),
        true,
      );
      await p.bob.evaluate(() => {
        boundMlsClient.remove_peer(1000n);
        boundMlsClient.merge_pending(1000n);
      });
    } finally {
      await browser.close();
    }
  });

  test(`${name}: signed key changes freeze old keys across reload and require exact review`, async () => {
    const browser = await type.launch({ headless: true });
    try {
      const p = await pair(browser);
      await join(p.alice, p.bob);
      const nextId = { ...p.bId, generation: 2 };
      const replacement = await device(browser, nextId, p.authorities);
      await p.b.enroll(replacement, nextId);
      const publicKey = await replacement.evaluate(() => Array.from(boundMlsClient.public_key()));
      const newFingerprint = await replacement.evaluate(() => boundMlsClient.fingerprint());
      const next = p.b.binding(nextId, Buffer.from(publicKey).toString('base64url'), 2);
      assert.equal(
        await p.alice.evaluate((token) => boundMlsClient.observe_binding(token, 1000n), next),
        'key_changed',
      );
      await restart(p.alice, p.authorities);
      assert.equal(
        await p.alice.evaluate((old) => {
          try {
            boundMlsClient.observe_binding(old, 1000n);
            return false;
          } catch {
            return true;
          }
        }, p.bToken),
        true,
      );
      assert.equal(
        await p.alice.evaluate(() => {
          try {
            boundMlsClient.send('pending review', 1000n);
            return false;
          } catch {
            return true;
          }
        }),
        true,
      );
      assert.equal(
        await p.alice.evaluate(
          ({ next, newFingerprint }) => {
            try {
              boundMlsClient.accept_key_change(
                next,
                'wrong-previous-fingerprint',
                newFingerprint,
                1000n,
              );
              return false;
            } catch {
              return true;
            }
          },
          { next, newFingerprint },
        ),
        true,
      );
      await p.alice.evaluate(
        ({ next, old, replacement }) =>
          boundMlsClient.accept_key_change(next, old, replacement, 1000n),
        { next, old: p.bFingerprint, replacement: newFingerprint },
      );
      const oldMessage = await p.bob.evaluate(() =>
        Array.from(boundMlsClient.send('retired key', 1000n)),
      );
      assert.equal(
        await p.alice.evaluate((bytes) => {
          try {
            boundMlsClient.receive(Uint8Array.from(bytes), 1000n);
            return false;
          } catch {
            return true;
          }
        }, oldMessage),
        true,
      );
      await replacement.evaluate(
        ({ next, peer, fingerprint }) => {
          boundMlsClient.bind_self(next, 1000n);
          boundMlsClient.confirm_peer(peer, fingerprint, 1000n);
        },
        { next, peer: p.aToken, fingerprint: p.aFingerprint },
      );
      await p.alice.evaluate(() => {
        boundMlsClient.remove_peer(1000n);
        boundMlsClient.merge_pending(1000n);
      });
      const packageBytes = await replacement.evaluate(() =>
        Array.from(boundMlsClient.key_package(1000n)),
      );
      const welcome = await p.alice.evaluate((bytes) => {
        const invitation = JSON.parse(boundMlsClient.invite(Uint8Array.from(bytes), 1000n)) as {
          welcome: number[];
        };
        boundMlsClient.merge_pending(1000n);
        return invitation.welcome;
      }, packageBytes);
      await replacement.evaluate(
        ({ welcome, group }) =>
          boundMlsClient.join(Uint8Array.from(welcome), Uint8Array.from(group), 1000n),
        { welcome, group },
      );
      assert.deepEqual(await exchange(p.alice, replacement), {
        kind: 'application',
        sender: p.aId,
        text: '確認済みの端末',
      });
    } finally {
      await browser.close();
    }
  });
}
