import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { after } from 'node:test';
import { createTestHarness } from 'wrangler';
import type { D1Database } from '@cloudflare/workers-types';
import type { DeviceIdentity, DeviceScope } from './device-store.js';

export const ORIGIN = 'https://messaging.test';
const activeHarnesses = new Set<ReturnType<typeof createTestHarness>>();
after(async () => {
  await Promise.all([...activeHarnesses].map((h) => h.close()));
});
export const keys = () => generateKeyPairSync('ed25519');
export const digest = (bytes: string | Buffer) =>
  createHash('sha256').update(bytes).digest('base64url');
export const pub = (key: KeyObject) => key.export({ format: 'jwk' }).x!;
export type Challenge = {
  enrollment_id: string;
  device: DeviceIdentity;
  nonce: string;
  expires_at: number;
  scope: DeviceScope;
};
export function proof(
  c: Challenge,
  k: ReturnType<typeof keys>,
  patch: Record<string, unknown> = {},
  headerPatch: Record<string, unknown> = {},
) {
  const now = Math.floor(Date.now() / 1000);
  const h = {
    typ: 'mikaki-device-registration+jwt',
    alg: 'EdDSA',
    kid: digest(Buffer.from(pub(k.publicKey), 'base64url')),
    ...headerPatch,
  };
  const claims = {
    aud: ORIGIN,
    device: c.device,
    public_key: pub(k.publicKey),
    nonce: c.nonce,
    iat: now,
    exp: now + 60,
    ...patch,
  };
  const input = `${Buffer.from(JSON.stringify(h)).toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}`;
  return `${input}.${sign(null, Buffer.from(input), k.privateKey).toString('base64url')}`;
}
export async function fixture() {
  const issuer = keys();
  const jwk = issuer.privateKey.export({ format: 'jwk' });
  const harness = createTestHarness({
    root: new URL('../../../', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('./server/wrangler.jsonc', import.meta.url).pathname,
        vars: {
          MESSAGING_ISSUER_KEY: JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d }),
        },
      },
    ],
  });
  activeHarnesses.add(harness);
  await harness.listen();
  const worker = harness.getWorker('mikaki-messaging-qualification');
  await worker.applyD1Migrations('DB');
  const env = (await worker.getEnv()) as { DB: D1Database };
  const schema = (
    await readFile(
      new URL('../../../crates/worker/messaging-migrations/0001_messaging.sql', import.meta.url),
      'utf8',
    )
  ).replace(/^--.*$/gm, '');
  await env.DB.batch(
    schema
      .split(';')
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => env.DB.prepare(s)),
  );
  await env.DB.exec(
    'CREATE TABLE fixture_messaging_fault(id INTEGER PRIMARY KEY,pattern TEXT,mode TEXT,account_id TEXT,remaining INTEGER) STRICT',
  );
  const seed = async (owner = randomBytes(32).toString('base64url')) => {
    const secret = randomBytes(32).toString('base64url'),
      credential = randomBytes(32).toString('base64url'),
      session = randomUUID();
    await env.DB.batch([
      env.DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(owner),
      env.DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(credential, owner),
      env.DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,unixepoch()+3600,0)').bind(
        session,
        owner,
        credential,
      ),
      env.DB.prepare('INSERT INTO sso_context VALUES(?,?,unixepoch())').bind(
        session,
        digest(secret),
      ),
    ]);
    return { owner, secret, credential, session };
  };
  const a = await seed(),
    b = await seed();
  async function request(
    path: string,
    method = 'GET',
    value?: unknown,
    who = a,
    headers: Record<string, string> = {},
  ) {
    return worker.fetch(`${ORIGIN}${path}`, {
      method,
      headers: {
        Cookie: `__Host-op-sso=${who.secret}`,
        Origin: ORIGIN,
        'Content-Type': 'application/json',
        ...headers,
      },
      ...(value === undefined
        ? {}
        : { body: typeof value === 'string' ? value : JSON.stringify(value) }),
    });
  }
  async function response<T>(
    response: Awaited<ReturnType<typeof request>>,
    status = 200,
  ): Promise<T> {
    assert.equal(response.status, status, await response.clone().text());
    assert.ok(response.headers.get('Cache-Control')?.includes('no-store'));
    return response.json() as Promise<T>;
  }
  async function start(
    k = keys(),
    device_id: string = randomUUID(),
    expected_revision = 0,
    who = a,
    operation: string = randomUUID(),
  ) {
    const payload = {
      device_id,
      public_key: pub(k.publicKey),
      storage_id: randomUUID(),
      key_id: randomUUID(),
      expected_revision,
    };
    const c = await response<Challenge>(
      await request('/messaging/enrollments', 'POST', payload, who, {
        'X-Operation-ID': operation,
      }),
    );
    return { k, c, payload, operation, who };
  }
  async function complete(
    d: Awaited<ReturnType<typeof start>>,
    signed = proof(d.c, d.k),
    status = 200,
  ) {
    return response<{ binding: string }>(
      await request(
        `/messaging/enrollments/${d.c.enrollment_id}/complete`,
        'POST',
        { proof: signed },
        d.who,
      ),
      status,
    );
  }
  function binding(token: string) {
    const [header, claims, signature] = token.split('.');
    assert.equal(
      verify(
        null,
        Buffer.from(`${header}.${claims}`),
        issuer.publicKey,
        Buffer.from(signature, 'base64url'),
      ),
      true,
    );
    assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url').toString()), {
      typ: 'mikaki-device-binding+jwt',
      alg: 'EdDSA',
      kid: digest(Buffer.from(pub(issuer.publicKey), 'base64url')),
    });
    return JSON.parse(Buffer.from(claims, 'base64url').toString()) as {
      device: DeviceIdentity;
      public_key: string;
      revision: number;
      status: string;
      iat: number;
      exp: number;
    };
  }
  const scope = (c: Challenge) =>
    digest(
      JSON.stringify([
        'mikaki-mls-device-state-v1',
        ORIGIN,
        ORIGIN,
        c.device.account_id,
        c.device.device_id,
        c.device.generation,
        c.scope.storage_id,
        c.scope.key_id,
        c.scope.fingerprint,
      ]),
    );
  return {
    harness,
    worker,
    env,
    a,
    b,
    seed,
    request,
    response,
    start,
    complete,
    binding,
    scope,
    issuer,
    close: async () => {
      await harness.close();
      activeHarnesses.delete(harness);
    },
  };
}
