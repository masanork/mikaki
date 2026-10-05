import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createECDH, createHash, randomBytes } from 'node:crypto';
import { createTestHarness } from 'wrangler';
import { chromium } from '@playwright/test';

const origin = 'https://mikaki.test';
const id = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');

function registration(credential: Buffer, challenge: string) {
  const key = createECDH('prime256v1');
  key.generateKeys();
  const pub = key.getPublicKey();
  const cose = Buffer.concat([
    Buffer.from('a5010203262001215820', 'hex'),
    pub.subarray(1, 33),
    Buffer.from('225820', 'hex'),
    pub.subarray(33),
  ]);
  const auth = Buffer.concat([
    createHash('sha256').update('mikaki.test').digest(),
    Buffer.from('4500000000', 'hex'),
    Buffer.alloc(16),
    Buffer.from([0, credential.length]),
    credential,
    cose,
  ]);
  const attestation = Buffer.concat([
    Buffer.from('a363666d74646e6f6e656761747453746d74a068617574684461746158', 'hex'),
    Buffer.from([auth.length]),
    auth,
  ]);
  return {
    id: credential.toString('base64url'),
    client_data: Buffer.from(
      JSON.stringify({ type: 'webauthn.create', challenge, origin }),
    ).toString('base64url'),
    attestation: attestation.toString('base64url'),
  };
}

test('same-account passkey registration enforces origin, freshness, replay, lockout, and idempotent retries', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        secrets: { MIKAKI_ISSUER: origin },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const env = await worker.getEnv();
    const source = randomBytes(32),
      target = randomBytes(32),
      outside = randomBytes(32);
    const sourcePrf = new Uint8Array(32).fill(0x23),
      targetPrf = new Uint8Array(32).fill(0x45);
    const secret = id(),
      time = Math.floor(Date.now() / 1000);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      env.DB.prepare("INSERT INTO account_security VALUES('outside',1,1)"),
      env.DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(
        source.toString('base64url'),
      ),
      env.DB.prepare("INSERT INTO credential VALUES(?,'outside',1)").bind(
        outside.toString('base64url'),
      ),
      env.DB.prepare(
        "INSERT INTO passkey_credential VALUES(?,'synthetic-public-key',?,0,0,0,1)",
      ).bind(source.toString('base64url'), id()),
      env.DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(
        source.toString('base64url'),
        time + 3600,
      ),
      env.DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(hash(secret), time),
    ]);
    const headers = {
      Cookie: `__Host-op-sso=${secret}`,
      Origin: origin,
      'Content-Type': 'application/json',
    };
    const start = () => worker.fetch(`${origin}/vault/passkeys/start`, { method: 'POST', headers });
    assert.equal((await worker.fetch(`${origin}/vault/passkeys`)).status, 401);
    assert.equal(
      (
        await worker.fetch(`${origin}/vault/passkeys/start`, {
          method: 'POST',
          headers: { ...headers, Origin: 'https://evil.test' },
        })
      ).status,
      403,
    );
    await env.DB.prepare("UPDATE sso_context SET auth_time=? WHERE sso_id='session'")
      .bind(time - 301)
      .run();
    assert.equal((await start()).status, 403);
    await env.DB.prepare("UPDATE sso_context SET auth_time=? WHERE sso_id='session'")
      .bind(time)
      .run();
    const started = await start();
    assert.equal(started.status, 200, await started.clone().text());
    const options = (await started.json()) as { transaction_id: string; challenge: string };
    const response = registration(target, options.challenge);
    const body = JSON.stringify({ transaction_id: options.transaction_id, response });
    const finish = (content = body) =>
      worker.fetch(`${origin}/vault/passkeys/finish`, { method: 'POST', headers, body: content });
    assert.equal((await finish()).status, 200);
    assert.equal((await finish()).status, 200);
    assert.equal(
      (
        await finish(
          JSON.stringify({
            transaction_id: options.transaction_id,
            response: registration(target, options.challenge),
          }),
        )
      ).status,
      409,
    );
    assert.equal(
      (
        await env.DB.prepare('SELECT count(*) AS n FROM credential WHERE account_id=?')
          .bind('owner')
          .first()
      ).n,
      2,
    );
    const failed = await start();
    const failureOptions = (await failed.json()) as typeof options;
    const bad = JSON.stringify({
      transaction_id: failureOptions.transaction_id,
      response: registration(randomBytes(32), id()),
    });
    for (let i = 0; i < 5; i++) assert.equal((await finish(bad)).status, 401);
    assert.equal((await finish(bad)).status, 400);
  } finally {
    await harness.close();
  }
});
