import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createTestHarness } from 'wrangler';

const root = fileURLToPath(new URL('../..', import.meta.url));
const opConfig = fileURLToPath(
  new URL('../../crates/worker/wrangler.recipient-local.jsonc', import.meta.url),
);
const claimsConfig = fileURLToPath(
  new URL('../../crates/userinfo-claim-worker/wrangler.local.jsonc', import.meta.url),
);
const verifierMockConfig = fileURLToPath(
  new URL('wrangler.recipient-verifier-mock.jsonc', import.meta.url),
);

test('owner recipient directory fails closed through claim Worker binding', async () => {
  const harness = createTestHarness({
    root,
    workers: [{ configPath: opConfig }, { configPath: claimsConfig }],
  });
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-worker');
    const claims = harness.getWorker('mikaki-userinfo-claim-worker');
    await op.applyD1Migrations('DB');
    await claims.applyD1Migrations('DB');
    const env = await op.getEnv();
    const secret = randomBytes(32).toString('base64url');
    const cookieHash = createHash('sha256').update(secret).digest('base64url');
    const future = Math.floor(Date.now() / 1000) + 3600;
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      env.DB.prepare("INSERT INTO credential VALUES('credential','owner',1)"),
      env.DB.prepare("INSERT INTO sso_session VALUES('session','owner','credential',1,?,0)").bind(
        future,
      ),
      env.DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
        cookieHash,
        future - 3600,
      ),
    ]);
    const url = 'https://mikaki.test/vault/recipient-keys/userinfo';
    assert.equal((await op.fetch(url)).status, 401);
    const headers = { Cookie: `__Host-op-sso=${secret}` };
    assert.equal((await op.fetch(url, { headers })).status, 404);
    const publicKey = Buffer.alloc(1184, 7);
    const keyId = createHash('sha256').update(publicKey).digest('base64url');
    await env.DB.prepare(
      `INSERT INTO vault_recipient_key
      (key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at)
      VALUES(?,'userinfo','ML-KEM-768',?,'VAULT_USERINFO_MLKEM_TEST',1,'staged',1,?)`,
    )
      .bind(keyId, publicKey, future - 3600)
      .run();
    await env.DB.prepare(
      "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=? WHERE key_id=?",
    )
      .bind(future - 3599, keyId)
      .run();
    const response = await op.fetch(url, { headers });
    assert.equal(response.status, 503);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
  } finally {
    await harness.close();
  }
});

test('owner receives only a verified active recipient directory', async () => {
  const harness = createTestHarness({
    root,
    workers: [{ configPath: opConfig }, { configPath: verifierMockConfig }],
  });
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-worker');
    await op.applyD1Migrations('DB');
    const env = await op.getEnv();
    const secret = randomBytes(32).toString('base64url');
    const cookieHash = createHash('sha256').update(secret).digest('base64url');
    const future = Math.floor(Date.now() / 1000) + 3600;
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      env.DB.prepare("INSERT INTO credential VALUES('credential','owner',1)"),
      env.DB.prepare("INSERT INTO sso_session VALUES('session','owner','credential',1,?,0)").bind(
        future,
      ),
      env.DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
        cookieHash,
        future - 3600,
      ),
    ]);
    const publicKey = Buffer.alloc(1184, 13);
    const keyId = createHash('sha256').update(publicKey).digest('base64url');
    await env.DB.prepare(
      `INSERT INTO vault_recipient_key
      (key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at)
      VALUES(?,'userinfo','ML-KEM-768',?,'VAULT_USERINFO_MLKEM_TEST',1,'staged',1,?)`,
    )
      .bind(keyId, publicKey, future - 3600)
      .run();
    await env.DB.prepare(
      "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=? WHERE key_id=?",
    )
      .bind(future - 3599, keyId)
      .run();
    const response = await op.fetch('https://mikaki.test/vault/recipient-keys/userinfo', {
      headers: { Cookie: `__Host-op-sso=${secret}` },
    });
    assert.equal(response.status, 200, await response.clone().text());
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    assert.deepEqual(await response.json(), {
      service_id: 'userinfo',
      algorithm: 'ML-KEM-768',
      key_id: keyId,
      public_key: publicKey.toString('base64url'),
      generation: 1,
      revision: 2,
    });
  } finally {
    await harness.close();
  }
});
