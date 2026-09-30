import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { exportJWK, generateKeyPair } from 'jose';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const root = new URL('../..', import.meta.url).pathname;
const opConfig = new URL('../../crates/worker/wrangler.recipient-local.jsonc', import.meta.url)
  .pathname;
const claimConfig = new URL(
  '../../crates/userinfo-claim-worker/wrangler.local.jsonc',
  import.meta.url,
).pathname;
const readyToken = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA';

test('readiness fails closed until OP policy, signing key, migrations and Claim Worker are usable', async () => {
  const keys = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = {
    ...(await exportJWK(keys.publicKey)),
    kid: 'ready-op',
    alg: 'ES256',
    use: 'sig',
  };
  const privateJwk = {
    ...(await exportJWK(keys.privateKey)),
    kid: 'ready-op',
    alg: 'ES256',
    use: 'sig',
  };
  const harness = createTestHarness({
    root,
    workers: [
      {
        configPath: opConfig,
        vars: { MIKAKI_ISSUER: 'https://mikaki.test' },
        secrets: {
          OP_PRIVATE_JWK: JSON.stringify(privateJwk),
          MIKAKI_READY_TOKEN: readyToken,
        },
      },
      { configPath: claimConfig },
    ],
  });
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-worker');
    const claim = harness.getWorker('mikaki-userinfo-claim-worker');
    const check = async (status: number, authorization: string | null = `Bearer ${readyToken}`) => {
      const response = await op.fetch('https://mikaki.test/ready', {
        headers: authorization === null ? {} : { Authorization: authorization },
      });
      assert.equal(response.status, status);
      assert.equal(response.headers.get('Cache-Control'), 'no-store');
      assert.equal(await response.text(), '');
    };
    assert.equal((await op.fetch('https://mikaki.test/health')).status, 200);
    await check(404, null);
    await check(404, `Bearer B${readyToken.slice(1)}`);
    await check(404, `Basic ${readyToken}`);
    await check(404, 'Bearer short');
    await check(503);
    assert.equal((await claim.fetch('https://internal.invalid/internal/ready')).status, 503);
    await op.applyD1Migrations('DB');
    await claim.applyD1Migrations('DB');
    assert.equal((await claim.fetch('https://internal.invalid/internal/ready')).status, 204);
    await check(503);
    const { DB } = await op.getEnv();
    await DB.prepare("INSERT INTO account_security VALUES('shared-binding-probe',0,1)").run();
    const { DB: claimDB } = await claim.getEnv();
    assert.equal(
      await claimDB
        .prepare(
          "SELECT count(*) AS n FROM account_security WHERE account_id='shared-binding-probe'",
        )
        .first('n'),
      1,
      'OP and claim Worker must read the same local D1',
    );
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Readiness fixture' });
    await check(503);
    await DB.prepare("INSERT INTO signing_key VALUES('ready-op',1,1,'ES256',?)")
      .bind(JSON.stringify(publicJwk))
      .run();
    await check(204);
    await check(404, null);
    const otherKeys = await generateKeyPair('ES256', { extractable: true });
    const wrongPublicJwk = {
      ...(await exportJWK(otherKeys.publicKey)),
      kid: 'ready-op',
      alg: 'ES256',
      use: 'sig',
    };
    await DB.prepare("UPDATE signing_key SET public_jwk=? WHERE kid='ready-op'")
      .bind(JSON.stringify(wrongPublicJwk))
      .run();
    await check(503);
    await DB.prepare("UPDATE signing_key SET public_jwk=? WHERE kid='ready-op'")
      .bind(JSON.stringify(publicJwk))
      .run();
    await check(204);
    await DB.prepare('DROP TABLE vault_recipient_key').run();
    await check(404, null);
    await check(503);
  } finally {
    await harness.close();
  }
});

test('readiness remains hidden when the monitoring secret is not provisioned', async () => {
  const harness = createTestHarness({
    root,
    workers: [{ configPath: opConfig }, { configPath: claimConfig }],
  });
  try {
    await harness.listen();
    const response = await harness
      .getWorker('mikaki-op-worker')
      .fetch('https://mikaki.test/ready', {
        headers: { Authorization: `Bearer ${readyToken}` },
      });
    assert.equal(response.status, 404);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    assert.equal(await response.text(), '');
  } finally {
    await harness.close();
  }
});
