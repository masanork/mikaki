import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import {
  bindAccessEmail,
  registerAccessClient,
  rotateAccessSecret,
} from '../../scripts/access-client-admin-store.ts';

test('Access registration and binding changes are atomic, revision fenced and audited', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      { configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    await DB.prepare("INSERT INTO account_security VALUES('owner',1,1),('other',1,1)").run();
    const secret = randomBytes(32).toString('base64url');
    const callback = 'https://team.cloudflareaccess.com/cdn-cgi/access/callback';
    await assert.rejects(
      registerAccessClient(
        DB,
        'access',
        'https://evil.example/cdn-cgi/access/callback',
        secret,
        'client_secret_basic',
        'operator',
        'test',
      ),
    );
    await registerAccessClient(
      DB,
      'access',
      callback,
      secret,
      'client_secret_basic',
      'operator',
      'test',
    );
    await assert.rejects(
      registerAccessClient(
        DB,
        'access',
        callback,
        secret,
        'client_secret_basic',
        'operator',
        'duplicate',
      ),
    );
    const stored = await DB.prepare(
      "SELECT secret_hash FROM client_secret WHERE client_id='access'",
    ).first();
    assert.notEqual(stored.secret_hash, secret);
    await bindAccessEmail(
      DB,
      'access',
      'owner',
      'Owner@example.test',
      0,
      'operator',
      'verified address',
    );
    await assert.rejects(
      bindAccessEmail(
        DB,
        'access',
        'other',
        'owner@example.test',
        0,
        'operator',
        'duplicate address',
      ),
    );
    await assert.rejects(
      bindAccessEmail(DB, 'access', 'owner', 'new@example.test', 3, 'operator', 'stale revision'),
    );
    assert.equal(
      (await DB.prepare('SELECT COUNT(*) AS n FROM access_email_binding_audit').first()).n,
      1,
    );
    await bindAccessEmail(DB, 'access', 'owner', null, 1, 'operator', 'revoke');
    await assert.rejects(
      bindAccessEmail(DB, 'access', 'owner', 'new@example.test', 1, 'operator', 'stale'),
    );
    await bindAccessEmail(
      DB,
      'access',
      'owner',
      'new@example.test',
      2,
      'operator',
      'verified replacement',
    );
    const competing = await Promise.allSettled([
      bindAccessEmail(DB, 'access', 'owner', 'one@example.test', 3, 'operator', 'first'),
      bindAccessEmail(DB, 'access', 'owner', 'two@example.test', 3, 'operator', 'second'),
    ]);
    assert.equal(competing.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal(
      (await DB.prepare('SELECT COUNT(*) AS n FROM access_email_binding_audit').first()).n,
      4,
    );
    const next = randomBytes(32).toString('base64url');
    await rotateAccessSecret(DB, 'access', 1, next, 'operator', 'rotate');
    await assert.rejects(rotateAccessSecret(DB, 'access', 1, secret, 'operator', 'stale'));
    await rotateAccessSecret(DB, 'access', 2, null, 'operator', 'retire');
    assert.deepEqual(await DB.prepare('SELECT revision,active FROM client_secret').first(), {
      revision: 3,
      active: 0,
    });
    assert.equal(
      (await DB.prepare('SELECT COUNT(*) AS n FROM access_client_secret_audit').first()).n,
      3,
    );
  } finally {
    await harness.close();
  }
});
