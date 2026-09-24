import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createTestHarness } from 'wrangler';

test('Vault attribute ciphertext is owner scoped and revision safe in workerd', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const env = await worker.getEnv();
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
    const url = 'https://mikaki.test/vault/attributes/name';
    assert.equal((await worker.fetch('https://mikaki.test/vault')).status, 401);
    const page = await worker.fetch('https://mikaki.test/vault', {
      headers: { Cookie: `__Host-op-sso=${secret}` },
    });
    assert.equal(page.status, 200);
    assert.match(await page.text(), /vault\/vault\.js/);
    const englishPage = await worker.fetch('https://mikaki.test/vault?lang=en', {
      headers: { Cookie: `__Host-op-sso=${secret}`, 'Accept-Language': 'ja' },
    });
    assert.match(await englishPage.text(), /<html lang="en">/);
    assert.equal((await worker.fetch('https://mikaki.test/vault/vault.js')).status, 200);
    const session = await worker.fetch('https://mikaki.test/vault/session', {
      headers: { Cookie: `__Host-op-sso=${secret}` },
    });
    assert.deepEqual(await session.json(), { credential_id: 'credential', account_id: 'owner' });
    const operation = () => randomBytes(32).toString('base64url');
    const content = (value) =>
      JSON.stringify({
        format_version: 1,
        ciphertext: Buffer.from(value).toString('base64url'),
        owner_envelope: randomBytes(48).toString('base64url'),
      });
    const headers = (op, precondition, cookie = secret) => ({
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: 'https://mikaki.test',
      'Content-Type': 'application/json',
      'X-Operation-ID': op,
      ...precondition,
    });
    const createOp = operation();
    const firstBody = content('ciphertext-one');
    const create = await worker.fetch(url, {
      method: 'PUT',
      headers: headers(createOp, { 'If-None-Match': '*' }),
      body: firstBody,
    });
    assert.equal(create.status, 200, await create.text());
    assert.equal(create.headers.get('etag'), '"1"');
    const retry = await worker.fetch(url, {
      method: 'PUT',
      headers: headers(createOp, { 'If-None-Match': '*' }),
      body: firstBody,
    });
    assert.equal(retry.status, 200);
    const reused = await worker.fetch(url, {
      method: 'PUT',
      headers: headers(createOp, { 'If-None-Match': '*' }),
      body: content('different'),
    });
    assert.equal(reused.status, 409);
    const fetched = await worker.fetch(url, { headers: { Cookie: `__Host-op-sso=${secret}` } });
    assert.equal(fetched.status, 200);
    assert.equal(
      ((await fetched.json()) as { ciphertext: string }).ciphertext,
      JSON.parse(firstBody).ciphertext,
    );
    const stored = await env.DB.prepare(
      "SELECT object_key FROM vault_attribute_head WHERE account_id='owner' AND attribute_id='name'",
    ).first();
    await env.VAULT_BLOBS.put(stored.object_key, 'tampered');
    assert.equal(
      (await worker.fetch(url, { headers: { Cookie: `__Host-op-sso=${secret}` } })).status,
      503,
    );
    const otherSecret = randomBytes(32).toString('base64url');
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('other',1,1)"),
      env.DB.prepare("INSERT INTO credential VALUES('other-credential','other',1)"),
      env.DB.prepare(
        "INSERT INTO sso_session VALUES('other-session','other','other-credential',1,?,0)",
      ).bind(future),
      env.DB.prepare("INSERT INTO sso_context VALUES('other-session',?,?)").bind(
        createHash('sha256').update(otherSecret).digest('base64url'),
        future - 3600,
      ),
    ]);
    assert.equal(
      (await worker.fetch(url, { headers: { Cookie: `__Host-op-sso=${otherSecret}` } })).status,
      404,
    );
    const keysBeforeStale = (await env.VAULT_BLOBS.list()).objects.length;
    const stale = await worker.fetch(url, {
      method: 'PUT',
      headers: headers(operation(), { 'If-None-Match': '*' }),
      body: content('stale'),
    });
    assert.equal(stale.status, 409);
    assert.equal((await env.VAULT_BLOBS.list()).objects.length, keysBeforeStale);
    const badOrigin = await worker.fetch(url, {
      method: 'PUT',
      headers: { ...headers(operation(), { 'If-Match': '"1"' }), Origin: 'https://evil.test' },
      body: content('bad-origin'),
    });
    assert.equal(badOrigin.status, 403);
    const update = await worker.fetch(url, {
      method: 'PUT',
      headers: headers(operation(), { 'If-Match': '"1"' }),
      body: content('ciphertext-two'),
    });
    assert.equal(update.status, 200);
    assert.equal(update.headers.get('etag'), '"2"');
    const concurrent = await Promise.all(
      ['parallel-a', 'parallel-b'].map((value) =>
        worker.fetch(url, {
          method: 'PUT',
          headers: headers(operation(), { 'If-Match': '"2"' }),
          body: content(value),
        }),
      ),
    );
    assert.deepEqual(concurrent.map((response) => response.status).sort(), [200, 409]);
    const removed = await worker.fetch(url, {
      method: 'DELETE',
      headers: headers(operation(), { 'If-Match': '"3"' }),
    });
    assert.equal(removed.status, 200);
    assert.equal(removed.headers.get('etag'), '"4"');
    const tombstone = await worker.fetch(url, { headers: { Cookie: `__Host-op-sso=${secret}` } });
    assert.equal(tombstone.status, 404);
    assert.equal(tombstone.headers.get('etag'), '"4"');
    const recreate = await worker.fetch(url, {
      method: 'PUT',
      headers: headers(operation(), { 'If-Match': '"4"' }),
      body: content('recreated'),
    });
    assert.equal(recreate.status, 200);
    assert.equal(recreate.headers.get('etag'), '"5"');
    const active = await env.DB.prepare(
      "SELECT object_key FROM vault_attribute_head WHERE account_id='owner' AND attribute_id='name'",
    ).first();
    assert.equal((await worker.fetch(url)).status, 401);
    await env.DB.prepare("UPDATE sso_session SET revoked=1 WHERE sso_id='session'").run();
    const afterRevoke = await worker.fetch(url, {
      method: 'PUT',
      headers: headers(operation(), { 'If-Match': '"5"' }),
      body: content('after-revoke'),
    });
    assert.equal(afterRevoke.status, 401);
    await env.VAULT_BLOBS.put('vault-attribute/orphan-test', 'orphan');
    await worker.scheduled({
      cron: '0 3 * * *',
      scheduledTime: new Date(Date.now() + 2 * 86400000),
    });
    assert.equal(await env.VAULT_BLOBS.get('vault-attribute/orphan-test'), null);
    assert.equal(await env.VAULT_BLOBS.get(stored.object_key), null);
    assert.ok(await env.VAULT_BLOBS.get(active.object_key));
  } finally {
    await harness.close();
  }
});
