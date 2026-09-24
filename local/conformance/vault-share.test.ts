import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createTestHarness } from 'wrangler';

test('Vault system sharing is opt-in, revision-bound, and revocable in workerd', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.recipient-local.jsonc', import.meta.url)
          .pathname,
      },
      { configPath: new URL('wrangler.recipient-verifier-mock.jsonc', import.meta.url).pathname },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const env = await worker.getEnv();
    const secret = randomBytes(32).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      env.DB.prepare("INSERT INTO credential VALUES('credential','owner',1)"),
      env.DB.prepare("INSERT INTO sso_session VALUES('session','owner','credential',1,?,0)").bind(
        now + 3600,
      ),
      env.DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
        createHash('sha256').update(secret).digest('base64url'),
        now,
      ),
    ]);
    const cookie = { Cookie: `__Host-op-sso=${secret}` };
    const attributeUrl = 'https://mikaki.test/vault/attributes/name';
    const shareUrl = 'https://mikaki.test/vault/shares/userinfo/name';
    const shareState = async (): Promise<{ enabled: boolean; active: boolean }> => {
      const response = await worker.fetch(shareUrl, { headers: cookie });
      const value: unknown = await response.json();
      if (
        typeof value !== 'object' ||
        value === null ||
        !('enabled' in value) ||
        typeof value.enabled !== 'boolean' ||
        !('active' in value) ||
        typeof value.active !== 'boolean'
      ) {
        throw new Error('invalid share status');
      }
      return { enabled: value.enabled, active: value.active };
    };
    const operation = () => randomBytes(32).toString('base64url');
    const mutationHeaders = (id, revision, contentType = false) => ({
      ...cookie,
      Origin: 'https://mikaki.test',
      'X-Operation-ID': id,
      'If-Match': `"${revision}"`,
      ...(contentType ? { 'Content-Type': 'application/json' } : {}),
    });
    const ciphertext = Buffer.from('stored-ciphertext');
    const digest = createHash('sha256').update(ciphertext).digest('base64url');
    const create = await worker.fetch(attributeUrl, {
      method: 'PUT',
      headers: {
        ...cookie,
        Origin: 'https://mikaki.test',
        'X-Operation-ID': operation(),
        'If-None-Match': '*',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        format_version: 1,
        ciphertext: ciphertext.toString('base64url'),
        owner_envelope: randomBytes(48).toString('base64url'),
      }),
    });
    assert.equal(create.status, 200, await create.text());
    const publicKey = randomBytes(1184);
    const keyId = createHash('sha256').update(publicKey).digest('base64url');
    await env.DB.prepare(
      `INSERT INTO vault_recipient_key
       (key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at)
       VALUES(?,'userinfo','ML-KEM-768',?,'VAULT_USERINFO_MLKEM_TEST',1,'staged',1,?)`,
    )
      .bind(keyId, publicKey, now)
      .run();
    await env.DB.prepare(
      "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=? WHERE key_id=?",
    )
      .bind(now + 1, keyId)
      .run();
    const frame = Buffer.concat([
      Buffer.from([0x4d, 0x4b, 0x56, 0x45, 1, 0, 0x41, 0, 1, 0, 2]),
      Buffer.from(keyId, 'base64url'),
      Buffer.from([0, 0, 0, 0, 0, 0, 0, 1]),
      randomBytes(1088 + 48),
    ]);
    const body = JSON.stringify({
      frame: frame.toString('base64url'),
      key_id: keyId,
      generation: 1,
      directory_revision: 2,
      ciphertext_sha256: digest,
    });
    assert.equal((await shareState()).enabled, false);
    const shareId = operation();
    const shareRequest = () =>
      worker.fetch(shareUrl, {
        method: 'POST',
        headers: mutationHeaders(shareId, 1, true),
        body,
      });
    assert.equal((await shareRequest()).status, 403);
    await env.DB.prepare('UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1').run();
    const shared = await shareRequest();
    assert.equal(shared.status, 200, await shared.text());
    assert.equal((await shareRequest()).status, 200);
    assert.equal((await shareState()).active, true);
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM vault_attribute_recipient_envelope WHERE account_id='owner'",
        ).first()
      ).total,
      1,
    );
    const conflict = await worker.fetch(shareUrl, {
      method: 'POST',
      headers: mutationHeaders(shareId, 1, true),
      body: JSON.stringify({ ...JSON.parse(body), ciphertext_sha256: 'x'.repeat(43) }),
    });
    assert.equal(conflict.status, 409);
    const staleDirectory = await worker.fetch(shareUrl, {
      method: 'POST',
      headers: mutationHeaders(operation(), 1, true),
      body: JSON.stringify({ ...JSON.parse(body), directory_revision: 1 }),
    });
    assert.equal(staleDirectory.status, 409);
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM vault_attribute_recipient_envelope WHERE account_id='owner'",
        ).first()
      ).total,
      1,
    );
    const revoked = await worker.fetch(shareUrl, {
      method: 'DELETE',
      headers: mutationHeaders(operation(), 1),
    });
    assert.equal(revoked.status, 200, await revoked.text());
    assert.equal((await shareState()).active, false);
    const renewed = await worker.fetch(shareUrl, {
      method: 'POST',
      headers: mutationHeaders(operation(), 1, true),
      body,
    });
    assert.equal(renewed.status, 200, await renewed.text());
    assert.equal((await shareState()).active, true);
    const updated = await worker.fetch(attributeUrl, {
      method: 'PUT',
      headers: mutationHeaders(operation(), 1, true),
      body: JSON.stringify({
        format_version: 1,
        ciphertext: Buffer.from('changed-ciphertext').toString('base64url'),
        owner_envelope: randomBytes(48).toString('base64url'),
      }),
    });
    assert.equal(updated.status, 200, await updated.text());
    assert.equal((await shareState()).active, false);
    const staleAttribute = await worker.fetch(shareUrl, {
      method: 'POST',
      headers: mutationHeaders(operation(), 1, true),
      body,
    });
    assert.equal(staleAttribute.status, 409);
    await env.DB.prepare('UPDATE vault_share_policy SET enabled=0,revision=3 WHERE id=1').run();
    assert.equal((await shareState()).active, false);
  } finally {
    await harness.close();
  }
});
