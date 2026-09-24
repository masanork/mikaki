import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createTestHarness } from 'wrangler';

test('RP name consent requires current system sharing and is independently revocable', async () => {
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
    const { DB: db } = await worker.getEnv();
    const secret = randomBytes(32).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const keyId = randomBytes(32).toString('base64url');
    const envelopeId = randomBytes(32).toString('base64url');
    const digest = randomBytes(32).toString('base64url');
    await db.batch([
      db.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      db.prepare("INSERT INTO credential VALUES('credential','owner',1)"),
      db
        .prepare("INSERT INTO sso_session VALUES('session','owner','credential',1,?,0)")
        .bind(now + 3600),
      db
        .prepare("INSERT INTO sso_context VALUES('session',?,?)")
        .bind(createHash('sha256').update(secret).digest('base64url'), now),
      db.prepare(
        "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'rp.example')",
      ),
      db.prepare("INSERT INTO app_connection VALUES('owner','rp',1,1)"),
      db
        .prepare(
          `INSERT INTO vault_attribute_head
        (account_id,attribute_id,revision,format_version,object_key,ciphertext_sha256,owner_envelope,deleted,updated_at)
        VALUES('owner','name',1,1,'blob',?,'owner-wrap',0,?)`,
        )
        .bind(digest, now),
      db
        .prepare(
          `INSERT INTO vault_recipient_key
        (key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at)
        VALUES(?,'userinfo','ML-KEM-768',zeroblob(1184),'VAULT_USERINFO_MLKEM_TEST',1,'staged',1,?)`,
        )
        .bind(keyId, now - 2),
    ]);
    await db
      .prepare(
        "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=? WHERE key_id=?",
      )
      .bind(now - 1, keyId)
      .run();
    await db
      .prepare(
        `INSERT INTO vault_attribute_recipient_envelope
      (envelope_id,account_id,attribute_id,attribute_revision,recipient_service,
      recipient_key_id,recipient_generation,suite,ciphertext_sha256,frame,created_at)
      VALUES(?,'owner','name',1,'userinfo',?,1,
      'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1',?,zeroblob(1187),?)`,
      )
      .bind(envelopeId, keyId, digest, now)
      .run();
    await db.prepare('UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1').run();
    await db
      .prepare(
        `INSERT INTO vault_attribute_grant
      (account_id,attribute_id,recipient_service,purpose,envelope_id,attribute_revision,
      version,status,expires_at,updated_at)
      VALUES('owner','name','userinfo','oidc.userinfo.name',?,1,1,'active',?,?)`,
      )
      .bind(envelopeId, now + 3000, now)
      .run();

    const url = 'https://mikaki.test/vault/releases/name';
    const headers = (version: number, operation = randomBytes(32).toString('base64url')) => ({
      Cookie: `__Host-op-sso=${secret}`,
      Origin: 'https://mikaki.test',
      'Content-Type': 'application/json',
      'If-Match': `"${version}"`,
      'X-Operation-ID': operation,
    });
    const body = JSON.stringify({
      client_id: 'rp',
      client_revision: 1,
      connection_grant_version: 1,
      policy_revision: 1,
    });
    const grant = (requestHeaders: Record<string, string>, requestBody = body) =>
      worker.fetch(url, { method: 'POST', headers: requestHeaders, body: requestBody });
    const status = () => worker.fetch(url, { headers: { Cookie: `__Host-op-sso=${secret}` } });
    assert.equal((await grant(headers(1))).status, 403);
    const disabled = await status();
    assert.equal(disabled.status, 200);
    assert.equal(((await disabled.json()) as { enabled: boolean }).enabled, false);
    await db.prepare('UPDATE vault_claim_release_policy SET enabled=1,revision=2 WHERE id=1').run();
    const operation = randomBytes(32).toString('base64url');
    const firstHeaders = headers(1, operation);
    const granted = await grant(
      firstHeaders,
      JSON.stringify({ ...JSON.parse(body), policy_revision: 2 }),
    );
    assert.equal(granted.status, 200, await granted.text());
    assert.equal(
      (await grant(firstHeaders, JSON.stringify({ ...JSON.parse(body), policy_revision: 2 })))
        .status,
      200,
    );
    assert.equal((await grant(firstHeaders, body)).status, 409);
    const current = await status();
    assert.equal(
      ((await current.json()) as { clients: { release_active: boolean }[] }).clients[0]
        .release_active,
      true,
    );
    const revoked = await worker.fetch(url, {
      method: 'DELETE',
      headers: headers(1),
      body: JSON.stringify({ client_id: 'rp' }),
    });
    assert.equal(revoked.status, 200, await revoked.text());
    const after = await status();
    assert.equal(
      ((await after.json()) as { clients: { release_active: boolean }[] }).clients[0]
        .release_active,
      false,
    );
    const renewed = await grant(
      headers(1),
      JSON.stringify({ ...JSON.parse(body), policy_revision: 2 }),
    );
    assert.equal(renewed.status, 200, await renewed.text());
    await db.prepare("UPDATE client SET revision=2 WHERE client_id='rp'").run();
    assert.deepEqual(
      await db
        .prepare("SELECT status,version FROM vault_claim_release WHERE client_id='rp'")
        .first(),
      { status: 'revoked', version: 4 },
    );
  } finally {
    await harness.close();
  }
});
