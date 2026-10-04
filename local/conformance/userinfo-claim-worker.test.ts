import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createTestHarness } from 'wrangler';

const configPath = fileURLToPath(
  new URL('../../crates/userinfo-claim-worker/wrangler.local.jsonc', import.meta.url),
);
const opConfigPath = fileURLToPath(
  new URL('../../crates/worker/wrangler.recipient-local.jsonc', import.meta.url),
);
const root = fileURLToPath(new URL('../..', import.meta.url));

test('claim Worker requires ClaimStore even when the retired local-test flag is set', async () => {
  const config = JSON.parse((await readFile(configPath, 'utf8')).replace(/,\s*([}\]])/g, '$1'));
  config.main = `${root}/crates/userinfo-claim-worker/build/worker/shim.mjs`;
  config.services = [];
  config.vars.MIKAKI_LEGACY_CLAIM_STORE = 'local-test';
  const harness = createTestHarness({ root, workers: [{ config }] });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-userinfo-claim-worker');
    const env = await worker.getEnv();
    assert.equal('DB' in env, false);
    assert.equal('VAULT_BLOBS' in env, false);
    const keyId = createHash('sha256').update('key').digest('base64url');
    assert.equal((await worker.fetch('https://internal.invalid/internal/ready')).status, 503);
    const response = await worker.fetch(
      `https://internal.invalid/internal/recipient-keys/${keyId}/verify`,
    );
    assert.equal(response.status, 503);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    const rejected = await worker.fetch(
      `https://internal.invalid/internal/recipient-keys/${keyId}/validate-envelope`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          origin: 'https://mikaki.test',
          account_id: 'owner',
          revision: 1,
          ciphertext: 'AA',
          frame: 'AA',
        }),
      },
    );
    assert.equal(rejected.status, 404);
    const absent = await worker.fetch('https://internal.invalid/internal/claims/name', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        access_hash: createHash('sha256').update('unused').digest('base64url'),
      }),
    });
    assert.equal(absent.status, 503, 'missing authority cannot be mistaken for absent consent');
    const malformed = await worker.fetch('https://internal.invalid/internal/claims/name', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ access_hash: 'short' }),
    });
    assert.equal(malformed.status, 503);
    const unknown = await worker.fetch('https://internal.invalid/');
    assert.equal(unknown.status, 404);
  } finally {
    await harness.close();
  }
});

test('legacy name heads and consent never authorize a UserInfo disclosure', async () => {
  const harness = createTestHarness({
    root,
    workers: [
      { configPath: opConfigPath, vars: { MIKAKI_ISSUER: 'https://mikaki.test' } },
      { configPath },
    ],
  });
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-worker');
    const worker = harness.getWorker('mikaki-userinfo-claim-worker');
    await op.applyD1Migrations('DB');
    const { DB, VAULT_BLOBS } = await op.getEnv();
    const now = Math.floor(Date.now() / 1000);
    const access = Buffer.alloc(32, 5).toString('base64url');
    const token = createHash('sha256').update(access).digest('base64url');
    const code = createHash('sha256').update('profile-code').digest('base64url');
    const ciphertext = Buffer.from('synthetic-invalid-ciphertext');
    const checksum = createHash('sha256').update(ciphertext).digest('base64url');
    const publicKey = Buffer.alloc(1184, 7);
    const keyId = createHash('sha256').update(publicKey).digest('base64url');
    await VAULT_BLOBS.put('name-object', ciphertext);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('credential','owner',1)"),
      DB.prepare(
        "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'https://rp.test')",
      ),
      DB.prepare(
        "INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES('rp','https://rp.test/cb')",
      ),
      DB.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256','{}')"),
      DB.prepare("INSERT INTO app_connection VALUES('owner','rp',1,1)"),
      DB.prepare("INSERT INTO sso_session VALUES('sso','owner','credential',1,?,0)").bind(
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('sso','secret',?)").bind(now),
      DB.prepare("INSERT INTO client_session VALUES('rp','sid','sso','owner','pairwise',1,0)"),
      DB.prepare(
        "INSERT INTO authorization_code(code_hash,client_id,sid,client_revision,redirect_uri,pkce_challenge,expires_at,consumed_by,consumed_at) VALUES(?,'rp','sid',1,'https://rp.test/cb','',?,'issue',?)",
      ).bind(code, now + 600, now),
      DB.prepare(
        "INSERT INTO code_context(code_hash,nonce,scope) VALUES(?,NULL,'openid profile')",
      ).bind(code),
      DB.prepare(
        "INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked) VALUES(?,'issue',?,?,'op',?,0)",
      ).bind(code, token, now + 600, now),
      DB.prepare(
        "INSERT INTO vault_attribute_head VALUES('owner','name',1,1,'name-object',?,'owner-envelope',0,?)",
      ).bind(checksum, now),
      DB.prepare(
        "INSERT INTO vault_recipient_key(key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at) VALUES(?,'userinfo','ML-KEM-768',?,'VAULT_USERINFO_MLKEM_TEST',1,'staged',1,?)",
      ).bind(keyId, publicKey, now),
    ]);
    await DB.prepare(
      "UPDATE vault_recipient_key SET state='active',revision=revision+1,activated_at=? WHERE key_id=?",
    )
      .bind(now, keyId)
      .run();
    const call = () =>
      worker.fetch('https://internal.invalid/internal/claims/name', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ access_hash: token }),
      });
    const userinfo = () =>
      op.fetch('https://mikaki.test/userinfo', {
        headers: { Authorization: `Bearer ${access}` },
      });
    assert.equal((await call()).status, 204);
    const absentProfile = await userinfo();
    assert.equal(absentProfile.status, 200);
    assert.deepEqual(await absentProfile.json(), { sub: 'pairwise' });
    await DB.prepare(
      'UPDATE vault_share_policy SET enabled=1,revision=revision+1 WHERE id=1',
    ).run();
    await DB.prepare(
      'UPDATE vault_claim_release_policy SET enabled=1,revision=revision+1 WHERE id=1',
    ).run();
    await DB.prepare(
      `INSERT INTO vault_attribute_recipient_envelope
      (envelope_id,account_id,attribute_id,attribute_revision,recipient_service,recipient_key_id,recipient_generation,suite,ciphertext_sha256,frame,created_at)
      VALUES(?,'owner','name',1,'userinfo',?,1,'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1',?,?,?)`,
    )
      .bind(
        createHash('sha256').update('envelope').digest('base64url'),
        keyId,
        checksum,
        Buffer.alloc(1187),
        now,
      )
      .run();
    const envelopeId = createHash('sha256').update('envelope').digest('base64url');
    await DB.prepare(
      `INSERT INTO vault_attribute_grant
      (account_id,attribute_id,recipient_service,purpose,envelope_id,attribute_revision,version,status,expires_at,updated_at)
      VALUES('owner','name','userinfo','oidc.userinfo.name',?,1,1,'active',?,?)`,
    )
      .bind(envelopeId, now + 3600, now)
      .run();
    await DB.prepare(
      `INSERT INTO vault_claim_release
      (account_id,client_id,claim,attribute_revision,system_grant_version,client_revision,connection_grant_version,version,status,expires_at,updated_at)
      VALUES('owner','rp','name',1,1,1,1,1,'active',?,?)`,
    )
      .bind(now + 600, now)
      .run();
    assert.equal(
      (await call()).status,
      204,
      'legacy consent is ignored before any recipient secret or ciphertext is accessed',
    );
    const unavailableProfile = await userinfo();
    assert.equal(unavailableProfile.status, 200);
    assert.deepEqual(await unavailableProfile.json(), { sub: 'pairwise' });
    assert.equal(
      await DB.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first('n'),
      0,
    );
    await DB.prepare(
      "UPDATE vault_claim_release SET status='revoked',version=version+1,updated_at=? WHERE account_id='owner' AND client_id='rp'",
    )
      .bind(now + 1)
      .run();
    assert.equal((await call()).status, 204);
    const revokedProfile = await userinfo();
    assert.equal(revokedProfile.status, 200);
    assert.deepEqual(await revokedProfile.json(), { sub: 'pairwise' });
  } finally {
    await harness.close();
  }
});
