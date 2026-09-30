import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { registerNativeClient } from '../../scripts/client-admin-store.ts';

const issuer = 'https://issuer.example';
const callback = `${issuer}/oidc/native/callback`;
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
const secret = () => randomBytes(32).toString('base64url');

test('Vault consent requires the matching live owner session and is decided once', async () => {
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.vars = { MIKAKI_ISSUER: issuer };
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [{ config }],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const clientId = randomUUID();
    await registerNativeClient(
      DB,
      { client_id: clientId, sector_identifier: 'issuer.example', redirect_uris: [callback] },
      'test',
      'Vault consent test',
    );
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',0,1)"),
      DB.prepare("INSERT INTO credential VALUES('passkey','owner',1)"),
      DB.prepare('INSERT INTO app_connection VALUES(?,?,1,1)').bind('owner', clientId),
      DB.prepare("INSERT INTO sso_session VALUES('sso','owner','passkey',0,?,0)").bind(now + 600),
      DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(hash('owner-cookie'), now),
    ]);
    const tx = secret();
    const state = secret();
    const authorizationUrl = new URL(`${issuer}/authorize`);
    authorizationUrl.searchParams.set('client_id', clientId);
    authorizationUrl.searchParams.set('state', state);
    const insert = DB.prepare(
      "INSERT INTO vault_oauth_consent(tx_id,sso_secret_hash,sso_id,account_id,client_id,client_revision,authorization_url,redirect_uri,state,attribute_id,resource,expires_at,created_at) VALUES(?, ?, 'sso', 'owner', ?, 1, ?, ?, ?, 'owner_note', 'https://mikaki.tossa.app/vault-api/', ?, ?)",
    );
    await insert
      .bind(
        tx,
        hash('owner-cookie'),
        clientId,
        authorizationUrl.toString(),
        callback,
        state,
        now + 300,
        now,
      )
      .run();
    const consentUrl = `${issuer}/vault/oauth/consent?tx=${tx}`;
    assert.equal((await worker.fetch(consentUrl)).status, 404);
    assert.equal(
      (await worker.fetch(consentUrl, { headers: { Cookie: '__Host-op-sso=wrong' } })).status,
      404,
    );
    const page = await worker.fetch(consentUrl, {
      headers: { Cookie: '__Host-op-sso=owner-cookie', 'Accept-Language': 'en' },
    });
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Owner note/);
    assert.equal(page.headers.get('cache-control'), 'no-store');
    const decide = (choice: string, origin = issuer, chosenTx = tx) =>
      worker.fetch(`${issuer}/vault/oauth/consent`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          Origin: origin,
          Cookie: '__Host-op-sso=owner-cookie',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ tx: chosenTx, decision: choice }).toString(),
      });
    assert.equal((await decide('approve', 'https://evil.example')).status, 404);
    const approved = await decide('approve');
    assert.equal(approved.status, 303, await approved.clone().text());
    const continued = new URL(approved.headers.get('location')!);
    assert.equal(continued.searchParams.get('vault_consent'), tx);
    assert.equal(continued.searchParams.get('state'), state);
    assert.equal((await decide('approve')).status, 404);

    const deniedTx = secret();
    await insert
      .bind(
        deniedTx,
        hash('owner-cookie'),
        clientId,
        authorizationUrl.toString(),
        callback,
        state,
        now + 300,
        now,
      )
      .run();
    const denied = await decide('deny', issuer, deniedTx);
    assert.equal(denied.status, 302);
    const destination = new URL(denied.headers.get('location')!);
    assert.equal(destination.searchParams.get('error'), 'access_denied');
    assert.equal(destination.searchParams.get('state'), state);
    assert.equal(destination.searchParams.get('iss'), issuer);
  } finally {
    await harness.close();
  }
});
