import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createTestHarness } from 'wrangler';
import { registerNativeClient } from '../../scripts/client-admin-store.ts';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const issuer = 'https://issuer.example';
const callback = 'https://app.example/oidc/callback';
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const secret = () => randomBytes(32).toString('base64url');

test('native public OIDC code and PKCE exchange stays separate from confidential RPs', async () => {
  const op = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = { ...(await exportJWK(op.publicKey)), kid: 'op', alg: 'ES256' };
  const privateJwk = { ...(await exportJWK(op.privateKey)), kid: 'op', alg: 'ES256' };
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.vars = {
    MIKAKI_ISSUER: issuer,
    MIKAKI_NATIVE_VAULT_OAUTH: 'preview',
    OP_PRIVATE_JWK: JSON.stringify(privateJwk),
  };
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [{ config }],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'native-oidc-test', reason: 'public-client exchange' },
    );
    const clientId = randomUUID();
    await registerNativeClient(
      DB,
      { client_id: clientId, sector_identifier: 'app.example', redirect_uris: [callback] },
      'test',
      'native callback',
    );
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('account',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('credential','account',1)"),
      DB.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256',?)").bind(
        JSON.stringify(publicJwk),
      ),
      DB.prepare('INSERT INTO app_connection VALUES(?,?,1,1)').bind('account', clientId),
      DB.prepare("INSERT INTO sso_session VALUES('sso','account','credential',1,?,0)").bind(
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(digest('cookie-secret'), now),
    ]);
    const metadata = (await (
      await worker.fetch(`${issuer}/.well-known/openid-configuration`)
    ).json()) as { token_endpoint_auth_methods_supported: string[] };
    assert.ok(metadata.token_endpoint_auth_methods_supported.includes('none'));

    const missingPkce = new URL(`${issuer}/authorize`);
    for (const [name, value] of Object.entries({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: callback,
      scope: 'openid',
      state: secret(),
      nonce: secret(),
    }))
      missingPkce.searchParams.set(name, value);
    const rejected = await worker.fetch(missingPkce.toString(), {
      headers: { Cookie: '__Host-op-sso=cookie-secret' },
      redirect: 'manual',
    });
    assert.equal(rejected.status, 302);
    assert.equal(
      new URL(rejected.headers.get('location')!).searchParams.get('error'),
      'invalid_request',
    );
    missingPkce.searchParams.set('redirect_uri', 'https://attacker.example/cb');
    assert.equal(
      (await worker.fetch(missingPkce.toString(), { redirect: 'manual' })).status,
      400,
      'unknown callbacks must not receive an authorization response',
    );

    const unsupportedResource = new URL(`${issuer}/authorize`);
    for (const [name, value] of Object.entries({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: callback,
      scope: 'openid',
      state: secret(),
      nonce: secret(),
      code_challenge: digest(secret()),
      code_challenge_method: 'S256',
    }))
      unsupportedResource.searchParams.set(name, value);
    unsupportedResource.searchParams.set('resource', `${issuer}/vault-api/`);
    const unsupported = await worker.fetch(unsupportedResource.toString(), {
      headers: { Cookie: '__Host-op-sso=cookie-secret' },
      redirect: 'manual',
    });
    assert.equal(
      new URL(unsupported.headers.get('location')!).searchParams.get('error'),
      'invalid_target',
    );
    unsupportedResource.searchParams.set('scope', 'openid vault.read');
    unsupportedResource.searchParams.set('resource', 'https://mikaki.tossa.app/vault-api/');
    unsupportedResource.searchParams.set(
      'authorization_details',
      JSON.stringify([
        {
          type: 'https://mikaki.tossa.app/authorization-details/vault-read-v1',
          locations: ['https://mikaki.tossa.app/vault-api/'],
          actions: ['read_ciphertext'],
          attribute: 'owner_note',
        },
      ]),
    );
    const disabledVault = await worker.fetch(unsupportedResource.toString(), {
      headers: { Cookie: '__Host-op-sso=cookie-secret' },
      redirect: 'manual',
    });
    assert.equal(
      new URL(disabledVault.headers.get('location')!).searchParams.get('error'),
      'invalid_target',
    );
    const legacyScope = new URL(`${issuer}/authorize`);
    for (const [name, value] of Object.entries({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: callback,
      scope: 'openid vault.read',
      state: secret(),
      nonce: secret(),
      code_challenge: digest(secret()),
      code_challenge_method: 'S256',
    }))
      legacyScope.searchParams.set(name, value);
    const scopeRejected = await worker.fetch(legacyScope.toString(), {
      headers: { Cookie: '__Host-op-sso=cookie-secret' },
      redirect: 'manual',
    });
    assert.equal(
      new URL(scopeRejected.headers.get('location')!).searchParams.get('error'),
      'invalid_scope',
    );

    const legacyReceipt = new URL(`${issuer}/authorize`);
    for (const [name, value] of Object.entries({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: callback,
      scope: 'openid',
      state: secret(),
      nonce: secret(),
      code_challenge: digest(secret()),
      code_challenge_method: 'S256',
      vault_consent: 'historical-receipt',
    }))
      legacyReceipt.searchParams.set(name, value);
    const receiptRejected = await worker.fetch(legacyReceipt.toString(), { redirect: 'manual' });
    assert.equal(
      new URL(receiptRejected.headers.get('location')!).searchParams.get('error'),
      'invalid_request',
    );
    assert.equal((await worker.fetch(`${issuer}/vault/oauth/consent?tx=historical`)).status, 404);
    assert.equal(
      (await worker.fetch(`${issuer}/vault/oauth/consent`, { method: 'POST' })).status,
      404,
    );
    assert.equal((await worker.fetch(`${issuer}/vault-api/attributes/owner_note`)).status, 404);

    async function authorize() {
      const verifier = secret();
      const state = secret();
      const nonce = secret();
      const url = new URL(`${issuer}/authorize`);
      for (const [name, value] of Object.entries({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: callback,
        scope: 'openid',
        state,
        nonce,
        code_challenge: digest(verifier),
        code_challenge_method: 'S256',
      }))
        url.searchParams.set(name, value);
      const response = await worker.fetch(url.toString(), {
        headers: { Cookie: '__Host-op-sso=cookie-secret' },
        redirect: 'manual',
      });
      assert.equal(response.status, 302, await response.clone().text());
      const redirect = new URL(response.headers.get('location')!);
      assert.equal(`${redirect.origin}${redirect.pathname}`, callback);
      assert.equal(redirect.searchParams.get('state'), state);
      assert.equal(redirect.searchParams.get('iss'), issuer);
      const code = redirect.searchParams.get('code');
      assert.ok(code);
      return { code, verifier, nonce };
    }

    async function token(
      code: string,
      verifier: string,
      extras: Record<string, string> = {},
      dpop?: string,
    ) {
      return worker.fetch(`${issuer}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          ...(dpop ? { DPoP: dpop } : {}),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: clientId,
          code,
          redirect_uri: callback,
          code_verifier: verifier,
          ...extras,
        }).toString(),
      });
    }

    const first = await authorize();
    assert.equal((await token(first.code, secret())).status, 400);
    assert.equal(
      (await token(first.code, first.verifier, { client_secret: 'embedded' })).status,
      400,
    );
    const reply = await token(first.code, first.verifier);
    assert.equal(reply.status, 200, await reply.clone().text());
    const issued = (await reply.json()) as { id_token: string; access_token: string };
    assert.ok(issued.id_token);
    assert.ok(issued.access_token);
    assert.equal((await token(first.code, first.verifier)).status, 400);
    const tokenRow = await DB.prepare('SELECT revoked FROM token_issue WHERE access_hash=?')
      .bind(digest(issued.access_token))
      .first();
    assert.equal(tokenRow.revoked, 1, 'valid replay revokes the previously issued token');

    const second = await authorize();
    assert.equal((await token(second.code, second.verifier)).status, 200);

    const desktopId = randomUUID();
    const registeredLoopback = 'http://127.0.0.1:0/oidc/callback';
    const actualLoopback = 'http://127.0.0.1:48231/oidc/callback';
    await registerNativeClient(
      DB,
      {
        client_id: desktopId,
        sector_identifier: '127.0.0.1',
        redirect_uris: [registeredLoopback],
      },
      'test',
      'desktop loopback',
    );
    await DB.prepare('INSERT INTO app_connection VALUES(?,?,1,1)').bind('account', desktopId).run();
    const desktopVerifier = secret();
    const desktopState = secret();
    const desktopUrl = new URL(`${issuer}/authorize`);
    for (const [name, value] of Object.entries({
      response_type: 'code',
      client_id: desktopId,
      redirect_uri: actualLoopback,
      scope: 'openid',
      state: desktopState,
      nonce: secret(),
      code_challenge: digest(desktopVerifier),
      code_challenge_method: 'S256',
    }))
      desktopUrl.searchParams.set(name, value);
    for (const uri of [
      'http://127.0.0.1:0/oidc/callback',
      'http://localhost:48231/oidc/callback',
      'http://127.0.0.1:48231/wrong-path',
      'http://127.0.0.2:48231/oidc/callback',
    ]) {
      desktopUrl.searchParams.set('redirect_uri', uri);
      assert.equal((await worker.fetch(desktopUrl, { redirect: 'manual' })).status, 400);
    }
    desktopUrl.searchParams.set('redirect_uri', actualLoopback);
    const desktopAuthorization = await worker.fetch(desktopUrl, {
      headers: { Cookie: '__Host-op-sso=cookie-secret' },
      redirect: 'manual',
    });
    assert.equal(desktopAuthorization.status, 302, await desktopAuthorization.clone().text());
    const desktopRedirect = new URL(desktopAuthorization.headers.get('location')!);
    assert.equal(`${desktopRedirect.origin}${desktopRedirect.pathname}`, actualLoopback);
    assert.equal(desktopRedirect.searchParams.get('state'), desktopState);
    const desktopCode = desktopRedirect.searchParams.get('code')!;
    assert.ok(desktopCode);
    const codeRow = await DB.prepare(
      'SELECT redirect_uri,redirect_uri_actual FROM authorization_code WHERE client_id=?',
    )
      .bind(desktopId)
      .first();
    assert.deepEqual(codeRow, {
      redirect_uri: registeredLoopback,
      redirect_uri_actual: actualLoopback,
    });
    async function desktopToken(redirectUri: string) {
      return worker.fetch(`${issuer}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: desktopId,
          code: desktopCode,
          redirect_uri: redirectUri,
          code_verifier: desktopVerifier,
        }).toString(),
      });
    }
    assert.equal((await desktopToken('http://127.0.0.1:48232/oidc/callback')).status, 400);
    assert.equal((await desktopToken(actualLoopback)).status, 200);
    assert.equal(
      await DB.prepare('SELECT count(*) AS n FROM client_key WHERE client_id=?')
        .bind(clientId)
        .first('n'),
      0,
    );
  } finally {
    await harness.close();
  }
});
