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
const resource = 'https://mikaki.tossa.app/vault-api/';
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const secret = () => randomBytes(32).toString('base64url');

test('preview Vault authorization consumes exact owner consent with its code and grant', async () => {
  const op = await generateKeyPair('ES256', { extractable: true });
  const sender = await generateKeyPair('ES256', { extractable: true });
  const senderJwk = await exportJWK(sender.publicKey);
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
    OP_PRIVATE_JWK: JSON.stringify(privateJwk),
    MIKAKI_NATIVE_VAULT_OAUTH: 'preview',
  };
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [{ config }],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB, VAULT_BLOBS } = await worker.getEnv();
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'native-vault-test', reason: 'consent-bound code issuance' },
    );
    const clientId = randomUUID();
    await registerNativeClient(
      DB,
      { client_id: clientId, sector_identifier: 'app.example', redirect_uris: [callback] },
      'test',
      'Vault native callback',
    );
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('passkey','owner',1)"),
      DB.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256',?)").bind(
        JSON.stringify(publicJwk),
      ),
      DB.prepare('INSERT INTO app_connection VALUES(?,?,1,1)').bind('owner', clientId),
      DB.prepare("INSERT INTO sso_session VALUES('sso','owner','passkey',1,?,0)").bind(now + 3600),
      DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(digest('owner-cookie'), now),
    ]);
    const verifier = secret();
    const state = secret();
    const authorization = new URL(`${issuer}/authorize`);
    for (const [name, value] of Object.entries({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: callback,
      scope: 'openid vault.read',
      state,
      nonce: secret(),
      code_challenge: digest(verifier),
      code_challenge_method: 'S256',
      resource,
      authorization_details: JSON.stringify([
        {
          type: 'https://mikaki.tossa.app/authorization-details/vault-read-v1',
          locations: [resource],
          actions: ['read_ciphertext'],
          attribute: 'owner_note',
        },
      ]),
    }))
      authorization.searchParams.set(name, value);
    const browser = (url: URL | string) =>
      worker.fetch(url, {
        headers: { Cookie: '__Host-op-sso=owner-cookie' },
        redirect: 'manual',
      });
    const start = await browser(authorization);
    assert.equal(start.status, 302, await start.clone().text());
    const review = new URL(start.headers.get('location')!);
    assert.equal(review.pathname, '/vault/oauth/consent');
    assert.equal((await browser(review)).status, 200);
    const tx = review.searchParams.get('tx')!;
    assert.equal(tx.length, 43);
    assert.equal(
      await DB.prepare('SELECT decision FROM vault_oauth_consent WHERE tx_id=?')
        .bind(tx)
        .first('decision'),
      'pending',
    );

    const approval = await worker.fetch(`${issuer}/vault/oauth/consent`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        Origin: issuer,
        Cookie: '__Host-op-sso=owner-cookie',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ tx, decision: 'approve' }).toString(),
    });
    assert.equal(approval.status, 303, await approval.clone().text());
    const continuation = new URL(approval.headers.get('location')!);
    assert.equal(continuation.searchParams.get('vault_consent'), tx);
    const tampered = new URL(continuation);
    tampered.searchParams.set('state', secret());
    const tamperedResult = await browser(tampered);
    assert.equal(
      new URL(tamperedResult.headers.get('location')!).searchParams.get('error'),
      'invalid_request',
    );
    assert.equal(
      await DB.prepare('SELECT decision FROM vault_oauth_consent WHERE tx_id=?')
        .bind(tx)
        .first('decision'),
      'approved',
    );

    const issued = await browser(continuation);
    assert.equal(issued.status, 302, await issued.clone().text());
    const callbackUrl = new URL(issued.headers.get('location')!);
    assert.equal(`${callbackUrl.origin}${callbackUrl.pathname}`, callback);
    assert.equal(callbackUrl.searchParams.get('state'), state);
    const code = callbackUrl.searchParams.get('code');
    assert.ok(code);
    assert.equal(
      await DB.prepare('SELECT decision FROM vault_oauth_consent WHERE tx_id=?')
        .bind(tx)
        .first('decision'),
      'consumed',
    );
    assert.equal(await DB.prepare('SELECT count(*) AS n FROM vault_oauth_grant').first('n'), 1);
    assert.equal(
      await DB.prepare('SELECT count(*) AS n FROM vault_oauth_code_context').first('n'),
      1,
    );
    assert.equal(
      await DB.prepare('SELECT scope FROM code_context WHERE code_hash=?')
        .bind(createHash('sha256').update(Buffer.from(code, 'base64url')).digest('base64url'))
        .first('scope'),
      'openid vault.read',
    );
    const replay = await browser(continuation);
    assert.equal(
      new URL(replay.headers.get('location')!).searchParams.get('error'),
      'invalid_request',
    );
    assert.equal(await DB.prepare('SELECT count(*) AS n FROM vault_oauth_grant').first('n'), 1);

    const token = (requestedResource?: string, proof?: string) =>
      worker.fetch(`${issuer}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          ...(proof ? { DPoP: proof } : {}),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: clientId,
          redirect_uri: callback,
          code,
          code_verifier: verifier,
          ...(requestedResource ? { resource: requestedResource } : {}),
        }).toString(),
      });
    const noResource = await token();
    assert.equal(noResource.status, 400, await noResource.clone().text());
    assert.equal(((await noResource.json()) as { error: string }).error, 'invalid_target');
    const wrongResource = await token(`${issuer}/userinfo`);
    assert.equal(wrongResource.status, 400, await wrongResource.clone().text());
    assert.equal(((await wrongResource.json()) as { error: string }).error, 'invalid_target');
    const noProof = await token(resource);
    assert.equal(noProof.status, 400, await noProof.clone().text());
    assert.equal(((await noProof.json()) as { error: string }).error, 'invalid_dpop_proof');
    const proof = (htu: string, accessToken?: string) =>
      new SignJWT({
        jti: randomUUID(),
        iat: Math.floor(Date.now() / 1000),
        htm: accessToken ? 'GET' : 'POST',
        htu,
        ...(accessToken ? { ath: digest(accessToken) } : {}),
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: senderJwk })
        .sign(sender.privateKey);
    const issuedToken = await token(resource, await proof(`${issuer}/token`));
    assert.equal(issuedToken.status, 200, await issuedToken.clone().text());
    const payload = (await issuedToken.json()) as {
      access_token: string;
      token_type: string;
      scope: string;
      authorization_details: unknown;
    };
    assert.equal(payload.token_type, 'DPoP');
    assert.equal(payload.scope, 'openid vault.read');
    assert.deepEqual(payload.authorization_details, [
      {
        type: 'https://mikaki.tossa.app/authorization-details/vault-read-v1',
        locations: [resource],
        actions: ['read_ciphertext'],
        attribute: 'owner_note',
      },
    ]);
    assert.deepEqual(
      await DB.prepare(
        'SELECT resource,attribute_id FROM vault_oauth_token_context WHERE access_hash=?',
      )
        .bind(digest(payload.access_token))
        .first(),
      { resource, attribute_id: 'owner_note' },
    );
    const userInfo = await worker.fetch(`${issuer}/userinfo`, {
      headers: {
        Authorization: `DPoP ${payload.access_token}`,
        DPoP: await proof(`${issuer}/userinfo`, payload.access_token),
      },
    });
    assert.equal(userInfo.status, 401, await userInfo.clone().text());
    const ownerUrl = `${issuer}/vault/attributes/owner_note`;
    const ciphertext = Buffer.from('encrypted-test-value').toString('base64url');
    const ownerEnvelope = randomBytes(48).toString('base64url');
    const ownerWrite = await worker.fetch(ownerUrl, {
      method: 'PUT',
      headers: {
        Cookie: '__Host-op-sso=owner-cookie',
        Origin: issuer,
        'Content-Type': 'application/json',
        'If-None-Match': '*',
        'X-Operation-ID': secret(),
      },
      body: JSON.stringify({ format_version: 1, ciphertext, owner_envelope: ownerEnvelope }),
    });
    assert.equal(ownerWrite.status, 200, await ownerWrite.clone().text());
    const apiUrl = `${issuer}/vault-api/attributes/owner_note`;
    const read = (url: string, authorization?: string, compact?: string) =>
      worker.fetch(url, {
        headers: {
          ...(authorization ? { Authorization: authorization } : {}),
          ...(compact ? { DPoP: compact } : {}),
        },
      });
    assert.equal((await read(apiUrl)).status, 401);
    assert.equal((await read(apiUrl, `Bearer ${payload.access_token}`)).status, 401);
    assert.equal((await read(apiUrl, `DPoP ${payload.access_token}`)).status, 401);
    assert.equal(
      (
        await read(
          `${issuer}/vault-api/attributes/name`,
          `DPoP ${payload.access_token}`,
          await proof(`${issuer}/vault-api/attributes/name`, payload.access_token),
        )
      ).status,
      401,
    );
    assert.equal(
      (
        await read(
          apiUrl,
          `DPoP ${payload.access_token}`,
          await proof(`${issuer}/userinfo`, payload.access_token),
        )
      ).status,
      401,
    );
    const readProof = await proof(apiUrl, payload.access_token);
    const fetched = await read(apiUrl, `DPoP ${payload.access_token}`, readProof);
    assert.equal(fetched.status, 200, await fetched.clone().text());
    assert.equal(fetched.headers.get('etag'), '"1"');
    assert.deepEqual(await fetched.json(), {
      format_version: 1,
      revision: 1,
      ciphertext,
      owner_envelope: ownerEnvelope,
    });
    assert.equal((await read(apiUrl, `DPoP ${payload.access_token}`, readProof)).status, 401);
    const head = (await DB.prepare(
      "SELECT object_key FROM vault_attribute_head WHERE account_id='owner' AND attribute_id='owner_note'",
    ).first()) as { object_key: string } | null;
    assert.ok(head);
    await VAULT_BLOBS.put(head.object_key, 'tampered');
    assert.equal(
      (
        await read(
          apiUrl,
          `DPoP ${payload.access_token}`,
          await proof(apiUrl, payload.access_token),
        )
      ).status,
      503,
    );
    await VAULT_BLOBS.put(head.object_key, Buffer.from(ciphertext, 'base64url'));
    const ownerDelete = await worker.fetch(ownerUrl, {
      method: 'DELETE',
      headers: {
        Cookie: '__Host-op-sso=owner-cookie',
        Origin: issuer,
        'If-Match': '"1"',
        'X-Operation-ID': secret(),
      },
    });
    assert.equal(ownerDelete.status, 200, await ownerDelete.clone().text());
    const deleted = await read(
      apiUrl,
      `DPoP ${payload.access_token}`,
      await proof(apiUrl, payload.access_token),
    );
    assert.equal(deleted.status, 404);
    assert.equal(deleted.headers.get('etag'), '"2"');
    await DB.prepare(
      "UPDATE vault_oauth_grant SET revoked=1,version=version+1 WHERE attribute_id='owner_note'",
    ).run();
    assert.equal(
      (
        await read(
          apiUrl,
          `DPoP ${payload.access_token}`,
          await proof(apiUrl, payload.access_token),
        )
      ).status,
      401,
    );
    const reusedCode = await token(resource, await proof(`${issuer}/token`));
    assert.equal(reusedCode.status, 400, await reusedCode.clone().text());
    assert.equal(((await reusedCode.json()) as { error: string }).error, 'invalid_grant');
  } finally {
    await harness.close();
  }
});
