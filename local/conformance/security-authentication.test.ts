/** SEC-03/04: real packaged OP, two Worker isolates, and shared durable state. */
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { exportJWK, generateKeyPair } from 'jose';
import { createTestHarness } from 'wrangler';
import { registerNativeClient } from '../../scripts/client-admin-store.ts';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const issuer = 'https://issuer.example';
const root = new URL('../../', import.meta.url).pathname;
const digest = (value: string | Uint8Array) =>
  createHash('sha256').update(value).digest('base64url');
const codeDigest = (value: string) => digest(Buffer.from(value, 'base64url'));
const secret = () => randomBytes(32).toString('base64url');

type Client = { id: string; callback: string };
type Grant = { code: string; codeHash: string; verifier: string };

test('authentication mix-up and code-race matrix preserves durable authority', async (t) => {
  const op = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = { ...(await exportJWK(op.publicKey)), kid: 'op', alg: 'ES256' };
  const privateJwk = { ...(await exportJWK(op.privateKey)), kid: 'op', alg: 'ES256' };
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  config.assets.directory = new URL('../../assets', import.meta.url).pathname;
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.vars = { MIKAKI_ISSUER: issuer, OP_PRIVATE_JWK: JSON.stringify(privateJwk) };
  const options = {
    root,
    workers: [
      { config },
      {
        config: {
          ...config,
          name: 'mikaki-security-authentication-second',
          queues: { ...config.queues, consumers: [] },
        },
      },
    ],
  };
  const harness = createTestHarness(options);
  try {
    await harness.listen();
    const first = harness.getWorker('mikaki-op-worker');
    const second = harness.getWorker('mikaki-security-authentication-second');
    await first.applyD1Migrations('DB');
    const { DB } = await first.getEnv();
    const { DB: secondDB } = await second.getEnv();
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'security-authentication-test', reason: 'SEC-03/04 attack matrix' },
    );
    const sourceCommit = execFileSync('/usr/bin/git', ['rev-parse', 'HEAD'], {
      cwd: root,
      encoding: 'utf8',
    }).trim();
    for (const worker of [first, second]) {
      const response = await worker.fetch(`${issuer}/version`);
      assert.equal(response.status, 200);
      assert.equal(
        ((await response.json()) as { source_commit: string }).source_commit,
        sourceCommit,
        'rebuild the packaged OP for this revision',
      );
    }

    const clients: [Client, Client] = [
      { id: randomUUID(), callback: 'https://alpha.example/oidc/callback' },
      { id: randomUUID(), callback: 'https://bravo.example/oidc/callback' },
    ];
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('credential','owner',1)"),
      DB.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256',?)").bind(
        JSON.stringify(publicJwk),
      ),
      DB.prepare("INSERT INTO sso_session VALUES('sso','owner','credential',1,?,0)").bind(
        now + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(digest('cookie-secret'), now),
    ]);
    for (const client of clients) {
      await registerNativeClient(
        DB,
        {
          client_id: client.id,
          sector_identifier: new URL(client.callback).hostname,
          redirect_uris: [client.callback],
        },
        'security-test',
        'SEC-03/04 client isolation',
      );
      await DB.prepare(
        'INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES(?,?,1,1)',
      )
        .bind('owner', client.id)
        .run();
      await DB.prepare(
        "UPDATE app_connection SET reviewed_redirect_uri=?,reviewed_scope='openid',reviewed_client_revision=1,reviewed_grant_version=1 WHERE account_id='owner' AND client_id=?",
      )
        .bind(client.callback, client.id)
        .run();
    }
    assert.equal(
      await secondDB.prepare('SELECT count(*) AS n FROM client').first('n'),
      3,
      'both isolates share the same D1 authority',
    );

    async function authorize(client: Client): Promise<Grant> {
      const verifier = secret();
      const state = secret();
      const nonce = secret();
      const url = new URL(`${issuer}/authorize`);
      for (const [name, value] of Object.entries({
        response_type: 'code',
        client_id: client.id,
        redirect_uri: client.callback,
        scope: 'openid',
        state,
        nonce,
        code_challenge: digest(verifier),
        code_challenge_method: 'S256',
      }))
        url.searchParams.set(name, value);
      const response = await first.fetch(url, {
        headers: { Cookie: '__Host-op-sso=cookie-secret' },
        redirect: 'manual',
      });
      assert.equal(response.status, 302, await response.clone().text());
      const redirected = new URL(response.headers.get('location') ?? '');
      assert.equal(`${redirected.origin}${redirected.pathname}`, client.callback);
      assert.equal(redirected.searchParams.get('state'), state);
      assert.equal(redirected.searchParams.get('iss'), issuer);
      const code = redirected.searchParams.get('code');
      assert.ok(code);
      return { code, codeHash: codeDigest(code), verifier };
    }

    function exchange(
      worker: typeof first,
      client: Client,
      grant: Grant,
      overrides: Record<string, string> = {},
    ) {
      return worker.fetch(`${issuer}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: client.id,
          code: grant.code,
          redirect_uri: client.callback,
          code_verifier: grant.verifier,
          ...overrides,
        }).toString(),
      });
    }

    async function state(grant: Grant) {
      return {
        code: await DB.prepare(
          'SELECT client_id,consumed_by,consumed_at FROM authorization_code WHERE code_hash=?',
        )
          .bind(grant.codeHash)
          .first(),
        issues: await DB.prepare('SELECT count(*) AS n FROM token_issue WHERE code_hash=?')
          .bind(grant.codeHash)
          .first('n'),
      };
    }

    await t.test('unregistered callback receives no redirect and creates no code', async () => {
      const before = await DB.prepare('SELECT count(*) AS n FROM authorization_code').first('n');
      const url = new URL(`${issuer}/authorize`);
      const client = clients[0];
      for (const [name, value] of Object.entries({
        response_type: 'code',
        client_id: client.id,
        redirect_uri: clients[1].callback,
        scope: 'openid',
        state: secret(),
        nonce: secret(),
        code_challenge: digest(secret()),
        code_challenge_method: 'S256',
      }))
        url.searchParams.set(name, value);
      const response = await first.fetch(url, {
        headers: { Cookie: '__Host-op-sso=cookie-secret' },
        redirect: 'manual',
      });
      assert.equal(response.status, 400);
      assert.equal(response.headers.get('location'), null);
      assert.equal(
        await DB.prepare('SELECT count(*) AS n FROM authorization_code').first('n'),
        before,
      );
    });

    await t.test('client, callback and PKCE substitutions do not consume the code', async () => {
      const grant = await authorize(clients[0]);
      for (const [client, overrides] of [
        [clients[1], {}],
        [clients[0], { redirect_uri: clients[1].callback }],
        [clients[0], { code_verifier: secret() }],
      ] as const) {
        const response = await exchange(first, client, grant, overrides);
        assert.equal(response.status, 400);
        assert.equal(((await response.json()) as { error: string }).error, 'invalid_grant');
        assert.deepEqual(await state(grant), {
          code: { client_id: clients[0].id, consumed_by: null, consumed_at: null },
          issues: 0,
        });
      }
      assert.equal((await exchange(first, clients[0], grant)).status, 200);
      assert.equal((await state(grant)).issues, 1);
    });

    await t.test(
      'parallel exchange across isolates has one issuer and revokes its raced token',
      async () => {
        const grant = await authorize(clients[0]);
        const responses = await Promise.all([
          exchange(first, clients[0], grant),
          exchange(second, clients[0], grant),
        ]);
        assert.deepEqual(responses.map((response) => response.status).sort(), [200, 400]);
        const stored = await DB.prepare(
          'SELECT count(*) AS n,min(revoked) AS minimum,max(revoked) AS maximum FROM token_issue WHERE code_hash=?',
        )
          .bind(grant.codeHash)
          .first();
        assert.deepEqual(stored, { n: 1, minimum: 1, maximum: 1 });
        assert.ok((await state(grant)).code.consumed_by);
      },
    );

    await t.test('valid replay revokes only the matching code issuance', async () => {
      const protectedGrant = await authorize(clients[1]);
      const protectedResponse = await exchange(first, clients[1], protectedGrant);
      assert.equal(protectedResponse.status, 200);
      const protectedToken = (await protectedResponse.json()) as { access_token: string };
      const replayedGrant = await authorize(clients[0]);
      const replayedResponse = await exchange(first, clients[0], replayedGrant);
      assert.equal(replayedResponse.status, 200);
      const replayedToken = (await replayedResponse.json()) as { access_token: string };
      assert.equal((await exchange(second, clients[0], replayedGrant)).status, 400);
      assert.equal(
        await DB.prepare('SELECT revoked FROM token_issue WHERE access_hash=?')
          .bind(digest(replayedToken.access_token))
          .first('revoked'),
        1,
      );
      assert.equal(
        await DB.prepare('SELECT revoked FROM token_issue WHERE access_hash=?')
          .bind(digest(protectedToken.access_token))
          .first('revoked'),
        0,
      );
    });
  } finally {
    await harness.close();
  }
});
