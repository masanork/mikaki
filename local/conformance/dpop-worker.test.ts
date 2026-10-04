import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const issuer = 'https://issuer.example';
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const codeDigest = (value: string) =>
  createHash('sha256').update(Buffer.from(value, 'base64url')).digest('base64url');
const secret = () => randomBytes(32).toString('base64url');

test('Rust Worker DPoP issuance and durable cross-worker resource authorization', async (t) => {
  const op = await generateKeyPair('ES256', { extractable: true });
  const client = await generateKeyPair('ES256', { extractable: true });
  const sender = await generateKeyPair('ES256', { extractable: true });
  const other = await generateKeyPair('ES256', { extractable: true });
  const opPublic = { ...(await exportJWK(op.publicKey)), kid: 'op', alg: 'ES256' };
  const clientPublic = await exportJWK(client.publicKey);
  const senderPublic = await exportJWK(sender.publicKey);
  const otherPublic = await exportJWK(other.publicKey);
  const jkt = await calculateJwkThumbprint(senderPublic);
  const privateJwk = { ...(await exportJWK(op.privateKey)), kid: 'op', alg: 'ES256' };
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.vars = { MIKAKI_ISSUER: issuer, OP_PRIVATE_JWK: JSON.stringify(privateJwk) };
  const options = {
    root: new URL('../..', import.meta.url).pathname,
    workers: [{ config }, { config: { ...config, name: 'mikaki-dpop-second' } }],
  };
  const harness = createTestHarness(options);
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    const second = harness.getWorker('mikaki-dpop-second');
    await worker.applyD1Migrations('DB');
    let { DB } = await worker.getEnv();
    const { DB: secondDB } = await second.getEnv();
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      {
        actor: 'dpop-worker-test',
        reason: 'durable sender constraint verification',
      },
    );
    const now = () => Math.floor(Date.now() / 1000);
    assert.ok(clientPublic.x && clientPublic.y);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('account',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('credential','account',1)"),
      DB.prepare(
        "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'https://rp.example')",
      ),
      DB.prepare(
        "INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES('rp','https://rp.example/callback')",
      ),
      DB.prepare("INSERT INTO client_key VALUES('rp','client',1,1,'ES256',?)").bind(
        Buffer.concat([
          Buffer.from([4]),
          Buffer.from(clientPublic.x, 'base64url'),
          Buffer.from(clientPublic.y, 'base64url'),
        ]),
      ),
      DB.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256',?)").bind(
        JSON.stringify(opPublic),
      ),
      DB.prepare("INSERT INTO app_connection VALUES('account','rp',1,1)"),
      DB.prepare("INSERT INTO sso_session VALUES('sso','account','credential',1,?,0)").bind(
        now() + 3600,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('sso','sso-secret',?)").bind(now()),
      DB.prepare(
        "INSERT INTO client_session VALUES('rp','sid','sso','account','pairwise-sub',1,0)",
      ),
    ]);
    assert.equal(
      await secondDB.prepare("SELECT count(*) AS n FROM client WHERE client_id='rp'").first('n'),
      1,
      'two distinct Worker instances share this D1',
    );
    async function grant(scope = 'openid') {
      const code = secret(),
        verifier = secret();
      await DB.batch([
        DB.prepare(
          "INSERT INTO authorization_code(code_hash,client_id,sid,client_revision,redirect_uri,pkce_challenge,expires_at,consumed_by,consumed_at) VALUES(?,'rp','sid',(SELECT revision FROM client WHERE client_id='rp'),'https://rp.example/callback',?,?,NULL,NULL)",
        ).bind(codeDigest(code), digest(verifier), now() + 60),
        DB.prepare("INSERT INTO code_context(code_hash,nonce,scope) VALUES(?,'nonce',?)").bind(
          codeDigest(code),
          scope,
        ),
      ]);
      return { code, verifier };
    }
    async function proof(
      overrides: Record<string, unknown> = {},
      resourceToken?: string,
      key = sender,
    ) {
      const publicJwk = key === sender ? senderPublic : otherPublic;
      return new SignJWT({
        jti: randomUUID(),
        iat: now(),
        htm: resourceToken ? 'GET' : 'POST',
        htu: `${issuer}/${resourceToken ? 'userinfo' : 'token'}`,
        ...(resourceToken ? { ath: digest(resourceToken) } : {}),
        ...overrides,
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk })
        .sign(key.privateKey);
    }
    async function exchange(
      input: Awaited<ReturnType<typeof grant>>,
      compact?: string,
      audience: string | string[] = `${issuer}/token`,
      notBefore?: number,
    ) {
      let builder = new SignJWT({ jti: randomUUID() })
        .setProtectedHeader({ alg: 'ES256', kid: 'client' })
        .setIssuer('rp')
        .setSubject('rp')
        .setAudience(audience)
        .setIssuedAt(now())
        .setExpirationTime(now() + 60);
      if (notBefore !== undefined) builder = builder.setNotBefore(notBefore);
      const assertion = await builder.sign(client.privateKey);
      return worker.fetch(`${issuer}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          ...(compact ? { DPoP: compact } : {}),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: 'rp',
          code: input.code,
          redirect_uri: 'https://rp.example/callback',
          code_verifier: input.verifier,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: assertion,
        }).toString(),
      });
    }
    const resource = (
      token: string,
      compact?: string,
      scheme = 'DPoP',
      target = worker,
      method = 'GET',
    ) =>
      target.fetch(`${issuer}/userinfo`, {
        method,
        headers: { Authorization: `${scheme} ${token}`, ...(compact ? { DPoP: compact } : {}) },
      });
    const issuedGrant = await grant();
    const tokenProof = await proof();
    const response = await exchange(issuedGrant, tokenProof);
    assert.equal(
      response.status,
      200,
      JSON.stringify({
        body: await response.clone().text(),
        used: await DB.prepare('SELECT count(*) AS n FROM dpop_proof_use').first('n'),
        dbNow: await DB.prepare("SELECT strftime('%s','now') AS n").first('n'),
        now: now(),
      }),
    );
    const tokens = (await response.json()) as { access_token: string; token_type: string };
    assert.equal(tokens.token_type, 'DPoP');
    const token = tokens.access_token;

    await t.test(
      'unbound issuance keeps its existing Bearer contract and malformed DPoP never consumes a code',
      async () => {
        const input = await grant();
        assert.equal((await exchange(input, 'malformed.proof.value')).status, 400);
        assert.equal(
          await DB.prepare('SELECT consumed_by FROM authorization_code WHERE code_hash=?')
            .bind(codeDigest(input.code))
            .first('consumed_by'),
          null,
        );
        const reply = await exchange(input);
        assert.equal(reply.status, 200);
        const bearer = (await reply.json()) as { token_type: string; access_token: string };
        assert.equal(bearer.token_type, 'Bearer');
        assert.equal((await resource(bearer.access_token, undefined, 'Bearer')).status, 200);
        assert.equal(
          (await resource(bearer.access_token, await proof({}, bearer.access_token))).status,
          401,
        );
      },
    );

    await t.test(
      'issuance persists immutable thumbprint, stores only proof identifier hashes, advertises ES256',
      async () => {
        const row = await DB.prepare('SELECT dpop_jkt FROM token_issue WHERE access_hash=?')
          .bind(digest(token))
          .first();
        assert.equal(row.dpop_jkt, jkt);
        await assert.rejects(
          DB.prepare('UPDATE token_issue SET dpop_jkt=NULL WHERE access_hash=?')
            .bind(digest(token))
            .run(),
        );
        const discovery = (await (
          await worker.fetch(`${issuer}/.well-known/openid-configuration`)
        ).json()) as { dpop_signing_alg_values_supported: string[] };
        assert.deepEqual(discovery.dpop_signing_alg_values_supported, ['ES256']);
        const ledger = await DB.prepare('SELECT jti_hash FROM dpop_proof_use').all();
        assert.equal(ledger.results.length, 1);
        assert.match(ledger.results[0].jti_hash, /^[A-Za-z0-9_-]{43}$/);
      },
    );
    await t.test('profile scope is carried from the code into the token response', async () => {
      const profile = await exchange(await grant('openid profile'), await proof());
      assert.equal(profile.status, 200);
      assert.equal(((await profile.json()) as { scope: string }).scope, 'openid profile');
    });
    await t.test(
      'Bearer fallback, absent/duplicate proofs, key substitution and incorrect ath/method/URL are rejected',
      async () => {
        assert.equal((await resource(token, undefined, 'Bearer')).status, 401);
        const missing = await resource(token);
        assert.equal(missing.status, 401);
        assert.match(
          missing.headers.get('www-authenticate') ?? '',
          /DPoP error="invalid_dpop_proof"/,
        );
        assert.equal((await resource(token, await proof({}, token, other))).status, 401);
        for (const changes of [
          { ath: digest('wrong') },
          { htm: 'POST' },
          { htu: `${issuer}/token` },
          { iat: now() - 71 },
          // Keep rejected future proofs outside the 10-second allowance after transport latency.
          { iat: now() + 71 },
        ]) {
          assert.equal(
            (await resource(token, await proof(changes, token))).status,
            401,
            JSON.stringify(changes),
          );
        }
        const p = await proof({}, token);
        assert.equal((await resource(token, `${p}, ${p}`)).status, 401);
        assert.equal((await resource(token, await proof({}, token), 'dPoP')).status, 200);
        assert.equal(
          (await resource(token, await proof({ htm: 'POST' }, token), 'DPoP', worker, 'POST'))
            .status,
          200,
        );
      },
    );
    await t.test('forged signature cannot poison a valid proof identifier', async () => {
      const compact = await proof({}, token);
      const [h, c] = compact.split('.');
      assert.equal(
        (await resource(token, `${h}.${c}.${randomBytes(64).toString('base64url')}`)).status,
        401,
      );
      assert.equal((await resource(token, compact)).status, 200);
    });
    await t.test(
      'simultaneous acceptance on two Worker instances has exactly one winner',
      async () => {
        const compact = await proof({}, token);
        const responses = await Promise.all([
          resource(token, compact),
          resource(token, compact, 'DPoP', second),
        ]);
        assert.deepEqual(responses.map((r) => r.status).sort(), [200, 401]);
        assert.equal((await resource(token, compact)).status, 401);
      },
    );
    await t.test('token proof replay leaves a different authorization code unused', async () => {
      const unused = await grant();
      const denied = await exchange(unused, tokenProof);
      assert.equal(denied.status, 400);
      assert.equal(((await denied.json()) as { error: string }).error, 'invalid_dpop_proof');
      assert.equal(
        await DB.prepare('SELECT consumed_by FROM authorization_code WHERE code_hash=?')
          .bind(codeDigest(unused.code))
          .first('consumed_by'),
        null,
      );
      assert.equal((await exchange(unused, await proof())).status, 200);
    });
    await t.test('ledger survives Worker reload', async () => {
      const compact = await proof({}, token);
      assert.equal((await resource(token, compact)).status, 200);
      await harness.update({
        ...options,
        workers: options.workers.map(({ config }) => ({
          config: { ...config, vars: { ...config.vars, RELOAD_MARKER: '1' } },
        })),
      });
      DB = (await worker.getEnv()).DB;
      assert.equal((await resource(token, compact)).status, 401);
      assert.equal((await resource(token, await proof({}, token))).status, 200);
    });
    await t.test(
      'bounded ledger fails closed at capacity and expired records are reclaimed',
      async () => {
        const marker = 'A'.repeat(43);
        await DB.prepare(
          "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 10000-(SELECT count(*) FROM dpop_proof_use)) INSERT INTO dpop_proof_use SELECT ?,printf('%043d',i),printf('%043d',i),strftime('%s','now')+70 FROM n",
        )
          .bind(marker)
          .run();
        assert.equal(
          await DB.prepare('SELECT count(*) AS n FROM dpop_proof_use').first('n'),
          10000,
        );
        const compact = await proof({}, token);
        assert.equal((await resource(token, compact)).status, 401);
        const input = await grant();
        assert.equal((await exchange(input, await proof())).status, 400);
        await DB.prepare(
          "UPDATE dpop_proof_use SET retain_until=strftime('%s','now')-1 WHERE jkt=?",
        )
          .bind(marker)
          .run();
        assert.equal((await resource(token, compact)).status, 200);
        assert.equal(
          await DB.prepare('SELECT count(*) AS n FROM dpop_proof_use WHERE jkt=?')
            .bind(marker)
            .first('n'),
          0,
        );
        assert.equal((await exchange(input, await proof())).status, 200);
      },
    );
    await t.test(
      'database write failure denies access and rolls back replay reservation',
      async () => {
        const compact = await proof({}, token);
        await DB.prepare(
          "CREATE TRIGGER fail_dpop BEFORE INSERT ON dpop_proof_use BEGIN SELECT RAISE(ABORT,'test storage failure'); END",
        ).run();
        assert.equal((await resource(token, compact)).status, 503);
        await DB.prepare('DROP TRIGGER fail_dpop').run();
        assert.equal((await resource(token, compact)).status, 200);
      },
    );
    await t.test(
      'token write failure rolls back code consumption and cannot fall back to Bearer',
      async () => {
        const input = await grant();
        const compact = await proof();
        await DB.prepare(
          "CREATE TRIGGER fail_token BEFORE INSERT ON token_issue BEGIN SELECT RAISE(ABORT,'test token failure'); END",
        ).run();
        assert.equal((await exchange(input, compact)).status, 500);
        await DB.prepare('DROP TRIGGER fail_token').run();
        assert.equal(
          await DB.prepare('SELECT consumed_by FROM authorization_code WHERE code_hash=?')
            .bind(codeDigest(input.code))
            .first('consumed_by'),
          null,
        );
        assert.equal(
          (await exchange(input, compact)).status,
          400,
          'accepted proof remains reserved even when grant fails',
        );
        assert.equal((await exchange(input, await proof())).status, 200);
      },
    );
    await t.test(
      'expiry, revocation, account epoch, parent session and consent are authoritative at resource acceptance',
      async () => {
        for (const [sql, restore] of [
          [
            'UPDATE token_issue SET revoked=1 WHERE access_hash=?',
            'UPDATE token_issue SET revoked=0 WHERE access_hash=?',
          ],
          [
            'UPDATE token_issue SET access_expires_at=1 WHERE access_hash=?',
            "UPDATE token_issue SET access_expires_at=strftime('%s','now')+60 WHERE access_hash=?",
          ],
        ]) {
          const compact = await proof({}, token);
          await DB.prepare(sql).bind(digest(token)).run();
          assert.equal((await resource(token, compact)).status, 401);
          await DB.prepare(restore).bind(digest(token)).run();
          assert.equal(
            (await resource(token, compact)).status,
            200,
            'invalid token did not reserve the proof',
          );
        }
        for (const [sql, restore] of [
          ['UPDATE account_security SET epoch=2', 'UPDATE account_security SET epoch=1'],
          ['UPDATE sso_session SET revoked=1', 'UPDATE sso_session SET revoked=0'],
          ['UPDATE app_connection SET active=0', 'UPDATE app_connection SET active=1'],
          ['UPDATE client SET active=0,revision=2', 'UPDATE client SET active=1,revision=3'],
        ]) {
          await DB.prepare(sql).run();
          assert.equal((await resource(token, await proof({}, token))).status, 401);
          await DB.prepare(restore).run();
        }
      },
    );
    await t.test('D1 nonces challenge, retry and rotate independently for AS and RS', async () => {
      await harness.update({
        ...options,
        workers: options.workers.map(({ config }) => ({
          config: { ...config, vars: { ...config.vars, MIKAKI_DPOP_NONCE_MODE: 'required' } },
        })),
      });
      DB = (await worker.getEnv()).DB;
      const input = await grant();
      const jti = randomUUID();
      const before = await DB.prepare('SELECT count(*) AS n FROM client_auth_use').first('n');
      const challenged = await exchange(input, await proof({ jti }));
      assert.equal(challenged.status, 400);
      assert.equal(((await challenged.json()) as { error: string }).error, 'use_dpop_nonce');
      const asNonce = challenged.headers.get('dpop-nonce');
      assert.match(asNonce ?? '', /^[A-Za-z0-9_-]{43}$/);
      assert.equal(
        await DB.prepare('SELECT count(*) AS n FROM client_auth_use').first('n'),
        before,
        'nonce challenge precedes client-assertion consumption',
      );
      const accepted = await exchange(input, await proof({ jti, nonce: asNonce }));
      assert.equal(accepted.status, 200, await accepted.clone().text());
      const bound = (await accepted.json()) as { access_token: string; token_type: string };
      assert.equal(bound.token_type, 'DPoP');

      const missingRs = await resource(bound.access_token);
      assert.equal(missingRs.status, 401);
      assert.match(missingRs.headers.get('www-authenticate') ?? '', /DPoP error="use_dpop_nonce"/);
      const rsNonce = missingRs.headers.get('dpop-nonce');
      assert.match(rsNonce ?? '', /^[A-Za-z0-9_-]{43}$/);
      assert.notEqual(rsNonce, asNonce, 'AS and RS have distinct nonce domains');
      const wrongScope = await resource(
        bound.access_token,
        await proof({ nonce: asNonce }, bound.access_token),
      );
      assert.equal(wrongScope.status, 401);
      assert.equal(wrongScope.headers.get('dpop-nonce'), rsNonce);
      assert.equal(
        (await resource(bound.access_token, await proof({ nonce: rsNonce }, bound.access_token)))
          .status,
        200,
      );
      assert.equal(
        (
          await resource(
            bound.access_token,
            await proof({ nonce: rsNonce }, bound.access_token),
            'DPoP',
            second,
          )
        ).status,
        200,
      );

      await DB.prepare(
        "UPDATE dpop_nonce SET challenge_until=strftime('%s','now')-1,accept_until=strftime('%s','now')+59 WHERE scope='as'",
      ).run();
      const overlap = await exchange(await grant(), await proof({ nonce: asNonce }));
      assert.equal(overlap.status, 200, 'recent nonce remains valid during rotation');
      const nextAs = await DB.prepare(
        "SELECT nonce FROM dpop_nonce WHERE scope='as' ORDER BY challenge_until DESC LIMIT 1",
      ).first('nonce');
      assert.notEqual(nextAs, asNonce);
      await DB.prepare(
        "UPDATE dpop_nonce SET challenge_until=1,accept_until=61 WHERE scope='as' AND nonce=?",
      )
        .bind(asNonce)
        .run();
      const expired = await exchange(await grant(), await proof({ nonce: asNonce }));
      assert.equal(expired.status, 400);
      assert.equal(((await expired.json()) as { error: string }).error, 'use_dpop_nonce');
      assert.equal(expired.headers.get('dpop-nonce'), nextAs);
      assert.equal(
        await DB.prepare('SELECT count(*) AS n FROM dpop_nonce WHERE scope=?')
          .bind('as')
          .first('n'),
        1,
      );
    });
    await t.test(
      'authenticated PAR is required, bound to its client, and consumed with code issuance',
      async () => {
        await harness.update({
          ...options,
          workers: options.workers.map(({ config }) => ({
            config: { ...config, vars: { ...config.vars, MIKAKI_PAR_MODE: 'required' } },
          })),
        });
        DB = (await worker.getEnv()).DB;
        const discovery = (await (
          await worker.fetch(`${issuer}/.well-known/openid-configuration`)
        ).json()) as Record<string, unknown>;
        assert.equal(discovery.pushed_authorization_request_endpoint, `${issuer}/par`);
        assert.equal(discovery.require_pushed_authorization_requests, true);
        const verifier = secret();
        const authorization = {
          client_id: 'rp',
          response_type: 'code',
          scope: 'openid',
          redirect_uri: 'https://rp.example/callback',
          state: secret(),
          nonce: secret(),
          code_challenge: digest(verifier),
          code_challenge_method: 'S256',
        };
        const direct = await worker.fetch(
          `${issuer}/authorize?${new URLSearchParams(authorization)}`,
        );
        assert.equal(direct.status, 400);
        const assertion = async () =>
          new SignJWT({ jti: randomUUID() })
            .setProtectedHeader({ alg: 'ES256', kid: 'client' })
            .setIssuer('rp')
            .setSubject('rp')
            .setAudience(issuer)
            .setIssuedAt(now())
            .setExpirationTime(now() + 60)
            .sign(client.privateKey);
        const push = async (extra: Record<string, string> = {}) =>
          worker.fetch(`${issuer}/par`, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              ...authorization,
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
              client_assertion: await assertion(),
              ...extra,
            }).toString(),
          });
        const pushed = await push({ dpop_jkt: jkt });
        assert.equal(pushed.status, 201, await pushed.clone().text());
        const { request_uri: requestUri } = (await pushed.json()) as { request_uri: string };
        const reference = `${issuer}/authorize?${new URLSearchParams({ client_id: 'rp', request_uri: requestUri })}`;
        assert.equal(
          (await worker.fetch(`${reference}&state=replace`, { redirect: 'manual' })).status,
          302,
        );
        assert.equal(
          (
            await worker.fetch(
              `${issuer}/authorize?${new URLSearchParams({ client_id: 'other', request_uri: requestUri })}`,
            )
          ).status,
          400,
        );
        assert.equal(
          await DB.prepare('SELECT consumed_by FROM par_request WHERE request_uri=?')
            .bind(requestUri)
            .first('consumed_by'),
          null,
        );
        const preload = await worker.fetch(reference, { redirect: 'manual' });
        assert.equal(preload.status, 302, 'a login redirect does not consume PAR');
        assert.equal(
          await DB.prepare('SELECT consumed_by FROM par_request WHERE request_uri=?')
            .bind(requestUri)
            .first('consumed_by'),
          null,
        );
        const stale = await push();
        assert.equal(stale.status, 201);
        const staleUri = ((await stale.json()) as { request_uri: string }).request_uri;
        await DB.prepare(
          "UPDATE par_request SET expires_at=strftime('%s','now')-1 WHERE request_uri=?",
        )
          .bind(staleUri)
          .run();
        assert.equal(
          (
            await worker.fetch(
              `${issuer}/authorize?${new URLSearchParams({ client_id: 'rp', request_uri: staleUri })}`,
            )
          ).status,
          400,
        );
        const revision = await push();
        assert.equal(revision.status, 201);
        const revisionUri = ((await revision.json()) as { request_uri: string }).request_uri;
        await DB.prepare('UPDATE client_key SET revision=revision+1 WHERE client_id=?')
          .bind('rp')
          .run();
        assert.equal(
          (
            await worker.fetch(
              `${issuer}/authorize?${new URLSearchParams({ client_id: 'rp', request_uri: revisionUri })}`,
            )
          ).status,
          400,
        );
        await DB.prepare('UPDATE client_key SET revision=revision-1 WHERE client_id=?')
          .bind('rp')
          .run();
        const cookie = secret();
        await DB.prepare('UPDATE sso_context SET secret_hash=?').bind(digest(cookie)).run();
        const withCookie = () =>
          worker.fetch(reference, {
            headers: { Cookie: `__Host-op-sso=${cookie}` },
            redirect: 'manual',
          });
        const response = await withCookie();
        assert.equal(response.status, 302, await response.clone().text());
        const location = new URL(response.headers.get('location') ?? '');
        assert.equal(location.searchParams.get('state'), authorization.state);
        const code = location.searchParams.get('code');
        assert.ok(code);
        assert.equal(
          (await withCookie()).status,
          400,
          'the second completion cannot issue another code',
        );
        assert.equal(
          await DB.prepare('SELECT dpop_jkt FROM authorization_code WHERE code_hash=?')
            .bind(codeDigest(code))
            .first('dpop_jkt'),
          jkt,
        );
        const missingProof = await exchange({ code, verifier });
        assert.equal(missingProof.status, 400);
        assert.equal(
          (await exchange({ code, verifier }, await proof({}, undefined, other))).status,
          400,
        );
        const accepted = await exchange({ code, verifier }, await proof());
        assert.equal(accepted.status, 200, await accepted.clone().text());
        assert.equal(((await accepted.json()) as { token_type: string }).token_type, 'DPoP');
      },
    );
    await t.test(
      'FAPI profile requires issuer assertions, PAR provenance and DPoP tokens',
      async () => {
        await harness.update({
          ...options,
          workers: options.workers.map(({ config }) => ({
            config: { ...config, vars: { ...config.vars, MIKAKI_DEPLOYMENT_PROFILE: 'fapi2' } },
          })),
        });
        DB = (await worker.getEnv()).DB;
        const metadata = (await (
          await worker.fetch(`${issuer}/.well-known/openid-configuration`)
        ).json()) as Record<string, unknown>;
        assert.equal(metadata.require_pushed_authorization_requests, true);
        assert.equal(metadata.claims_parameter_supported, false);
        assert.equal((metadata.claims_supported as string[]).includes('verified_claims'), false);
        assert.deepEqual(metadata.token_endpoint_auth_signing_alg_values_supported, ['ES256']);
        assert.deepEqual(metadata.grant_types_supported, ['authorization_code']);
        const verifier = secret();
        const params = {
          client_id: 'rp',
          response_type: 'code',
          scope: 'openid',
          redirect_uri: 'https://rp.example/callback',
          state: secret(),
          nonce: secret(),
          code_challenge: digest(verifier),
          code_challenge_method: 'S256',
        };
        const direct = await worker.fetch(`${issuer}/authorize?client_id=rp`, {
          headers: { 'Accept-Language': 'en' },
          redirect: 'manual',
        });
        assert.equal(direct.status, 400);
        assert.match(await direct.text(), /missing a pushed authorization request/);
        const push = async (audience: string | string[], nbf?: number) => {
          let jwt = new SignJWT({ jti: randomUUID() })
            .setProtectedHeader({ alg: 'ES256', kid: 'client' })
            .setIssuer('rp')
            .setSubject('rp')
            .setAudience(audience)
            .setIssuedAt(now())
            .setExpirationTime(now() + 60);
          if (nbf !== undefined) jwt = jwt.setNotBefore(nbf);
          return worker.fetch(`${issuer}/par`, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              ...params,
              dpop_jkt: jkt,
              client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
              client_assertion: await jwt.sign(client.privateKey),
            }).toString(),
          });
        };
        assert.equal((await push(`${issuer}/par`)).status, 401);
        assert.equal((await push([issuer])).status, 401);
        assert.equal((await push(issuer, now() + 11)).status, 401);
        const par = await push(issuer, now() + 10);
        assert.equal(par.status, 201, await par.clone().text());
        const requestUri = ((await par.json()) as { request_uri: string }).request_uri;
        const reference = `${issuer}/authorize?${new URLSearchParams({ client_id: 'rp', request_uri: requestUri })}`;
        const pending = await worker.fetch(
          `${reference}&redirect_uri=${encodeURIComponent('https://wrong.example/callback')}`,
          { redirect: 'manual' },
        );
        assert.equal(pending.status, 302);
        const browserCookie = pending.headers.get('set-cookie')?.split(';')[0];
        assert.ok(browserCookie);
        const login = await worker.fetch(pending.headers.get('location') ?? '', {
          headers: { Cookie: browserCookie },
        });
        assert.equal(login.status, 200, await login.clone().text());
        assert.match(await login.text(), /data-rp-uri="https:\/\/rp\.example\/callback"/);
        const tx = new URL(pending.headers.get('location') ?? '').searchParams.get('tx');
        assert.ok(tx);
        const deny = () =>
          worker.fetch(`${issuer}/login/deny`, {
            method: 'POST',
            headers: {
              Cookie: browserCookie,
              Origin: issuer,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ tx }),
          });
        const denied = await deny();
        assert.equal(denied.status, 200);
        const deniedLocation = ((await denied.json()) as { location: string }).location;
        const deniedUrl = new URL(deniedLocation);
        assert.equal(deniedUrl.searchParams.get('error'), 'access_denied');
        assert.equal(deniedUrl.searchParams.get('state'), params.state);
        assert.equal((await deny()).status, 400);
        const cookie = secret();
        await DB.prepare('UPDATE sso_context SET secret_hash=?').bind(digest(cookie)).run();
        const authorized = await worker.fetch(reference, {
          headers: { Cookie: `__Host-op-sso=${cookie}` },
          redirect: 'manual',
        });
        assert.equal(authorized.status, 302, await authorized.clone().text());
        const code = new URL(authorized.headers.get('location') ?? '').searchParams.get('code');
        assert.ok(code);
        assert.equal((await exchange({ code, verifier }, undefined, issuer)).status, 400);
        const challenge = await exchange({ code, verifier }, await proof(), issuer);
        assert.equal(challenge.status, 400);
        assert.equal(((await challenge.json()) as { error: string }).error, 'use_dpop_nonce');
        const asNonce = challenge.headers.get('dpop-nonce');
        assert.match(asNonce ?? '', /^[A-Za-z0-9_-]{43}$/);
        assert.equal(
          (await exchange({ code, verifier }, await proof({ nonce: asNonce }), `${issuer}/token`))
            .status,
          401,
        );
        assert.equal(
          (await exchange({ code, verifier }, await proof({ nonce: asNonce }), [issuer])).status,
          401,
        );
        assert.equal(
          (await exchange({ code, verifier }, await proof({ nonce: asNonce }), issuer, now() + 11))
            .status,
          401,
        );
        const issued = await exchange(
          { code, verifier },
          await proof({ nonce: asNonce }),
          issuer,
          now() + 10,
        );
        assert.equal(issued.status, 200, await issued.clone().text());
        const bound = (await issued.json()) as {
          token_type: string;
          access_token: string;
          refresh_token?: string;
        };
        assert.equal(bound.token_type, 'DPoP');
        assert.equal(bound.refresh_token, undefined);
        assert.equal((await resource(bound.access_token, undefined, 'Bearer')).status, 401);
        const resourceChallenge = await resource(
          bound.access_token,
          await proof({}, bound.access_token),
        );
        assert.equal(resourceChallenge.status, 401);
        const rsNonce = resourceChallenge.headers.get('dpop-nonce');
        assert.match(rsNonce ?? '', /^[A-Za-z0-9_-]{43}$/);
        assert.equal(
          (await resource(bound.access_token, await proof({ nonce: rsNonce }, bound.access_token)))
            .status,
          200,
        );
        assert.equal(
          (await exchange(await grant(), await proof({ nonce: asNonce }), issuer)).status,
          400,
        );
        const competing = await push(issuer);
        assert.equal(competing.status, 201);
        const competingUri = ((await competing.json()) as { request_uri: string }).request_uri;
        const competingUrl = `${issuer}/authorize?${new URLSearchParams({ client_id: 'rp', request_uri: competingUri })}`;
        const outcomes = await Promise.all(
          [worker, second].map((target) =>
            target.fetch(competingUrl, {
              headers: { Cookie: `__Host-op-sso=${cookie}` },
              redirect: 'manual',
            }),
          ),
        );
        assert.deepEqual(outcomes.map((response) => response.status).sort(), [302, 400]);
      },
    );
  } finally {
    await harness.close();
  }
});
