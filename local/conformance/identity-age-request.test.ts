import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const issuer = 'https://mikaki.test';
const redirect = 'https://rp.example/cb';
const now = () => Math.floor(Date.now() / 1000);
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
const codeHash = (value: string) =>
  createHash('sha256').update(Buffer.from(value, 'base64url')).digest('base64url');
const secret = () => randomBytes(32).toString('base64url');
const claims = (names = [':age_over_18'], expected?: boolean) =>
  JSON.stringify({
    userinfo: {
      mikaki_linked_document: {
        attributes: Object.fromEntries(
          names.map((name) => [
            name,
            expected === undefined ? null : { essential: true, value: expected },
          ]),
        ),
      },
    },
    _asc: {
      transformed_claims: {
        age_over_18: { claim: 'birthdate', fn: ['years_ago', ['gte', 18]] },
        age_over_20: { claim: 'birthdate', fn: ['years_ago', ['gte', 20]] },
      },
    },
  });

for (const algorithm of ['ES256', 'RS256'] as const)
  test(`${algorithm}: authenticated age PAR binds code, release and signed minimal UserInfo with durable audit`, async () => {
    const opKey = await generateKeyPair(algorithm, { extractable: true });
    const client = await generateKeyPair('ES256', { extractable: true });
    const sender = await generateKeyPair('ES256', { extractable: true });
    const clientJwk = await exportJWK(client.publicKey);
    const senderJwk = await exportJWK(sender.publicKey);
    const jkt = await calculateJwkThumbprint(senderJwk);
    const publicJwk = { ...(await exportJWK(opKey.publicKey)), kid: 'op', alg: algorithm };
    const privateJwk = { ...(await exportJWK(opKey.privateKey)), kid: 'op', alg: algorithm };
    const policy = JSON.stringify([
      {
        id: 'fixture',
        document_type: 'my_number_card',
        n: Buffer.alloc(256, 7).toString('base64url'),
        e: 'AQAB',
        subject_key_identifier: null,
        not_before: now() - 60,
        not_after: now() + 3600,
      },
    ]);
    const config = JSON.parse(
      await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
    );
    config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
    config.d1_databases[0].migrations_dir = new URL(
      '../../crates/worker/migrations',
      import.meta.url,
    ).pathname;
    config.queues.consumers = [];
    config.vars = {
      MIKAKI_ISSUER: issuer,
      OP_PRIVATE_JWK: JSON.stringify(privateJwk),
      MIKAKI_PAR_MODE: 'required',
      IDENTITY_ENABLED: 'true',
      IDENTITY_USERINFO_ENABLED: 'true',
      IDENTITY_AGE_REQUESTS_ENABLED: 'true',
      IDENTITY_TRUSTED_KEYS: policy,
    };
    const harness = createTestHarness({
      root: new URL('../..', import.meta.url).pathname,
      workers: [
        { config },
        {
          config: {
            ...config,
            name: 'age-disabled',
            vars: { ...config.vars, IDENTITY_AGE_REQUESTS_ENABLED: 'false' },
          },
        },
      ],
    });
    try {
      await harness.listen();
      const worker = harness.getWorker('mikaki-op-worker');
      const disabled = harness.getWorker('age-disabled');
      await worker.applyD1Migrations('DB');
      const { DB } = await worker.getEnv();
      await activateWorkerPolicy(
        DB,
        JSON.parse(
          await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
        ),
        { actor: 'identity-age-test', reason: 'authenticated age request qualification' },
      );
      await DB.batch([
        DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
        DB.prepare("INSERT INTO credential VALUES('passkey','owner',1)"),
        DB.prepare(
          "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'https://rp.example')",
        ),
        DB.prepare("INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES('rp',?)").bind(
          redirect,
        ),
        DB.prepare("INSERT INTO client_key VALUES('rp','client',1,1,'ES256',?)").bind(
          Buffer.concat([
            Buffer.from([4]),
            Buffer.from(clientJwk.x!, 'base64url'),
            Buffer.from(clientJwk.y!, 'base64url'),
          ]),
        ),
        DB.prepare("INSERT INTO signing_key VALUES('op',1,1,?,?)").bind(
          algorithm,
          JSON.stringify(publicJwk),
        ),
        DB.prepare(
          "INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES('owner','rp',1,1)",
        ),
        DB.prepare("INSERT INTO sso_session VALUES('sso','owner','passkey',1,?,0)").bind(
          now() + 7200,
        ),
        DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(hash('cookie'), now()),
      ]);
      await DB.prepare(
        "UPDATE app_connection SET reviewed_redirect_uri=?,reviewed_scope='openid profile',reviewed_client_revision=1,reviewed_grant_version=1",
      )
        .bind(redirect)
        .run();
      const document = secret();
      const verified = {
        attributes: {
          name: 'PRIVATE NAME',
          address: 'PRIVATE ADDRESS',
          birth_date: '1990-02-28',
          gender: '1',
          verification: 'verified',
          document_type: 'my_number_card',
          expiry_date: null,
          backend_verifiable: true,
        },
        trusted_key_id: 'fixture',
        verified_at: now() - 10,
        assurance: 'issuer_signed_static_data',
        attributes_source: 'my_number_card',
      };
      await DB.prepare(
        "INSERT INTO identity_transaction(tx_id,poll_hash,holder_json,document_json,policy_hash,created_at,expires_at,state,account_id,epoch,session_hash) VALUES(?,?,'{}',?,?,?,?,'pending','owner',1,?)",
      )
        .bind(
          document,
          secret(),
          JSON.stringify(verified),
          hash(policy),
          now(),
          now() + 600,
          hash('cookie'),
        )
        .run();
      await DB.prepare("UPDATE identity_transaction SET state='approved' WHERE tx_id=?")
        .bind(document)
        .run();
      const html = await (
        await worker.fetch(`${issuer}/identity`, { headers: { Cookie: '__Host-op-sso=cookie' } })
      ).text();
      const releaseForm = /<form method=post action=\/identity\/release>(.*?)<\/form>/s.exec(
        html,
      )![1];
      const csrf = /name=csrf value='([^']+)'/.exec(releaseForm)![1];
      const grant = async (version: number, fields: string[]) => {
        const response = await worker.fetch(`${issuer}/identity/release`, {
          method: 'POST',
          headers: {
            Cookie: '__Host-op-sso=cookie',
            Origin: issuer,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            csrf,
            document,
            recipient: JSON.stringify(['rp', 1, 1, version]),
            action: 'grant',
            ...Object.fromEntries(fields.map((field) => [field, 'on'])),
          }).toString(),
          redirect: 'manual',
        });
        assert.equal(response.status, 303, await response.clone().text());
      };
      const assertion = (endpoint: string) =>
        new SignJWT({ jti: randomUUID() })
          .setProtectedHeader({ alg: 'ES256', kid: 'client' })
          .setIssuer('rp')
          .setSubject('rp')
          .setAudience(endpoint)
          .setIssuedAt(now())
          .setExpirationTime(now() + 60)
          .sign(client.privateKey);
      const push = async (
        raw = claims(),
        target = worker,
        scope = 'openid profile',
        pop = false,
      ) => {
        const verifier = secret();
        const response = await target.fetch(`${issuer}/par`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: 'rp',
            response_type: 'code',
            redirect_uri: redirect,
            scope,
            state: secret(),
            nonce: secret(),
            code_challenge: hash(verifier),
            code_challenge_method: 'S256',
            prompt: 'none',
            claims: raw,
            ...(pop ? { dpop_jkt: jkt } : {}),
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: await assertion(`${issuer}/par`),
          }).toString(),
        });
        return { response, verifier };
      };
      const authorize = (uri: string, extra = '') =>
        worker.fetch(
          `${issuer}/authorize?${new URLSearchParams({ client_id: 'rp', request_uri: uri })}${extra}`,
          { headers: { Cookie: '__Host-op-sso=cookie' }, redirect: 'manual' },
        );
      const proof = async (method: string, endpoint: string, access?: string) =>
        new SignJWT({
          jti: randomUUID(),
          iat: now(),
          htm: method,
          htu: endpoint,
          ...(access ? { ath: hash(access) } : {}),
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: senderJwk })
          .sign(sender.privateKey);
      const issue = async (raw = claims(), pop = false) => {
        const { response, verifier } = await push(raw, worker, 'openid profile', pop);
        assert.equal(response.status, 201, await response.clone().text());
        const { request_uri: uri } = (await response.json()) as { request_uri: string };
        assert.equal(
          (await authorize(uri, `&claims=${encodeURIComponent(claims([':age_over_20']))}`)).status,
          400,
        );
        const authorized = await authorize(uri);
        assert.equal(authorized.status, 302, await authorized.clone().text());
        const location = new URL(authorized.headers.get('location')!);
        const code = location.searchParams.get('code');
        assert.ok(code, location.toString());
        const bound = await DB.prepare('SELECT * FROM identity_age_request WHERE code_hash=?')
          .bind(codeHash(code))
          .first();
        assert.equal(bound!.request_json, raw);
        assert.equal(bound!.request_hash, hash(raw));
        assert.equal(bound!.document_id, document);
        assert.deepEqual(
          JSON.parse(bound!.fields_json as string),
          Object.keys(JSON.parse(raw).userinfo.mikaki_linked_document.attributes).map((name) =>
            name.slice(1),
          ),
        );
        assert.equal((await authorize(uri)).status, 400, 'PAR cannot be consumed twice');
        const tokenResponse = await worker.fetch(`${issuer}/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            ...(pop ? { DPoP: await proof('POST', `${issuer}/token`) } : {}),
          },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: 'rp',
            code,
            redirect_uri: redirect,
            code_verifier: verifier,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: await assertion(`${issuer}/token`),
          }).toString(),
        });
        assert.equal(tokenResponse.status, 200, await tokenResponse.clone().text());
        const token = (await tokenResponse.json()) as { access_token: string; id_token: string };
        const id = await jwtVerify(token.id_token, opKey.publicKey, {
          issuer,
          audience: 'rp',
          algorithms: [algorithm],
        });
        return {
          ...token,
          sub: id.payload.sub!,
          code: codeHash(code),
          release: bound!.release_version,
        };
      };
      const userinfo = async (token: { access_token: string }, pop = false, target = worker) =>
        target.fetch(`${issuer}/userinfo`, {
          headers: {
            Authorization: `${pop ? 'DPoP' : 'Bearer'} ${token.access_token}`,
            ...(pop ? { DPoP: await proof('GET', `${issuer}/userinfo`, token.access_token) } : {}),
          },
        });
      const signed = async (
        token: Awaited<ReturnType<typeof issue>>,
        expected: Record<string, boolean>,
        pop = false,
      ) => {
        const response = await userinfo(token, pop);
        assert.equal(response.status, 200, await response.clone().text());
        assert.equal(response.headers.get('content-type'), 'application/jwt');
        assert.equal(response.headers.get('cache-control'), 'no-store');
        const compact = await response.text();
        const { payload, protectedHeader } = await jwtVerify(compact, opKey.publicKey, {
          issuer,
          audience: 'rp',
          algorithms: [algorithm],
          typ: 'JWT',
        });
        assert.equal(protectedHeader.kid, 'op');
        assert.equal(payload.sub, token.sub);
        assert.deepEqual(Object.keys(payload).sort(), [
          'aud',
          'exp',
          'iat',
          'iss',
          'mikaki_linked_document',
          'sub',
        ]);
        const linked = payload.mikaki_linked_document as any;
        assert.deepEqual(linked.attributes, expected);
        assert.equal(linked.evidence._mikaki.assurance, 'issuer_signed_static_data');
        assert.equal(linked.evidence._mikaki.live_possession_verified, false);
        assert.equal(linked.evidence._mikaki.government_credential, false);
        assert.equal(
          linked.evidence.check_details[0].time,
          new Date(verified.verified_at * 1000).toISOString().replace('.000Z', 'Z'),
        );
        assert.ok(payload.exp! > payload.iat! && payload.exp! - payload.iat! <= 300);
        assert.ok(
          !JSON.stringify(payload).includes('PRIVATE') &&
            !JSON.stringify(payload).includes('1990-02-28'),
        );
        await assert.rejects(jwtVerify(compact, opKey.publicKey, { issuer, audience: 'other-rp' }));
        await assert.rejects(
          jwtVerify(
            compact.replace(
              /\.([^.])([^.]+)$/,
              (_, first, rest) => '.' + (first === 'A' ? 'B' : 'A') + rest,
            ),
            opKey.publicKey,
            {
              issuer,
              audience: 'rp',
            },
          ),
        );
        const audit = await DB.prepare(
          'SELECT * FROM identity_age_audit WHERE response_digest=? AND code_hash=?',
        )
          .bind(hash(compact), token.code)
          .first();
        assert.ok(audit);
        assert.equal(audit.code_hash, token.code);
        assert.equal(audit.client_id, 'rp');
        assert.equal(audit.release_version, token.release);
        assert.equal(audit.expires_at, payload.exp);
        assert.equal(audit.signing_generation, 1);
        assert.ok(
          !JSON.stringify(audit).includes('PRIVATE') &&
            !JSON.stringify(audit).includes(token.access_token),
        );
        return compact;
      };
      assert.equal((await push(claims(), disabled)).response.status, 400);
      assert.equal((await push(claims(), worker, 'openid')).response.status, 400);
      for (const invalid of [
        '{}',
        claims().replace(':age_over_18', 'birthdate'),
        claims().replace('"gte",18', '"gte",12'),
        claims().replace('"attributes":', '"attributes":{},"attributes":'),
        claims().replace('"mikaki_linked_document":', '"verified_claims":'),
      ])
        assert.equal((await push(invalid)).response.status, 400);
      const pending = await push();
      assert.equal(pending.response.status, 201);
      const { request_uri: pendingUri } = (await pending.response.json()) as {
        request_uri: string;
      };
      const missing = await authorize(pendingUri);
      assert.equal(
        new URL(missing.headers.get('location')!).searchParams.get('error'),
        'consent_required',
      );
      assert.equal(
        await DB.prepare('SELECT consumed_by FROM par_request WHERE request_uri=?')
          .bind(pendingUri)
          .first('consumed_by'),
        null,
      );
      await grant(0, ['birthdate']);
      assert.equal(
        new URL((await authorize(pendingUri)).headers.get('location')!).searchParams.get('error'),
        'consent_required',
        'raw birthdate consent does not authorize its derivation',
      );
      await grant(1, ['name', 'birthdate', 'age_over_18', 'age_over_20']);
      const token = await issue();
      await signed(token, { ':age_over_18': true });
      assert.equal(
        (await userinfo(token, false, disabled)).status,
        403,
        'feature withdrawal cannot fall back to raw JSON',
      );
      const popToken = await issue(claims([':age_over_18', ':age_over_20']), true);
      assert.equal((await userinfo(popToken)).status, 401);
      await signed(popToken, { ':age_over_18': true, ':age_over_20': true }, true);
      await DB.prepare('UPDATE token_issue SET access_expires_at=unixepoch()+90 WHERE code_hash=?')
        .bind(token.code)
        .run();
      const compact = await signed(token, { ':age_over_18': true });
      const ttl = await jwtVerify(compact, opKey.publicKey, { issuer, audience: 'rp' });
      assert.ok(
        ttl.payload.exp! <= now() + 90,
        'signed lifetime is clipped to access token lifetime',
      );
      await DB.exec(
        "CREATE TRIGGER fail_age_audit BEFORE INSERT ON identity_age_audit BEGIN SELECT RAISE(ABORT,'fixture audit unavailable'); END",
      );
      const before = await DB.prepare('SELECT count(*) AS n FROM identity_age_audit').first('n');
      assert.equal(
        (await userinfo(token)).status,
        503,
        'audit failure suppresses the signed response',
      );
      assert.equal(
        await DB.prepare('SELECT count(*) AS n FROM identity_age_audit').first('n'),
        before,
      );
      await DB.exec('DROP TRIGGER fail_age_audit');
      const capped = await issue();
      await signed(capped, { ':age_over_18': true });
      await DB.batch(
        Array.from({ length: 99 }, () =>
          DB.prepare(
            'INSERT INTO identity_age_audit SELECT ?,code_hash,client_id,request_hash,document_id,release_version,response_digest,signing_kid,signing_generation,assurance,issued_at,expires_at FROM identity_age_audit WHERE code_hash=? LIMIT 1',
          ).bind(secret(), capped.code),
        ),
      );
      assert.equal(
        (await userinfo(capped)).status,
        403,
        'audit capacity cannot release an unrecorded response',
      );
      assert.equal(
        await DB.prepare('SELECT count(*) AS n FROM identity_age_audit WHERE code_hash=?')
          .bind(capped.code)
          .first('n'),
        100,
      );
      await assert.rejects(
        DB.prepare("UPDATE identity_age_request SET request_json='{}' WHERE code_hash=?")
          .bind(token.code)
          .run(),
        /age request must/,
      );
      await grant(2, ['name', 'birthdate', 'age_over_18', 'age_over_20']);
      assert.equal(
        (await userinfo(token)).status,
        403,
        'replaced consent needs a new authorization even if fields remain',
      );
      assert.equal((await userinfo(popToken, true)).status, 403);
      await DB.prepare(
        "UPDATE identity_document SET document_json=json_set(document_json,'$.attributes.birth_date','2010-02-28') WHERE document_id=?",
      )
        .bind(document)
        .run();
      const young = await issue();
      await signed(young, { ':age_over_18': false });
      const constrained = await push(claims([':age_over_18'], true));
      const { request_uri: constrainedUri } = (await constrained.response.json()) as {
        request_uri: string;
      };
      assert.equal(
        new URL((await authorize(constrainedUri)).headers.get('location')!).searchParams.get(
          'error',
        ),
        'access_denied',
      );
      for (const [set, restore] of [
        [
          "UPDATE identity_document SET document_json=json_set(document_json,'$.attributes.birth_date','3000-01-01')",
          "UPDATE identity_document SET document_json=json_set(document_json,'$.attributes.birth_date','2010-02-28')",
        ],
        [
          "UPDATE identity_document SET document_json=json_set(document_json,'$.assurance','live_possession')",
          "UPDATE identity_document SET document_json=json_set(document_json,'$.assurance','issuer_signed_static_data')",
        ],
        [
          "UPDATE identity_document SET document_json=json_set(document_json,'$.trusted_key_id','unknown')",
          "UPDATE identity_document SET document_json=json_set(document_json,'$.trusted_key_id','fixture')",
        ],
        [
          "UPDATE identity_document SET policy_hash='changed'",
          `UPDATE identity_document SET policy_hash='${hash(policy)}'`,
        ],
        [
          'UPDATE identity_claim_release SET expires_at=unixepoch()',
          'UPDATE identity_claim_release SET expires_at=unixepoch()+600',
        ],
        [
          'UPDATE identity_document SET valid_until=unixepoch()',
          'UPDATE identity_document SET valid_until=unixepoch()+600',
        ],
        [
          "UPDATE identity_document SET document_json=json_set(document_json,'$.attributes.birth_date','1990-02-30')",
          "UPDATE identity_document SET document_json=json_set(document_json,'$.attributes.birth_date','2010-02-28')",
        ],
      ]) {
        await DB.exec(set);
        assert.equal((await userinfo(young)).status, 403);
        await DB.exec(restore);
      }
      await DB.prepare("UPDATE identity_claim_release SET active=0 WHERE client_id='rp'").run();
      assert.equal((await userinfo(young)).status, 403);
      await DB.prepare("UPDATE account_security SET epoch=epoch+1 WHERE account_id='owner'").run();
      assert.equal((await userinfo(young)).status, 401);
    } finally {
      await harness.close();
    }
  });
