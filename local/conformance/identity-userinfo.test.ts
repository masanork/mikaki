import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';

const root = 'https://mikaki.test';
const hash = (v: string) => createHash('sha256').update(v).digest('base64url');
const secret = () => randomBytes(32).toString('base64url');

test('linked-document userinfo requires current owner/RP/field consent and revocation cannot be undone by a stale form', async () => {
  const config = JSON.parse(
    await readFile(
      new URL('../../crates/worker/wrangler.recipient-local.jsonc', import.meta.url),
      'utf8',
    ),
  );
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  const policy = JSON.stringify([
    {
      id: 'fixture',
      document_type: 'my_number_card',
      n: Buffer.alloc(256, 7).toString('base64url'),
      e: 'AQAB',
      subject_key_identifier: null,
      not_before: Math.floor(Date.now() / 1000) - 60,
      not_after: Math.floor(Date.now() / 1000) + 3600,
    },
  ]);
  config.vars = {
    MIKAKI_ISSUER: root,
    IDENTITY_ENABLED: 'true',
    IDENTITY_USERINFO_ENABLED: 'true',
    IDENTITY_TRUSTED_KEYS: policy,
  };
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      { config },
      {
        config: {
          ...config,
          name: 'identity-userinfo-disabled',
          vars: { ...config.vars, IDENTITY_USERINFO_ENABLED: 'false' },
        },
      },
      {
        configPath: new URL(
          '../../crates/userinfo-claim-worker/wrangler.local.jsonc',
          import.meta.url,
        ).pathname,
      },
    ],
  });
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-worker');
    const disabled = harness.getWorker('identity-userinfo-disabled');
    await op.applyD1Migrations('DB');
    const { DB } = await op.getEnv();
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('passkey','owner',1)"),
      DB.prepare("INSERT INTO sso_session VALUES('sso','owner','passkey',1,?,0)").bind(now + 7200),
      DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(hash('cookie'), now),
      DB.prepare("INSERT INTO account_security VALUES('other',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('other-key','other',1)"),
      DB.prepare("INSERT INTO sso_session VALUES('other-sso','other','other-key',1,?,0)").bind(
        now + 7200,
      ),
      DB.prepare("INSERT INTO sso_context VALUES('other-sso',?,?)").bind(hash('other-cookie'), now),
      DB.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256','{}')"),
    ]);
    const tokens: Record<string, string> = {};
    for (const [client, scope] of [
      ['rp', 'openid profile'],
      ['openid-only', 'openid'],
      ['other-rp', 'openid profile'],
    ]) {
      const code = secret(),
        access = secret();
      tokens[client] = access;
      await DB.batch([
        DB.prepare(
          'INSERT INTO client(client_id,revision,active,sector_identifier) VALUES(?,1,1,?)',
        ).bind(client, `https://${client}.example`),
        DB.prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)').bind(
          client,
          `https://${client}.example/cb`,
        ),
        DB.prepare("INSERT INTO app_connection VALUES('owner',?,1,1)").bind(client),
        DB.prepare("INSERT INTO client_session VALUES(?,'sid','sso','owner',?,1,0)").bind(
          client,
          `pairwise-${client}`,
        ),
        DB.prepare(
          "INSERT INTO authorization_code(code_hash,client_id,sid,client_revision,redirect_uri,pkce_challenge,expires_at,consumed_by,consumed_at) VALUES(?,?,'sid',1,?,'',?,?,?)",
        ).bind(code, client, `https://${client}.example/cb`, now + 600, client, now),
        DB.prepare('INSERT INTO code_context(code_hash,nonce,scope) VALUES(?,NULL,?)').bind(
          code,
          scope,
        ),
        DB.prepare(
          "INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked) VALUES(?,?,?,?,'op',?,0)",
        ).bind(code, client, hash(access), now + 600, now),
      ]);
    }
    const sender = await generateKeyPair('ES256', { extractable: true });
    const senderJwk = await exportJWK(sender.publicKey);
    const senderThumbprint = await calculateJwkThumbprint(senderJwk);
    const popAccess = secret(),
      popCode = secret();
    await DB.batch([
      DB.prepare(
        "INSERT INTO authorization_code(code_hash,client_id,sid,client_revision,redirect_uri,pkce_challenge,expires_at,consumed_by,consumed_at) VALUES(?,'rp','sid',1,'https://rp.example/cb','',?,'pop-issue',?)",
      ).bind(popCode, now + 600, now),
      DB.prepare(
        "INSERT INTO code_context(code_hash,nonce,scope) VALUES(?,NULL,'openid profile')",
      ).bind(popCode),
      DB.prepare(
        "INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked,dpop_jkt) VALUES(?,'pop-issue',?,?,'op',?,0,?)",
      ).bind(popCode, hash(popAccess), now + 600, now, senderThumbprint),
    ]);
    const popResponse = async () =>
      op.fetch(`${root}/userinfo`, {
        headers: {
          Authorization: `DPoP ${popAccess}`,
          DPoP: await new SignJWT({
            jti: secret(),
            iat: Math.floor(Date.now() / 1000),
            htm: 'GET',
            htu: `${root}/userinfo`,
            ath: hash(popAccess),
          })
            .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: senderJwk })
            .sign(sender.privateKey),
        },
      });
    const callPop = async () => {
      const response = await popResponse();
      assert.equal(response.status, 200, await response.clone().text());
      return response.json();
    };
    const doc = secret();
    const verified = {
      attributes: {
        name: '試験 太郎',
        address: '東京都',
        birth_date: '1990-02-28',
        gender: '1',
        verification: 'verified',
        document_type: 'my_number_card',
        expiry_date: null,
        backend_verifiable: true,
      },
      trusted_key_id: 'fixture',
      verified_at: now,
      assurance: 'issuer_signed_static_data',
      attributes_source: 'my_number_card',
    };
    await DB.prepare(
      "INSERT INTO identity_transaction(tx_id,poll_hash,holder_json,document_json,policy_hash,created_at,expires_at,state,account_id,epoch,session_hash) VALUES(?,?,'{}',?,?,?,?,'pending','owner',1,?)",
    )
      .bind(doc, secret(), JSON.stringify(verified), hash(policy), now, now + 600, hash('cookie'))
      .run();
    await DB.prepare("UPDATE identity_transaction SET state='approved' WHERE tx_id=?")
      .bind(doc)
      .run();
    const call = async (client = 'rp', worker = op) => {
      const response = await worker.fetch(`${root}/userinfo`, {
        headers: { Authorization: `Bearer ${tokens[client]}` },
      });
      assert.equal(response.status, 200, await response.clone().text());
      assert.equal(response.headers.get('cache-control'), 'no-store');
      return (await response.json()) as Record<string, unknown>;
    };
    const discovery = await op.fetch(`${root}/.well-known/openid-configuration`);
    assert.equal(discovery.status, 200);
    assert.ok(
      ((await discovery.json()) as { claims_supported: string[] }).claims_supported.includes(
        'mikaki_linked_document',
      ),
    );
    const disabledDiscovery = await disabled.fetch(`${root}/.well-known/openid-configuration`);
    assert.equal(disabledDiscovery.status, 200);
    assert.equal(
      (
        (await disabledDiscovery.json()) as { claims_supported: string[] }
      ).claims_supported.includes('mikaki_linked_document'),
      false,
    );
    assert.deepEqual(await call(), { sub: 'pairwise-rp' });
    const page = await op.fetch(`${root}/identity`, {
      headers: { Cookie: '__Host-op-sso=cookie' },
    });
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /アプリへの属性公開/);
    const form = /<form method=post action=\/identity\/release>(.*?)<\/form>/s.exec(html)![1];
    const csrf = /name=csrf value='([^']+)'/.exec(form)![1];
    const release = async (
      recipient: unknown,
      fields: Record<string, string>,
      action = 'grant',
      cookie = 'cookie',
      origin = root,
      csrfValue = csrf,
      worker = op,
    ) =>
      worker.fetch(`${root}/identity/release`, {
        method: 'POST',
        headers: {
          Origin: origin,
          Cookie: `__Host-op-sso=${cookie}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          document: doc,
          recipient: JSON.stringify(recipient),
          csrf: csrfValue,
          action,
          ...fields,
        }).toString(),
        redirect: 'manual',
      });
    assert.equal(
      (await release(['rp', 1, 1, 0], { name: 'on' }, 'grant', 'cookie', 'https://evil.example'))
        .status,
      403,
    );
    assert.equal(
      (await release(['rp', 1, 1, 0], { name: 'on' }, 'grant', 'other-cookie')).status,
      403,
    );
    assert.equal((await release(['rp', 1, 1, 0], {}, 'grant')).status, 400);
    assert.equal(
      (await release(['rp', 1, 1, 0], { name: 'on' }, 'grant', 'cookie', root, secret())).status,
      403,
    );
    assert.equal((await release(['rp', 2, 1, 0], { name: 'on' })).status, 409);
    const grantedBefore = Math.floor(Date.now() / 1000);
    assert.equal((await release(['rp', 1, 1, 0], { name: 'on', birthdate: 'on' })).status, 303);
    const grantedAfter = Math.floor(Date.now() / 1000);
    const expected = {
      attributes: { name: '試験 太郎', birthdate: '1990-02-28' },
      evidence: {
        document_type: 'my_number_card',
        assurance: 'issuer_signed_static_data',
        attributes_source: 'my_number_card',
        verified_at: now,
        live_possession_verified: false,
        government_credential: false,
      },
    };
    assert.deepEqual(await call(), { sub: 'pairwise-rp', mikaki_linked_document: expected });
    assert.deepEqual(await callPop(), { sub: 'pairwise-rp', mikaki_linked_document: expected });
    assert.equal(
      (await op.fetch(`${root}/userinfo`, { headers: { Authorization: `Bearer ${popAccess}` } }))
        .status,
      401,
    );
    assert.deepEqual(await call('other-rp'), { sub: 'pairwise-other-rp' });
    assert.deepEqual(await call('rp', disabled), { sub: 'pairwise-rp' });
    assert.equal((await release(['openid-only', 1, 1, 0], { address: 'on' })).status, 303);
    assert.deepEqual(await call('openid-only'), { sub: 'pairwise-openid-only' });
    const row = await DB.prepare(
      "SELECT expires_at FROM identity_claim_release WHERE client_id='rp'",
    ).first();
    assert.ok(row!.expires_at >= grantedBefore + 3600);
    assert.ok(row!.expires_at <= grantedAfter + 3600);
    // An older grant form cannot restore a revoked release: tombstone version survives.
    assert.equal((await release(['rp', 0, 0, 1], {}, 'revoke')).status, 303);
    assert.deepEqual(await call(), { sub: 'pairwise-rp' });
    assert.equal((await release(['rp', 1, 1, 0], { name: 'on' })).status, 409);
    assert.deepEqual(await callPop(), { sub: 'pairwise-rp' });
    assert.equal((await release(['rp', 1, 1, 2], { address: 'on' })).status, 303);
    assert.deepEqual((await call()).mikaki_linked_document, {
      ...expected,
      attributes: { address: '東京都' },
    });
    for (const [set, restore] of [
      [
        "UPDATE identity_claim_release SET expires_at=unixepoch() WHERE client_id='rp'",
        "UPDATE identity_claim_release SET expires_at=unixepoch()+600 WHERE client_id='rp'",
      ],
      [
        `UPDATE identity_document SET valid_until=unixepoch() WHERE document_id='${doc}'`,
        `UPDATE identity_document SET valid_until=unixepoch()+600 WHERE document_id='${doc}'`,
      ],
      [
        `UPDATE identity_document SET policy_hash='changed' WHERE document_id='${doc}'`,
        `UPDATE identity_document SET policy_hash='${hash(policy)}' WHERE document_id='${doc}'`,
      ],
    ]) {
      await DB.prepare(set).run();
      assert.deepEqual(await call(), { sub: 'pairwise-rp' });
      await DB.prepare(restore).run();
    }
    await DB.prepare(
      "UPDATE identity_document SET document_json=json_set(document_json,'$.attributes.expiry_date','2020-01-01') WHERE document_id=?",
    )
      .bind(doc)
      .run();
    assert.deepEqual(await call(), { sub: 'pairwise-rp' });
    await DB.prepare(
      "UPDATE identity_document SET document_json=json_set(document_json,'$.attributes.expiry_date',NULL) WHERE document_id=?",
    )
      .bind(doc)
      .run();
    await DB.prepare(
      "UPDATE identity_document SET document_json=json_set(document_json,'$.trusted_key_id','unknown') WHERE document_id=?",
    )
      .bind(doc)
      .run();
    assert.deepEqual(await call(), { sub: 'pairwise-rp' });
    await DB.prepare(
      "UPDATE identity_document SET document_json=json_set(document_json,'$.trusted_key_id','fixture') WHERE document_id=?",
    )
      .bind(doc)
      .run();
    assert.equal((await release(['other-rp', 1, 1, 0], { name: 'on' })).status, 303);
    await DB.prepare("UPDATE app_connection SET active=0 WHERE client_id='other-rp'").run();
    assert.equal(
      (
        await op.fetch(`${root}/userinfo`, {
          headers: { Authorization: `Bearer ${tokens['other-rp']}` },
        })
      ).status,
      401,
    );
    await DB.prepare("UPDATE app_connection SET active=1 WHERE client_id='other-rp'").run();
    assert.deepEqual(await call('other-rp'), { sub: 'pairwise-other-rp' });
    assert.equal((await release(['other-rp', 1, 1, 0], { name: 'on' })).status, 409);
    // A fresh client registration invalidates the old authorization and release.
    await DB.prepare("UPDATE client SET revision=2 WHERE client_id='rp'").run();
    assert.deepEqual(await call(), { sub: 'pairwise-rp' });
    assert.equal((await release(['rp', 1, 1, 3], { name: 'on' })).status, 409);
    await DB.prepare('UPDATE identity_document SET revoked=1 WHERE document_id=?').bind(doc).run();
    assert.equal(
      await DB.prepare("SELECT active FROM identity_claim_release WHERE client_id='rp'").first(
        'active',
      ),
      0,
    );
    assert.deepEqual(await call(), { sub: 'pairwise-rp' });
    assert.equal((await release(['rp', 2, 1, 4], { name: 'on' })).status, 409);
    await DB.prepare("UPDATE account_security SET epoch=2 WHERE account_id='owner'").run();
    assert.equal(
      (await op.fetch(`${root}/userinfo`, { headers: { Authorization: `Bearer ${tokens.rp}` } }))
        .status,
      401,
    );
    assert.equal((await popResponse()).status, 401);
  } finally {
    await harness.close();
  }
});
