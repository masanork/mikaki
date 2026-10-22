import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  importJWK,
  calculateJwkThumbprint,
  CompactEncrypt,
} from 'jose';
import { fixtureKey } from './support/android-attestation-fixture.ts';
import { createTestHarness } from 'wrangler';
import { identityFixture } from './support/identity-fixture.ts';
import { passportPolicyFingerprint } from '../../scripts/check-identity-haip-production.ts';
const root = 'https://issuer.example',
  issuer = `${root}/identity/issuer`;
const hash = (s: string | Uint8Array) => createHash('sha256').update(s).digest('base64url');
const secret = () => randomBytes(32).toString('base64url');

test('HAIP passport uses the existing authenticated PAR/code/DPoP/encrypted credential endpoints without a downgrade', async () => {
  const now = Math.floor(Date.now() / 1000),
    client = 'passport-wallet',
    redirect = 'https://wallet.example/callback';
  const attesterIssuer = `${root}/identity/attester`;
  const cert = async (name: string) =>
    (
      await readFile(new URL(`../../crates/identity/tests/fixtures/${name}.der`, import.meta.url))
    ).toString('base64');
  const chain = await Promise.all(['trust/attester', 'trust/intermediate'].map(cert));
  const anchor = await cert('trust/root');
  const signing = Object.fromEntries(
    await Promise.all(
      ['sd_jwt', 'mdoc'].map(async (purpose) => {
        const prefix = purpose === 'sd_jwt' ? 'sd' : 'mdoc';
        return [
          purpose,
          {
            chain: [await cert(`credential/${prefix}-signer`)],
            trust_anchors: [await cert(`credential/${prefix}-ca`)],
          },
        ];
      }),
    ),
  );
  const instance = await generateKeyPair('ES256', { extractable: true });
  const sender = await generateKeyPair('ES256', { extractable: true }),
    otherSender = await generateKeyPair('ES256', { extractable: true });
  const senderJwk = await exportJWK(sender.publicKey),
    senderJkt = await calculateJwkThumbprint(senderJwk);
  const holder = await generateKeyPair('ES256', { extractable: true }),
    holderJwk = await exportJWK(holder.publicKey);
  const attesterKey = await importJWK(fixtureKey(5), 'ES256');
  const encryption = await generateKeyPair('ECDH-ES', { extractable: true });
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  config.queues.consumers = [];
  config.name = 'passport-haip';
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  if (config.assets) config.assets.directory = new URL('../../assets', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.vars = {
    MIKAKI_ISSUER: root,
    IDENTITY_ENABLED: 'true',
    IDENTITY_PASSPORT_ENABLED: 'true',
    IDENTITY_WALLET_ENABLED: 'true',
    IDENTITY_HAIP_ENABLED: 'true',
    MIKAKI_DPOP_NONCE_MODE: 'required',
    IDENTITY_TRUSTED_KEYS: JSON.stringify(identityFixture().trust),
    IDENTITY_ISSUER_JWK: JSON.stringify({ ...fixtureKey(4), kid: 'issuer' }),
    IDENTITY_CREDENTIAL_CERTIFICATES: JSON.stringify(signing),
    IDENTITY_CREDENTIAL_ENCRYPTION_JWK: JSON.stringify({
      ...(await exportJWK(encryption.privateKey)),
      kid: 'encryption',
      alg: 'ECDH-ES',
      use: 'enc',
    }),
    IDENTITY_WALLET_CLIENTS: JSON.stringify([
      {
        client_id: client,
        name: 'Passport test wallet',
        redirect_uri: redirect,
        attesters: [attesterIssuer],
      },
    ]),
    IDENTITY_WALLET_ATTESTERS: JSON.stringify([
      { issuer: attesterIssuer, trust_anchors: [anchor] },
    ]),
    IDENTITY_KEY_ATTESTATION_TRUST: JSON.stringify({ trust_anchors: [anchor] }),
  };
  config.ratelimits = [
    { name: 'IDENTITY_RATE_LIMIT', namespace_id: '1030', simple: { limit: 1000, period: 60 } },
  ];
  const harness = await createTestHarness({
    workers: [
      { config },
      {
        config: {
          ...config,
          name: 'passport-haip-missing-wallet',
          vars: { ...config.vars, IDENTITY_WALLET_ENABLED: 'false' },
        },
      },
      {
        config: {
          ...config,
          name: 'passport-haip-no-crl',
          vars: { ...config.vars, IDENTITY_PASSPORT_CRLS: '[]' },
        },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('passport-haip');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const metadataResponse = await worker.fetch(
      `${root}/.well-known/openid-credential-issuer/identity/issuer`,
    );
    assert.equal(metadataResponse.status, 200);
    const metadata = (await metadataResponse.json()) as any;
    assert.equal(metadata.credential_request_encryption.encryption_required, true);
    assert.equal(metadata.credential_response_encryption.encryption_required, true);
    assert.deepEqual(
      metadata.credential_configurations_supported.passport_dg1.credential_metadata.claims.map(
        (c: { path: string[] }) => c.path,
      ),
      [
        'name_mrz',
        'issuing_state',
        'nationality',
        'birth_date_mrz',
        'expiry_date_mrz',
        'sex_mrz',
      ].map((f) => [f]),
    );
    assert.equal(
      (
        await harness
          .getWorker('passport-haip-no-crl')
          .fetch(`${root}/.well-known/openid-credential-issuer/identity/issuer`)
      ).status,
      503,
    );
    assert.equal(
      (
        await harness
          .getWorker('passport-haip-missing-wallet')
          .fetch(`${root}/.well-known/openid-credential-issuer/identity/issuer`)
      ).status,
      503,
    );
    assert.ok(
      metadata.credential_configurations_supported.passport_dg1.passport_evidence_policy
        .valid_until > now,
    );
    assert.deepEqual(
      metadata.credential_configurations_supported.passport_dg1.proof_types_supported.jwt
        .key_attestations_required,
      {},
    );
    const oauth = (await (
      await worker.fetch(`${root}/.well-known/oauth-authorization-server/identity/issuer`)
    ).json()) as any;
    assert.deepEqual(oauth.grant_types_supported, ['authorization_code']);
    assert.equal(oauth.require_pushed_authorization_requests, true);
    assert.ok(oauth.scopes_supported.includes('passport_dg1'));
    assert.equal(
      (await worker.fetch(`${root}/identity/passport/poll`, { method: 'POST' })).status,
      404,
    );
    assert.equal(
      (await worker.fetch(`${root}/identity/passport/approve?tx=${secret()}`)).status,
      404,
    );
    const dg1 = await readFile(
      new URL('../../crates/identity/src/passport/fixtures/dg1.bin', import.meta.url),
    );
    const sod = await readFile(
      new URL('../../crates/identity/src/passport/fixtures/trust-rsa.sod', import.meta.url),
    );
    const evidence = { dg1: dg1.toString('base64url'), sod: sod.toString('base64url') };
    assert.equal(
      (
        await worker.fetch(`${root}/identity/passport/intake`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ evidence, holder_jwk: senderJwk }),
        })
      ).status,
      422,
    );
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('passport-haip-owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('passport-haip-key','passport-haip-owner',1)"),
      DB.prepare(
        "INSERT INTO sso_session VALUES('passport-haip-sso','passport-haip-owner','passport-haip-key',1,?,0)",
      ).bind(now + 3600),
      DB.prepare("INSERT INTO sso_context VALUES('passport-haip-sso',?,?)").bind(
        hash('passport-haip-cookie'),
        now,
      ),
    ]);
    // Compare the independent Rust metadata with the production Node smoke policy.
    const policy = passportPolicyFingerprint(),
      tx = secret();
    assert.equal(
      metadata.credential_configurations_supported.passport_dg1.passport_evidence_policy
        .fingerprint,
      policy,
    );
    // Privileged fixture seed exercises transport/consent only; production never trusts synthetic passport roots.
    await DB.prepare(
      "INSERT INTO identity_passport_transaction(tx_id,poll_hash,holder_json,projection_json,evidence_hash,policy_hash,created_at,expires_at,evidence_until,state,haip) VALUES(?1,?2,?3,?4,?5,?6,unixepoch(),unixepoch()+600,unixepoch()+600,'pending',1)",
    )
      .bind(
        tx,
        hash(secret()),
        JSON.stringify(senderJwk),
        JSON.stringify({
          name_mrz: 'ERIKSSON ANNA MARIA',
          issuing_state: 'UTO',
          nationality: 'UTO',
          birth_date_mrz: '690806',
          expiry_date_mrz: '940623',
          sex_mrz: 'F',
        }),
        hash(JSON.stringify(evidence)),
        policy,
      )
      .run();
    const pkce = secret(),
      walletState = secret();
    const parameters = {
      client_id: client,
      redirect_uri: redirect,
      response_type: 'code',
      scope: 'passport_dg1',
      state: walletState,
      code_challenge: hash(pkce),
      code_challenge_method: 'S256',
      dpop_jkt: senderJkt,
      issuer_state: tx,
    };
    const clientHeaders = async () => ({
      'OAuth-Client-Attestation': await new SignJWT({
        iss: attesterIssuer,
        sub: client,
        iat: now,
        exp: now + 300,
        cnf: { jwk: await exportJWK(instance.publicKey) },
      })
        .setProtectedHeader({ typ: 'oauth-client-attestation+jwt', alg: 'ES256', x5c: chain })
        .sign(attesterKey),
      'OAuth-Client-Attestation-PoP': await new SignJWT({
        iss: client,
        aud: issuer,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
        jti: secret(),
      })
        .setProtectedHeader({ typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' })
        .sign(instance.privateKey),
    });
    const dpop = async (endpoint: string, nonce?: string, access?: string, key = sender) =>
      new SignJWT({
        htu: `${issuer}/${endpoint}`,
        htm: 'POST',
        iat: Math.floor(Date.now() / 1000),
        jti: secret(),
        ...(nonce ? { nonce } : {}),
        ...(access ? { ath: hash(access) } : {}),
      })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: await exportJWK(key.publicKey) })
        .sign(key.privateKey);
    let asNonce: string | undefined;
    async function form(endpoint: string, body: Record<string, string>, key = sender) {
      for (let attempt = 0; attempt < 2; attempt++) {
        const r = await worker.fetch(`${issuer}/${endpoint}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            ...(await clientHeaders()),
            DPoP: await dpop(endpoint, asNonce, undefined, key),
          },
          body: new URLSearchParams(body).toString(),
        });
        if (r.headers.get('dpop-nonce')) asNonce = r.headers.get('dpop-nonce')!;
        if ((r.status === 400 || r.status === 401) && attempt === 0) {
          const b = (await r.clone().json()) as any;
          if (b.error === 'use_dpop_nonce') continue;
        }
        return r;
      }
      throw Error('nonce retry failed');
    }
    const noSender = await worker.fetch(`${issuer}/par`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(await clientHeaders()) },
      body: new URLSearchParams(parameters).toString(),
    });
    assert.equal(noSender.status, 400);
    assert.equal((await form('par', parameters, otherSender)).status, 400);
    const pushed = await form('par', parameters);
    assert.equal(pushed.status, 201, await pushed.clone().text());
    const par = (await pushed.json()) as any;
    const browser = `${issuer}/authorize?${new URLSearchParams({ client_id: client, request_uri: par.request_uri })}`;
    const page = await worker.fetch(browser, {
      headers: { Cookie: '__Host-op-sso=passport-haip-cookie' },
    });
    assert.equal(page.status, 200, await page.clone().text());
    const html = await page.text();
    assert.match(html, /YYMMDD/);
    assert.match(html, /ERIKSSON ANNA MARIA/);
    assert.match(html, /Wallet連携鍵/);
    const style = /<style>([\s\S]*?)<\/style>/.exec(html)![1];
    assert.ok(
      page.headers
        .get('content-security-policy')!
        .includes(`'sha256-${createHash('sha256').update(style).digest('base64')}'`),
    );
    assert.equal(page.headers.get('cache-control'), 'no-store');
    if (process.env.MIKAKI_PASSPORT_PREVIEW === '1') {
      const { chromium } = await import('@playwright/test');
      const previewBrowser = await chromium.launch();
      try {
        const screen = await previewBrowser.newPage({ viewport: { width: 390, height: 844 } });
        await screen.route('https://issuer.example/**', (route) =>
          route.fulfill({ status: 200, headers: Object.fromEntries(page.headers), body: html }),
        );
        await screen.goto(browser);
        assert.equal(
          await screen.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          true,
        );
        await screen.screenshot({
          path: new URL(
            '../../docs/identity-wallet-preview/passport-haip-consent.png',
            import.meta.url,
          ).pathname,
          fullPage: true,
        });
      } finally {
        await previewBrowser.close();
      }
    }
    const csrf = /name=csrf value='([^']+)'/.exec(html)![1];
    const consent = () =>
      worker.fetch(`${issuer}/authorize`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          Cookie: '__Host-op-sso=passport-haip-cookie',
          Origin: root,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant: tx,
          document: tx,
          csrf,
          decision: 'approve',
        }).toString(),
      });
    const approved = await consent();
    assert.equal(approved.status, 303, await approved.clone().text());
    assert.equal((await consent()).status, 409);
    const callback = new URL(approved.headers.get('location')!);
    assert.equal(callback.origin, 'https://wallet.example');
    assert.equal(callback.searchParams.get('state'), walletState);
    assert.equal(callback.searchParams.get('iss'), issuer);
    const tokenBody = {
      grant_type: 'authorization_code',
      code: callback.searchParams.get('code')!,
      client_id: client,
      redirect_uri: redirect,
      code_verifier: pkce,
    };
    assert.equal((await form('token', { ...tokenBody, code_verifier: secret() })).status, 400);
    assert.equal((await form('token', tokenBody, otherSender)).status, 400);
    const tokenResponse = await form('token', tokenBody);
    assert.equal(tokenResponse.status, 200, await tokenResponse.clone().text());
    const token = (await tokenResponse.json()) as any;
    assert.equal(token.token_type, 'DPoP');
    assert.equal(token.scope, 'passport_dg1');
    assert.ok(token.expires_in > 0 && token.expires_in <= 120);
    const cNonce = (
      (await (await worker.fetch(`${issuer}/nonce`, { method: 'POST' })).json()) as any
    ).c_nonce;
    const keyAttestation = await new SignJWT({
      iat: now,
      exp: now + 300,
      nonce: cNonce,
      attested_keys: [holderJwk],
    })
      .setProtectedHeader({ typ: 'key-attestation+jwt', alg: 'ES256', x5c: chain })
      .sign(attesterKey);
    const proof = await new SignJWT({ iss: client, aud: issuer, iat: now, nonce: cNonce })
      .setProtectedHeader({
        typ: 'openid4vci-proof+jwt',
        alg: 'ES256',
        jwk: holderJwk,
        key_attestation: keyAttestation,
      })
      .sign(holder.privateKey);
    const unattested = await new SignJWT({ iss: client, aud: issuer, iat: now, nonce: cNonce })
      .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: holderJwk })
      .sign(holder.privateKey);
    const responseKey = await generateKeyPair('ECDH-ES', { extractable: true });
    const responseJwk = {
      ...(await exportJWK(responseKey.publicKey)),
      kid: 'response',
      alg: 'ECDH-ES',
      use: 'enc',
    };
    let resourceNonce: string | undefined;
    async function issue(
      holderProof: string,
      encrypted = true,
      key = sender,
      evidenceValue = evidence,
      direct = false,
    ) {
      const payload = {
        credential_configuration_id: 'passport_dg1',
        proofs: direct ? { attestation: [holderProof] } : { jwt: [holderProof] },
        passport_evidence: evidenceValue,
        ...(encrypted
          ? { credential_response_encryption: { jwk: responseJwk, enc: 'A256GCM' } }
          : {}),
      };
      for (let attempt = 0; attempt < 2; attempt++) {
        const wire = encrypted
          ? await new CompactEncrypt(Buffer.from(JSON.stringify(payload)))
              .setProtectedHeader({
                alg: 'ECDH-ES',
                enc: 'A256GCM',
                kid: 'encryption',
                cty: 'json',
              })
              .encrypt(encryption.publicKey)
          : JSON.stringify(payload);
        const r = await worker.fetch(`${issuer}/credential`, {
          method: 'POST',
          headers: {
            'Content-Type': encrypted ? 'application/jwt' : 'application/json',
            Authorization: `DPoP ${token.access_token}`,
            DPoP: await dpop('credential', resourceNonce, token.access_token, key),
          },
          body: wire,
        });
        if (r.headers.get('dpop-nonce')) resourceNonce = r.headers.get('dpop-nonce')!;
        if (r.status === 401 && attempt === 0) {
          const b = (await r.clone().json()) as any;
          if (b.error === 'use_dpop_nonce') continue;
        }
        return r;
      }
      throw Error('nonce retry failed');
    }
    assert.equal(
      (
        await worker.fetch(`${issuer}/credential`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token.access_token}`,
          },
          body: JSON.stringify({
            credential_configuration_id: 'passport_dg1',
            passport_evidence: evidence,
            proofs: { jwt: [proof] },
          }),
        })
      ).status,
      401,
    );
    assert.equal((await issue(proof, true, otherSender)).status, 401);
    assert.equal((await issue(proof, false)).status, 400);
    assert.equal((await issue(unattested)).status, 400);
    const rejectedEvidence = await issue(proof);
    assert.equal(rejectedEvidence.status, 422, await rejectedEvidence.clone().text());
    assert.equal(((await rejectedEvidence.json()) as any).error, 'passport_verification_failed');
    assert.equal(
      (await issue(keyAttestation, true, sender, evidence, true)).status,
      422,
      'direct attestation is accepted before independent passport trust rejects the synthetic evidence',
    );
    assert.equal(
      (
        await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?1')
          .bind(hash(cNonce))
          .first()
      )?.used,
      0,
    );
    assert.equal(
      (
        await DB.prepare('SELECT state FROM identity_passport_transaction WHERE tx_id=?1')
          .bind(tx)
          .first()
      )?.state,
      'token',
    );
    assert.equal((await form('token', tokenBody)).status, 400);
    assert.equal(
      (
        await DB.prepare('SELECT state FROM identity_passport_transaction WHERE tx_id=?1')
          .bind(tx)
          .first()
      )?.state,
      'denied',
    );
    assert.equal(
      (
        await DB.prepare('SELECT projection_json FROM identity_passport_transaction WHERE tx_id=?1')
          .bind(tx)
          .first()
      )?.projection_json,
      '{}',
    );
  } finally {
    await harness.close();
  }
});
test('passport issuer gates real trust, owner consent, one-use grants and atomic nonce consumption in workerd', async () => {
  const signer = await generateKeyPair('ES256', { extractable: true }),
    holder = await generateKeyPair('ES256', { extractable: true });
  const holderJwk = await exportJWK(holder.publicKey);
  const config = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  config.queues.consumers = [];
  if (config.assets) config.assets.directory = new URL('../../assets', import.meta.url).pathname;
  config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  config.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  config.vars = {
    MIKAKI_ISSUER: root,
    IDENTITY_ENABLED: 'true',
    IDENTITY_PASSPORT_ENABLED: 'true',
    IDENTITY_TRUSTED_KEYS: JSON.stringify(identityFixture().trust),
    IDENTITY_ISSUER_JWK: JSON.stringify({ ...(await exportJWK(signer.privateKey)), kid: 'issuer' }),
  };
  config.ratelimits = [
    { name: 'IDENTITY_RATE_LIMIT', namespace_id: '1030', simple: { limit: 1000, period: 60 } },
  ];
  const harness = await createTestHarness({
    workers: [
      { config },
      {
        config: {
          ...config,
          name: 'passport-disabled',
          vars: { ...config.vars, IDENTITY_PASSPORT_ENABLED: 'false' },
        },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker'),
      disabled = harness.getWorker('passport-disabled');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const now = Math.floor(Date.now() / 1000);
    const post = (path: string, data: unknown, headers: Record<string, string> = {}) =>
      worker.fetch(`${root}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(data),
      });
    const dg1 = await readFile(
      new URL('../../crates/identity/src/passport/fixtures/dg1.bin', import.meta.url),
    );
    const sod = await readFile(
      new URL('../../crates/identity/src/passport/fixtures/trust-rsa.sod', import.meta.url),
    );
    const evidence = { dg1: dg1.toString('base64url'), sod: sod.toString('base64url') };
    assert.equal(
      (await disabled.fetch(`${root}/identity/passport/intake`, { method: 'POST' })).status,
      404,
    );
    const disabledMeta = await disabled.fetch(
      `${root}/.well-known/openid-credential-issuer/identity/issuer`,
    );
    assert.equal(
      ((await disabledMeta.json()) as any).credential_configurations_supported.passport_dg1,
      undefined,
    );
    const meta = await worker.fetch(`${root}/.well-known/openid-credential-issuer/identity/issuer`);
    assert.equal(
      ((await meta.json()) as any).credential_configurations_supported.passport_dg1.vct,
      `${issuer}/types/passport-dg1`,
    );
    const untrusted = await post('/identity/passport/intake', { evidence, holder_jwk: holderJwk });
    assert.equal(untrusted.status, 422);
    assert.equal(((await untrusted.json()) as any).error, 'passport_verification_failed');
    assert.equal(
      (
        await post('/identity/passport/intake', {
          evidence: { ...evidence, issuer_trust: 'csca_verified' },
          holder_jwk: holderJwk,
        })
      ).status,
      400,
    );
    assert.equal(
      (
        await post('/identity/passport/intake', {
          evidence: { ...evidence, sod: evidence.sod + '=' },
          holder_jwk: holderJwk,
        })
      ).status,
      400,
    );
    assert.equal(
      (await DB.prepare('SELECT count(*) AS n FROM identity_passport_transaction').first())?.n,
      0,
    );
    await DB.batch([
      DB.prepare("INSERT INTO account_security VALUES('passport-owner',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('passport-key','passport-owner',1)"),
      DB.prepare(
        "INSERT INTO sso_session VALUES('passport-sso','passport-owner','passport-key',1,?,0)",
      ).bind(now + 3600),
      DB.prepare("INSERT INTO sso_context VALUES('passport-sso',?,?)").bind(
        hash('passport-cookie'),
        now,
      ),
      DB.prepare("INSERT INTO account_security VALUES('passport-other',1,1)"),
      DB.prepare("INSERT INTO credential VALUES('passport-other-key','passport-other',1)"),
      DB.prepare(
        "INSERT INTO sso_session VALUES('passport-other-sso','passport-other','passport-other-key',1,?,0)",
      ).bind(now + 3600),
      DB.prepare("INSERT INTO sso_context VALUES('passport-other-sso',?,?)").bind(
        hash('other-cookie'),
        now,
      ),
    ]);
    const policy = passportPolicyFingerprint();
    const projection = {
      name_mrz: 'ERIKSSON ANNA MARIA',
      issuing_state: 'UTO',
      nationality: 'UTO',
      birth_date_mrz: '690806',
      expiry_date_mrz: '940623',
      sex_mrz: 'F',
    };
    // Privileged D1 seed isolates consent/ledger tests. It is NOT a successful government-evidence intake.
    async function seed(policyHash = policy) {
      const tx = secret(),
        poll = secret();
      await DB.prepare(
        "INSERT INTO identity_passport_transaction(tx_id,poll_hash,holder_json,projection_json,evidence_hash,policy_hash,created_at,expires_at,evidence_until,state) VALUES(?1,?2,?3,?4,?5,?6,unixepoch(),unixepoch()+600,unixepoch()+600,'pending')",
      )
        .bind(
          tx,
          hash(poll),
          JSON.stringify(holderJwk),
          JSON.stringify(projection),
          hash(JSON.stringify(evidence)),
          policyHash,
        )
        .run();
      return { tx, poll };
    }
    const flow = await seed();
    assert.equal(
      (await worker.fetch(`${root}/identity/passport/approve?tx=${flow.tx}`)).status,
      401,
    );
    const page = await worker.fetch(`${root}/identity/passport/approve?tx=${flow.tx}`, {
      headers: { Cookie: '__Host-op-sso=passport-cookie' },
    });
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.ok(html.includes('個人番号欄'));
    assert.ok(html.includes('世紀'));
    const csrf = /name=csrf value='([^']+)'/.exec(html)![1];
    const decision = (cookie = 'passport-cookie', origin = root, choice = 'approve') =>
      worker.fetch(`${root}/identity/passport/approve`, {
        method: 'POST',
        headers: {
          Cookie: `__Host-op-sso=${cookie}`,
          Origin: origin,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ tx: flow.tx, csrf, decision: choice }).toString(),
      });
    assert.equal((await decision('passport-cookie', 'https://evil.example')).status, 403);
    assert.equal((await decision('other-cookie')).status, 409);
    assert.equal((await decision()).status, 200);
    assert.equal((await decision()).status, 409);
    const pollBody = { transaction_id: flow.tx, poll_secret: flow.poll };
    const offer = await post('/identity/passport/poll', pollBody);
    assert.equal(offer.status, 200);
    const offerBody = (await offer.json()) as any;
    assert.deepEqual(offerBody.credential_offer.credential_configuration_ids, ['passport_dg1']);
    assert.equal((await post('/identity/passport/poll', pollBody)).status, 409);
    const code =
      offerBody.credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
        'pre-authorized_code'
      ];
    const tokenRequest = () =>
      worker.fetch(`${issuer}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          'pre-authorized_code': code,
        }).toString(),
      });
    const token = await tokenRequest();
    assert.equal(token.status, 200);
    const grant = (await token.json()) as any;
    assert.equal(grant.scope, 'passport_dg1');
    assert.ok(grant.expires_in > 0 && grant.expires_in <= 120);
    assert.equal((await tokenRequest()).status, 400);
    const nonceResponse = await worker.fetch(`${issuer}/nonce`, { method: 'POST' });
    const nonce = ((await nonceResponse.json()) as any).c_nonce;
    const proof = await new SignJWT({ nonce, exp: now + 90, jti: secret() })
      .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: holderJwk })
      .setAudience(issuer)
      .setIssuedAt(now)
      .sign(holder.privateKey);
    const credentialBody = {
      credential_configuration_id: 'passport_dg1',
      proofs: { jwt: [proof] },
      passport_evidence: evidence,
    };
    assert.equal(
      (
        await post(
          '/identity/issuer/credential',
          {
            ...credentialBody,
            passport_evidence: { ...evidence, sod: Buffer.from('changed').toString('base64url') },
          },
          { Authorization: `Bearer ${grant.access_token}` },
        )
      ).status,
      403,
    );
    const blocked = await post('/identity/issuer/credential', credentialBody, {
      Authorization: `Bearer ${grant.access_token}`,
    });
    assert.equal(blocked.status, 422);
    assert.equal(((await blocked.json()) as any).error, 'passport_verification_failed');
    const row = await DB.prepare('SELECT state FROM identity_passport_transaction WHERE tx_id=?1')
      .bind(flow.tx)
      .first();
    assert.equal(row?.state, 'token');
    assert.equal(
      (
        await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?1')
          .bind(hash(nonce))
          .first()
      )?.used,
      0,
    );
    // The real issuance commit trigger consumes a nonce atomically and scrubs temporary data.
    await DB.prepare(
      "UPDATE identity_passport_transaction SET state='issued',proof_nonce_hash=?1 WHERE tx_id=?2",
    )
      .bind(hash(nonce), flow.tx)
      .run();
    const scrub = await DB.prepare(
      'SELECT projection_json,holder_json,access_hash,evidence_hash FROM identity_passport_transaction WHERE tx_id=?1',
    )
      .bind(flow.tx)
      .first();
    assert.deepEqual(scrub, {
      projection_json: '{}',
      holder_json: '{}',
      access_hash: null,
      evidence_hash: '',
    });
    assert.equal(
      (
        await DB.prepare('SELECT used FROM identity_nonce WHERE nonce_hash=?1')
          .bind(hash(nonce))
          .first()
      )?.used,
      1,
    );
    const replay = await seed();
    await DB.prepare("UPDATE identity_passport_transaction SET state='token' WHERE tx_id=?1")
      .bind(replay.tx)
      .run();
    await assert.rejects(
      DB.prepare(
        "UPDATE identity_passport_transaction SET state='issued',proof_nonce_hash=?1 WHERE tx_id=?2",
      )
        .bind(hash(nonce), replay.tx)
        .run(),
      /passport_nonce_unavailable/,
    );
    assert.equal(
      (
        await DB.prepare('SELECT state FROM identity_passport_transaction WHERE tx_id=?1')
          .bind(replay.tx)
          .first()
      )?.state,
      'token',
    );

    const denied = await seed();
    const denyPage = await worker.fetch(`${root}/identity/passport/approve?tx=${denied.tx}`, {
      headers: { Cookie: '__Host-op-sso=passport-cookie' },
    });
    const denyCsrf = /name=csrf value='([^']+)'/.exec(await denyPage.text())![1];
    const denyResponse = await worker.fetch(`${root}/identity/passport/approve`, {
      method: 'POST',
      headers: {
        Cookie: '__Host-op-sso=passport-cookie',
        Origin: root,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ tx: denied.tx, csrf: denyCsrf, decision: 'deny' }).toString(),
    });
    assert.equal(denyResponse.status, 200);
    const deniedRow = await DB.prepare(
      'SELECT state,projection_json,holder_json,evidence_hash,access_hash FROM identity_passport_transaction WHERE tx_id=?1',
    )
      .bind(denied.tx)
      .first();
    assert.deepEqual(deniedRow, {
      state: 'denied',
      projection_json: '{}',
      holder_json: '{}',
      evidence_hash: '',
      access_hash: null,
    });
    assert.equal(
      (
        await post('/identity/passport/poll', {
          transaction_id: denied.tx,
          poll_secret: denied.poll,
        })
      ).status,
      404,
    );

    for (const policyHash of [
      'wrong-policy',
      // Previous SHA-1-compatible policy, with the same pinned anchors and CRL.
      'JgN0G554r6Uwq3moFcjxmIrBntr5dqUOaJNX8dPlQL4',
    ]) {
      const changed = await seed(policyHash);
      assert.equal(
        (
          await worker.fetch(`${root}/identity/passport/approve?tx=${changed.tx}`, {
            headers: { Cookie: '__Host-op-sso=passport-cookie' },
          })
        ).status,
        404,
      );
    }

    // Account revocation and expiry prevent access before any raw-evidence verification.
    const revoked = await seed(),
      revokedAccess = secret();
    await DB.prepare(
      "UPDATE identity_passport_transaction SET state='token',account_id='passport-owner',epoch=1,access_hash=?1,token_expires_at=unixepoch()+60 WHERE tx_id=?2",
    )
      .bind(hash(revokedAccess), revoked.tx)
      .run();
    await DB.prepare("UPDATE account_security SET epoch=2 WHERE account_id='passport-owner'").run();
    assert.equal(
      (
        await post('/identity/issuer/credential', credentialBody, {
          Authorization: `Bearer ${revokedAccess}`,
        })
      ).status,
      401,
    );
    const expired = await seed();
    await DB.prepare(
      'UPDATE identity_passport_transaction SET expires_at=unixepoch() WHERE tx_id=?1',
    )
      .bind(expired.tx)
      .run();
    assert.equal(
      (
        await post('/identity/passport/poll', {
          transaction_id: expired.tx,
          poll_secret: expired.poll,
        })
      ).status,
      404,
    );
  } finally {
    await harness.close();
  }
});
