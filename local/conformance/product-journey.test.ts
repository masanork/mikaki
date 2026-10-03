import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { chromium, expect } from '@playwright/test';
import { exportJWK, generateKeyPair } from 'jose';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { issueBootstrapInvite } from '../../scripts/enrollment-store.ts';
import { journeyServer } from './support/journey-server.ts';
import { journeyRp } from './support/journey-rp.ts';
import { startBrowserEvidence } from './support/browser-evidence.ts';

test('Rust product journey: invite, real virtual Passkey/PRF, Vault, RP code exchange and logout denial', async () => {
  let dispatch: Parameters<typeof journeyServer>[0] = async () => {
    throw new Error('Journey not ready');
  };
  const server = await journeyServer((url, init) => dispatch(url, init));
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  let evidence: Awaited<ReturnType<typeof startBrowserEvidence>> | undefined;
  let failure: unknown;
  let harness: ReturnType<typeof createTestHarness> | undefined;
  try {
    const issuer = `https://mikaki.test:${server.port}`,
      rpOrigin = `https://journey-rp.test:${server.port}`,
      clientId = 'journey-rp';
    const opKeys = await generateKeyPair('ES256', { extractable: true });
    const rpKeys = await generateKeyPair('ES256', { extractable: true });
    const publicJwk = {
      ...(await exportJWK(opKeys.publicKey)),
      kid: 'journey-op',
      alg: 'ES256',
      use: 'sig',
    };
    const privateJwk = {
      ...(await exportJWK(opKeys.privateKey)),
      kid: 'journey-op',
      alg: 'ES256',
      use: 'sig',
    };
    const rpJwk = await exportJWK(rpKeys.publicKey);
    assert.ok(rpJwk.x && rpJwk.y);
    const sec1 = Buffer.concat([
      Buffer.from([4]),
      Buffer.from(rpJwk.x, 'base64url'),
      Buffer.from(rpJwk.y, 'base64url'),
    ]);
    harness = createTestHarness({
      root: new URL('../..', import.meta.url).pathname,
      workers: [
        {
          configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
          vars: { MIKAKI_ISSUER: issuer },
          secrets: { OP_PRIVATE_JWK: JSON.stringify(privateJwk) },
        },
      ],
    });
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Full product journey' });
    await DB.batch([
      DB.prepare(
        "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES(?,1,1,'journey-rp.test')",
      ).bind(clientId),
      DB.prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)').bind(
        clientId,
        `${rpOrigin}/callback`,
      ),
      DB.prepare("INSERT INTO client_key VALUES(?,'journey-rp',1,1,'ES256',?)").bind(
        clientId,
        sec1,
      ),
      DB.prepare("INSERT INTO signing_key VALUES('journey-op',1,1,'ES256',?)").bind(
        JSON.stringify(publicJwk),
      ),
    ]);
    const { invitation } = await issueBootstrapInvite(DB, 'test', 'Disposable journey owner');
    const rp = await journeyRp(
      issuer,
      rpOrigin,
      clientId,
      rpKeys.privateKey,
      publicJwk,
      (url, init) => worker.fetch(url, init),
    );
    let callback = '';
    dispatch = async (url, init) => {
      const target = new URL(url);
      if (target.origin === issuer) return worker.fetch(url, { ...init, redirect: 'manual' });
      if (target.origin === rpOrigin) {
        if (target.pathname === '/callback') callback = url;
        return rp.handle(new Request(url, init));
      }
      throw new Error('Unexpected journey origin');
    };
    browser = await chromium.launch({
      headless: true,
      args: [
        '--host-resolver-rules=MAP mikaki.test 127.0.0.1, MAP journey-rp.test 127.0.0.1',
        '--no-proxy-server',
      ],
    });
    const context = await browser.newContext({ locale: 'en-US', ignoreHTTPSErrors: true });
    evidence = await startBrowserEvidence(context, 'product-journey');
    const page = await context.newPage();
    page.setDefaultTimeout(10_000);
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    const cdp = await context.newCDPSession(page);
    await context.addInitScript(() => {
      const get = navigator.credentials.get.bind(navigator.credentials);
      let count = 0;
      Object.defineProperty(window, 'vaultCeremonyCount', { get: () => count });
      navigator.credentials.get = (options) => {
        count++;
        return get(options);
      };
    });
    await cdp.send('WebAuthn.enable', { enableUI: false });
    let ownerAssertions = 0;
    cdp.on('WebAuthn.credentialAsserted', () => {
      ownerAssertions++;
    });
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        ctap2Version: 'ctap2_1',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        hasPrf: true,
        automaticPresenceSimulation: true,
        isUserVerified: true,
      },
    });
    await page.goto(`${issuer}/?lang=en`);
    await page.getByRole('link', { name: 'Register with an invitation', exact: true }).click();
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await page.getByLabel('Invitation code', { exact: true }).fill(invitation);
    await page.getByRole('button', { name: 'Register with invitation', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Registration complete', exact: true }),
    ).toBeVisible();
    assert.equal(page.url(), `${issuer}/enroll/complete?lang=en`);
    assert.equal((await DB.prepare('SELECT COUNT(*) AS n FROM passkey_credential').first()).n, 1);
    await page.goto(`${issuer}/vault?lang=en`);
    await page.locator('#unlock').click();
    await page.locator('#name').fill('Journey owner');
    await page.locator('#save').click();
    await expect(page.locator('#status')).toHaveText('Saved.');
    await page.locator('#reload-profile').click();
    await expect(page.locator('#name')).toHaveValue('Journey owner');
    assert.equal(
      await page.evaluate(
        () => (window as unknown as { vaultCeremonyCount: number }).vaultCeremonyCount,
      ),
      1,
    );
    await page.reload();
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Journey owner');
    // The opt-in hierarchy uses one actual virtual WebAuthn/PRF ceremony for
    // both supported records and repeated saves. The default uses the same name/note records.
    const beforeOwner = ownerAssertions;
    await page.goto(`${issuer}/vault?lang=en&storage=owner-v2`);
    await expect(page.locator('#owner-name')).toHaveCount(0);
    await page.locator('#owner-unlock').click();
    await expect(page.locator('#owner-name')).toHaveValue('Journey owner');
    assert.equal(ownerAssertions, beforeOwner + 1);
    await page.locator('#owner-name').fill('Unified journey owner');
    await page.locator('#owner-profile-save').click();
    await expect(page.locator('#owner-profile-status')).toHaveText(
      'Saved and verified. Vault stays open.',
    );
    await page.locator('#owner-note-title').fill('Journey record');
    await page.locator('#owner-note-text').fill('One unlock protects both supported records.');
    await page.locator('#owner-note-save').click();
    await expect(page.locator('#owner-note-status')).toHaveText(
      'Saved and verified. Vault stays open.',
    );
    await page.locator('#owner-name').fill('Unified journey owner updated');
    await page.locator('#owner-profile-save').click();
    await expect(page.locator('#owner-profile-status')).toHaveText(
      'Saved and verified. Vault stays open.',
    );
    assert.equal(ownerAssertions, beforeOwner + 1);
    await page.reload();
    await expect(page.locator('#owner-name')).toHaveCount(0);
    await page.locator('#owner-unlock').click();
    await expect(page.locator('#owner-name')).toHaveValue('Unified journey owner updated');
    await expect(page.locator('#owner-note-text')).toHaveValue(
      'One unlock protects both supported records.',
    );
    assert.equal(ownerAssertions, beforeOwner + 2);
    await page.goto(`${issuer}/vault?lang=en`);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Unified journey owner updated');
    // Traverse actual HTTPS history; the default automation browser reloads the page.
    // Saved plaintext must require a new Passkey/PRF unlock after returning.
    await page.goto(`${issuer}/?lang=en`);
    await page.goBack();
    await expect(page.locator('#name')).toHaveCount(0);
    await expect(page.locator('#save')).toHaveCount(0);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Unified journey owner updated');
    await page.goto(rpOrigin);
    await page.getByRole('link', { name: 'Sign in', exact: true }).click();
    // Chromium's virtual authenticator can satisfy the normal automatic login.
    // Leave the actual credential ceremony and PRF implementation intact.
    await expect(
      page.getByRole('heading', { name: 'Signed-in application', exact: true }),
    ).toBeVisible();
    assert.ok(rp.lastExchange);
    assert.ok(callback);
    // Replay both browser callback state and the actual OP code exchange.
    assert.equal((await page.goto(callback))?.status(), 400);
    const replay = await rp.post('/token', {
      grant_type: 'authorization_code',
      code: rp.lastExchange.code,
      redirect_uri: `${rpOrigin}/callback`,
      code_verifier: rp.lastExchange.verifier,
    });
    assert.equal(replay.status, 400);
    // Code reuse revokes the earlier token family; do not mistake that for logout.
    assert.equal((await page.goto(`${rpOrigin}/protected`))?.status(), 401);
    await page.goto(rpOrigin);
    await page.getByRole('link', { name: 'Sign in', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Signed-in application', exact: true }),
    ).toBeVisible();
    assert.equal((await page.goto(`${rpOrigin}/protected`))?.status(), 200);
    await page.goto(`${issuer}/vault?lang=en`);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Unified journey owner updated');
    await page.getByRole('link', { name: 'Log out', exact: false }).click();
    await page.getByRole('button', { name: 'Log out', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'You have logged out', exact: true }),
    ).toBeVisible();
    assert.equal(
      (await worker.fetch(`${issuer}/vault?lang=en`, { redirect: 'manual' })).status,
      302,
    );
    await expect(page.locator('#name')).toHaveCount(0);
    assert.equal((await page.goto(`${rpOrigin}/protected`))?.status(), 401);
    await expect(
      page.getByRole('heading', { name: 'Sign-in required', exact: true }),
    ).toBeVisible();
    // Follow actual HTTPS redirects from the public entry, without an RP or native app.
    const connectionsBefore = (await DB.prepare('SELECT COUNT(*) AS n FROM app_connection').first())
      .n;
    let webFinish: { url: string; headers: Record<string, string>; body: string } | undefined;
    page.on('request', async (request) => {
      if (new URL(request.url()).pathname === '/login/finish')
        webFinish = {
          url: request.url(),
          headers: await request.allHeaders(),
          body: request.postData()!,
        };
    });
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
    await page.goto(`${issuer}/?lang=en`);
    await page.getByRole('link', { name: 'Sign in', exact: true }).click();
    await expect(
      page.getByRole('link', { name: 'Register with an invitation', exact: true }),
    ).toHaveAttribute('href', '/enroll?lang=en');
    await expect(page.locator('details.registration')).toHaveCount(0);
    const pendingTx = new URL(page.url()).searchParams.get('tx')!;
    const unusedInvite = 'i'.repeat(43);
    await DB.prepare(
      "INSERT INTO enrollment_invite(invite_hash,kind,issuer_account_id,issued_at,expires_at) SELECT ?,'normal',account_id,unixepoch(),unixepoch()+300 FROM account_role WHERE role='admin'",
    )
      .bind(createHash('sha256').update(unusedInvite).digest('base64url'))
      .run();
    const invalidRegistration = await worker.fetch(`${issuer}/register/start`, {
      method: 'POST',
      headers: {
        origin: issuer,
        'content-type': 'application/json',
        cookie: (await context.cookies(issuer))
          .map((cookie) => `${cookie.name}=${cookie.value}`)
          .join('; '),
      },
      body: JSON.stringify({ tx: pendingTx, invitation: unusedInvite }),
    });
    assert.equal(invalidRegistration.status, 400);
    assert.equal(
      (
        await DB.prepare('SELECT consumed_at FROM enrollment_invite WHERE invite_hash=?')
          .bind(createHash('sha256').update(unusedInvite).digest('base64url'))
          .first()
      ).consumed_at,
      null,
    );
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
    await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
    await page.waitForURL(`${issuer}/vault?lang=en`);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Unified journey owner updated');
    assert.equal(
      (await DB.prepare('SELECT COUNT(*) AS n FROM app_connection').first()).n,
      connectionsBefore,
    );
    assert.ok(webFinish);
    assert.equal(
      (
        await worker.fetch(webFinish.url, {
          method: 'POST',
          headers: webFinish.headers,
          body: webFinish.body,
        })
      ).status,
      400,
    );
    const tx = (JSON.parse(webFinish.body) as { tx: string }).tx;
    for (const destination of [
      'https://evil.test/vault',
      `${issuer}/admin`,
      `${issuer}/vault?agent_oauth_request=${'x'.repeat(43)}`,
      `${issuer}/vault#fragment`,
    ]) {
      await DB.prepare(
        'UPDATE web_login_transaction SET consumed=0,authorization_url=? WHERE tx_id=?',
      )
        .bind(destination, tx)
        .run();
      const rejected = await worker.fetch(webFinish.url, {
        method: 'POST',
        headers: webFinish.headers,
        body: webFinish.body,
      });
      assert.equal(rejected.status, 400);
      assert.equal(((await rejected.json()) as { error: string }).error, 'invalid_continuation');
    }
    await DB.prepare(
      'UPDATE web_login_transaction SET consumed=1,authorization_url=? WHERE tx_id=?',
    )
      .bind(`${issuer}/vault?lang=en`, tx)
      .run();
    await page.goto(`${issuer}/signin?lang=en`);
    await page.waitForURL(`${issuer}/vault?lang=en`);
    await page.locator('#unlock').click();
    await expect(page.locator('#name')).toHaveValue('Unified journey owner updated');
    await page.goto(`${issuer}/?lang=en`);
    const formerSso = (await context.cookies(issuer)).find(
      (cookie) => cookie.name === '__Host-op-sso',
    );
    assert.ok(formerSso, 'The history journey needs an authenticated SSO');
    const logoutTab = await context.newPage();
    logoutTab.on('pageerror', (error) => errors.push(error.message));
    await logoutTab.goto(`${issuer}/logout?lang=en`);
    await logoutTab.getByRole('button', { name: 'Log out', exact: true }).click();
    await expect(
      logoutTab.getByRole('heading', { name: 'You have logged out', exact: true }),
    ).toBeVisible();
    // A history entry cannot restore the revoked SSO or its decrypted display.
    // Keep the virtual authenticator pending so a new login cannot mask rejection.
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
    await page.goBack();
    await page.waitForURL((url) => url.origin === issuer && url.pathname === '/login');
    await expect(page.locator('[data-owner-login="true"]')).toHaveCount(1);
    await expect(page.locator('#name')).toHaveCount(0);
    assert.equal(
      (
        await worker.fetch(`${issuer}/vault?lang=en`, {
          redirect: 'manual',
          headers: { cookie: `__Host-op-sso=${formerSso.value}` },
        })
      ).status,
      302,
    );
    assert.deepEqual(errors, []);
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    await evidence?.finish(failure);
    await browser?.close();
    await server.close();
    await harness?.close();
  }
});
