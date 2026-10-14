import { startBrowserEvidence } from './support/browser-evidence.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { readFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { issueBootstrapInvite } from '../../scripts/enrollment-store.ts';

function requiredHeader(
  response: { headers: { get(name: string): string | null } },
  name: string,
): string {
  const value = response.headers.get(name);
  assert.ok(value, `${name} header is required`);
  return value;
}

test('bootstrap passkey enrollment, Vault PRF encryption, and sign-in work in Chromium', async () => {
  const issuer = 'https://mikaki.test';
  const redirectUri = 'https://rp.example/callback';
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        vars: { MIKAKI_ISSUER: issuer },
      },
    ],
  });
  let browser;
  let evidence: Awaited<ReturnType<typeof startBrowserEvidence>> | undefined;
  let failure: unknown;
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    let { DB } = await worker.getEnv();
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'browser enrollment test' });
    await DB.batch([
      DB.prepare(
        "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('test-client',1,1,'rp.example')",
      ),
      DB.prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)').bind(
        'test-client',
        redirectUri,
      ),
    ]);
    const { invitation } = await issueBootstrapInvite(DB, 'operator', 'first account');
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    evidence = await startBrowserEvidence(page.context(), 'enrollment-browser');
    const errors: string[] = [];
    const passkeyEvents: string[] = [];
    let finishBody;
    let lostFinishBody;
    let loseNextFinishResponse = false;
    let concurrentFinishStatuses: number[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => {
      if (message.text().startsWith('passkey-test:')) passkeyEvents.push(message.text());
    });
    await context.addInitScript(() => {
      if (location.pathname !== '/login') return;
      const credentials = navigator.credentials;
      const get = credentials.get.bind(credentials);
      let calls = 0;
      Object.defineProperty(credentials, 'get', {
        configurable: true,
        value: (options: CredentialRequestOptions) => {
          calls += 1;
          if (calls !== 1) {
            if (calls === 2) {
              console.info('passkey-test:button-cancelled');
              return Promise.reject(new DOMException('Cancelled', 'NotAllowedError'));
            }
            console.info('passkey-test:button-retry');
            return get(options);
          }
          console.info('passkey-test:auto-start');
          return new Promise<Credential | null>((_resolve, reject) => {
            options.signal?.addEventListener(
              'abort',
              () => {
                console.info('passkey-test:auto-aborted');
                reject(new DOMException('Aborted', 'AbortError'));
              },
              { once: true },
            );
          });
        },
      });
    });
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable', { enableUI: false });
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
    await page.route(
      (url) => url.hostname === 'mikaki.test',
      async (route) => {
        try {
          const request = route.request();
          if (new URL(request.url()).pathname === '/register/finish') {
            if (loseNextFinishResponse) lostFinishBody = request.postData();
            else finishBody = request.postData();
          }
          if (new URL(request.url()).pathname === '/authorize') {
            await route.fulfill({
              status: 200,
              contentType: 'text/html',
              body: '<h1>Authorization resumed</h1>',
            });
            return;
          }
          const forward = async () =>
            worker.fetch(request.url(), {
              method: request.method(),
              headers: await request.allHeaders(),
              redirect: 'manual',
              ...(request.postDataBuffer() ? { body: request.postDataBuffer() } : {}),
            });
          const lostFinish =
            new URL(request.url()).pathname === '/register/finish' && loseNextFinishResponse;
          if (lostFinish) {
            // An unrelated failed batch must remain a server error and roll back
            // invite/transaction consumption so the same verified input can retry.
            await DB.prepare(
              "CREATE TRIGGER fail_test_registration BEFORE INSERT ON account_security BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END",
            ).run();
            try {
              const rejected = await forward();
              assert.equal(rejected.status, 500);
              assert.equal(
                (await DB.prepare('SELECT COUNT(*) AS n FROM account_security').first()).n,
                1,
              );
              assert.equal(
                (
                  await DB.prepare(
                    "SELECT COUNT(*) AS n FROM enrollment_invite WHERE kind='normal' AND consumed_at IS NULL",
                  ).first()
                ).n,
                1,
              );
            } finally {
              await DB.prepare('DROP TRIGGER fail_test_registration').run();
            }
          }
          const responses = await Promise.all(
            lostFinish ? Array.from({ length: 8 }, forward) : [forward()],
          );
          if (lostFinish) {
            concurrentFinishStatuses = responses.map((response) => response.status).sort();
            assert.deepEqual(concurrentFinishStatuses, [200, ...Array<number>(7).fill(400)]);
            loseNextFinishResponse = false;
            await route.abort('failed');
            return;
          }
          const response = responses[0];
          await route.fulfill({
            status: response.status,
            headers: Object.fromEntries(response.headers),
            body: await response.text(),
          });
        } catch (error) {
          errors.push(String(error));
          await route.fulfill({ status: 500, body: 'route failed' });
        }
      },
    );
    const authorize = new URL('/authorize', issuer);
    authorize.search = new URLSearchParams({
      client_id: 'test-client',
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid',
      state: 's'.repeat(43),
      code_challenge: createHash('sha256').update('v'.repeat(43)).digest('base64url'),
      code_challenge_method: 'S256',
    }).toString();
    const pending = await worker.fetch(`${issuer}/enroll?lang=ja`, { redirect: 'manual' });
    assert.equal(pending.status, 302);
    const initialBrowserCookie = requiredHeader(pending, 'set-cookie').split(';')[0];
    const initialLoginUrl = requiredHeader(pending, 'location');
    await context.addCookies([
      {
        name: '__Host-op-browser',
        value: initialBrowserCookie.split('=')[1],
        domain: 'mikaki.test',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
      },
    ]);
    await page.goto(initialLoginUrl);
    await page.getByRole('button', { name: '招待で登録する' }).waitFor();
    assert.equal(
      await page.evaluate(() => getComputedStyle(document.documentElement).backgroundColor),
      'rgb(7, 17, 28)',
    );
    await page.getByLabel('招待コード').fill(invitation);
    await page.getByRole('button', { name: '招待で登録する' }).click();
    await page.getByRole('heading', { name: '登録が完了しました' }).waitFor();
    const firstSso = (await context.cookies(issuer)).find(
      (cookie) => cookie.name === '__Host-op-sso',
    );
    assert.ok(firstSso);
    await page.goto(`${issuer}/vault?storage=legacy-v1`);
    await page.getByRole('button', { name: 'Passkeyで開く' }).click();
    await page.getByLabel('表示名', { exact: true }).fill('Vault browser test');
    await page.getByRole('button', { name: '保存', exact: true }).click();
    await page.getByRole('status').getByText('保存しました').waitFor();
    await page.reload();
    await page.getByRole('button', { name: 'Passkeyで開く' }).click();
    await page.waitForFunction(
      () =>
        (document.querySelector('#name') as HTMLInputElement | null)?.value ===
        'Vault browser test',
    );
    assert.equal(
      await page.getByLabel('表示名', { exact: true }).inputValue(),
      'Vault browser test',
    );
    await page.getByLabel('表示名', { exact: true }).fill('Updated vault name');
    await page.getByRole('button', { name: '保存', exact: true }).click();
    await page.getByRole('status').getByText('保存しました').waitFor();
    await page.reload();
    await page.getByRole('button', { name: 'Passkeyで開く' }).click();
    await page.waitForFunction(
      () =>
        (document.querySelector('#name') as HTMLInputElement | null)?.value ===
        'Updated vault name',
    );
    assert.equal(
      (await DB.prepare('SELECT closed FROM bootstrap_state WHERE id=1').first()).closed,
      1,
    );
    assert.equal(
      (await DB.prepare("SELECT COUNT(*) AS n FROM account_role WHERE role='admin'").first()).n,
      1,
    );
    assert.equal((await DB.prepare('SELECT COUNT(*) AS n FROM passkey_credential').first()).n, 1);
    assert.equal(
      (
        await DB.prepare(
          'SELECT COUNT(*) AS n FROM enrollment_invite WHERE consumed_at IS NOT NULL',
        ).first()
      ).n,
      1,
    );
    assert.ok(finishBody);
    const replay = await worker.fetch(`${issuer}/register/finish`, {
      method: 'POST',
      headers: { cookie: initialBrowserCookie, origin: issuer, 'content-type': 'application/json' },
      body: finishBody,
    });
    assert.equal(replay.status, 400);
    assert.equal((await DB.prepare('SELECT COUNT(*) AS n FROM account_security').first()).n, 1);

    await page.goto(`${issuer}/admin`);
    await page.getByText('招待コードを直接渡す', { exact: true }).click();
    await page.getByRole('button', { name: 'Passkeyで招待を発行' }).click();
    const normalInvitation = await page.locator('code').textContent();
    assert.equal(normalInvitation?.length, 43);
    assert.equal(
      (await DB.prepare("SELECT COUNT(*) AS n FROM enrollment_invite WHERE kind='normal'").first())
        .n,
      1,
    );

    await context.clearCookies();
    const secondPending = await worker.fetch(authorize.href, { redirect: 'manual' });
    const secondBrowserCookie = requiredHeader(secondPending, 'set-cookie').split(';')[0];
    await context.addCookies([
      {
        name: '__Host-op-browser',
        value: secondBrowserCookie.split('=')[1],
        domain: 'mikaki.test',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
      },
    ]);
    const autoStarted = page.waitForEvent('console', {
      predicate: (message) => message.text() === 'passkey-test:auto-start',
    });
    await page.goto(requiredHeader(secondPending, 'location'));
    await autoStarted;
    await page.waitForFunction(() => document.querySelector('#passkey') !== null);
    assert.equal(
      await page
        .locator('.auth-primary')
        .evaluate((node) => getComputedStyle(node).backgroundColor),
      'rgba(0, 0, 0, 0)',
    );
    await page.getByRole('button', { name: 'Passkeyでサインイン' }).click();
    await page.getByRole('alert').waitFor();
    assert.ok(passkeyEvents.includes('passkey-test:auto-aborted'));
    assert.ok(passkeyEvents.includes('passkey-test:button-cancelled'));
    await page.getByRole('button', { name: 'Passkeyでサインイン' }).click();
    await page.getByRole('heading', { name: '接続先を確認してください' }).waitFor();
    assert.equal(
      (
        await DB.prepare(
          "SELECT COUNT(*) AS n FROM app_connection WHERE client_id='test-client'",
        ).first()
      ).n,
      0,
    );
    await page.getByRole('button', { name: 'この接続を続ける' }).click();
    await page.getByRole('heading', { name: 'Authorization resumed' }).waitFor();
    assert.ok(passkeyEvents.includes('passkey-test:button-retry'));
    const secondSso = (await context.cookies(issuer)).find(
      (cookie) => cookie.name === '__Host-op-sso',
    );
    assert.ok(secondSso);
    const secondAuthorization = await worker.fetch(authorize.href, {
      headers: { cookie: `${secondSso.name}=${secondSso.value}` },
      redirect: 'manual',
    });
    assert.ok(new URL(requiredHeader(secondAuthorization, 'location')).searchParams.get('code'));

    await context.clearCookies();
    const normalPending = await worker.fetch(`${issuer}/enroll`, { redirect: 'manual' });
    const normalBrowserCookie = requiredHeader(normalPending, 'set-cookie').split(';')[0];
    await context.addCookies([
      {
        name: '__Host-op-browser',
        value: normalBrowserCookie.split('=')[1],
        domain: 'mikaki.test',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
      },
    ]);
    await page.goto(requiredHeader(normalPending, 'location'));
    await page.getByLabel('招待コード').fill(normalInvitation);
    loseNextFinishResponse = true;
    await page.getByRole('button', { name: '招待で登録する' }).click();
    await page.getByRole('alert').waitFor();
    assert.ok(lostFinishBody);
    assert.deepEqual(concurrentFinishStatuses, [200, ...Array<number>(7).fill(400)]);
    assert.equal((await DB.prepare('SELECT COUNT(*) AS n FROM account_security').first()).n, 2);
    assert.equal((await DB.prepare('SELECT COUNT(*) AS n FROM passkey_credential').first()).n, 2);
    const lostResponseReplay = await worker.fetch(`${issuer}/register/finish`, {
      method: 'POST',
      headers: {
        cookie: normalBrowserCookie,
        origin: issuer,
        'content-type': 'application/json',
      },
      body: lostFinishBody,
    });
    assert.equal(lostResponseReplay.status, 400);
    assert.equal((await DB.prepare('SELECT COUNT(*) AS n FROM account_security').first()).n, 2);
    assert.equal(
      (await DB.prepare("SELECT COUNT(*) AS n FROM account_role WHERE role='admin'").first()).n,
      1,
    );
    await context.clearCookies();
    // Recover the credential whose registration response was lost, rather than
    // relying on the virtual authenticator's unspecified multi-account selection.
    const lostCredential = (JSON.parse(lostFinishBody!) as { response: { id: string } }).response
      .id;
    const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
    assert.ok(
      credentials.some(
        (credential) =>
          Buffer.from(credential.credentialId, 'base64').toString('base64url') === lostCredential,
      ),
    );
    for (const credential of credentials) {
      if (Buffer.from(credential.credentialId, 'base64').toString('base64url') !== lostCredential)
        await cdp.send('WebAuthn.removeCredential', {
          authenticatorId,
          credentialId: credential.credentialId,
        });
    }
    const afterLostResponse = await worker.fetch(authorize.href, { redirect: 'manual' });
    const recoveryBrowserCookie = requiredHeader(afterLostResponse, 'set-cookie').split(';')[0];
    await context.addCookies([
      {
        name: '__Host-op-browser',
        value: recoveryBrowserCookie.split('=')[1],
        domain: 'mikaki.test',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
      },
    ]);
    await page.goto(requiredHeader(afterLostResponse, 'location'));
    await page.getByRole('button', { name: 'Passkeyでサインイン' }).click();
    // The injected cancellation occurs on the first button attempt after every navigation.
    await page.getByRole('alert').waitFor();
    await page.getByRole('button', { name: 'Passkeyでサインイン' }).click();
    await page.getByRole('heading', { name: '接続先を確認してください' }).waitFor();
    await page.getByRole('button', { name: 'この接続を続ける' }).click();
    await page.getByRole('heading', { name: 'Authorization resumed' }).waitFor();
    assert.equal(
      await DB.prepare(
        "SELECT reviewed_scope FROM app_connection WHERE client_id='test-client' AND account_id=(SELECT account_id FROM credential WHERE credential_id=?)",
      )
        .bind(lostCredential)
        .first('reviewed_scope'),
      'openid',
    );

    // A changed authenticated PAR must carry its authoritative profile scope
    // through the review and real finish, even with a conflicting outer query.
    const clientKey = await generateKeyPair('ES256', { extractable: true });
    const clientJwk = await exportJWK(clientKey.publicKey);
    await DB.prepare("INSERT INTO client_key VALUES('test-client','review',1,1,'ES256',?)")
      .bind(
        Buffer.concat([
          Buffer.from([4]),
          Buffer.from(clientJwk.x!, 'base64url'),
          Buffer.from(clientJwk.y!, 'base64url'),
        ]),
      )
      .run();
    await harness.update({
      root: new URL('../..', import.meta.url).pathname,
      workers: [
        {
          configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
          vars: { MIKAKI_ISSUER: issuer, MIKAKI_PAR_MODE: 'required' },
        },
      ],
    });
    DB = (await worker.getEnv()).DB;
    const now = Math.floor(Date.now() / 1000);
    const assertion = await new SignJWT({ jti: randomUUID() })
      .setProtectedHeader({ alg: 'ES256', kid: 'review' })
      .setIssuer('test-client')
      .setSubject('test-client')
      .setAudience(`${issuer}/par`)
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .sign(clientKey.privateKey);
    const pushed = await worker.fetch(`${issuer}/par`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        ...Object.fromEntries(authorize.searchParams),
        scope: 'openid profile',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      }).toString(),
    });
    assert.equal(pushed.status, 201, await pushed.clone().text());
    const reference = `${issuer}/authorize?${new URLSearchParams({ client_id: 'test-client', request_uri: ((await pushed.json()) as { request_uri: string }).request_uri, scope: 'openid' })}`;
    const currentSso = (await context.cookies(issuer)).find(
      (cookie) => cookie.name === '__Host-op-sso',
    )!;
    const parPending = await worker.fetch(reference, {
      redirect: 'manual',
      headers: { cookie: `${currentSso.name}=${currentSso.value}` },
    });
    const parLogin = requiredHeader(parPending, 'location');
    assert.equal(new URL(parLogin).pathname, '/login');
    const parBrowser = requiredHeader(parPending, 'set-cookie').split(';')[0].split('=')[1];
    await context.addCookies([
      {
        name: '__Host-op-browser',
        value: parBrowser,
        domain: 'mikaki.test',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
      },
    ]);
    const beforeReview = await worker.fetch(parLogin, {
      headers: { cookie: `__Host-op-browser=${parBrowser}` },
    });
    const parHtml = await beforeReview.text();
    assert.match(parHtml, /data-login-scope="openid profile"/);
    assert.match(parHtml, /data-connection-review-required="true"/);
    await page.goto(parLogin);
    await page.locator('#passkey').click();
    await page.getByRole('alert').waitFor();
    await page.locator('#passkey').click();
    await page.locator('#connection-approve').waitFor();
    assert.equal(
      await DB.prepare(
        "SELECT reviewed_scope FROM app_connection WHERE client_id='test-client' AND account_id=(SELECT account_id FROM credential WHERE credential_id=?)",
      )
        .bind(lostCredential)
        .first('reviewed_scope'),
      'openid',
    );
    await page.locator('#connection-approve').click();
    await page.getByRole('heading', { name: 'Authorization resumed' }).waitFor();
    assert.equal(
      await DB.prepare(
        "SELECT reviewed_scope FROM app_connection WHERE client_id='test-client' AND account_id=(SELECT account_id FROM credential WHERE credential_id=?)",
      )
        .bind(lostCredential)
        .first('reviewed_scope'),
      'openid profile',
    );
    const parSso = (await context.cookies(issuer)).find(
      (cookie) => cookie.name === '__Host-op-sso',
    )!;
    const parResumed = await worker.fetch(reference, {
      redirect: 'manual',
      headers: { cookie: `${parSso.name}=${parSso.value}` },
    });
    assert.ok(
      new URL(requiredHeader(parResumed, 'location')).searchParams.get('code'),
      'reviewed PAR resumes and issues one code',
    );
    assert.deepEqual(errors, []);
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    await evidence?.finish(failure);
    await browser?.close();
    await harness.close();
  }
});
