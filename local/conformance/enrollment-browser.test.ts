import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { issueBootstrapInvite } from '../../scripts/enrollment-store.ts';

test('bootstrap invitation registers a passkey and the new account can sign in', async () => {
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
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
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
    const errors = [];
    let finishBody;
    page.on('pageerror', (error) => errors.push(error.message));
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        automaticPresenceSimulation: true,
        isUserVerified: true,
      },
    });
    await page.route(
      (url) => url.hostname === 'mikaki.test',
      async (route) => {
        try {
          const request = route.request();
          if (new URL(request.url()).pathname === '/register/finish')
            finishBody = request.postData();
          if (new URL(request.url()).pathname === '/authorize') {
            await route.fulfill({
              status: 200,
              contentType: 'text/html',
              body: '<h1>Authorization resumed</h1>',
            });
            return;
          }
          const response = await worker.fetch(request.url(), {
            method: request.method(),
            headers: await request.allHeaders(),
            redirect: 'manual',
            ...(request.postDataBuffer() ? { body: request.postDataBuffer() } : {}),
          });
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
    const pending = await worker.fetch(`${issuer}/enroll`, { redirect: 'manual' });
    assert.equal(pending.status, 302);
    const initialBrowserCookie = pending.headers.get('set-cookie').split(';')[0];
    const initialLoginUrl = pending.headers.get('location');
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
    await page.getByLabel('招待コード').fill(invitation);
    await page.getByRole('button', { name: '招待で登録する' }).click();
    await page.getByRole('heading', { name: '登録が完了しました' }).waitFor();
    const firstSso = (await context.cookies(issuer)).find(
      (cookie) => cookie.name === '__Host-op-sso',
    );
    assert.ok(firstSso);
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
    const secondBrowserCookie = secondPending.headers.get('set-cookie').split(';')[0];
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
    await page.goto(secondPending.headers.get('location'));
    await page.getByRole('button', { name: 'Passkeyで許可してログイン' }).click();
    await page.getByRole('heading', { name: 'Authorization resumed' }).waitFor();
    const secondSso = (await context.cookies(issuer)).find(
      (cookie) => cookie.name === '__Host-op-sso',
    );
    assert.ok(secondSso);
    const secondAuthorization = await worker.fetch(authorize.href, {
      headers: { cookie: `${secondSso.name}=${secondSso.value}` },
      redirect: 'manual',
    });
    assert.ok(new URL(secondAuthorization.headers.get('location')).searchParams.get('code'));

    await context.clearCookies();
    const normalPending = await worker.fetch(`${issuer}/enroll`, { redirect: 'manual' });
    const normalBrowserCookie = normalPending.headers.get('set-cookie').split(';')[0];
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
    await page.goto(normalPending.headers.get('location'));
    await page.getByLabel('招待コード').fill(normalInvitation);
    await page.getByRole('button', { name: '招待で登録する' }).click();
    await page.getByRole('heading', { name: '登録が完了しました' }).waitFor();
    assert.equal((await DB.prepare('SELECT COUNT(*) AS n FROM account_security').first()).n, 2);
    assert.equal(
      (await DB.prepare("SELECT COUNT(*) AS n FROM account_role WHERE role='admin'").first()).n,
      1,
    );
    assert.deepEqual(errors, []);
  } finally {
    await browser?.close();
    await harness.close();
  }
});
