import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium } from '@playwright/test';
import { importJWK, SignJWT } from 'jose';
import { startLocal } from '../runtime.ts';
import { CLIENT, OP, RP } from '../shared.ts';

test('Docs RP serves bilingual guides and keeps only isolated OIDC session state', async () => {
  const local = await startLocal({ scheduler: false, docs: true });
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({
      locale: 'en-US',
      extraHTTPHeaders: { 'Accept-Language': 'en-US' },
    });
    const page = await context.newPage();
    page.setDefaultTimeout(5000);
    page.setDefaultNavigationTimeout(5000);

    const docsDir = new URL('../../apps/mikaki-docs/dist/', import.meta.url);
    const japaneseHome = await readFile(new URL('index.html', docsDir), 'utf8');
    const englishHome = await readFile(new URL('en/index.html', docsDir), 'utf8');
    const japaneseFaq = await readFile(new URL('faq.html', docsDir), 'utf8');
    const englishFaq = await readFile(new URL('en/faq.html', docsDir), 'utf8');
    assert.match(japaneseHome, /<html lang="ja">/);
    assert.match(japaneseHome, /mikakiのドキュメント/);
    assert.match(englishHome, /<html lang="en">/);
    assert.match(englishHome, /mikaki documentation/i);
    assert.match(japaneseFaq, /<html lang="ja">/);
    assert.match(japaneseFaq, /よくある質問|FAQ/);
    assert.match(englishFaq, /<html lang="en">/);
    assert.match(englishFaq, /Frequently asked questions|FAQ/);
    assert.doesNotMatch(
      japaneseHome + englishHome + japaneseFaq + englishFaq,
      /<form|Sign in with mikaki/,
    );

    await page.goto(`${RP}/session?lang=en`);
    const sessionPage = await page.locator('main').innerText();
    assert.match(sessionPage, /does not request your name, email or Vault contents/);
    assert.match(sessionPage, /Sign in with mikaki/);
    assert.doesNotMatch(sessionPage, /\bsub\b|\bsid\b|token/i);
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        ctap2Version: 'ctap2_1',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });

    const browserId = (await context.cookies()).find(
      (entry) => entry.name === '__Host-help-browser' && entry.domain === new URL(RP).hostname,
    )?.value;
    assert.ok(browserId, 'the Docs session page establishes its browser-bound CSRF cookie');
    const csrf = await page.locator('form[action="/login"] input[name="csrf"]').inputValue();
    for (const origin of [undefined, 'null', 'https://attacker.example']) {
      const headers: Record<string, string> = {
        Cookie: `__Host-help-browser=${browserId}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      };
      if (origin) headers.Origin = origin;
      const denied = await local.rp.fetch(`${RP}/login`, {
        method: 'POST',
        headers,
        body: new URLSearchParams({ csrf }),
        redirect: 'manual',
      });
      assert.equal(denied.status, 403, 'CSRF alone does not bypass the same-origin check');
    }
    assert.equal(
      (await local.rpDB.prepare('SELECT COUNT(*) AS count FROM login_transaction').first()).count,
      0,
      'rejected origins create no OIDC transaction',
    );
    const loginRequest = page.waitForRequest(
      (request) => new URL(request.url()).pathname === '/login' && request.method() === 'POST',
    );
    const loginResponse = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === '/login' && response.request().method() === 'POST',
    );
    await page.getByRole('button', { name: 'Sign in with mikaki' }).click();
    const request = await loginRequest;
    const response = await loginResponse;
    assert.equal(request.headers().origin, RP, 'same-origin HTML form POST carries its Origin');
    assert.equal(response.status(), 303);
    const authorize = new URL(response.headers()['location']!);
    assert.equal(authorize.origin, OP);
    assert.equal(authorize.pathname, '/authorize');
    assert.equal(authorize.searchParams.get('scope'), 'openid');
    assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
    const loginCount = (await local.rpDB
      .prepare('SELECT COUNT(*) AS count FROM login_transaction')
      .first()) as { count: number } | null;
    assert.equal(loginCount?.count, 1);

    await page.waitForURL(`${OP}/login?**`);
    await page.getByRole('checkbox').check();
    await page.locator('#invitation').fill(local.invitation);
    await page.getByRole('button', { name: /Register with invitation/ }).click();
    await page.waitForURL(`${RP}/session*`);

    const stored = (await local.rpDB.prepare('SELECT sid,sub FROM rp_session LIMIT 1').first()) as {
      sid: string;
      sub: string;
    } | null;
    assert.ok(
      stored?.sid && stored.sub,
      'the Docs form, OIDC callback and session check establish the isolated session',
    );
    const docsSessionCookie = async () =>
      (await context.cookies()).find(
        (entry) => entry.name === '__Host-help-session' && entry.domain === new URL(RP).hostname,
      );
    assert.ok(await docsSessionCookie(), 'the callback sets the Docs-only session cookie');
    const sessionCheckRequest = page.waitForRequest(
      (request) =>
        new URL(request.url()).pathname === '/session/check' && request.method() === 'POST',
    );
    const sessionCheckResponse = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === '/session/check' &&
        response.request().method() === 'POST',
    );
    await page.getByRole('button', { name: 'Check session again' }).click();
    const checkedRequest = await sessionCheckRequest;
    assert.equal(checkedRequest.headers().origin, RP);
    const checkedResponse = await sessionCheckResponse;
    assert.equal(checkedResponse.status(), 303);
    assert.equal(checkedResponse.headers()['location'], `${RP}/session`);
    await page.waitForURL(`${RP}/session*`);
    const opSession = (await local.opDB
      .prepare('SELECT revoked FROM client_session WHERE client_id=? AND sid=?')
      .bind(CLIENT, stored.sid)
      .first()) as { revoked: number } | null;
    assert.equal(opSession?.revoked, 0);

    await page.getByRole('button', { name: 'Sign out of Docs' }).click();
    await page.waitForURL(`${RP}/`);
    assert.equal(await local.rpDB.prepare('SELECT sid FROM rp_session').first(), null);
    assert.equal(
      await docsSessionCookie(),
      undefined,
      'RP logout expires the Docs-only browser cookie',
    );
    assert.equal(
      (
        (await local.opDB
          .prepare('SELECT revoked FROM client_session WHERE client_id=? AND sid=?')
          .bind(CLIENT, stored.sid)
          .first()) as { revoked: number } | null
      )?.revoked,
      0,
      'Docs logout leaves the OP SSO session active',
    );

    await page.goto(`${RP}/session?lang=en`);
    await page.getByRole('button', { name: 'Sign in with mikaki' }).click();
    await page.waitForURL(`${RP}/session*`);
    const storedAfterLogout = (await local.rpDB
      .prepare('SELECT sid,sub FROM rp_session LIMIT 1')
      .first()) as { sid: string; sub: string } | null;
    assert.ok(storedAfterLogout?.sid && storedAfterLogout.sub);
    const { sid, sub } = storedAfterLogout;

    const opKey = await importJWK(JSON.parse(local.opKeys.private), 'ES256');
    const logoutToken = (audience: string) =>
      new SignJWT({
        sid,
        sub,
        jti: crypto.randomUUID(),
        events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'logout+jwt', kid: 'local-op-1' })
        .setIssuer(OP)
        .setAudience(audience)
        .setIssuedAt()
        .setExpirationTime('2m')
        .sign(opKey);
    const wrongAudience = await local.rp.fetch(`${RP}/backchannel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ logout_token: await logoutToken('another-client') }),
    });
    assert.equal(wrongAudience.status, 400);
    assert.ok(await local.rpDB.prepare('SELECT sid FROM rp_session WHERE sid=?').bind(sid).first());
    const backchannel = await local.rp.fetch(`${RP}/backchannel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ logout_token: await logoutToken(CLIENT) }),
    });
    assert.equal(backchannel.status, 200);
    assert.equal(
      await local.rpDB.prepare('SELECT sid FROM rp_session WHERE sid=?').bind(sid).first(),
      null,
    );
    assert.ok(
      await local.rpDB.prepare('SELECT sid FROM logout_tombstone WHERE sid=?').bind(sid).first(),
    );

    for (let index = 0; index < 61; index++) {
      const limited = await local.rp.fetch(`${RP}/login`, {
        method: 'POST',
        headers: {
          Origin: RP,
          Cookie: `__Host-help-browser=client-a`,
          'cf-connecting-ip': '192.0.2.10',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ csrf: 'invalid' }),
      });
      if (index === 60) assert.equal(limited.status, 429);
    }
    const otherSource = await local.rp.fetch(`${RP}/login`, {
      method: 'POST',
      headers: {
        Origin: RP,
        Cookie: `__Host-help-browser=client-b`,
        'cf-connecting-ip': '192.0.2.10',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ csrf: 'invalid' }),
    });
    assert.equal(
      otherSource.status,
      429,
      'rotating browser cookies from one source IP cannot bypass the rate-limit budget',
    );
    const otherClient = await local.rp.fetch(`${RP}/login`, {
      method: 'POST',
      headers: {
        Origin: RP,
        Cookie: `__Host-help-browser=client-c`,
        'cf-connecting-ip': '192.0.2.11',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ csrf: 'invalid' }),
    });
    assert.equal(
      otherClient.status,
      403,
      'a different source IP has an independent rate-limit budget',
    );

    const health = await context.request.get(`${RP}/health`);
    assert.equal(health.status(), 200);
    assert.deepEqual(await health.json(), { status: 'ok', issuer: OP, origin: RP, mode: 'docs' });
  } finally {
    await browser.close();
    await local.close();
  }
});
