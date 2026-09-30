import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chromium } from '@playwright/test';
import { importJWK, SignJWT } from 'jose';
import { startLocal } from '../runtime.ts';
import { CLIENT, OP, RP, hash, now } from '../shared.ts';

test('helpdesk RP completes passkey login and protects tickets', async () => {
  let holdCheck = false;
  let notifyHeld = () => {};
  let releaseCheck = () => {};
  const held = new Promise<void>((resolve) => (notifyHeld = resolve));
  const released = new Promise<void>((resolve) => (releaseCheck = resolve));
  const local = await startLocal({
    scheduler: false,
    helpdesk: true,
    beforeSessionCheckResponse: async () => {
      if (!holdCheck) return;
      holdCheck = false;
      notifyHeld();
      await released;
    },
  });
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({
      locale: 'en-US',
      extraHTTPHeaders: { 'Accept-Language': 'en-US' },
    });
    const page = await context.newPage();
    page.setDefaultTimeout(5000);
    page.setDefaultNavigationTimeout(5000);
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
    await page.goto(RP);
    await page.getByRole('link', { name: 'Help', exact: true }).click();
    await page.getByRole('link', { name: 'Log in with a passkey' }).click();
    assert.match(await page.locator('main').innerText(), /unlock your device/);
    assert.equal(await page.locator('html').getAttribute('lang'), 'en');
    await page.getByRole('link', { name: 'Language', exact: true }).click();
    assert.equal(new URL(page.url()).pathname, '/help/passkeys');
    assert.equal(await page.locator('html').getAttribute('lang'), 'ja');
    assert.match(await page.locator('main').innerText(), /端末のロック/);
    await page.getByRole('link', { name: '言語', exact: true }).click();
    for (const locale of ['ja', 'en']) {
      const vault = await context.request.get(`${RP}/help/vault?lang=${locale}`);
      assert.equal(vault.headers()['content-language'], locale);
      assert.match(await vault.text(), locale === 'ja' ? /通常のログインだけなら/ : /normal login/);
      const sessions = await context.request.get(`${RP}/help/sessions?lang=${locale}`);
      assert.match(
        await sessions.text(),
        locale === 'ja' ? /アプリごとに/ : /Each app has its own/,
      );
      const missing = await context.request.get(`${RP}/help/missing?lang=${locale}`);
      assert.equal(missing.status(), 404);
      assert.match(await missing.text(), locale === 'ja' ? /見つかりません/ : /Not found/);
      assert.doesNotMatch(await missing.text(), /not_found/);
    }
    await page.goto(`${RP}/tickets`);
    assert.match(await page.locator('main').innerText(), /Please log in to access support tickets/);
    await page.goto(RP);
    await page.getByRole('button', { name: 'Log in with Mikaki' }).click();
    await page.waitForURL(`${OP}/login?**`);
    assert.equal(new URL(page.url()).searchParams.get('lang'), 'en');
    assert.equal(await page.locator('html').getAttribute('lang'), 'en');
    const loginTx = new URL(page.url()).searchParams.get('tx');
    await page.getByLabel('Language').selectOption('ja');
    await page.getByLabel('言語').selectOption('en');
    await page.getByLabel('Language').waitFor();
    assert.equal(new URL(page.url()).searchParams.get('tx'), loginTx);
    await page.getByRole('checkbox').check();
    await page.getByLabel('Invitation code', { exact: true }).fill(local.invitation);
    await page.getByRole('button', { name: 'Register with invitation' }).click();
    await page.waitForURL(`${RP}/tickets`);
    assert.match(await page.locator('main').innerText(), /You have no support tickets yet/);
    await page.getByRole('link', { name: 'New support ticket' }).click();
    await page.getByLabel('Subject').fill('ログインの相談');
    await page.getByLabel('Message').fill('新しい端末でログインしたい');
    await page.getByRole('button', { name: 'Send' }).click();
    await page.waitForURL(`${RP}/tickets/*`);
    const ticketId = new URL(page.url()).pathname.split('/')[2];
    assert.match(await page.locator('main').innerText(), /新しい端末でログインしたい/);
    await page.getByRole('link', { name: 'Language', exact: true }).click();
    assert.equal(new URL(page.url()).pathname, `/tickets/${ticketId}`);
    assert.match(await page.locator('main').innerText(), /対応中/);
    assert.match(await page.locator('main').innerText(), /新しい端末でログインしたい/);
    await page.getByRole('link', { name: '言語', exact: true }).click();
    const owner = (await local.rpDB
      .prepare('SELECT owner_sub FROM ticket WHERE id=?')
      .bind(ticketId)
      .first()) as { owner_sub: string };
    assert.ok(owner.owner_sub);
    await local.rpDB
      .prepare('UPDATE rp_session SET idle_expires_at=?,idle_timeout_seconds=? WHERE sub=?')
      .bind(now() + 5, 60, owner.owner_sub)
      .run();
    await page.reload();
    const renewed = (await local.rpDB
      .prepare('SELECT idle_expires_at FROM rp_session WHERE sub=?')
      .bind(owner.owner_sub)
      .first()) as { idle_expires_at: number };
    assert.ok(renewed.idle_expires_at > now() + 50);
    await page.getByLabel('Reply').fill('端末の設定を確認しました');
    await page.getByRole('button', { name: 'Send' }).click();
    assert.match(await page.locator('main').innerText(), /端末の設定を確認しました/);
    const strangerToken = crypto.randomUUID();
    await local.rpDB
      .prepare(
        'INSERT INTO rp_session(token_hash,sid,sub,auth_time,lease_until,parent_expires_at,idle_expires_at,idle_timeout_seconds) VALUES(?,?,?,?,?,?,?,?)',
      )
      .bind(
        await hash(strangerToken),
        'other-sid',
        'other-sub',
        now(),
        now() + 60,
        now() + 600,
        now() + 600,
        600,
      )
      .run();
    const denied = await context.request.get(`${RP}/tickets/${ticketId}`, {
      headers: { Cookie: `__Host-help-session=${strangerToken}` },
    });
    assert.equal(denied.status(), 404);
    await local.rpDB.prepare('INSERT INTO staff(sub) VALUES(?)').bind('other-sub').run();
    const staffView = await context.request.get(`${RP}/tickets/${ticketId}`, {
      headers: { Cookie: `__Host-help-session=${strangerToken}` },
    });
    assert.equal(staffView.status(), 200);
    const staffBrowser = crypto.randomUUID();
    const staffReply = await context.request.post(`${RP}/tickets/${ticketId}/reply`, {
      headers: {
        Origin: RP,
        Cookie: `__Host-help-session=${strangerToken}; __Host-help-browser=${staffBrowser}`,
      },
      form: { csrf: await hash(staffBrowser), message: '担当者からの返信' },
      maxRedirects: 0,
    });
    assert.equal(staffReply.status(), 303);
    await page.reload();
    assert.match(await page.locator('main').innerText(), /担当者からの返信/);
    await local.rpDB.prepare('DELETE FROM staff WHERE sub=?').bind('other-sub').run();
    const revokedStaff = await context.request.get(`${RP}/tickets/${ticketId}`, {
      headers: { Cookie: `__Host-help-session=${strangerToken}` },
    });
    assert.equal(revokedStaff.status(), 404);
    await page.getByRole('button', { name: 'Close ticket' }).click();
    assert.match(await page.locator('main').innerText(), /Closed/);
    const rpCookies = (await context.cookies()).filter((c) => c.domain === '127.0.0.1');
    const blockedReply = await page.request.post(`${RP}/tickets/${ticketId}/reply`, {
      headers: { Origin: RP, Cookie: rpCookies.map((c) => `${c.name}=${c.value}`).join('; ') },
      form: {
        csrf: await hash(rpCookies.find((c) => c.name === '__Host-help-browser')!.value),
        message: 'late reply',
      },
      maxRedirects: 0,
    });
    assert.equal(blockedReply.status(), 409);
    const ownerSession = (await local.rpDB
      .prepare('SELECT sid,token_hash FROM rp_session WHERE sub=?')
      .bind(owner.owner_sub)
      .first()) as { sid: string; token_hash: string } | null;
    assert.ok(ownerSession);
    const opKey = await importJWK(JSON.parse(local.opKeys.private), 'ES256');
    const logoutToken = (audience: string, extra: Record<string, unknown> = {}) =>
      new SignJWT({
        sid: ownerSession.sid,
        sub: owner.owner_sub,
        jti: crypto.randomUUID(),
        events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
        ...extra,
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'logout+jwt', kid: 'local-op-1' })
        .setIssuer(OP)
        .setAudience(audience)
        .setIssuedAt()
        .setExpirationTime('2m')
        .sign(opKey);
    const wrongAudience = await context.request.post(`${RP}/backchannel`, {
      form: { logout_token: await logoutToken('other-client') },
    });
    assert.equal(wrongAudience.status(), 400);
    const withNonce = await context.request.post(`${RP}/backchannel`, {
      form: { logout_token: await logoutToken(CLIENT, { nonce: 'forbidden' }) },
    });
    assert.equal(withNonce.status(), 400);
    const nonemptyEvent = await context.request.post(`${RP}/backchannel`, {
      form: {
        logout_token: await logoutToken(CLIENT, {
          events: { 'http://schemas.openid.net/event/backchannel-logout': { unexpected: true } },
        }),
      },
    });
    assert.equal(nonemptyEvent.status(), 400);
    const wrongSubject = await context.request.post(`${RP}/backchannel`, {
      form: { logout_token: await logoutToken(CLIENT, { sub: 'other-sub' }) },
    });
    assert.equal(wrongSubject.status(), 400);
    const forged = await new SignJWT({
      sid: ownerSession.sid,
      sub: owner.owner_sub,
      jti: crypto.randomUUID(),
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'logout+jwt', kid: 'local-op-1' })
      .setIssuer(OP)
      .setAudience(CLIENT)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(await importJWK(JSON.parse(local.rpKeys.private), 'ES256'));
    const badSignature = await context.request.post(`${RP}/backchannel`, {
      form: { logout_token: forged },
    });
    assert.equal(badSignature.status(), 400);
    assert.ok(
      await local.rpDB
        .prepare('SELECT sid FROM rp_session WHERE sid=?')
        .bind(ownerSession.sid)
        .first(),
    );
    const signedLogout = await logoutToken(CLIENT);
    const backchannel = await context.request.post(`${RP}/backchannel`, {
      form: { logout_token: signedLogout },
    });
    assert.equal(backchannel.status(), 200);
    const duplicate = await context.request.post(`${RP}/backchannel`, {
      form: { logout_token: signedLogout },
    });
    assert.equal(duplicate.status(), 200);
    assert.equal(
      await local.rpDB
        .prepare('SELECT sid FROM rp_session WHERE sid=?')
        .bind(ownerSession.sid)
        .first(),
      null,
    );
    assert.ok(
      await local.rpDB
        .prepare('SELECT sid FROM logout_tombstone WHERE sid=?')
        .bind(ownerSession.sid)
        .first(),
    );
    await local.opDB
      .prepare('UPDATE client_session SET revoked=1 WHERE sid=?')
      .bind(ownerSession.sid)
      .run();
    await local.rpDB
      .prepare('UPDATE rp_session SET lease_until=? WHERE token_hash=?')
      .bind(now() - 1, ownerSession.token_hash)
      .run();
    const revoked = await context.request.get(`${RP}/tickets/${ticketId}`, {
      headers: { Cookie: rpCookies.map((c) => `${c.name}=${c.value}`).join('; ') },
    });
    assert.equal(revoked.status(), 401);
    const logout = await context.request.post(`${RP}/logout`, {
      headers: { Origin: RP, Cookie: rpCookies.map((c) => `${c.name}=${c.value}`).join('; ') },
      form: { csrf: await hash(rpCookies.find((c) => c.name === '__Host-help-browser')!.value) },
      maxRedirects: 0,
    });
    assert.equal(logout.status(), 303);
    const remaining = (await local.rpDB
      .prepare('SELECT COUNT(*) AS count FROM rp_session WHERE sub=?')
      .bind(owner.owner_sub)
      .first()) as { count: number } | null;
    assert.equal(remaining?.count, 0);
    await local.rpDB
      .prepare(
        'INSERT INTO login_transaction(state_hash,browser_hash,nonce,verifier,expires_at) VALUES(?,?,?,?,?)',
      )
      .bind('expired', 'browser', 'nonce', 'verifier', now() - 1)
      .run();
    await local.rp.scheduled({ cron: '0 3 * * *', scheduledTime: new Date() });
    const expired = (await local.rpDB
      .prepare('SELECT COUNT(*) AS count FROM login_transaction WHERE state_hash=?')
      .bind('expired')
      .first()) as { count: number };
    assert.equal(expired.count, 0);

    await page.goto(RP);
    holdCheck = true;
    const pendingLogin = page.getByRole('button', { name: 'Log in with Mikaki' }).click();
    await held;
    const pendingSession = (await local.opDB
      .prepare('SELECT sid,sub FROM client_session WHERE revoked=0 ORDER BY rowid DESC LIMIT 1')
      .first()) as { sid: string; sub: string } | null;
    assert.ok(pendingSession);
    assert.notEqual(pendingSession.sid, ownerSession.sid);
    const beforeCallback = await context.request.post(`${RP}/backchannel`, {
      form: {
        logout_token: await logoutToken(CLIENT, {
          sid: pendingSession.sid,
          sub: pendingSession.sub,
        }),
      },
    });
    assert.equal(beforeCallback.status(), 200);
    releaseCheck();
    await pendingLogin;
    assert.match(
      await page.locator('main').innerText(),
      /Your session has expired or you have been logged out/,
    );
    assert.equal(
      await local.rpDB
        .prepare('SELECT sid FROM rp_session WHERE sid=?')
        .bind(pendingSession.sid)
        .first(),
      null,
    );
  } finally {
    releaseCheck();
    await browser.close();
    await local.close();
  }
});
