import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chromium } from '@playwright/test';
import { startLocal } from '../runtime.ts';
import { OP, RP, hash, now } from '../shared.ts';

test('helpdesk RP completes passkey login and protects tickets', async () => {
  const local = await startLocal({ scheduler: false, helpdesk: true });
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ locale: 'en-US' });
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
    await page.getByRole('link', { name: 'ヘルプ', exact: true }).click();
    await page.getByRole('link', { name: 'パスキーでログインする' }).click();
    assert.match(await page.locator('main').innerText(), /端末のロック/);
    await page.goto(`${RP}/tickets`);
    assert.match(await page.locator('main').innerText(), /login_required/);
    await page.goto(RP);
    await page.getByRole('button', { name: 'Mikaki でログイン' }).click();
    await page.waitForURL(`${OP}/login?**`);
    await page.getByLabel('Language').selectOption('en');
    await page.getByRole('checkbox').check();
    await page.getByLabel('Invitation code', { exact: true }).fill(local.invitation);
    await page.getByRole('button', { name: 'Register with invitation' }).click();
    await page.waitForURL(`${RP}/tickets`);
    assert.match(await page.locator('main').innerText(), /まだ問い合わせはありません/);
    await page.getByRole('link', { name: '新しい問い合わせ' }).click();
    await page.getByLabel('件名').fill('ログインの相談');
    await page.getByLabel('内容').fill('新しい端末でログインしたい');
    await page.getByRole('button', { name: '送信' }).click();
    await page.waitForURL(`${RP}/tickets/*`);
    const ticketId = new URL(page.url()).pathname.split('/')[2];
    assert.match(await page.locator('main').innerText(), /新しい端末でログインしたい/);
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
    await page.getByLabel('返信').fill('端末の設定を確認しました');
    await page.getByRole('button', { name: '送信' }).click();
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
    await page.getByRole('button', { name: '終了する' }).click();
    assert.match(await page.locator('main').innerText(), /終了/);
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
  } finally {
    await browser.close();
    await local.close();
  }
});
