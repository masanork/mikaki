import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chromium } from '@playwright/test';
import { startLocal } from '../runtime.ts';
import { OP, RP, now } from '../shared.ts';

test('login-only RP isolates data, checks active leases and removes known revoked sessions', async () => {
  let checks = 0;
  const local = await startLocal({
    scheduler: false,
    helpdesk: true,
    demo: true,
    beforeSessionCheckResponse: async () => {
      checks += 1;
    },
  });
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({
      locale: 'en-US',
      extraHTTPHeaders: { 'Accept-Language': 'en-US' },
    });
    const page = await context.newPage();
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
    const health = await context.request.get(`${RP}/health`);
    assert.equal(health.status(), 200);
    assert.equal((await health.json()).mode, 'login-demo');
    for (const path of [
      '/help',
      '/tickets',
      '/tickets/new',
      '/tickets/00000000-0000-4000-8000-000000000001',
    ]) {
      assert.equal((await context.request.get(`${RP}${path}`)).status(), 404);
      assert.equal(
        (
          await context.request.post(`${RP}${path}`, { form: { title: 'must not store' } })
        ).status(),
        404,
      );
    }
    assert.equal((await context.request.get(`${RP}/session`)).status(), 401);
    const ja = await context.request.get(`${RP}/?lang=ja`);
    assert.match(await ja.text(), /公開IdPへの接続を試す/);
    assert.match(ja.headers()['x-robots-tag'], /noindex/);
    assert.equal(ja.headers()['referrer-policy'], 'strict-origin');
    await page.goto(`${RP}/?lang=en`);
    await page.getByRole('button', { name: 'Sign in with mikaki' }).click();
    await page.waitForURL(`${OP}/login?**`);
    await page.getByRole('checkbox').check();
    await page.getByLabel('Invitation code', { exact: true }).fill(local.invitation);
    await page.getByRole('button', { name: 'Register with invitation' }).click();
    await page.waitForURL(`${RP}/session`);
    assert.match(await page.locator('main').innerText(), /Signed in/);
    assert.equal(checks, 1);
    const session = (await local.rpDB
      .prepare('SELECT sid, sub, parent_expires_at, lease_until FROM rp_session')
      .first()) as {
      sid: string;
      sub: string;
      parent_expires_at: number;
      lease_until: number;
    } | null;
    assert.ok(session);
    assert.ok(session.parent_expires_at <= now() + 3600);
    assert.ok(session.lease_until <= session.parent_expires_at);
    assert.ok(!(await page.locator('main').innerText()).includes(session.sub));
    assert.ok(!(await page.locator('main').innerText()).includes(session.sid));
    assert.equal(
      (
        await context.request.post(`${RP}/session/check`, {
          headers: { Origin: RP },
          form: { csrf: 'wrong' },
        })
      ).status(),
      403,
    );
    await page.getByRole('button', { name: 'Check session again' }).click();
    await page.getByRole('heading', { name: 'Signed in', exact: true }).waitFor();
    assert.equal(checks, 2);
    await page.getByRole('button', { name: 'Sign out of this demo' }).click();
    await page.waitForURL(`${RP}/`);
    assert.equal((await context.request.get(`${RP}/session`)).status(), 401);
    assert.equal(await local.rpDB.prepare('SELECT sid FROM rp_session').first(), null);
    const opSession = (await local.opDB
      .prepare('SELECT revoked FROM client_session WHERE sid=?')
      .bind(session.sid)
      .first()) as { revoked: number } | null;
    assert.equal(opSession?.revoked, 0, 'app logout must not end OP login');
    await page.getByRole('button', { name: 'Sign in with mikaki' }).click();
    await page.waitForURL(`${RP}/session`);
    const next = (await local.rpDB.prepare('SELECT sid, lease_until FROM rp_session').first()) as {
      sid: string;
      lease_until: number;
    } | null;
    assert.ok(next && next.lease_until > now());
    await local.opDB
      .prepare('UPDATE client_session SET revoked=1 WHERE sid=?')
      .bind(next.sid)
      .run();
    await page.getByRole('button', { name: 'Check session again' }).click();
    assert.match(await page.locator('main').innerText(), /expired or you have been logged out/);
    assert.equal(await local.rpDB.prepare('SELECT sid FROM rp_session').first(), null);
    assert.equal((await context.request.get(`${RP}/session`)).status(), 401);
    assert.equal(
      (
        (await local.rpDB.prepare('SELECT COUNT(*) AS count FROM ticket').first()) as {
          count: number;
        } | null
      )?.count,
      0,
    );
    assert.equal(
      (
        await context.request.get(
          `${RP}/callback?code=invalid&state=invalid&iss=${encodeURIComponent(OP)}`,
        )
      ).status(),
      400,
    );
    const transaction = await local.rpDB
      .prepare('SELECT state_hash FROM login_transaction LIMIT 1')
      .first();
    assert.equal(transaction, null, 'successful login transactions are consumed');
  } finally {
    await browser.close();
    await local.close();
  }
});
