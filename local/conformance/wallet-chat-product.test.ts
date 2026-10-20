import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir } from 'node:fs/promises';
import { chromium, expect } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { walletPresentationLink } from '../../crates/worker/ui/messaging/wallet-presentation.ts';
import { createNativeUiPage, startNativeUiServer } from './support/native-client-ui.ts';

test('Chat only offers an explicit Wallet handoff for bounded presentation invocations', () => {
  const valid =
    'openid4vp:?client_id=verifier&request_uri=https%3A%2F%2Fverifier.example%2Frequest%3Fid%3Done';
  assert.equal(walletPresentationLink(valid), valid);
  for (const invalid of [
    'https://verifier.example/',
    'javascript:alert(1)',
    valid + '&client_id=other',
    valid + '&secret=unexpected',
    valid.replace('https%3A', 'http%3A'),
    valid.replace('openid4vp:', 'openid4vp://attacker'),
    ' ' + valid,
    valid + '#fragment',
    valid + '&request_uri_method=delete',
  ])
    assert.equal(walletPresentationLink(invalid), null, invalid);
});

test('native MVP shows Wallet and Chat, multiple credentials and explicit presentation review', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    signedIn: true,
    identityReader: true,
    identityWallet: true,
    identityInventory: [
      {
        id: 'one',
        title: '本人確認属性証明',
        issuer: 'https://issuer.example',
        format: 'dc+sd-jwt',
        expires_at: Math.floor(Date.now() / 1000) + 240,
        fields: { name: '試験 太郎' },
      },
      {
        id: 'two',
        title: '会員証（試験）',
        issuer: 'https://club.example',
        format: 'mso_mdoc',
        expires_at: Math.floor(Date.now() / 1000) + 240,
        fields: { name: '試験 太郎' },
      },
    ],
  });
  try {
    await expect(page.locator('#wallet')).toBeVisible();
    assert.deepEqual(await page.locator('#navigation a').allTextContents(), ['Wallet', 'Chat']);
    await expect(page.locator('.wallet-card')).toHaveCount(2);
    await expect(page.locator('#identity-form')).toBeHidden();
    await expect(page.locator('#identity-vp-form')).toBeHidden();
    await page.getByRole('button', { name: /会員証（試験）/ }).click();
    await expect(page.locator('#wallet-card-values')).toContainText('試験 太郎');
    await page.getByRole('link', { name: 'Chat', exact: true }).click();
    await expect(page.locator('#wallet-card-values')).toBeEmpty();
    await page.locator('#open-chat').click();
    assert.ok(
      await page.evaluate(() =>
        window.__nativeUiTest.arguments.some(
          (call) => call.command === 'open_mikaki_web' && call.args?.['destination'] === 'chat',
        ),
      ),
    );
    assert.equal(await page.evaluate(() => sessionStorage.length), 0);
    assert.equal(await page.evaluate(() => localStorage.length), 0);
    await page.getByRole('link', { name: 'Walletを開く', exact: true }).click();
    await expect(page.locator('.wallet-card')).toHaveCount(2);
    const audit = await new AxeBuilder({ page }).analyze();
    assert.deepEqual(
      audit.violations.map((v) => v.id),
      [],
    );
    const out = new URL(
      process.env['MIKAKI_WALLET_CHAT_PREVIEW'] === '1'
        ? '../../docs/wallet-chat-mvp-preview/'
        : '../generated/wallet-chat-mvp-preview/',
      import.meta.url,
    );
    await mkdir(out, { recursive: true });
    for (const width of [320, 390, 1080]) {
      await page.setViewportSize({ width, height: 844 });
      assert.equal(
        await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        true,
      );
      await page.screenshot({ path: new URL(`wallet-${width}.png`, out).pathname, fullPage: true });
    }
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});
