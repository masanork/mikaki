import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import { createNativeUiPage, startNativeUiServer } from './support/native-client-ui.ts';

test('native shell loads accounts in its WebView and keeps Wallet local', async (t) => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch({ headless: true });
  try {
    for (const platform of ['desktop', 'mobile'] as const) {
      await t.test(
        `${platform}: WebView navigation needs no native OIDC session or discovery`,
        async () => {
          const { page, errors } = await createNativeUiPage(browser, server.url, { platform });
          try {
            await page.getByRole('button', { name: 'Web版を開く' }).click();
            await page.getByRole('button', { name: 'Vaultを開く' }).click();
            const calls = await page.evaluate(() => window.__nativeUiTest.arguments);
            assert.deepEqual(
              calls.filter((call) => call.command === 'open_mikaki_web').map((call) => call.args),
              [{ destination: 'signin' }, { destination: 'vault' }],
            );
            assert.equal(
              calls.some((call) => /native_session|auth_status|login/.test(call.command)),
              false,
            );
            assert.equal(await page.locator('#login, #account, #logout-dialog').count(), 0);
            await page.getByRole('link', { name: 'Walletを開く' }).click();
            await page.locator('#wallet').waitFor({ state: 'visible' });
            assert.equal(await page.locator('#navigation').isVisible(), true);
            await page.goBack();
            await page.locator('#home').waitFor({ state: 'visible' });
            assert.deepEqual(errors, []);
          } finally {
            await page.close();
          }
        },
      );
    }
    await t.test(
      'failed WebView navigation can be retried without exposing diagnostic details',
      async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url);
        try {
          await page.evaluate(() => {
            window.__nativeUiTest.failures.open_mikaki_web = 'internal failure';
          });
          await page.getByRole('button', { name: 'Web版を開く' }).click();
          assert.match((await page.locator('#status').textContent()) ?? '', /開けませんでした/);
          assert.doesNotMatch(
            (await page.locator('#status').textContent()) ?? '',
            /internal failure/,
          );
          await page.evaluate(() => {
            delete window.__nativeUiTest.failures.open_mikaki_web;
          });
          await page.getByRole('button', { name: 'Web版を開く' }).click();
          assert.match((await page.locator('#status').textContent()) ?? '', /開いています/);
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      },
    );
    await t.test(
      'appearance, back navigation and narrow layouts work without downloading fonts',
      async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url);
        try {
          const requests: string[] = [];
          page.on('request', (request) => requests.push(request.url()));
          await page.locator('#open-settings').click();
          await page.getByLabel('テーマ').selectOption('dark');
          await page.reload();
          await page.locator('#settings').waitFor({ state: 'visible' });
          assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
          assert.equal(await page.evaluate(() => localStorage.length), 1);
          assert.equal(
            requests.some((url) => /fonts|\.woff2/.test(url)),
            false,
          );
          for (const width of [320, 375, 480, 1080]) {
            await page.setViewportSize({ width, height: 812 });
            assert.ok(
              await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
            );
          }
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      },
    );
  } finally {
    await browser.close();
    await server.close();
  }
});
