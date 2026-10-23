import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium, expect } from '@playwright/test';
import { createNativeUiPage, startNativeUiServer } from './support/native-client-ui.ts';

test('packaged native frontend boots Wallet with only the declared assets', async () => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch();
  try {
    const { page, errors } = await createNativeUiPage(browser, server.url);
    await page.getByRole('link', { name: 'Walletを開く', exact: true }).click();
    await expect(page.locator('#wallet')).toBeVisible();
    assert.deepEqual(errors, []);
  } finally {
    await browser.close();
    await server.close();
  }
});

test('native shell loads accounts in its WebView and keeps Wallet local', async (t) => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch({ headless: true });
  try {
    for (const platform of ['desktop', 'mobile'] as const) {
      await t.test(
        `${platform}: WebView navigation remains available without native Wallet login or discovery`,
        async () => {
          const { page, errors } = await createNativeUiPage(browser, server.url, { platform });
          try {
            await page.locator('#open-settings').click();
            await page.getByRole('button', { name: 'アカウントを開く' }).click();
            await page.getByRole('link', { name: 'Chat', exact: true }).click();
            await page.locator('#open-chat').click();
            const calls = await page.evaluate(() => window.__nativeUiTest.arguments);
            assert.deepEqual(
              calls.filter((call) => call.command === 'open_mikaki_web').map((call) => call.args),
              [{ destination: 'signin' }, { destination: 'chat' }],
            );
            assert.equal(
              calls.some((call) =>
                /^(start_.*login|cancel_native_login|clear_native_session)$/.test(call.command),
              ),
              false,
            );
            assert.equal(await page.locator('#login, #account, #logout-dialog').count(), 0);
            await page.getByRole('link', { name: 'Walletを開く' }).click();
            await page.locator('#wallet').waitFor({ state: 'visible' });
            assert.equal(await page.locator('#navigation').isVisible(), true);
            await page.goBack();
            await page.locator('#chat').waitFor({ state: 'visible' });
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
          await page.locator('#open-settings').click();
          await page.getByRole('button', { name: 'アカウントを開く' }).click();
          assert.match((await page.locator('#status').textContent()) ?? '', /開けませんでした/);
          assert.doesNotMatch(
            (await page.locator('#status').textContent()) ?? '',
            /internal failure/,
          );
          await page.evaluate(() => {
            delete window.__nativeUiTest.failures.open_mikaki_web;
          });
          await page.locator('#open-settings').click();
          await page.getByRole('button', { name: 'アカウントを開く' }).click();
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

test('shared Android sign-in returns to Wallet and opens Chat directly with the same account', async () => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch();
  try {
    const { page, errors } = await createNativeUiPage(browser, server.url, {
      platform: 'mobile',
      sharedSession: true,
    });
    await page.locator('#wallet-login').click();
    await expect(page.locator('#chat')).toBeVisible();
    await expect
      .poll(() =>
        page.evaluate(() =>
          window.__nativeUiTest.arguments.some(
            (c) => c.command === 'set_app_workspace' && c.args?.visible === true,
          ),
        ),
      )
      .toBe(true);
    await page.evaluate(() => window.__nativeUiTest.complete());
    await expect(page.locator('#wallet')).toBeVisible();
    await expect(page.locator('#wallet-account-status')).toContainText('ログイン済み');
    await page.getByRole('link', { name: 'Chat', exact: true }).click();
    await expect(page.locator('#open-chat')).toBeHidden();
    await expect
      .poll(() =>
        page.evaluate(
          () =>
            window.__nativeUiTest.arguments.filter((c) => c.command === 'set_app_workspace').at(-1)
              ?.args?.visible,
        ),
      )
      .toBe(true);
    await page.getByRole('link', { name: 'Walletを開く', exact: true }).click();
    await expect
      .poll(() =>
        page.evaluate(
          () =>
            window.__nativeUiTest.arguments.filter((c) => c.command === 'set_app_workspace').at(-1)
              ?.args?.visible,
        ),
      )
      .toBe(false);
    const calls = await page.evaluate(() => window.__nativeUiTest.calls);
    assert.equal(calls.filter((c) => c === 'start_mobile_login').length, 1);
    assert.equal(calls.includes('open_mikaki_web'), false);
    assert.deepEqual(errors, []);
    await page.close();
  } finally {
    await browser.close();
    await server.close();
  }
});

test('shared account reports actionable connection failures without disclosing raw errors', async () => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch();
  try {
    for (const [phase, message] of [
      ['configuration_required', '更新'],
      ['connection_failed', 'ネットワーク'],
      ['secure_connection_failed', '安全な接続'],
    ] as const) {
      const { page, errors } = await createNativeUiPage(browser, server.url, {
        platform: 'mobile',
        sharedSession: true,
        phase,
      });
      await expect(page.locator('#wallet-account-status')).toContainText(message);
      await expect(page.locator('#wallet-login')).toBeEnabled();
      assert.deepEqual(errors, []);
      await page.close();
    }
  } finally {
    await browser.close();
    await server.close();
  }
});

test('unconfirmed shared session clears cached identity display before allowing a retry', async () => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch();
  try {
    const { page, errors } = await createNativeUiPage(browser, server.url, {
      platform: 'mobile',
      sharedSession: true,
      signedIn: true,
      identityDocuments: [
        {
          id: 'saved-private-document',
          saved_at: 1,
          preview: {
            name: '秘密の氏名',
            address: '秘密の住所',
            birth_date: '2000-01-01',
            gender: '1',
            verification: 'unverified',
            document_type: 'my_number_card',
            backend_verifiable: false,
          },
        },
      ],
    });
    await expect(page.locator('.document-card')).toHaveCount(1);
    await page.getByRole('button', { name: /MY NUMBER CARD/ }).click();
    await expect(page.locator('#wallet-card-values')).toContainText('秘密の住所');
    await page.evaluate(() => {
      window.__nativeUiTest.failures.mobile_auth_status = 'private internal diagnostic';
      window.dispatchEvent(new Event('focus'));
    });
    await expect(page.locator('.document-card')).toHaveCount(0);
    await expect(page.locator('#wallet-account-status')).toContainText('ネットワーク');
    await expect(page.locator('#wallet-login')).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => window.__nativeUiTest.calls.includes('reset_app_workspace')))
      .toBe(true);
    assert.doesNotMatch(
      await page.locator('body').innerText(),
      /秘密の氏名|秘密の住所|private internal diagnostic/,
    );
    assert.deepEqual(errors, []);
    await page.close();
  } finally {
    await browser.close();
    await server.close();
  }
});
