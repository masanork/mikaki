import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import {
  createNativeUiPage,
  resumeNativeUi,
  startNativeUiServer,
} from './support/native-client-ui.ts';

test('native mobile UI keeps authentication and navigation consistent', async (t) => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch({ headless: true });
  try {
    await t.test(
      'login returns to a home with no diagnostic operations; back and theme persist',
      async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url);
        try {
          await page.locator('#login').click();
          await page.locator('#waiting').waitFor({ state: 'visible' });
          await page.evaluate(() => window.__nativeUiTest.complete());
          await resumeNativeUi(page);
          await page.locator('#home').waitFor({ state: 'visible' });
          assert.equal(await page.locator('#vault-key').isVisible(), false);
          assert.equal(await page.locator('#navigation').isVisible(), true);
          await page.getByRole('link', { name: 'アカウント情報' }).click();
          await page.locator('#account').waitFor({ state: 'visible' });
          await page.goBack();
          await page.locator('#home').waitFor({ state: 'visible' });
          await page.locator('#open-settings').click();
          await page.getByLabel('テーマ').selectOption('dark');
          assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
          await page.reload();
          await page.locator('#welcome').waitFor({ state: 'visible' });
          assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
          assert.equal(await page.evaluate(() => localStorage.length), 1);
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
    await t.test(
      'mobile cancellation clears pending authority and permits a new attempt',
      async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url);
        try {
          await page.locator('#login').click();
          await page.locator('#waiting').waitFor({ state: 'visible' });
          await page.locator('#cancel-login').click();
          await page.locator('#welcome').waitFor({ state: 'visible' });
          assert.ok(
            await page.evaluate(() => window.__nativeUiTest.calls.includes('cancel_native_login')),
          );
          await page.evaluate(() => window.__nativeUiTest.complete());
          await resumeNativeUi(page);
          assert.equal(await page.locator('#home').isVisible(), false);
          await page.locator('#login').click();
          await page.locator('#waiting').waitFor({ state: 'visible' });
          await page.evaluate(() => window.__nativeUiTest.complete('expired'));
          await resumeNativeUi(page);
          await page.locator('#welcome').waitFor({ state: 'visible' });
          assert.match((await page.locator('#status').textContent()) ?? '', /時間切れ/);
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      },
    );
    await t.test('a delayed desktop login result cannot undo cancellation', async () => {
      const { page, errors } = await createNativeUiPage(browser, server.url, {
        platform: 'desktop',
      });
      try {
        await page.evaluate(() => window.__nativeUiTest.hold('start_desktop_login'));
        await page.locator('#login').click();
        await page.locator('#waiting').waitFor({ state: 'visible' });
        await page.locator('#cancel-login').click();
        await page.locator('#welcome').waitFor({ state: 'visible' });
        await page.evaluate(() => window.__nativeUiTest.release('start_desktop_login'));
        await resumeNativeUi(page);
        assert.equal(await page.locator('#home').isVisible(), false);
        assert.equal(await page.locator('#navigation').isVisible(), false);
        assert.deepEqual(errors, []);
      } finally {
        await page.close();
      }
    });
    await t.test(
      'logout failure preserves the session; successful logout blocks stale reads and history',
      async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, { signedIn: true });
        try {
          await page.locator('#open-settings').click();
          await page.locator('#open-logout').click();
          await page.evaluate(() => {
            window.__nativeUiTest.failures.clear_native_session = 'synthetic failure';
          });
          await page.locator('#clear').click();
          await page.locator('#logout-error').waitFor({ state: 'visible' });
          assert.equal(await page.locator('#logout-dialog').isVisible(), true);
          assert.equal(await page.evaluate(() => window.__nativeUiTest.subject), 'synthetic-user');
          await page.evaluate(() => {
            delete window.__nativeUiTest.failures.clear_native_session;
            window.__nativeUiTest.hold('clear_native_session');
            window.__nativeUiTest.hold('mobile_auth_status');
          });
          await resumeNativeUi(page); // This snapshot still carries the old session.
          await page.locator('#clear').click();
          await page.evaluate(() => window.__nativeUiTest.release('clear_native_session'));
          await page.locator('#welcome').waitFor({ state: 'visible' });
          await page.evaluate(() => window.__nativeUiTest.release('mobile_auth_status'));
          await resumeNativeUi(page);
          await page.goBack();
          assert.equal(await page.locator('#home').isVisible(), false);
          assert.equal(await page.locator('#account').isVisible(), false);
          assert.equal(await page.locator('#navigation').isVisible(), false);
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      },
    );
    await t.test(
      'restore a pending login and recover from polling failure on app resume',
      async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          phase: 'pending',
        });
        try {
          await page.locator('#waiting').waitFor({ state: 'visible' });
          await page.evaluate(() => {
            window.__nativeUiTest.failures.mobile_auth_status = 'diagnostic-only error';
          });
          await resumeNativeUi(page);
          await page.locator('#check-auth').waitFor({ state: 'visible' });
          assert.doesNotMatch(
            (await page.locator('#status').textContent()) ?? '',
            /diagnostic-only/,
          );
          await page.evaluate(() => {
            delete window.__nativeUiTest.failures.mobile_auth_status;
            window.__nativeUiTest.complete();
          });
          await page.locator('#check-auth').click();
          await page.locator('#home').waitFor({ state: 'visible' });
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      },
    );
    await t.test(
      'Vault preview stays in diagnostics and retains approval/read behavior',
      async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          signedIn: true,
          preview: true,
        });
        try {
          assert.equal(await page.locator('#vault').isVisible(), false);
          await page.locator('#open-settings').click();
          await page.getByRole('link', { name: '診断' }).click();
          await page.locator('#vault').waitFor({ state: 'visible' });
          assert.equal(await page.locator('#vault-read').isDisabled(), true);
          await page.locator('#vault-key').click();
          await page.getByText('端末の署名鍵を利用できます。', { exact: true }).waitFor();
          await page.locator('#vault-consent').click();
          await page.locator('#waiting').waitFor({ state: 'visible' });
          await page.evaluate(() => window.__nativeUiTest.complete('vault_complete'));
          await resumeNativeUi(page);
          await page.locator('#diagnostics').waitFor({ state: 'visible' });
          await page.locator('#vault-read').click();
          await page
            .getByText('暗号文を取得しました。revision 1、形式 1。', { exact: true })
            .waitFor();
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
