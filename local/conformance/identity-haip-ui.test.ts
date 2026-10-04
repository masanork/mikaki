import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chromium } from '@playwright/test';
import { createNativeUiPage, startNativeUiServer } from './support/native-client-ui.ts';

test('native wallet issuance keeps authorization in Rust and rejects late UI results', async (t) => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch({ headless: true });
  try {
    await t.test('unconfigured wallet stays hidden', async () => {
      const { page, errors } = await createNativeUiPage(browser, server.url);
      try {
        assert.equal(await page.locator('#identity-wallet-issuance').isVisible(), false);
        assert.deepEqual(errors, []);
      } finally {
        await page.close();
      }
    });
    for (const format of ['dc+sd-jwt', 'mso_mdoc'])
      await t.test(`approval and native receipt: ${format}`, async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          identityWallet: true,
          identityFormat: format,
        });
        try {
          await page.locator('#open-settings').click();
          await page.getByRole('link', { name: '診断' }).click();
          await page
            .locator('#identity-wallet-format')
            .selectOption(format === 'mso_mdoc' ? 'linked_document_mdoc' : 'linked_document');
          await page.locator('#identity-wallet-start').click();
          await page.locator('#identity-wallet-receive').waitFor({ state: 'visible' });
          await page.locator('#identity-wallet-receive').click();
          await page
            .getByText('まだ承認されていません。ブラウザでの操作を完了してください。', {
              exact: true,
            })
            .waitFor();
          await page.evaluate(() =>
            window.__nativeUiTest.emit('identity-issuance-updated', 'ready'),
          );
          await page
            .getByText('発行が承認されました。「承認を確認して受け取る」を選んでください。', {
              exact: true,
            })
            .waitFor();
          await page.locator('#identity-wallet-receive').click();
          await page.waitForFunction(() =>
            document
              .querySelector('#identity-wallet-status')
              ?.textContent?.includes('署名を確認しました'),
          );
          assert.equal(await page.locator('#identity-wallet-receive').isVisible(), false);
          const args = await page.evaluate(() =>
            window.__nativeUiTest.arguments.filter(
              (c) => c.command === 'start_identity_wallet_issuance',
            ),
          );
          assert.deepEqual(args[0].args, {
            configuration: format === 'mso_mdoc' ? 'linked_document_mdoc' : 'linked_document',
          });
          assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      });
    for (const command of ['start_identity_wallet_issuance', 'receive_identity_wallet_credential'])
      await t.test(`cancellation blocks late ${command}`, async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          identityWallet: true,
        });
        try {
          await page.locator('#open-settings').click();
          await page.getByRole('link', { name: '診断' }).click();
          if (command === 'start_identity_wallet_issuance')
            await page.evaluate(() => window.__nativeUiTest.hold('start_identity_wallet_issuance'));
          await page.locator('#identity-wallet-start').click();
          if (command === 'receive_identity_wallet_credential') {
            await page.locator('#identity-wallet-receive').waitFor({ state: 'visible' });
            await page.evaluate(() =>
              window.__nativeUiTest.emit('identity-issuance-updated', 'ready'),
            );
            await page
              .getByText('発行が承認されました。「承認を確認して受け取る」を選んでください。', {
                exact: true,
              })
              .waitFor();
            await page.evaluate(() =>
              window.__nativeUiTest.hold('receive_identity_wallet_credential'),
            );
            await page.locator('#identity-wallet-receive').click();
          }
          await page.locator('#identity-wallet-cancel').click();
          await page.getByText('証明書の受取を取り消しました。', { exact: true }).waitFor();
          await page.evaluate((name) => window.__nativeUiTest.release(name), command);
          await page.waitForFunction(
            () => !document.querySelector<HTMLButtonElement>('#identity-wallet-start')?.disabled,
          );
          assert.equal(
            await page.locator('#identity-wallet-status').textContent(),
            '証明書の受取を取り消しました。',
          );
          assert.equal(await page.locator('#identity-wallet-receive').isVisible(), false);
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      });
    await t.test('restored pending state, denial, expiry and cancellation failure', async () => {
      const { page, errors } = await createNativeUiPage(browser, server.url, {
        identityWallet: true,
        identityWalletPhase: 'pending',
      });
      try {
        await page.locator('#identity-wallet-receive').waitFor({ state: 'visible' });
        await page.evaluate(() =>
          window.__nativeUiTest.emit('identity-issuance-updated', 'denied'),
        );
        await page
          .getByText('発行が拒否されました。証明書は受け取っていません。', { exact: true })
          .waitFor();
        assert.equal(await page.locator('#identity-wallet-receive').isVisible(), false);
        await page.locator('#identity-wallet-start').click();
        await page.locator('#identity-wallet-receive').waitFor({ state: 'visible' });
        await page.evaluate(() =>
          window.__nativeUiTest.emit('identity-issuance-updated', 'expired'),
        );
        await page
          .getByText('受取操作の有効期限が切れました。もう一度始めてください。', { exact: true })
          .waitFor();
        await page.locator('#identity-wallet-start').click();
        await page.locator('#identity-wallet-receive').waitFor({ state: 'visible' });
        await page.evaluate(() => {
          window.__nativeUiTest.failures.cancel_identity_wallet_issuance = 'failed';
        });
        await page.locator('#identity-wallet-cancel').click();
        await page
          .getByText('受取を取り消せませんでした。もう一度取り消してください。', { exact: true })
          .waitFor();
        assert.equal(await page.locator('#identity-wallet-start').isDisabled(), true);
        await page.evaluate(() => {
          delete window.__nativeUiTest.failures.cancel_identity_wallet_issuance;
        });
        await page.locator('#identity-wallet-cancel').click();
        await page.getByText('証明書の受取を取り消しました。', { exact: true }).waitFor();
        assert.deepEqual(errors, []);
      } finally {
        await page.close();
      }
    });
  } finally {
    await browser.close();
    await server.close();
  }
});
