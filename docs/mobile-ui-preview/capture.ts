import { mkdir } from 'node:fs/promises';
import { chromium } from '@playwright/test';
import {
  createNativeUiPage,
  startNativeUiServer,
} from '../../local/conformance/support/native-client-ui.ts';

const output = new URL('./', import.meta.url);
await mkdir(output, { recursive: true });
const server = await startNativeUiServer();
const browser = await chromium.launch({ headless: true });
try {
  for (const screen of ['home', 'wallet', 'settings', 'dark', 'diagnostics']) {
    const { page, errors } = await createNativeUiPage(browser, server.url, {
      identityReader: screen === 'wallet',
      identityWallet: screen === 'wallet',
    });
    try {
      if (['settings', 'dark', 'diagnostics'].includes(screen))
        await page.locator('#open-settings').click();
      if (screen === 'wallet') await page.getByRole('link', { name: 'Walletを開く' }).click();
      if (screen === 'dark') await page.getByLabel('テーマ').selectOption('dark');
      if (screen === 'diagnostics') await page.getByRole('link', { name: '診断' }).click();
      await page.screenshot({ path: new URL(`${screen}.png`, output).pathname, fullPage: true });
      if (errors.length) throw new Error(errors.join('\n'));
    } finally {
      await page.close();
    }
  }
} finally {
  await browser.close();
  await server.close();
}
