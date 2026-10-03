import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { chromium, expect } from '@playwright/test';
import { startPreview } from './serve.mjs';
import { auditAccessibility } from '../../local/conformance/support/accessibility-audit.ts';

const server = await startPreview();
let browser;
try {
  browser = await chromium.launch({ headless: true });
  const directory = new URL('./', import.meta.url).pathname;
  await mkdir(directory, { recursive: true });
  for (const [label, width] of [
    ['desktop', 1440],
    ['mobile', 390],
  ]) {
    const page = await browser.newPage({
      viewport: { width, height: 1000 },
      reducedMotion: 'reduce',
    });
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.goto(server.url);
    await page.locator('#fence').waitFor();
    await expect.poll(() => page.locator('#fence').getAttribute('data-light-phase')).toBe('still');
    await page.screenshot({ path: `${directory}locked-${label}.png`, fullPage: true });
    await page.getByRole('button', { name: 'Passkeyで開く', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#main')).toBeFocused();
    await expect(page.getByLabel('表示名')).toHaveValue('山田 太郎');
    await page.getByLabel('表示名').fill('山田 花子');
    await page.getByRole('button', { name: '保存', exact: true }).click();
    await expect(page.getByRole('status')).toHaveText('保存しました。');
    await expect(page.locator('body')).toHaveAttribute('data-ceremony-count', '1');
    await auditAccessibility(page, `usage-profile-${label}`);
    await page.screenshot({ path: `${directory}profile-${label}.png`, fullPage: true });
    await page.getByRole('button', { name: '記録', exact: true }).click();
    await expect(page.getByRole('heading', { name: '記録', exact: true })).toBeFocused();
    await page.screenshot({ path: `${directory}records-${label}.png`, fullPage: true });
    await page.getByRole('button', { name: '内容を確認', exact: true }).click();
    await page.screenshot({ path: `${directory}review-${label}.png`, fullPage: true });
    await page.getByRole('button', { name: 'この内容で保管', exact: true }).click();
    await page.getByRole('button', { name: /次の作業への引き継ぎ/ }).click();
    await page.getByRole('button', { name: '別のAIに渡す', exact: true }).click();
    await auditAccessibility(page, `usage-sharing-${label}`);
    await page.screenshot({ path: `${directory}sharing-${label}.png`, fullPage: true });
    await page.getByRole('button', { name: 'この記録だけ渡す', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: '次の作業をするAI', exact: true }),
    ).toBeVisible();
    await page.getByRole('button', { name: '取得を停止', exact: true }).click();
    await expect(page.getByRole('status')).toHaveText('これからの取得を停止しました。');
    await expect(page.locator('body')).toHaveAttribute('data-ceremony-count', '1');
    await page.getByRole('button', { name: 'ロック', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Passkeyで開く', exact: true })).toBeFocused();
    assert.equal(await page.locator('#content').textContent(), '');
    await page.keyboard.press('Enter');
    await expect(page.locator('body')).toHaveAttribute('data-ceremony-count', '2');
    for (const narrow of [width, 320]) {
      await page.setViewportSize({ width: narrow, height: 1000 });
      assert.equal(
        await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),
        false,
      );
    }
    assert.deepEqual(errors, []);
    await page.close();
    console.log(`${label}: fictional unlock/save/review/share/stop/lock flow and layout passed`);
  }
} finally {
  await browser?.close();
  await server.close();
}
