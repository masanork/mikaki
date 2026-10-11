/** Actual authenticated Rust OP page/assets, primary D1 and Git-backed private RPC. */
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, expect } from '@playwright/test';
import { auditAccessibility } from './support/accessibility-audit.ts';
import { createSourceFixture } from './support/work-source-fixture.ts';

test('owner source review uses authenticated native records and actual Git file contents', async (t) => {
  const f = await createSourceFixture();
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
  context.setDefaultTimeout(10000);
  const page = await context.newPage();
  const errors: string[] = [],
    violations: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.exposeFunction('sourceCspViolation', (directive: string) =>
    violations.push(directive),
  );
  await page.addInitScript(() => {
    let hidden = false;
    Object.defineProperty(document, 'visibilityState', {
      get: () => (hidden ? 'hidden' : 'visible'),
    });
    Object.defineProperty(window, 'setSourceHidden', {
      value: (value: boolean) => {
        hidden = value;
        document.dispatchEvent(new Event('visibilitychange'));
      },
    });
    document.addEventListener('securitypolicyviolation', (event) => {
      void (
        window as unknown as { sourceCspViolation: (d: string) => Promise<void> }
      ).sourceCspViolation(event.violatedDirective);
    });
  });
  await context.addCookies([
    {
      name: '__Host-op-sso',
      value: f.first.cookie,
      domain: 'work.test',
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'Lax',
    },
  ]);
  let failRead = false,
    corruptRead = false;
  let holdRead = false,
    releaseRead: (() => void) | undefined,
    readStarted: (() => void) | undefined;
  await context.route('https://work.test/**', async (route) => {
    const request = route.request();
    if (failRead && new URL(request.url()).pathname === '/work/sources/read') {
      await route.abort('failed');
      return;
    }
    const response = await f.worker.fetch(request.url(), {
      method: request.method(),
      headers: await request.allHeaders(),
      body: request.postData() ?? undefined,
    });
    if (holdRead && new URL(request.url()).pathname === '/work/sources/read') {
      readStarted?.();
      await new Promise<void>((resolve) => (releaseRead = resolve));
    }
    const bytes = Buffer.from(await response.arrayBuffer());
    if (
      corruptRead &&
      new URL(request.url()).pathname === '/work/sources/read' &&
      response.status === 200
    ) {
      const body = JSON.parse(bytes.toString());
      body.record.files[0].content = 'SUBSTITUTED_BROWSER_CONTENT';
      await route.fulfill({
        status: 200,
        headers: Object.fromEntries(response.headers),
        body: JSON.stringify(body),
      });
      return;
    }
    await route.fulfill({
      status: response.status,
      headers: Object.fromEntries(response.headers),
      body: bytes,
    });
  });
  const shots = new URL('../../artifacts/work-source-review/', import.meta.url).pathname;
  await mkdir(shots, { recursive: true });
  const chosen = () => page.getByRole('checkbox', { name: 'preferences/writing.md', exact: false });
  async function fresh(lang = 'ja') {
    failRead = false;
    await page.goto(`https://work.test/work/source-review?lang=${lang}`);
    await expect(chosen()).toBeVisible();
  }
  const preview = () => page.getByRole('button', { name: '選んだファイルを確認', exact: true });
  try {
    await f.register('code', f.first, {
      role: 'code',
      label: 'Synthetic code',
      files: [],
      ...f.codeSource,
    });
    await f.register('foreign', f.foreign, { label: 'FOREIGN_ONLY' });
    await t.test(
      'pinned code history and selected real text are visible without issuing permission',
      async () => {
        await fresh();
        await expect(
          page.getByText(
            'このコードをコピーする場合、履歴 2 コミット、現行 3 ファイルが含まれます。',
            {
              exact: true,
            },
          ),
        ).toBeVisible();
        await expect(page.getByText('FOREIGN_ONLY', { exact: true })).toHaveCount(0);
        await expect(preview()).toBeDisabled();
        await chosen().check();
        await preview().click();
        await expect(page.locator('pre')).toHaveText(f.contents['preferences/writing.md']);
        await expect(
          page.getByRole('heading', { name: '確認したファイル内容', exact: true }),
        ).toBeFocused();
        assert.equal(
          (await page.textContent('body'))!.includes('SYNTHETIC_HISTORICAL_ONLY'),
          false,
        );
        assert.equal((await page.textContent('body'))!.includes('SYNTHETIC_UNSELECTED'), false);
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_disclosure').first('n'), 0);
        await page.evaluate(() => scrollTo(0, 0));
        await page.screenshot({ path: `${shots}/selected-ja.png`, fullPage: true });
      },
    );
    await t.test('selection edits and reload discard the prior plaintext preview', async () => {
      await chosen().uncheck();
      await expect(page.locator('pre')).toHaveCount(0);
      await chosen().check();
      await preview().click();
      await expect(page.locator('pre')).toBeVisible();
      await page.getByRole('button', { name: '登録情報を再読み込み', exact: true }).click();
      await expect(chosen()).not.toBeChecked();
      await expect(page.locator('pre')).toHaveCount(0);
      await chosen().check();
      await preview().click();
      await expect(page.locator('pre')).toBeVisible();
      await page.reload();
      await expect(chosen()).not.toBeChecked();
      await expect(page.locator('pre')).toHaveCount(0);
      assert.deepEqual(
        await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })),
        { local: 0, session: 0 },
      );
    });
    await t.test('stale access requires a fresh source list and fresh file selection', async () => {
      await chosen().check();
      await f.DB.prepare(
        "UPDATE work_source_access SET access_revision=2 WHERE owner_id=? AND source_id='personal'",
      )
        .bind(f.first.account)
        .run();
      await preview().click();
      await expect(page.getByRole('alert')).toContainText('権限または参照版が変わりました');
      await expect(page.locator('pre')).toHaveCount(0);
      await page.getByRole('button', { name: '登録情報を再読み込み', exact: true }).click();
      await expect(chosen()).not.toBeChecked();
      await chosen().check();
      await preview().click();
      await expect(page.locator('pre')).toHaveText(f.contents['preferences/writing.md']);
    });
    await t.test(
      'network or payload verification failure clears all reviewed contents',
      async () => {
        failRead = true;
        await preview().click();
        await expect(page.getByRole('alert')).toContainText('参照ファイルを確認できませんでした');
        await expect(page.locator('pre')).toHaveCount(0);
        failRead = false;
        await f.fault('personal', 'reply-content');
        await preview().click();
        await expect(page.getByRole('alert')).toContainText('権限または参照版が変わりました');
        await expect(page.locator('pre')).toHaveCount(0);
        await f.DB.prepare('DELETE FROM source_reader_fault').run();
      },
    );
    await t.test(
      'Japanese/English and narrow keyboard review render untrusted long text safely under CSP',
      async () => {
        await fresh();
        await page.setViewportSize({ width: 375, height: 812 });
        const long = page.getByRole('checkbox', { name: 'decisions/long.md', exact: false });
        await long.focus();
        await page.keyboard.press('Space');
        await expect(long).toBeChecked();
        await preview().focus();
        await page.keyboard.press('Enter');
        await expect(page.locator('pre')).toHaveText(f.contents['decisions/long.md']);
        await page.getByRole('region', { name: 'decisions/long.md', exact: true }).focus();
        await page.keyboard.press('ArrowDown');
        await expect
          .poll(() => page.locator('pre').evaluate((node) => node.scrollTop))
          .toBeGreaterThan(0);
        assert.equal(await page.evaluate(() => 'sourceInjected' in globalThis), false);
        assert.equal(
          await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          true,
        );
        await page.evaluate(() => scrollTo(0, 0));
        await page.screenshot({ path: `${shots}/mobile-ja.png`, fullPage: true });
        await page.getByRole('combobox', { name: /Language|言語/ }).selectOption('en');
        await expect(
          page.getByRole('heading', { name: 'Review source files', exact: true }),
        ).toBeVisible();
        await expect(page.locator('pre')).toHaveCount(0);
        await expect(chosen()).not.toBeChecked();
        await chosen().check();
        await page.getByRole('button', { name: 'Inspect selected files', exact: true }).click();
        await expect(page.locator('pre')).toHaveText(f.contents['preferences/writing.md']);
        await page.evaluate(() => scrollTo(0, 0));
        await page.screenshot({ path: `${shots}/selected-en.png`, fullPage: true });
        await auditAccessibility(page, 'work-source-review-en');
        assert.deepEqual(errors, []);
        assert.deepEqual(violations, []);
      },
    );
    await t.test('display hash verification rejects substituted transport text', async () => {
      await fresh();
      await chosen().check();
      corruptRead = true;
      await preview().click();
      await expect(page.getByRole('alert')).toContainText('権限または参照版が変わりました');
      await expect(page.locator('pre')).toHaveCount(0);
      corruptRead = false;
    });
    await t.test(
      'hide, late read reply and manual lock discard plaintext and require fresh selection',
      async () => {
        await fresh();
        await chosen().check();
        holdRead = true;
        const started = new Promise<void>((resolve) => (readStarted = resolve));
        await preview().click();
        await started;
        await expect(preview()).toBeDisabled();
        await page.evaluate(() =>
          (window as unknown as { setSourceHidden: (v: boolean) => void }).setSourceHidden(true),
        );
        releaseRead?.();
        holdRead = false;
        await page.evaluate(() =>
          (window as unknown as { setSourceHidden: (v: boolean) => void }).setSourceHidden(false),
        );
        await expect(
          page.getByRole('button', { name: '登録情報を再読み込み', exact: true }),
        ).toBeVisible();
        await expect(page.locator('pre')).toHaveCount(0);
        await page.getByRole('button', { name: '登録情報を再読み込み', exact: true }).click();
        await expect(chosen()).not.toBeChecked();
        await chosen().check();
        await preview().click();
        await expect(page.locator('pre')).toBeVisible();
        await page.getByRole('button', { name: '画面をロック', exact: true }).click();
        await expect(page.locator('pre')).toHaveCount(0);
        await auditAccessibility(page, 'work-source-review-locked');
        await page.getByRole('button', { name: '参照画面を再び開く', exact: true }).click();
        await expect(chosen()).not.toBeChecked();
      },
    );
    await t.test(
      'revalidating a revoked real OP session locks the review and clears its inspected text',
      async () => {
        await chosen().check();
        await preview().click();
        await expect(page.locator('pre')).toBeVisible();
        await f.DB.prepare('UPDATE sso_session SET revoked=1 WHERE account_id=?')
          .bind(f.first.account)
          .run();
        await page.getByRole('button', { name: '登録情報を再読み込み', exact: true }).click();
        await expect(page.getByRole('heading', { name: /ロック/ })).toBeVisible();
        await expect(page.locator('pre')).toHaveCount(0);
        await expect(chosen()).toHaveCount(0);
      },
    );
  } finally {
    releaseRead?.();
    await context.close();
    await browser.close();
    await f.close();
  }
});
