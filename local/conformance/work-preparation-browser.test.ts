/** Production OP entry, Rust owner page/assets and independent checkpoint; Git-backed source
 * contents, seeded OP SSO and explicitly synthetic preparation verification. */
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, expect } from '@playwright/test';
import { createSourceFixture } from './support/work-source-fixture.ts';
import { seedPreparationReview } from './support/work-preparation-review-fixture.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';

test('owner preparation review keeps copy evidence, access and delegation separate', async (t) => {
  const f = await createSourceFixture(undefined, true, 'product');
  const s = await seedPreparationReview(f);
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
  context.setDefaultTimeout(10000);
  const page = await context.newPage();
  const errors: string[] = [],
    violations: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.exposeFunction('preparationCspViolation', (d: string) => violations.push(d));
  await page.addInitScript(() => {
    let hidden = false;
    Object.defineProperty(document, 'visibilityState', {
      get: () => (hidden ? 'hidden' : 'visible'),
    });
    Object.defineProperty(window, 'setPreparationHidden', {
      value: (v: boolean) => {
        hidden = v;
        document.dispatchEvent(new Event('visibilitychange'));
      },
    });
    document.addEventListener('securitypolicyviolation', (e) => {
      void (
        window as unknown as { preparationCspViolation: (d: string) => Promise<void> }
      ).preparationCspViolation(e.violatedDirective);
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
  let hold = false,
    release: (() => void) | undefined,
    started: (() => void) | undefined,
    corrupt = '',
    fail = false;
  await context.route('https://work.test/**', async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (fail && path === '/work/sources/read') {
      await route.abort();
      return;
    }
    const response = await f.worker.fetch(request.url(), {
      method: request.method(),
      headers: await request.allHeaders(),
      body: request.postData() ?? undefined,
    });
    if (hold && path.startsWith('/work/disclosures/')) {
      started?.();
      await new Promise<void>((r) => (release = r));
    }
    let bytes = Buffer.from(await response.arrayBuffer());
    if (
      response.status === 200 &&
      ((corrupt === 'content' && path === '/work/sources/read') ||
        (corrupt === 'manifest' && path.startsWith('/work/disclosures/')) ||
        (corrupt === 'oversize' && path === '/work/preparations'))
    ) {
      if (corrupt === 'oversize') bytes = Buffer.from(' '.repeat(65537));
      else {
        const body = JSON.parse(bytes.toString());
        if (corrupt === 'content') body.record.files[0].content = 'SUBSTITUTED_CONTENT';
        else body.record.digest = 'a'.repeat(64);
        bytes = Buffer.from(JSON.stringify(body));
      }
    }
    await route.fulfill({
      status: response.status,
      headers: Object.fromEntries(response.headers),
      body: bytes,
    });
  });
  const shots = new URL('../../artifacts/work-preparation-review/', import.meta.url).pathname;
  await mkdir(shots, { recursive: true });
  const refresh = () => page.getByRole('button', { name: '準備一覧を再読み込み', exact: true });
  const choose = () => page.locator('.preparation-list button').first();
  const inspect = () => page.getByRole('button', { name: 'コピー対象を確認', exact: true });
  const details = () => page.getByRole('heading', { name: 'コピー内容', exact: true });
  const fresh = async () => {
    await page.goto('https://work.test/work/preparation-review?lang=ja');
    await expect(choose()).toBeVisible();
  };
  try {
    await t.test(
      'pinned disclosure and actual selected Git text render before any delegation',
      async () => {
        await fresh();
        await choose().click();
        await expect(details()).toBeFocused();
        await expect(page.getByText('コピー開始前', { exact: true })).toBeVisible();
        await page.locator('.work-record-details > summary').click();
        await expect(page.getByText('実行用の登録は未完了', { exact: true })).toBeVisible();
        await page.locator('.work-record-details > summary').click();
        await page.locator('.work-selected-files > summary').click();
        await expect(page.getByText('preferences/writing.md', { exact: true })).toBeVisible();
        await expect(page.getByText('3 ファイル · 2 コミット', { exact: true })).toBeVisible();
        await inspect().click();
        await expect(page.locator('pre')).toHaveText(f.contents['preferences/writing.md']);
        await expect(
          page.getByRole('heading', { name: '確認したファイル内容', exact: true }),
        ).toBeFocused();
        assert.equal((await page.textContent('body'))!.includes('SYNTHETIC_UNSELECTED'), false);
        assert.equal(
          (await page.textContent('body'))!.includes('SYNTHETIC_HISTORICAL_ONLY'),
          false,
        );
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
        await page.evaluate(() => scrollTo(0, 0));
        await page.screenshot({ path: shots + '/selected-ja.png', fullPage: true });
      },
    );
    await t.test(
      'verification is historical; current authority additionally requires materialization',
      async () => {
        await s.call({ action: 'dispatch-preparation', id: s.reserved.id });
        await refresh().click();
        await choose().click();
        await expect(page.getByText('コピーの完了は未確認', { exact: true })).toBeVisible();
        await s.verify(s.reserved.id);
        await refresh().click();
        await choose().click();
        await expect(page.getByText('コピーの検証記録あり', { exact: true })).toBeVisible();
        await page.locator('.work-record-details > summary').click();
        await expect(page.getByText('実行用の登録は未完了', { exact: true })).toBeVisible();
        await page.locator('.work-record-details > summary').click();
        await s.call({ action: 'materialize-preparation', id: s.reserved.id });
        await refresh().click();
        await choose().click();
        await page.locator('.work-record-details > summary').click();
        await expect(page.getByText('現在の利用条件を確認済み', { exact: true })).toBeVisible();
        await page.locator('.work-record-details > summary').click();
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
      },
    );
    await t.test(
      'refresh, transport substitution and oversized data discard inspected contents',
      async () => {
        await inspect().click();
        await expect(page.locator('pre')).toBeVisible();
        await refresh().click();
        await expect(page.locator('pre')).toHaveCount(0);
        await expect(details()).toHaveCount(0);
        corrupt = 'manifest';
        await choose().click();
        await expect(page.getByRole('alert')).toContainText('準備情報を確認できません');
        await expect(details()).toHaveCount(0);
        corrupt = '';
        await choose().click();
        corrupt = 'content';
        await inspect().click();
        await expect(page.locator('pre')).toHaveCount(0);
        await expect(page.getByRole('alert')).toContainText('参照版が変わりました');
        corrupt = 'oversize';
        await refresh().click();
        await expect(choose()).toHaveCount(0);
        await expect(page.getByRole('alert')).toContainText('準備情報を確認できません');
        corrupt = '';
        await refresh().click();
        await choose().click();
        fail = true;
        await inspect().click();
        await expect(page.locator('pre')).toHaveCount(0);
        fail = false;
      },
    );
    await t.test(
      'mobile, Japanese/English, focus and CSP use the existing product display lease',
      async () => {
        await fresh();
        await page.setViewportSize({ width: 375, height: 812 });
        await choose().focus();
        await page.keyboard.press('Enter');
        await expect(details()).toBeFocused();
        await inspect().click();
        await expect(page.locator('pre')).toHaveText(f.contents['preferences/writing.md']);
        assert.equal(
          await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          true,
        );
        await page.evaluate(() => scrollTo(0, 0));
        await page.screenshot({ path: shots + '/mobile-ja.png', fullPage: true });
        await page.getByRole('combobox', { name: /Language|言語/ }).selectOption('en');
        await expect(
          page.getByRole('heading', { name: 'Review the copy', exact: true }),
        ).toBeVisible();
        await expect(page.locator('pre')).toHaveCount(0);
        await choose().click();
        await expect(page.getByText('Copy verification recorded', { exact: true })).toBeVisible();
        await page.getByRole('button', { name: 'Check copy contents', exact: true }).click();
        await expect(page.locator('pre')).toHaveText(f.contents['preferences/writing.md']);
        await page.evaluate(() => scrollTo(0, 0));
        await page.screenshot({ path: shots + '/selected-en.png', fullPage: true });
        await auditAccessibility(page, 'work-preparation-review-en');
        assert.deepEqual(
          await page.evaluate(() => ({
            local: localStorage.length,
            session: sessionStorage.length,
          })),
          { local: 0, session: 0 },
        );
        assert.deepEqual(errors, []);
        assert.deepEqual(violations, []);
      },
    );
    await t.test(
      'hidden late manifest replies and manual lock cannot restore old reviews',
      async () => {
        await fresh();
        hold = true;
        const began = new Promise<void>((r) => (started = r));
        await choose().click();
        await began;
        await page.evaluate(() =>
          (
            window as unknown as { setPreparationHidden: (v: boolean) => void }
          ).setPreparationHidden(true),
        );
        release?.();
        hold = false;
        await page.evaluate(() =>
          (
            window as unknown as { setPreparationHidden: (v: boolean) => void }
          ).setPreparationHidden(false),
        );
        await expect(refresh()).toBeVisible();
        await expect(details()).toHaveCount(0);
        await expect(page.locator('pre')).toHaveCount(0);
        await refresh().click();
        await choose().click();
        await inspect().click();
        await expect(page.locator('pre')).toBeVisible();
        await page.getByRole('button', { name: '画面をロック', exact: true }).click();
        await expect(details()).toHaveCount(0);
        await expect(page.locator('pre')).toHaveCount(0);
        await auditAccessibility(page, 'work-preparation-review-locked');
        await page.getByRole('button', { name: '参照画面を再び開く', exact: true }).click();
        await expect(choose()).toBeVisible();
        await expect(details()).toHaveCount(0);
      },
    );
    await t.test(
      'absolute preparation expiry clears details and plaintext without preserving inspection',
      async () => {
        await fresh();
        await choose().click();
        await inspect().click();
        await expect(page.locator('pre')).toBeVisible();
        await page.clock.setFixedTime(new Date(Date.now() + 601000));
        await expect(details()).toHaveCount(0);
        await expect(page.locator('pre')).toHaveCount(0);
        await expect(choose()).toBeDisabled();
        await expect(
          page.getByRole('link', { name: '新しいコピーを準備', exact: true }),
        ).toHaveAttribute('href', '/work/source-review?lang=ja');
        await page.clock.setFixedTime(new Date());
        await fresh();
      },
    );
    await t.test('a replacement OP owner locks the old display lease on resume', async () => {
      await choose().click();
      await inspect().click();
      await expect(page.locator('pre')).toBeVisible();
      await context.addCookies([
        {
          name: '__Host-op-sso',
          value: f.foreign.cookie,
          domain: 'work.test',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
        },
      ]);
      await page.evaluate(() =>
        (window as unknown as { setPreparationHidden: (v: boolean) => void }).setPreparationHidden(
          true,
        ),
      );
      await page.evaluate(() =>
        (window as unknown as { setPreparationHidden: (v: boolean) => void }).setPreparationHidden(
          false,
        ),
      );
      await expect(
        page.getByRole('heading', { name: '準備の確認画面をロックしました', exact: true }),
      ).toBeVisible();
      await expect(page.locator('pre')).toHaveCount(0);
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
      await fresh();
    });
    await t.test(
      'revoked source preserves copy evidence but denies fresh plaintext inspection',
      async () => {
        await choose().click();
        await inspect().click();
        await expect(page.locator('pre')).toBeVisible();
        await f.DB.prepare(
          "UPDATE work_source_access SET active=0,access_revision=access_revision+1 WHERE owner_id=? AND source_id='personal'",
        )
          .bind(f.first.account)
          .run();
        const downloads: string[] = [];
        const downloaded = (download: { suggestedFilename(): string }) =>
          downloads.push(download.suggestedFilename());
        page.on('download', downloaded);
        await page.getByText('照合用の記録', { exact: true }).click();
        await page.getByRole('button', { name: '開示記録を保存', exact: true }).click();
        await expect(page.getByRole('alert')).toContainText('参照版が変わりました');
        assert.deepEqual(downloads, []);
        page.off('download', downloaded);
        await refresh().click();
        await choose().click();
        await expect(page.getByText('コピーの検証記録あり', { exact: true })).toBeVisible();
        await expect(page.getByText('現在は利用できません', { exact: true })).toBeVisible();
        await page.getByText('照合用の記録', { exact: true }).click();
        await expect(
          page.getByRole('button', { name: '開示記録を保存', exact: true }),
        ).toBeDisabled();
        await inspect().click();
        await expect(page.getByRole('alert')).toContainText('参照版が変わりました');
        await expect(page.locator('pre')).toHaveCount(0);
      },
    );
  } finally {
    release?.();
    await context.close();
    await browser.close();
    await f.close();
  }
});

test('revoked OP SSO refuses a disclosure download and locks the complete review', async () => {
  // A separate owner/runtime keeps this authority check independent of the
  // preceding suite's request budget. Production rate limits remain intact.
  const f = await createSourceFixture(undefined, true, 'product');
  const s = await seedPreparationReview(f);
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext();
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
    await context.route('https://work.test/**', async (route) => {
      const request = route.request();
      const response = await f.worker.fetch(request.url(), {
        method: request.method(),
        headers: await request.allHeaders(),
        body: request.postData() ?? undefined,
      });
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    const page = await context.newPage();
    const downloads: string[] = [];
    page.on('download', (download) => downloads.push(download.suggestedFilename()));
    await page.goto('https://work.test/work/preparation-review?lang=ja#' + s.reserved.id);
    await expect(page.getByRole('heading', { name: 'コピー内容', exact: true })).toBeVisible();
    await page.getByText('照合用の記録', { exact: true }).click();
    await f.revokeSession();
    assert.equal((await f.http('/work/preparations')).status, 401);
    await page.getByRole('button', { name: '開示記録を保存', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: '準備の確認画面をロックしました', exact: true }),
    ).toBeVisible();
    await expect(page.getByRole('heading', { name: 'コピー内容', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '開示記録を保存', exact: true })).toHaveCount(0);
    assert.deepEqual(downloads, []);
  } finally {
    await browser.close();
    await f.close();
  }
});
