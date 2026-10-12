/** The actual product progress bundle and primary Native job, with synthetic
 * identity/provider mapping and real local Git. No browser grants authority. */
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, expect } from '@playwright/test';
import { copyJobFixture } from './support/work-copy-job-fixture.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';
import { measure } from '../../scripts/check-worker-budgets.ts';

test('copy progress needs a fresh start acknowledgement and discards late results on lock', async (t) => {
  const f = await copyJobFixture({ LOCAL_COPY_TRIGGER_DISABLED: 'true' });
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
  const page = await context.newPage(),
    errors: string[] = [],
    posted: unknown[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await context.addCookies([
    {
      name: '__Host-op-sso',
      value: 'synthetic-delivery-session',
      domain: 'work.test',
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'Lax',
    },
  ]);
  await page.addInitScript(() =>
    Object.defineProperty(window, 'hideCopyProgress', {
      value: () => {
        Object.defineProperty(document, 'visibilityState', {
          configurable: true,
          get: () => 'hidden',
        });
        document.dispatchEvent(new Event('visibilitychange'));
      },
    }),
  );
  let hold = false,
    started: (() => void) | undefined,
    release: (() => void) | undefined;
  await context.route('https://work.test/**', async (route) => {
    const request = route.request(),
      url = new URL(request.url());
    if (request.method() === 'POST' && url.pathname.endsWith('/copy'))
      posted.push(JSON.parse(request.postData()!));
    const response = await f.productFetch(url.pathname + url.search, {
      method: request.method(),
      headers: await request.allHeaders(),
      body: request.postData() ?? undefined,
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    if (hold && request.method() === 'POST' && url.pathname.endsWith('/copy')) {
      started?.();
      await new Promise<void>((r) => (release = r));
    }
    await route
      .fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: bytes,
      })
      .catch(() => {});
  });
  const shots = new URL('../../artifacts/work-copy-job/', import.meta.url).pathname;
  await mkdir(shots, { recursive: true });
  const url = (lang: string) => `https://work.test/work/copy-review?lang=${lang}#${f.p.id}`;
  try {
    assert.equal((await f.approve()).status, 200);
    await t.test(
      'Japanese review exposes no automatic start and stays within the existing bundle cap',
      async () => {
        const measurements = [];
        for (const path of [
          '/work/source-review.js',
          '/work/preparation-review.js',
          '/work/copy-review.js',
          '/work/browser-assistant.js',
        ]) {
          const asset = await f.productFetch(path);
          assert.equal(asset.status, 200);
          const measured = measure(path, new Uint8Array(await asset.arrayBuffer()));
          assert.ok(
            measured.raw <= (path.endsWith('browser-assistant.js') ? 16 : 192) * 1024,
            path,
          );
          assert.ok(measured.gzip <= (path.endsWith('browser-assistant.js') ? 8 : 64) * 1024, path);
          measurements.push(measured);
        }
        const version = await f.product('/version');
        assert.equal(version.status, 200);
        await writeFile(
          shots + '/budgets.json',
          JSON.stringify({ source: version.body, measurements }, null, 2) + '\n',
        );
        await page.goto(url('ja'));
        await expect(page.getByRole('heading', { name: 'コピーの進捗', exact: true }))
          .toBeVisible()
          .catch(async (error) => {
            throw new Error(
              String(error) +
                ' ' +
                JSON.stringify(errors) +
                ' ' +
                (await page.locator('body').innerText()).slice(0, 600),
            );
          });
        await expect(
          page.getByRole('button', { name: 'コピーを開始', exact: true }),
        ).toBeDisabled();
        assert.equal(posted.length, 0);
        await page.getByRole('checkbox').focus();
        await page.keyboard.press('Space');
        await expect(page.getByRole('button', { name: 'コピーを開始', exact: true })).toBeEnabled();
        await auditAccessibility(page, 'work-copy-start');
        await page.screenshot({ path: shots + '/start-ja.png', fullPage: true });
        await page.evaluate(() => (window as any).hideCopyProgress());
        await expect(page.getByRole('checkbox')).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'コピーを開始', exact: true })).toHaveCount(
          0,
        );
      },
    );
    await t.test('English mobile navigation discards acknowledgement', async () => {
      await page.setViewportSize({ width: 375, height: 900 });
      await page.goto(url('en'));
      await expect(page.getByRole('button', { name: 'Start copy', exact: true })).toBeDisabled();
      await expect(page.getByRole('checkbox')).not.toBeChecked();
      assert.equal(
        await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        true,
      );
      await auditAccessibility(page, 'work-copy-mobile');
      await page.screenshot({ path: shots + '/start-en-mobile.png', fullPage: true });
    });
    await t.test(
      'a committed start arriving after lock cannot revive the visible view',
      async () => {
        await page.goto(url('ja'));
        await page.getByRole('checkbox').check();
        const pending = new Promise<void>((r) => (started = r));
        hold = true;
        await page.getByRole('button', { name: 'コピーを開始', exact: true }).click();
        await pending;
        await page.getByRole('button', { name: '画面をロック', exact: true }).click();
        await expect(
          page.getByRole('heading', { name: '準備の確認画面をロックしました', exact: true }),
        ).toBeVisible();
        release?.();
        release = undefined;
        hold = false;
        await expect(page.getByRole('button', { name: 'コピーを開始', exact: true })).toHaveCount(
          0,
        );
        assert.deepEqual(posted, [{ format_version: 1, review_digest: f.digest }]);
        assert.equal((await f.copy()).body.record.job.state, 'queued');
        assert.equal((await f.remote()).counts.create ?? 0, 0);
      },
    );
    await t.test(
      'refresh recovers the retained queue and verified result without another start',
      async () => {
        await page.goto(url('en'));
        await expect(
          page.getByText('The start request is saved. Execution is not yet confirmed.', {
            exact: true,
          }),
        ).toBeVisible();
        await expect(page.getByRole('checkbox')).toHaveCount(0);
        for (let n = 0; n < 19; n++) assert.equal((await f.advance(n)).status, 200);
        await page.getByRole('button', { name: 'Refresh progress', exact: true }).click();
        await expect(
          page.getByText(
            'Both copies are verified and the copy credentials are confirmed closed. No work has been delegated.',
            { exact: true },
          ),
        ).toBeVisible();
        await expect(page.getByRole('button', { name: 'Start copy', exact: true })).toHaveCount(0);
        assert.equal(posted.length, 1);
        assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
        await auditAccessibility(page, 'work-copy-verified');
        await page.screenshot({ path: shots + '/verified-en-mobile.png', fullPage: true });
      },
    );
    await t.test(
      'withdrawn approval retains navigation to the existing verified copy',
      async () => {
        assert.equal(
          (
            await f.product(`/work/preparations/${f.p.id}/copy-consent`, 'DELETE', {
              format_version: 1,
              review_digest: f.digest,
            })
          ).status,
          200,
        );
        await page.goto('https://work.test/work/preparation-review?lang=ja');
        await page.locator('.preparation-list button').first().click();
        const progress = page.getByRole('link', { name: 'コピーの進捗を開く', exact: true });
        await expect(progress).toBeVisible();
        await progress.click();
        await expect(
          page.getByText(
            'コードと選択ファイルのコピーを検証し、コピー用の認証情報の失効を確認しました。作業の委任は未実行です。',
            { exact: true },
          ),
        ).toBeVisible();
        await expect(page.getByRole('button', { name: 'コピーを開始', exact: true })).toHaveCount(
          0,
        );
        assert.equal(posted.length, 1);
      },
    );
    assert.deepEqual(errors, []);
  } finally {
    release?.();
    await browser.close();
    await f.close();
  }
});
