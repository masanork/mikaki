/** Opt-in product route and real Native consent, with synthetic local SSO/Git. */
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, expect } from '@playwright/test';
import { createSourceFixture } from './support/work-source-fixture.ts';
import { seedPreparationReview } from './support/work-preparation-review-fixture.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';

test('copy approval is explicit, scoped, bilingual and discarded when the owner view locks', async (t) => {
  const f = await createSourceFixture(undefined, true, 'product', true);
  const s = await seedPreparationReview(f);
  const destination = JSON.parse(s.reserved.body).data.plan;
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
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
  await page.addInitScript(() => {
    Object.defineProperty(window, 'hideCopyReview', {
      value: () => {
        Object.defineProperty(document, 'visibilityState', {
          configurable: true,
          get: () => 'hidden',
        });
        document.dispatchEvent(new Event('visibilitychange'));
      },
    });
  });
  const posted: any[] = [];
  let hold = false,
    started: (() => void) | undefined,
    release: (() => void) | undefined;
  await context.route('https://work.test/**', async (route) => {
    const request = route.request();
    if (request.method() === 'POST' && request.url().endsWith('/copy-consent'))
      posted.push(JSON.parse(request.postData()!));
    const response = await f.worker.fetch(request.url(), {
      method: request.method(),
      headers: await request.allHeaders(),
      body: request.postData() ?? undefined,
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    if (hold && request.method() === 'POST' && request.url().endsWith('/copy-consent')) {
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
  const choose = () => page.locator('.preparation-list button').first();
  const inspect = () => page.getByRole('button', { name: 'コピー対象を確認', exact: true });
  const approve = () => page.getByRole('button', { name: 'このコピーを承認', exact: true });
  const checkbox = () => page.getByRole('checkbox');
  const shots = new URL('../../artifacts/work-copy-consent/', import.meta.url).pathname;
  await mkdir(shots, { recursive: true });
  try {
    await t.test(
      'review and actual text inspection do not automatically authorize copying',
      async () => {
        await page.goto('https://work.test/work/preparation-review?lang=ja');
        await expect(choose()).toContainText(destination.task_name);
        await choose().click();
        await expect(approve()).toHaveCount(0);
        await expect(checkbox()).toHaveCount(0);
        await expect(page.getByText('Cloudflare Artifacts', { exact: true })).toBeVisible();
        await expect(page.locator('.work-record-details')).not.toHaveAttribute('open');
        await expect(page.locator('.work-destination')).toContainText(
          destination.task_namespace + ' / ' + destination.task_name,
        );
        await expect(page.locator('.work-destination')).toContainText(
          destination.snapshot_namespace + ' / ' + destination.snapshot_name,
        );
        await page.locator('.work-record-details > summary').click();
        await expect(page.getByText('a'.repeat(32), { exact: true })).toBeVisible();
        await page.locator('.work-record-details > summary').click();
        await page.locator('main').focus();
        await page.evaluate(() => scrollTo(0, 0));
        await page.screenshot({ path: shots + '/review-compact-ja.png', fullPage: true });
        await inspect().click();
        await expect(page.locator('pre')).toHaveText(f.contents['preferences/writing.md']);
        await expect(checkbox()).toBeEnabled();
        await expect(approve()).toBeDisabled();
        assert.equal(posted.length, 0);
        await auditAccessibility(page, 'work-copy-consent-review');
        await page.screenshot({ path: shots + '/review-ja.png', fullPage: true });
      },
    );
    await t.test(
      'English mobile review exposes the same operator and requires a fresh acknowledgement',
      async () => {
        await page.setViewportSize({ width: 375, height: 900 });
        await page.goto('https://work.test/work/preparation-review?lang=en');
        await choose().click();
        await expect(
          page.getByRole('button', { name: 'Approve this copy', exact: true }),
        ).toHaveCount(0);
        await page.getByRole('button', { name: 'Check copy contents', exact: true }).click();
        await expect(checkbox()).toBeEnabled();
        assert.equal(
          await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          true,
        );
        await auditAccessibility(page, 'work-copy-consent-mobile');
        await page.locator('main').focus();
        await page.evaluate(() => scrollTo(0, 0));
        await page.screenshot({ path: shots + '/review-en-mobile.png', fullPage: true });
      },
    );
    await t.test(
      'one explicit approval persists the exact review, without creating a grant, token or copy',
      async () => {
        await page.goto('https://work.test/work/preparation-review?lang=ja');
        await choose().click();
        await inspect().click();
        await expect(checkbox()).toBeEnabled();
        await checkbox().focus();
        await page.keyboard.press('Space');
        await expect(approve()).toBeEnabled();
        await approve().click();
        await expect(
          page.getByText('コピーの承認を記録しました。コピーの開始・完了は別途確認されます。', {
            exact: true,
          }),
        ).toBeVisible();
        assert.equal(posted.length, 1);
        assert.deepEqual(Object.keys(posted[0]).sort(), ['format_version', 'review_digest']);
        assert.equal(
          await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
            .bind(s.reserved.id)
            .first('state'),
          'reserved',
        );
        for (const table of ['work_grant', 'work_run', 'work_credential_attempt'])
          assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM ' + table).first('n'), 0);
        await page.getByRole('button', { name: 'コピーの承認を取り消す', exact: true }).click();
        await expect(
          page.getByText('コピーの承認を取り消しました。新しいコピーは許可されません。', {
            exact: true,
          }),
        ).toBeVisible();
        await expect(approve()).toHaveCount(0);
      },
    );
    await t.test(
      'a late successful mutation never resurrects an approval after the view locks',
      async () => {
        const d = await s.call({
          action: 'disclosure',
          disclosure: f.disclosure,
          expires_at: Math.floor(Date.now() / 1000) + 720,
        });
        const p = await s.reserve('late-copy-task', d.digest);
        await page.goto('https://work.test/work/preparation-review?lang=ja');
        await expect(page.locator(`[data-preparation-id="${s.reserved.id}"]`)).toContainText(
          destination.task_name,
        );
        await expect(page.locator(`[data-preparation-id="${p.id}"]`)).toContainText(
          JSON.parse(p.body).data.plan.task_name,
        );
        await page.locator(`[data-preparation-id="${p.id}"]`).click();
        await inspect().click();
        await checkbox().check();
        const ready = new Promise<void>((r) => (started = r));
        hold = true;
        await approve().click();
        await ready;
        await page.evaluate(() =>
          (window as unknown as { hideCopyReview: () => void }).hideCopyReview(),
        );
        await expect(checkbox()).toHaveCount(0);
        await expect(page.locator('pre')).toHaveCount(0);
        hold = false;
        release?.();
        await expect(
          page.getByText('コピーの承認を記録しました。コピーの開始・完了は別途確認されます。', {
            exact: true,
          }),
        ).toHaveCount(0);
        assert.equal(
          await f.DB.prepare('SELECT active FROM work_copy_consent WHERE preparation_id=?')
            .bind(p.id)
            .first('active'),
          1,
        );
        await page.goto('https://work.test/work/preparation-review?lang=ja');
        await page.locator(`[data-preparation-id="${p.id}"]`).click();
        await expect(
          page.getByRole('button', { name: 'コピーの承認を取り消す', exact: true }),
        ).toBeVisible();
      },
    );
    assert.deepEqual(errors, []);
  } finally {
    release?.();
    await browser.close();
    await f.close();
  }
});
