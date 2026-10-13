/** Owner-created preparations and real Native approval. Synthetic local SSO;
 * Git bytes are real, and this page never creates remote effects or a grant. */
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, expect } from '@playwright/test';
import { createSourceFixture } from './support/work-source-fixture.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';

test('owner source selection creates a preparation and opens fresh separate copy review', async (t) => {
  const f = await createSourceFixture(undefined, true, 'product', true, 3600, true);
  await f.register('code', f.first, {
    role: 'code',
    label: 'Synthetic code',
    files: [],
    ...f.codeSource,
  });
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.stack ?? e.message));
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
    Object.defineProperty(window, 'hideComposition', {
      value: () => {
        Object.defineProperty(document, 'visibilityState', {
          configurable: true,
          get: () => 'hidden',
        });
        document.dispatchEvent(new Event('visibilitychange'));
      },
    });
  });
  let hold = false,
    started: (() => void) | undefined,
    release: (() => void) | undefined;
  let corrupt: '' | 'digest' | 'oversize' = '';
  let latest: any;
  const submitted: any[] = [];
  await context.route('https://work.test/**', async (route) => {
    const request = route.request();
    const creating =
      request.method() === 'POST' && new URL(request.url()).pathname === '/work/preparations';
    if (creating) submitted.push(JSON.parse(request.postData()!));
    const response = await f.worker.fetch(request.url(), {
      method: request.method(),
      headers: await request.allHeaders(),
      body: request.postData() ?? undefined,
    });
    let bytes = Buffer.from(await response.arrayBuffer());
    if (creating && response.status === 200) {
      latest = JSON.parse(bytes.toString()).record;
      if (hold) {
        started?.();
        await new Promise<void>((r) => (release = r));
      }
      if (corrupt === 'digest') {
        const b = JSON.parse(bytes.toString());
        b.record.request_digest = 'f'.repeat(64);
        bytes = Buffer.from(JSON.stringify(b));
      }
      if (corrupt === 'oversize') bytes = Buffer.from(' '.repeat(4097));
    }
    await route
      .fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: bytes,
      })
      .catch(() => {});
  });
  const count = (
    table:
      | 'work_preparation'
      | 'work_copy_consent'
      | 'work_credential_attempt'
      | 'work_grant'
      | 'work_run',
  ) => f.DB.prepare('SELECT count(*) AS n FROM ' + table).first('n');
  const code = () => page.getByRole('radio', { name: /Synthetic code/ });
  const file = (path = 'preferences/writing.md') =>
    page.getByRole('checkbox', { name: new RegExp(path.replaceAll('.', '\\.')) });
  const prepare = (lang = 'ja') =>
    page.getByRole('button', { name: lang === 'ja' ? '準備を作成' : 'Prepare copy', exact: true });
  const preview = (lang = 'ja') =>
    page.getByRole('button', {
      name: lang === 'ja' ? '選んだファイルを確認' : 'Inspect selected files',
      exact: true,
    });
  const link = (lang = 'ja') =>
    page.getByRole('link', {
      name: lang === 'ja' ? 'コピー内容を確認' : 'Review the copy',
      exact: true,
    });
  async function fresh(lang = 'ja', paths = ['preferences/writing.md']) {
    await page.goto('https://work.test/work/source-review?lang=' + lang);
    await expect(code()).toBeVisible();
    await code().check();
    if (paths.length)
      for (const summary of await page.locator('.work-reference-source > summary').all())
        await summary.click();
    for (const path of paths) await file(path).check();
    if (paths.length) {
      await expect(prepare(lang)).toBeDisabled();
      await preview(lang).click();
    }
    await expect(prepare(lang)).toBeEnabled();
  }
  const shots = new URL('../../artifacts/work-preparation-compose/', import.meta.url).pathname;
  await mkdir(shots, { recursive: true });
  try {
    await t.test(
      'Japanese content selection persists only a preparation and requires a second explicit approval',
      async () => {
        await page.goto('https://work.test/work/source-review?lang=ja');
        await expect(code()).toBeVisible();
        await expect(prepare()).toBeDisabled();
        assert.equal(await count('work_preparation'), 0);
        await code().check();
        for (const summary of await page.locator('.work-reference-source > summary').all())
          await summary.click();
        await file().check();
        await expect(prepare()).toBeDisabled();
        await preview().click();
        await expect(prepare()).toBeEnabled();
        await page.screenshot({ path: shots + 'source-ja.png', fullPage: true });
        await auditAccessibility(page, 'work-preparation-compose-ja');
        await prepare().click();
        await expect(link()).toBeVisible();
        assert.equal(await count('work_preparation'), 1);
        assert.equal(await count('work_copy_consent'), 0);
        assert.equal(await count('work_credential_attempt'), 0);
        const id = latest.preparation_id;
        await link().click();
        await expect(page).toHaveURL(new RegExp('/work/preparation-review\\?lang=ja#' + id + '$'));
        const approve = page.getByRole('button', { name: 'このコピーを承認', exact: true });
        await expect(approve).toHaveCount(0);
        await page.getByRole('button', { name: 'コピー対象を確認', exact: true }).click();
        await expect(page.getByRole('checkbox')).toBeEnabled();
        await page.getByRole('checkbox').check();
        await expect(approve).toBeEnabled();
        await approve.click();
        await expect(
          page.getByRole('button', { name: 'コピーの承認を取り消す', exact: true }),
        ).toBeVisible();
        assert.equal(await count('work_copy_consent'), 1);
        for (const table of ['work_credential_attempt', 'work_grant', 'work_run'] as const)
          assert.equal(await count(table), 0);
        assert.equal(
          await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
            .bind(id)
            .first('state'),
          'reserved',
        );
      },
    );
    await t.test(
      'English mobile code-only preparation uses the same boundaries and preserves locale on the review link',
      async () => {
        await page.setViewportSize({ width: 375, height: 900 });
        await fresh('en', []);
        await expect(preview('en')).toHaveCount(0);
        await expect(page.getByText('Code to copy: Synthetic code', { exact: true })).toBeVisible();
        await expect(page.getByText('No reference files', { exact: true })).toBeVisible();
        await page.screenshot({ path: shots + 'source-en-mobile.png', fullPage: true });
        await auditAccessibility(page, 'work-preparation-compose-en-mobile');
        assert.equal(
          await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          true,
        );
        await prepare('en').focus();
        await page.keyboard.press('Enter');
        await expect(link('en')).toBeVisible();
        assert.equal(await count('work_preparation'), 2);
        assert.equal(await count('work_copy_consent'), 1);
        await link('en').click();
        await expect(
          page.getByRole('button', { name: 'Approve this copy', exact: true }),
        ).toHaveCount(0);
        await expect(page.locator('html')).toHaveAttribute('lang', 'en');
        await expect(page.getByText('SYNTHETIC_UNSELECTED', { exact: false })).toHaveCount(0);
      },
    );
    await t.test(
      'a late committed creation cannot restore text or a preparation link after the view locks',
      async () => {
        await fresh('ja', ['decisions/long.md']);
        hold = true;
        const pending = new Promise<void>((r) => (started = r));
        await prepare().click();
        await pending;
        assert.equal(await count('work_preparation'), 3);
        await page.evaluate(() => {
          (window as unknown as { hideComposition: () => void }).hideComposition();
        });
        await expect(page.locator('.source-preview pre')).toHaveCount(0);
        await expect(link()).toHaveCount(0);
        release?.();
        hold = false;
        await expect(link()).toHaveCount(0);
        await page.goto(
          'https://work.test/work/preparation-review?lang=ja#' + latest.preparation_id,
        );
        await expect(
          page.getByRole('button', { name: 'このコピーを承認', exact: true }),
        ).toHaveCount(0);
        assert.equal(await count('work_copy_consent'), 1);
      },
    );
    await t.test(
      'substituted and oversized replies reject the link while exact retries recover the same retained preparation',
      async () => {
        await fresh('ja', ['decisions/long.md', 'preferences/writing.md']);
        corrupt = 'digest';
        await prepare().click();
        await expect(page.getByRole('alert')).toBeVisible();
        await expect(link()).toHaveCount(0);
        assert.equal(await count('work_preparation'), 4);
        const id = latest.preparation_id;
        await preview().click();
        await expect(prepare()).toBeEnabled();
        corrupt = 'oversize';
        await prepare().click();
        await expect(page.getByRole('alert')).toBeVisible();
        await expect(link()).toHaveCount(0);
        assert.equal(latest.preparation_id, id);
        assert.equal(await count('work_preparation'), 4);
        corrupt = '';
        await preview().click();
        await expect(prepare()).toBeEnabled();
        await prepare().click();
        await expect(link()).toBeVisible();
        assert.equal(latest.preparation_id, id);
        assert.equal(await count('work_preparation'), 4);
        assert.equal(await count('work_copy_consent'), 1);
        assert.equal(
          await f.DB.prepare(
            "SELECT count(*) AS n FROM work_audit WHERE action='preparation.reserve'",
          ).first('n'),
          4,
        );
      },
    );
    assert.deepEqual(errors, []);
    for (const input of submitted) {
      assert.deepEqual(Object.keys(input).sort(), [
        'code',
        'contexts',
        'expires_at',
        'format_version',
      ]);
      assert.deepEqual(Object.keys(input.code).sort(), [
        'access_revision',
        'source_id',
        'source_revision',
      ]);
    }
  } finally {
    release?.();
    await browser.close();
    await f.close();
  }
});
