import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir } from 'node:fs/promises';
import { chromium, expect } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { createNativeUiPage, startNativeUiServer } from './support/native-client-ui.ts';
import {
  walletDocument,
  walletCredential,
  passportAuthenticationNote,
} from '../../apps/mikaki-client/ui/wallet-model.js';

async function fillPassport(page: import('@playwright/test').Page) {
  await page.locator('#wallet-add-button').click();
  await page.locator('[data-document-type="passport"]').click();
  await expect(page.locator('#identity-passport-number')).toBeFocused();
  await page.locator('#identity-passport-number').fill('L898902C');
  await page.locator('#identity-passport-birth').fill('1969-08-06');
  await page.locator('#identity-passport-expiry').fill('2034-06-23');
}

test('passport data is saved explicitly, masked until requested and reused only for read preparation', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    signedIn: true,
    identityReader: true,
    identityWallet: true,
    identityDocuments: documents,
  });
  try {
    await expect(page.locator('.document-card')).toHaveCount(2);
    await fillPassport(page);
    await expect(page.locator('#identity-pin')).toBeHidden();
    await page.setViewportSize({ width: 320, height: 900 });
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    for (const id of ['number', 'birth', 'expiry']) {
      const bounds = await page.locator('#identity-passport-' + id).boundingBox();
      assert(bounds && bounds.x >= 0 && bounds.x + bounds.width <= 320);
    }
    await page.setViewportSize({ width: 390, height: 900 });
    assert.deepEqual(
      (await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id),
      [],
    );
    const output = new URL('../../docs/identity-wallet-preview/', import.meta.url);
    await page.screenshot({
      path: new URL('wallet-passport-access.png', output).pathname,
      fullPage: true,
    });
    await page.locator('#identity-read').click();
    await expect(page.locator('#identity-preview')).toBeVisible();
    await expect(page.locator('#identity-preview-note')).toContainText('発行国の署名は未検証');
    await expect(page.locator('#identity-link')).toBeHidden();
    await expect(page.locator('.document-card')).toHaveCount(2);
    for (const id of ['number', 'birth', 'expiry'])
      await expect(page.locator('#identity-passport-' + id)).toHaveValue('');
    const calls = await page.evaluate(() => window.__nativeUiTest.arguments);
    assert.deepEqual(calls.find((c) => c.command === 'read_identity_passport')?.args, {
      documentNumber: 'L898902C',
      birthDate: '1969-08-06',
      expiryDate: '2034-06-23',
    });
    assert.equal(
      calls.some((c) => c.command === 'read_identity_card'),
      false,
    );
    await page.locator('#identity-save-document').click();
    await expect(page.locator('.document-card')).toHaveCount(3);
    await expect(page.locator('#wallet-document-count')).toHaveText('3');
    await page.locator('#identity-clear').click();
    await page
      .locator('#identity-reader')
      .evaluate((node: HTMLDetailsElement) => (node.open = false));
    const passport = page.getByRole('button', { name: /PASSPORT/ });
    await expect(passport).toHaveClass(/burgundy/);
    await passport.click();
    await expect(page.locator('#wallet-card-note')).toContainText('発行国の署名は未検証');
    await expect(page.locator('#wallet-card-values')).not.toContainText('L898902C');
    await expect(page.locator('#wallet-passport-values')).toBeEmpty();
    assert.equal(
      await page.evaluate(() => window.__nativeUiTest.calls.includes('identity_passport_details')),
      false,
    );
    for (const id of [
      'wallet-document-receive',
      'wallet-credential-present',
      'wallet-credential-proximity',
    ])
      await expect(page.locator('#' + id)).toBeHidden();
    await expect(page.locator('#wallet-document-reread')).toHaveText('パスポートを読み取り直す');
    await page.setViewportSize({ width: 390, height: 1700 });
    await page.screenshot({
      path: new URL('wallet-passport.png', output).pathname,
      fullPage: true,
    });
    await page.locator('#wallet-passport-reveal').click();
    await expect(page.locator('#wallet-passport-values')).toContainText('L898902C');
    await expect(page.locator('.passport-mrz')).toContainText('P<UTOERIKSSON');
    await expect(page.locator('#wallet-documents')).not.toContainText('L898902C');
    await expect(page.locator('#wallet-passport-reveal')).toHaveAttribute('aria-expanded', 'true');
    assert.equal((await page.locator('.passport-mrz').textContent())?.length, 89);
    assert.deepEqual(
      (await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id),
      [],
    );
    for (const width of [320, 390]) {
      await page.setViewportSize({ width, height: 1700 });
      assert.equal(
        await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        true,
      );
    }
    await page
      .locator('#wallet-card-detail')
      .screenshot({ path: new URL('wallet-passport-revealed.png', output).pathname });
    await page.locator('#wallet-passport-reveal').click();
    await expect(page.locator('#wallet-passport-values')).toBeEmpty();
    await page.getByRole('link', { name: 'Chat', exact: true }).click();
    await page.getByRole('link', { name: 'Walletを開く', exact: true }).click();
    await expect(page.locator('.document-card')).toHaveCount(3);
    await passport.click();
    await expect(page.locator('#wallet-passport-values')).toBeEmpty();
    await page.locator('#wallet-document-reread').click();
    await expect(page.locator('#identity-passport-number')).toBeFocused();
    await expect(page.locator('#identity-passport-number')).toHaveValue('L898902C');
    await expect(page.locator('#identity-passport-birth')).toHaveValue('1969-08-06');
    await expect(page.locator('#identity-passport-expiry')).toHaveValue('2034-06-23');
    assert.equal(
      await page.evaluate(
        () => window.__nativeUiTest.calls.filter((c) => c === 'read_identity_passport').length,
      ),
      1,
    );
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    const commands = await page.evaluate(() => window.__nativeUiTest.calls);
    for (const command of [
      'start_identity_link',
      'start_identity_wallet_issuance',
      'review_identity_presentation',
    ])
      assert.equal(commands.includes(command), false);
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});

const savedPassport = {
  id: 'passport',
  saved_at: 1792522800,
  passport: {
    document_number: 'L898902C3',
    mrz:
      'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<' +
      'L898902C36UTO7408122F1204159ZE184226B<<<<<10',
  },
  preview: {
    name: 'ERIKSSON ANNA MARIA',
    address: '',
    birth_date: '1974-08-12',
    gender: '2',
    verification: 'unverified',
    document_type: 'passport',
    expiry_date: '2012-04-15',
    backend_verifiable: false,
  },
};
test('DG1/SOD consistency is displayed without granting issuer trust or presentation authority', async (t) => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  try {
    for (const state of ['consistent', 'invalid', 'unsupported'])
      await t.test(state, async () => {
        const report = {
          state,
          checked_data_groups: state === 'consistent' ? [1] : [],
          issuer_trust: 'not_configured',
        };
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          signedIn: true,
          identityReader: true,
          identityWallet: true,
          identityPassportAuthentication: report,
        });
        try {
          await fillPassport(page);
          await page.locator('#identity-read').click();
          await expect(page.locator('#identity-preview-note')).toContainText(
            state === 'consistent'
              ? 'DG1のハッシュとSOD署名の整合性を確認しました'
              : state === 'invalid'
                ? 'DG1と署名情報の整合性を確認できませんでした'
                : '署名方式・形式には未対応',
          );
          await expect(page.locator('#identity-link')).toBeHidden();
          await page.locator('#identity-save-document').click();
          await page.locator('#identity-clear').click();
          await page
            .locator('#identity-reader')
            .evaluate((node: HTMLDetailsElement) => (node.open = false));
          await page.locator('.document-card').click();
          await expect(page.locator('#wallet-card-note')).toContainText(
            passportAuthenticationNote(report),
          );
          await expect(page.locator('#wallet-credential-present')).toBeHidden();
          await expect(page.locator('#wallet-document-receive')).toBeHidden();
          await expect(page.locator('.wallet-card')).toHaveCount(0);
          if (state === 'consistent') {
            await expect(page.locator('.document-card')).toContainText('署名整合 · 発行国未確認');
            await expect(page.locator('#wallet-card-note')).toContainText(
              '写真など他のデータは未検証',
            );
            await page.setViewportSize({ width: 390, height: 1700 });
            await page.locator('#wallet-card-detail').screenshot({
              path: new URL(
                '../../docs/identity-wallet-preview/wallet-passport-signature.png',
                import.meta.url,
              ).pathname,
            });
          }
          assert.equal(
            await page.evaluate(() => window.__nativeUiTest.calls.includes('start_identity_link')),
            false,
          );
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

test('UI cannot treat a claimed issuer-trusted or incomplete DG scope as verification', () => {
  for (const report of [
    { state: 'consistent', issuer_trust: 'trusted', checked_data_groups: [1] },
    { state: 'consistent', issuer_trust: 'not_configured', checked_data_groups: [] },
    { state: 'consistent', issuer_trust: 'not_configured', checked_data_groups: [1, 2] },
  ]) {
    assert.equal(passportAuthenticationNote(report).includes('整合性を確認しました'), false);
    const item = walletDocument({ ...savedPassport, passport_authentication: report });
    assert.equal(item.status.includes('署名整合'), false);
    assert.deepEqual(item.presentation, { formats: [], available: false });
  }
});

test('CSCA and revocation results preserve DG1 scope and never create presentation authority', async (t) => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  try {
    for (const [revocation, text] of [
      ['good', '失効リストに掲載されていないことを確認しました'],
      ['missing', '失効情報がないため'],
      ['stale', '失効情報が古いため'],
      ['invalid', '失効情報の検証に失敗しました'],
      ['revoked', '失効リストに掲載されています'],
    ])
      await t.test(revocation, async () => {
        const now = Math.floor(Date.now() / 1000);
        const report = {
          state: 'consistent',
          checked_data_groups: [1],
          issuer_trust: 'csca_verified',
          revocation,
          checked_at: now - 10,
          valid_until: now + 120,
        };
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          signedIn: true,
          identityReader: true,
          identityWallet: true,
          identityPassportAuthentication: report,
        });
        try {
          await fillPassport(page);
          await page.locator('#identity-read').click();
          await expect(page.locator('#identity-preview-note')).toContainText(text);
          await expect(page.locator('#identity-preview-note')).toContainText(
            '写真など他のデータは未検証',
          );
          await expect(page.locator('#identity-link')).toBeHidden();
          await page.locator('#identity-save-document').click();
          await page.locator('#identity-clear').click();
          await page.locator('.document-card').click();
          await expect(page.locator('#wallet-card-note')).toContainText(text);
          await expect(page.locator('#wallet-credential-present')).toBeHidden();
          await expect(page.locator('#wallet-document-receive')).toBeHidden();
          await expect(page.locator('.wallet-card')).toHaveCount(0);
          if (revocation === 'good') {
            await page.setViewportSize({ width: 390, height: 1700 });
            await page.locator('#wallet-card-detail').screenshot({
              path: new URL(
                '../../docs/identity-wallet-preview/wallet-passport-csca.png',
                import.meta.url,
              ).pathname,
            });
          }
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

test('expired, future and incomplete native trust reports cannot retain a trusted label', () => {
  const at = Date.now(),
    now = Math.floor(at / 1000);
  const good = {
    state: 'consistent',
    checked_data_groups: [1],
    issuer_trust: 'csca_verified',
    revocation: 'good',
    checked_at: now - 10,
    valid_until: now + 60,
  };
  const record = {
    ...savedPassport,
    preview: { ...savedPassport.preview, expiry_date: '2099-12-31' },
  };
  assert.equal(
    walletDocument({ ...record, passport_authentication: good }, at).status,
    '発行国署名 · DG1確認',
  );
  for (const change of [
    { valid_until: now },
    { checked_at: now + 10 },
    { checked_at: undefined },
    { valid_until: undefined },
    { revocation: 'future_unknown_state' },
  ]) {
    const report = { ...good, ...change };
    assert.equal(
      passportAuthenticationNote(report, at).includes('掲載されていないことを確認しました'),
      false,
    );
    const item = walletDocument({ ...record, passport_authentication: report }, at);
    assert.equal(item.status.includes('DG1確認'), false);
    assert.deepEqual(item.presentation, { formats: [], available: false });
  }
});

test('trust expiry removes passport success labels before a delayed inventory refresh', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const now = Math.floor(Date.now() / 1000);
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    signedIn: true,
    identityReader: true,
    identityDocuments: [
      {
        ...savedPassport,
        preview: { ...savedPassport.preview, expiry_date: '2099-12-31' },
        passport_authentication: {
          state: 'consistent',
          checked_data_groups: [1],
          issuer_trust: 'csca_verified',
          revocation: 'good',
          checked_at: now - 10,
          valid_until: now + 120,
        },
      },
    ],
  });
  try {
    await page.clock.install();
    await page.reload();
    await expect(page.locator('.document-card')).toContainText('発行国署名 · DG1確認');
    await page.locator('.document-card').click();
    await page.evaluate(() => window.__nativeUiTest.hold('identity_document_inventory'));
    await page.clock.fastForward(121_000);
    await expect(page.locator('.document-card')).toHaveCount(0);
    await expect(page.locator('#wallet-card-detail')).toBeHidden();
    await page.evaluate(() => window.__nativeUiTest.release('identity_document_inventory'));
    await expect(page.locator('.document-card')).toContainText('署名整合 · 信頼期限切れ');
    await page.locator('.document-card').click();
    await expect(page.locator('#wallet-card-note')).toContainText('確認期限が切れた');
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});

test('passport issuance reviews raw-data transfer separately and sends only a native review id on approval', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const now = Math.floor(Date.now() / 1000);
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    signedIn: true,
    identityReader: true,
    passportIssuance: true,
    identityDocuments: [
      {
        ...savedPassport,
        passport_authentication: {
          state: 'consistent',
          checked_data_groups: [1],
          issuer_trust: 'csca_verified',
          revocation: 'good',
          checked_at: now,
          valid_until: now + 600,
        },
      },
    ],
  });
  try {
    await page.locator('.document-card').click();
    await page.locator('#wallet-passport-issue').click();
    await expect(page.locator('#passport-issuance-review')).toBeVisible();
    await expect(page.locator('#passport-issuance-review')).toContainText(
      'MRZ全文（個人番号欄を含む）',
    );
    await expect(page.locator('#passport-review-values')).toContainText('690806');
    await expect(page.locator('#passport-review-values')).not.toContainText('1969');
    assert.equal(
      await page.evaluate(() => window.__nativeUiTest.calls.includes('confirm_passport_issuance')),
      false,
    );
    await page.setViewportSize({ width: 390, height: 1700 });
    await page.locator('#passport-issuance-review').screenshot({
      path: new URL(
        '../../docs/identity-wallet-preview/passport-issuance-review.png',
        import.meta.url,
      ).pathname,
    });
    await page.locator('#passport-review-cancel').click();
    await expect(page.locator('#passport-issuance-review')).toBeHidden();
    assert.equal(
      await page.evaluate(() => window.__nativeUiTest.calls.includes('confirm_passport_issuance')),
      false,
    );
    await page.locator('.document-card').click();
    await page.locator('#wallet-passport-issue').click();
    await expect(page.locator('#passport-issuance-review')).toBeVisible();
    await page.locator('#passport-review-confirm').click();
    await expect(page.locator('#identity-issuance-status')).toContainText('ブラウザで6項目');
    const args = await page.evaluate(() =>
      window.__nativeUiTest.arguments.filter((c) => c.command === 'confirm_passport_issuance'),
    );
    assert.deepEqual(args, [
      {
        command: 'confirm_passport_issuance',
        args: { reviewId: 'fixture-passport-review', approve: true },
      },
    ]);
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});

test('passport HAIP handoff uses the attested Wallet receiver without a legacy fallback', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const now = Math.floor(Date.now() / 1000);
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    signedIn: true,
    identityReader: true,
    identityWallet: true,
    passportIssuance: true,
    passportHaip: true,
    identityDocuments: [
      {
        ...savedPassport,
        passport_authentication: {
          state: 'consistent',
          checked_data_groups: [1],
          issuer_trust: 'csca_verified',
          revocation: 'good',
          checked_at: now,
          valid_until: now + 600,
        },
      },
    ],
  });
  try {
    await page.locator('.document-card').click();
    await page.locator('#wallet-passport-issue').click();
    await expect(page.locator('#passport-issuance-review')).toBeVisible();
    await page.locator('#passport-review-confirm').click();
    await expect(page.locator('#identity-wallet-receive')).toBeVisible();
    await expect(page.locator('#identity-receive')).toBeHidden();
    await expect(page.locator('#identity-wallet-status')).toContainText('Wallet連携鍵');
    await page.evaluate(() => window.__nativeUiTest.emit('identity-issuance-updated', 'ready'));
    await page.locator('#identity-wallet-receive').click();
    await expect
      .poll(() =>
        page.evaluate(() =>
          window.__nativeUiTest.calls.includes('receive_identity_wallet_credential'),
        ),
      )
      .toBe(true);
    const calls = await page.evaluate(() => window.__nativeUiTest.calls);
    assert.equal(calls.includes('receive_identity_credential'), false);
    assert.equal(calls.includes('start_identity_link'), false);
    assert.deepEqual(errors, []);
  } finally {
    await browser.close();
    await server.close();
  }
});

test('late passport issuance reviews cannot reopen after navigation or app hiding', async (t) => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  try {
    for (const action of ['navigate', 'hide'])
      await t.test(action, async () => {
        const now = Math.floor(Date.now() / 1000);
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          signedIn: true,
          identityReader: true,
          passportIssuance: true,
          identityDocuments: [
            {
              ...savedPassport,
              passport_authentication: {
                state: 'consistent',
                checked_data_groups: [1],
                issuer_trust: 'csca_verified',
                revocation: 'good',
                checked_at: now,
                valid_until: now + 600,
              },
            },
          ],
        });
        try {
          await page.locator('.document-card').click();
          await page.evaluate(() => window.__nativeUiTest.hold('review_passport_issuance'));
          await page.locator('#wallet-passport-issue').click();
          if (action === 'navigate') await page.locator('a[href="#chat"]').click();
          else
            await page.evaluate(() => {
              Object.defineProperty(document, 'hidden', { configurable: true, value: true });
              document.dispatchEvent(new Event('visibilitychange'));
            });
          await page.evaluate(() => window.__nativeUiTest.release('review_passport_issuance'));
          await expect(page.locator('#passport-issuance-review')).toBeHidden();
          await expect(page.locator('#passport-review-values')).toBeEmpty();
          assert.equal(
            await page.evaluate(() =>
              window.__nativeUiTest.calls.includes('confirm_passport_issuance'),
            ),
            false,
          );
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

test('late passport details are discarded after close, navigation, hiding or deletion', async (t) => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  try {
    for (const action of ['close', 'navigate', 'hide', 'delete'])
      await t.test(action, async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          signedIn: true,
          identityReader: true,
          identityDocuments: [savedPassport],
        });
        try {
          await page.locator('.document-card').click();
          await page.evaluate(() => window.__nativeUiTest.hold('identity_passport_details'));
          await page.locator('#wallet-passport-reveal').click();
          if (action === 'close') await page.locator('#wallet-detail-close').click();
          else if (action === 'navigate')
            await page.getByRole('link', { name: 'Chat', exact: true }).click();
          else if (action === 'hide')
            await page.evaluate(() => {
              Object.defineProperty(document, 'hidden', { configurable: true, value: true });
              document.dispatchEvent(new Event('visibilitychange'));
            });
          else {
            page.once('dialog', (d) => d.accept());
            await page.locator('#wallet-document-remove').click();
            await expect(page.locator('.document-card')).toHaveCount(0);
          }
          await page.evaluate(() => window.__nativeUiTest.release('identity_passport_details'));
          await expect(page.locator('#wallet-passport-values')).toBeEmpty();
          await expect(page.locator('#wallet-passport-section')).toBeHidden();
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

test('late passport prefill cannot undo navigation, type changes or a manual edit', async (t) => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  try {
    for (const action of ['navigate', 'type', 'edit'])
      await t.test(action, async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          signedIn: true,
          identityReader: true,
          identityDocuments: [savedPassport],
        });
        try {
          await page.locator('.document-card').click();
          await page.evaluate(() => window.__nativeUiTest.hold('identity_passport_details'));
          await page.locator('#wallet-document-reread').click();
          if (action === 'navigate') {
            await page.getByRole('link', { name: 'Chat', exact: true }).click();
            await page.getByRole('link', { name: 'Walletを開く', exact: true }).click();
          } else if (action === 'type')
            await page.locator('#identity-type').selectOption('my_number_card');
          else await page.locator('#identity-passport-number').fill('MANUAL');
          await page.evaluate(() => window.__nativeUiTest.release('identity_passport_details'));
          await expect(page.locator('#identity-passport-number')).toHaveValue(
            action === 'edit' ? 'MANUAL' : '',
          );
          await expect(page.locator('#identity-passport-birth')).toHaveValue('');
          await expect(page.locator('#identity-passport-expiry')).toHaveValue('');
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

test('passport navigation and cancellation clear access data and suppress a late read result', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    signedIn: true,
    identityReader: true,
  });
  try {
    await fillPassport(page);
    await page.getByRole('link', { name: 'Chat', exact: true }).click();
    for (const id of ['number', 'birth', 'expiry'])
      await expect(page.locator('#identity-passport-' + id)).toHaveValue('');
    await page.getByRole('link', { name: 'Walletを開く', exact: true }).click();
    await fillPassport(page);
    await page.evaluate(() => window.__nativeUiTest.hold('read_identity_passport'));
    await page.locator('#identity-read').click();
    await expect(page.locator('#identity-cancel')).toBeVisible();
    await page.locator('#identity-cancel').click();
    await page.evaluate(() => window.__nativeUiTest.release('read_identity_passport'));
    await expect(page.locator('#identity-read')).toBeEnabled();
    await expect(page.locator('#identity-preview')).toBeHidden();
    await expect(page.locator('.document-card')).toHaveCount(0);
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});

test('passport authentication failure leaves no save or link path and clears access fields', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    signedIn: true,
    identityReader: true,
    identityFailure: { code: 'passport_authentication_failed' },
  });
  try {
    await fillPassport(page);
    await page.locator('#identity-read').click();
    await expect(page.locator('#identity-status')).toContainText('旅券との認証に失敗');
    await expect(page.locator('#identity-preview')).toBeHidden();
    for (const id of ['number', 'birth', 'expiry'])
      await expect(page.locator('#identity-passport-' + id)).toHaveValue('');
    await expect(page.locator('.document-card')).toHaveCount(0);
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});

const documents = [
  {
    id: 'my_number_card',
    saved_at: 1792522800,
    preview: {
      name: '試験 花子',
      address: '東京都千代田区（テストデータ）',
      birth_date: '1992-04-12',
      gender: '2',
      verification: 'unverified',
      document_type: 'my_number_card',
      expiry_date: null,
      backend_verifiable: true,
    },
  },
  {
    id: 'driving_license',
    saved_at: 1792522800,
    preview: {
      name: '試験 花子',
      address: '東京都千代田区（テストデータ）',
      birth_date: '1992-04-12',
      gender: '',
      verification: 'unverified',
      document_type: 'driving_license',
      expiry_date: '2030-04-12',
      backend_verifiable: true,
    },
  },
];

test('read documents remain non-presentable and never claim an mDL or passport credential', () => {
  const read = walletDocument(documents[1]);
  assert.equal(read.source, 'card_read');
  assert.deepEqual(read.presentation, { formats: [], available: false });
  assert.equal(
    walletDocument({
      ...documents[1],
      preview: { ...documents[1].preview, expiry_date: '2000-01-01' },
    }).status,
    '期限切れ · 読取記録',
  );
  assert.throws(() =>
    walletDocument({
      ...documents[0],
      preview: { ...documents[0].preview, verification: 'verified' },
    }),
  );
  assert.throws(() =>
    walletCredential({
      id: 'bad',
      title: '',
      issuer: '',
      format: 'invented-vc',
      expires_at: 0,
      fields: {},
    }),
  );
});

test('Wallet keeps the document collection private across navigation and presents accessible cards', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    signedIn: true,
    identityReader: true,
    identityWallet: true,
    identityDocuments: documents,
    identityInventory: [
      {
        id: 'credential',
        title: 'Mikaki本人確認属性証明',
        issuer: 'https://issuer.example',
        format: 'mso_mdoc',
        expires_at: Math.floor(Date.now() / 1000) + 240,
        fields: { name: '試験 花子' },
      },
    ],
  });
  try {
    await expect(page.locator('.document-card')).toHaveCount(2);
    await expect(page.locator('#wallet-document-count')).toHaveText('2');
    await expect(page.locator('#wallet-empty')).toBeHidden();
    await expect(page.locator('#wallet-documents')).not.toContainText('東京都');
    await page.locator('#wallet-privacy').click();
    await expect(page.locator('#wallet-documents')).not.toContainText('試験 花子');
    await page.locator('#wallet-privacy').click();
    await page.getByRole('button', { name: /MY NUMBER CARD/ }).click();
    await expect(page.locator('#wallet-card-values')).toContainText('東京都');
    await expect(page.locator('#wallet-card-note')).toContainText(
      '公的な身分証の代わりには使えません',
    );
    await page.getByRole('link', { name: 'Chat', exact: true }).click();
    await expect(page.locator('#wallet-documents')).toBeEmpty();
    await expect(page.locator('#wallet-card-values')).toBeEmpty();
    await expect(page.locator('#wallet-card-title')).toBeEmpty();
    await page.getByRole('link', { name: 'Walletを開く', exact: true }).click();
    await expect(page.locator('.document-card')).toHaveCount(2);
    assert.deepEqual(
      (await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id),
      [],
    );
    const output = new URL('../../docs/identity-wallet-preview/', import.meta.url);
    await mkdir(output, { recursive: true });
    for (const width of [320, 390, 1080]) {
      await page.setViewportSize({ width, height: 900 });
      assert.equal(
        await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        true,
      );
      await page.screenshot({
        path: new URL(`wallet-${width}.png`, output).pathname,
        fullPage: true,
      });
    }
    await page.locator('#wallet-add-button').click();
    await expect(page.locator('[data-document-type="passport"]')).toContainText('パスポート');
    await expect(page.locator('[data-document-type="passport"]')).toContainText('BAC対応');
    assert.equal(await page.locator('#identity-type option[value="passport"]').count(), 1);
    await page.setViewportSize({ width: 390, height: 900 });
    await page.screenshot({ path: new URL('wallet-add.png', output).pathname, fullPage: true });
    await page.locator('#open-settings').click();
    await page.getByLabel('テーマ').selectOption('dark');
    await page.getByRole('link', { name: 'Walletを開く', exact: true }).click();
    await expect(page.locator('.document-card')).toHaveCount(2);
    await page.locator('#wallet-add').evaluate((node: HTMLDetailsElement) => (node.open = false));
    await page.screenshot({ path: new URL('wallet-dark.png', output).pathname, fullPage: true });
    assert.deepEqual(
      (await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id),
      [],
    );
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});

test('a native read enters Wallet only after save, survives navigation, and can be removed explicitly', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    signedIn: true,
    identityReader: true,
  });
  try {
    await expect(page.locator('#wallet-empty')).toBeVisible();
    await page.locator('#wallet-empty-add').click();
    await page.locator('[data-document-type="driving_license"]').click();
    await expect(page.locator('#identity-type')).toHaveValue('driving_license');
    await page.locator('#identity-pin').fill('1234');
    await page.locator('#identity-read').click();
    await expect(page.locator('#identity-preview')).toBeVisible();
    await expect(page.locator('.document-card')).toHaveCount(0);
    await expect(page.locator('#identity-link')).toBeDisabled();
    await page.locator('#identity-save-document').click();
    await expect(page.locator('.document-card')).toHaveCount(1);
    const args = await page.evaluate(() =>
      window.__nativeUiTest.arguments.find((v) => v.command === 'save_identity_document'),
    );
    assert.equal(args?.args, undefined, 'attributes cannot be supplied by the WebView');
    await expect(page.locator('#identity-pin')).toHaveValue('');
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    await page.getByRole('link', { name: 'Chat', exact: true }).click();
    await page.getByRole('link', { name: 'Walletを開く', exact: true }).click();
    await expect(page.locator('.document-card')).toHaveCount(1);
    await page.locator('.document-card').click();
    page.once('dialog', (dialog) => dialog.accept());
    await page.locator('#wallet-document-remove').click();
    await expect(page.locator('.document-card')).toHaveCount(0);
    await expect(page.locator('#wallet-empty')).toBeVisible();
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});

test('document and credential details lead to explicit read, issuance and presentation preparation', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    signedIn: true,
    identityReader: true,
    identityWallet: true,
    identityDocuments: documents,
    identityInventory: [
      {
        id: 'credential',
        title: 'Mikaki本人確認属性証明',
        issuer: 'https://issuer.example',
        format: 'mso_mdoc',
        expires_at: Math.floor(Date.now() / 1000) + 240,
        fields: { name: '試験 花子' },
      },
    ],
  });
  try {
    await expect(page.locator('.document-card')).toHaveCount(2);
    const licence = page.getByRole('button', { name: /DRIVING LICENCE/ });
    await licence.click();
    await expect(page.locator('#wallet-credential-present')).toBeHidden();
    await page.locator('#wallet-detail-close').click();
    await expect(licence).toBeFocused();
    await licence.click();
    await page.locator('#wallet-document-reread').click();
    await expect(page.locator('#identity-type')).toHaveValue('driving_license');
    await expect(page.locator('#identity-pin')).toBeFocused();
    await expect(page.locator('#identity-pin')).toHaveValue('');
    await licence.click();
    await page.locator('#wallet-document-receive').click();
    await expect(page.locator('#identity-wallet-format')).toBeFocused();
    await expect(page.locator('#identity-wallet-start')).toBeVisible();
    await page.locator('.wallet-card').click();
    await expect(page.locator('#wallet-document-reread')).toBeHidden();
    await page.locator('#wallet-credential-present').click();
    await expect(page.locator('#identity-vp-request')).toBeFocused();
    await page.locator('.wallet-card').click();
    await page.locator('#wallet-credential-proximity').click();
    await expect(page.locator('#identity-proximity-engagement')).toBeFocused();
    const calls = await page.evaluate(() => window.__nativeUiTest.calls);
    for (const command of [
      'read_identity_card',
      'start_identity_link',
      'start_identity_wallet_issuance',
      'review_identity_presentation',
      'start_identity_proximity',
    ])
      assert.equal(calls.includes(command), false, command);
    const output = new URL('../../docs/identity-wallet-preview/', import.meta.url);
    await page.setViewportSize({ width: 390, height: 2200 });
    await page.evaluate(() => window.scrollTo(0, 0));
    await licence.click();
    await page.locator('#wallet-card-detail').screenshot({
      path: new URL('wallet-document-detail.png', output).pathname,
    });
    await page.locator('.wallet-card').click();
    await page.locator('#wallet-card-detail').screenshot({
      path: new URL('wallet-credential-detail.png', output).pathname,
    });
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});

test('expired credentials disappear while a native refresh is still pending', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    signedIn: true,
    identityInventory: [
      {
        id: 'short',
        title: '短期証明書',
        issuer: 'https://issuer.example',
        format: 'dc+sd-jwt',
        expires_at: Math.floor(Date.now() / 1000) + 120,
        fields: { name: '試験 花子' },
      },
    ],
  });
  try {
    await page.clock.install();
    await page.reload();
    await expect(page.locator('.wallet-card')).toHaveCount(1);
    await page.locator('.wallet-card').click();
    await expect(page.locator('#wallet-credential-proximity')).toBeHidden();
    await page.evaluate(() => window.__nativeUiTest.hold('identity_wallet_inventory'));
    await page.clock.fastForward(121_000);
    await expect(page.locator('.wallet-card')).toHaveCount(0);
    await expect(page.locator('#wallet-card-detail')).toBeHidden();
    await expect(page.locator('#wallet-card-values')).toBeEmpty();
    await page.evaluate(() => window.__nativeUiTest.release('identity_wallet_inventory'));
    await expect(page.locator('#wallet-status')).toContainText('証明書はまだありません');
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});

test('Wallet login binds document storage without changing in-app Web navigation, and logout scrubs the collection', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    platform: 'mobile',
    identityReader: true,
    identityDocuments: documents,
  });
  try {
    await expect(page.locator('#wallet-login')).toBeVisible();
    await expect(page.locator('.document-card')).toHaveCount(0);
    assert.equal(
      await page.evaluate(() =>
        window.__nativeUiTest.calls.includes('identity_document_inventory'),
      ),
      false,
    );
    await page.locator('#wallet-login').click();
    await expect(page.locator('#wallet-login-cancel')).toBeVisible();
    await page.evaluate(() => window.__nativeUiTest.complete());
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await expect(page.locator('.document-card')).toHaveCount(2);
    await expect(page.locator('#wallet-logout')).toBeVisible();
    await page.locator('.document-card').first().click();
    await expect(page.locator('#wallet-card-detail')).toBeVisible();
    await page.locator('#wallet-logout').click();
    await expect(page.locator('.document-card')).toHaveCount(0);
    await expect(page.locator('#wallet-card-detail')).toBeHidden();
    await expect(page.locator('#wallet-card-values')).toBeEmpty();
    await expect(page.locator('#wallet-login')).toBeVisible();
    await page.locator('#open-settings').click();
    await page.locator('[data-web-destination="signin"]').click();
    assert.deepEqual(
      await page.evaluate(
        () =>
          window.__nativeUiTest.arguments.filter((c) => c.command === 'open_mikaki_web').at(-1)
            ?.args,
      ),
      { destination: 'signin' },
    );
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});

test('a late native Wallet login cannot restore document details after cancellation', async () => {
  const server = await startNativeUiServer(),
    browser = await chromium.launch();
  const { page, errors } = await createNativeUiPage(browser, server.url, {
    platform: 'mobile',
    identityReader: true,
    identityDocuments: documents,
  });
  try {
    await page.locator('#wallet-login').click();
    await page.locator('#wallet-login-cancel').click();
    await page.evaluate(() => window.__nativeUiTest.complete());
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await expect(page.locator('#wallet-login')).toBeVisible();
    await expect(page.locator('.document-card')).toHaveCount(0);
    assert.equal(
      await page.evaluate(() =>
        window.__nativeUiTest.calls.includes('identity_document_inventory'),
      ),
      false,
    );
    assert.deepEqual(errors, []);
  } finally {
    await page.close();
    await browser.close();
    await server.close();
  }
});
