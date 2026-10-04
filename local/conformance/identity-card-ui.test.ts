import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import { createNativeUiPage, startNativeUiServer } from './support/native-client-ui.ts';

test('identity card preview keeps PIN and attributes temporary', async (t) => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch({ headless: true });
  try {
    await t.test('shows unverified four attributes and clears them on navigation', async () => {
      const { page, errors } = await createNativeUiPage(browser, server.url, {
        identityReader: true,
      });
      try {
        await page.locator('#open-settings').click();
        await page.getByRole('link', { name: '診断' }).click();
        await page.locator('#identity-pin').fill('1234');
        await page.locator('#identity-read').click();
        await page.locator('#identity-preview').waitFor({ state: 'visible' });
        assert.equal(await page.locator('#identity-pin').inputValue(), '');
        assert.equal(await page.locator('#identity-name').textContent(), '試験 太郎');
        assert.match((await page.locator('#identity-preview').textContent()) ?? '', /紐付けはまだ/);
        assert.equal(await page.evaluate(() => localStorage.length), 0);
        assert.equal(await page.evaluate(() => sessionStorage.length), 0);
        await page.locator('#diagnostics [data-back]').click();
        await page.locator('#settings').waitFor({ state: 'visible' });
        assert.equal(await page.locator('#identity-name').textContent(), '');
        assert.deepEqual(errors, []);
      } finally {
        await page.close();
      }
    });

    await t.test('late read after cancellation cannot restore attributes', async () => {
      const { page, errors } = await createNativeUiPage(browser, server.url, {
        identityReader: true,
      });
      try {
        await page.locator('#open-settings').click();
        await page.getByRole('link', { name: '診断' }).click();
        await page.evaluate(() => window.__nativeUiTest.hold('read_identity_card'));
        await page.locator('#identity-pin').fill('1234');
        await page.locator('#identity-read').click();
        await page.locator('#identity-cancel').click();
        assert.ok(
          await page.evaluate(() => window.__nativeUiTest.calls.includes('cancel_identity_card')),
        );
        await page.evaluate(() => window.__nativeUiTest.release('read_identity_card'));
        await page.waitForFunction(
          () => !document.querySelector<HTMLButtonElement>('#identity-read')?.disabled,
        );
        assert.equal(await page.locator('#identity-preview').isVisible(), false);
        assert.equal(await page.locator('#identity-name').textContent(), '');
        assert.equal(await page.locator('#identity-pin').inputValue(), '');
        assert.deepEqual(errors, []);
      } finally {
        await page.close();
      }
    });

    await t.test(
      'credential erasure discards an in-flight card read and its late attributes',
      async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          identityReader: true,
        });
        try {
          await page.locator('#open-settings').click();
          await page.getByRole('link', { name: '診断' }).click();
          await page.locator('#identity-pin').fill('1234');
          await page.locator('#identity-read').click();
          await page.locator('#identity-preview').waitFor({ state: 'visible' });
          await page.locator('#identity-link').click();
          await page.locator('#identity-issuance').waitFor({ state: 'visible' });
          await page.evaluate(() => window.__nativeUiTest.hold('read_identity_card'));
          await page.locator('#identity-pin').fill('1234');
          await page.locator('#identity-read').click();
          await page.locator('#identity-credential-clear').click();
          assert.ok(
            await page.evaluate(() => window.__nativeUiTest.calls.includes('cancel_identity_card')),
          );
          assert.ok(
            await page.evaluate(() =>
              window.__nativeUiTest.calls.includes('clear_identity_credential'),
            ),
          );
          await page.evaluate(() => window.__nativeUiTest.release('read_identity_card'));
          await page.waitForFunction(
            () => !document.querySelector<HTMLButtonElement>('#identity-read')?.disabled,
          );
          assert.equal(await page.locator('#identity-preview').isVisible(), false);
          assert.equal(await page.locator('#identity-name').textContent(), '');
          assert.equal(await page.locator('#identity-pin').inputValue(), '');
          assert.equal(await page.locator('#identity-pin2').inputValue(), '');
          assert.equal(await page.locator('#identity-issuance').isVisible(), false);
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      },
    );
    await t.test('wrong PIN reports remaining attempts without retry', async () => {
      const { page, errors } = await createNativeUiPage(browser, server.url, {
        identityReader: true,
        identityFailure: { code: 'pin_failed', remaining_retries: 2 },
      });
      try {
        await page.locator('#open-settings').click();
        await page.getByRole('link', { name: '診断' }).click();
        await page.locator('#identity-pin').fill('1234');
        await page.locator('#identity-read').click();
        await page.waitForFunction(() =>
          document.querySelector('#identity-status')?.textContent?.includes('残り2回'),
        );
        assert.equal(
          await page.evaluate(
            () => window.__nativeUiTest.calls.filter((c) => c === 'read_identity_card').length,
          ),
          1,
        );
        assert.equal(await page.locator('#identity-pin').inputValue(), '');
        assert.equal(await page.locator('#identity-preview').isVisible(), false);
        assert.deepEqual(errors, []);
      } finally {
        await page.close();
      }
    });

    await t.test(
      'license PIN2 gates linking and OID4VCI receipt stays out of web storage',
      async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          identityReader: true,
        });
        try {
          await page.locator('#open-settings').click();
          await page.getByRole('link', { name: '診断' }).click();
          await page.locator('#identity-type').selectOption('driving_license');
          assert.equal(await page.locator('#identity-pin2-field').isVisible(), true);
          await page.locator('#identity-pin').fill('1234');
          await page.locator('#identity-read').click();
          await page.locator('#identity-preview').waitFor({ state: 'visible' });
          assert.equal(await page.locator('#identity-link').isDisabled(), true);
          await page.locator('#identity-pin').fill('1234');
          await page.locator('#identity-pin2').fill('5678');
          await page.locator('#identity-read').click();
          await page.locator('#identity-preview').waitFor({ state: 'visible' });
          assert.equal(await page.locator('#identity-pin2').inputValue(), '');
          assert.equal(await page.locator('#identity-link').isDisabled(), false);
          await page.locator('#identity-link').click();
          await page.waitForFunction(() =>
            document
              .querySelector('#identity-holder')
              ?.textContent?.includes('synthetic-holder-key'),
          );
          await page.locator('#identity-receive').click();
          await page.waitForFunction(() =>
            document.querySelector('#identity-issuance-status')?.textContent?.includes('SD-JWT'),
          );
          assert.equal(await page.evaluate(() => localStorage.length), 0);
          assert.equal(await page.evaluate(() => sessionStorage.length), 0);
          await page.locator('#identity-credential-clear').click();
          assert.equal(await page.locator('#identity-issuance').isVisible(), false);
          assert.equal(await page.locator('#identity-holder').textContent(), '');
          assert.ok(
            await page.evaluate(() =>
              window.__nativeUiTest.calls.includes('clear_identity_credential'),
            ),
          );
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      },
    );
    await t.test('late credential receipt cannot restore UI after erasure', async () => {
      const { page, errors } = await createNativeUiPage(browser, server.url, {
        identityReader: true,
      });
      try {
        await page.locator('#open-settings').click();
        await page.getByRole('link', { name: '診断' }).click();
        await page.locator('#identity-pin').fill('1234');
        await page.locator('#identity-read').click();
        await page.locator('#identity-preview').waitFor({ state: 'visible' });
        await page.locator('#identity-link').click();
        await page.locator('#identity-receive').waitFor({ state: 'visible' });
        await page.evaluate(() => window.__nativeUiTest.hold('receive_identity_credential'));
        await page.locator('#identity-receive').click();
        await page.locator('#identity-credential-clear').click();
        await page.evaluate(() => window.__nativeUiTest.release('receive_identity_credential'));
        await page.waitForFunction(
          () => !document.querySelector<HTMLButtonElement>('#identity-read')?.disabled,
        );
        assert.equal(await page.locator('#identity-holder').textContent(), '');
        assert.equal(await page.locator('#identity-issuance-status').textContent(), '');
        assert.equal(await page.locator('#identity-issuance').isVisible(), false);
        assert.deepEqual(errors, []);
      } finally {
        await page.close();
      }
    });
    await t.test('cancelled link cannot restore an approval or receipt UI', async () => {
      const { page, errors } = await createNativeUiPage(browser, server.url, {
        identityReader: true,
      });
      try {
        await page.locator('#open-settings').click();
        await page.getByRole('link', { name: '診断' }).click();
        await page.locator('#identity-pin').fill('1234');
        await page.locator('#identity-read').click();
        await page.locator('#identity-preview').waitFor({ state: 'visible' });
        await page.evaluate(() => window.__nativeUiTest.hold('start_identity_link'));
        await page.locator('#identity-link').click();
        await page.locator('#identity-credential-clear').click();
        await page.evaluate(() => window.__nativeUiTest.release('start_identity_link'));
        await page.waitForFunction(
          () => !document.querySelector<HTMLButtonElement>('#identity-read')?.disabled,
        );
        assert.equal(await page.locator('#identity-holder').textContent(), '');
        assert.equal(await page.locator('#identity-issuance').isVisible(), false);
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

test('presentation review requires explicit consent and discards late or hidden attributes', async (t) => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch({ headless: true });
  try {
    for (const action of ['approve', 'deny', 'navigate', 'late', 'mdoc'] as const) {
      await t.test(action, async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          identityReader: true,
          identityFormat: action === 'mdoc' ? 'mso_mdoc' : undefined,
        });
        try {
          await page.locator('#open-settings').click();
          await page.getByRole('link', { name: '診断' }).click();
          if (action === 'mdoc') {
            await page.locator('#identity-pin').fill('1234');
            await page.locator('#identity-read').click();
            await page.locator('#identity-preview').waitFor({ state: 'visible' });
            await page.locator('#identity-credential-format').selectOption('linked_document_mdoc');
            for (const width of [320, 375, 480]) {
              await page.setViewportSize({ width, height: 812 });
              assert.equal(
                await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),
                false,
              );
            }
            await page.locator('#identity-link').click();
            await page.waitForFunction(() =>
              document
                .querySelector('#identity-holder')
                ?.textContent?.includes('synthetic-holder-key'),
            );
            const args = await page.evaluate(
              () =>
                window.__nativeUiTest.arguments.find((c) => c.command === 'start_identity_link')
                  ?.args,
            );
            assert.deepEqual(args, { configuration: 'linked_document_mdoc' });
            await page.locator('#identity-receive').click();
            await page.waitForFunction(() =>
              document
                .querySelector('#identity-issuance-status')
                ?.textContent?.includes('mdoc属性証明書'),
            );
          }
          if (action === 'late')
            await page.evaluate(() => window.__nativeUiTest.hold('review_identity_presentation'));
          await page.locator('#identity-vp-request').fill('synthetic.signed.request');
          await page.locator('#identity-vp-review').click();
          if (action === 'late') {
            await page.locator('#diagnostics [data-back]').click();
            await page.evaluate(() =>
              window.__nativeUiTest.release('review_identity_presentation'),
            );
          } else {
            await page.locator('#identity-vp-consent').waitFor({ state: 'visible' });
            assert.match(await page.locator('#identity-vp-target').innerText(), /verifier.example/);
            assert.match(await page.locator('#identity-vp-values').innerText(), /試験 太郎/);
            assert.doesNotMatch(await page.locator('#identity-vp-values').innerText(), /東京都/);
            if (action === 'mdoc')
              assert.match(await page.locator('#identity-vp-values').innerText(), /保存予定/);
            assert.equal(
              await page.evaluate(() =>
                window.__nativeUiTest.calls.includes('confirm_identity_presentation'),
              ),
              false,
            );
            if (action === 'navigate') await page.locator('#diagnostics [data-back]').click();
            else
              await page
                .locator('#identity-vp-' + (action === 'mdoc' ? 'approve' : action))
                .click();
          }
          await page.waitForFunction(() =>
            window.__nativeUiTest.calls.includes('confirm_identity_presentation'),
          );
          const args = await page.evaluate(() =>
            window.__nativeUiTest.arguments
              .filter((c) => c.command === 'confirm_identity_presentation')
              .map((c) => c.args),
          );
          assert.deepEqual(args, [
            { reviewId: 'fixture-review', approve: action === 'approve' || action === 'mdoc' },
          ]);
          assert.equal(await page.locator('#identity-vp-values').textContent(), '');
          assert.equal(await page.locator('#identity-vp-request').inputValue(), '');
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      });
    }

    for (const action of [
      'approve',
      'cancel',
      'navigate',
      'late-start',
      'late-review',
      'nfc',
      'qr_nfc',
      'nfc_negotiated',
      'nfc_negotiated_data',
      'disconnect',
    ]) {
      await t.test('proximity consent and cancellation: ' + action, async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          identityReader: true,
          identityFormat: 'mso_mdoc',
        });
        try {
          await page.locator('#open-settings').click();
          await page.getByRole('link', { name: '診断' }).click();
          const held =
            action === 'late-start'
              ? 'start_identity_proximity'
              : action === 'late-review'
                ? 'review_identity_proximity'
                : null;
          if (held) await page.evaluate((c) => window.__nativeUiTest.hold(c), held);
          if (
            action === 'nfc' ||
            action === 'qr_nfc' ||
            action === 'nfc_negotiated' ||
            action === 'nfc_negotiated_data'
          )
            await page.locator('#identity-proximity-engagement').selectOption(action);
          await page.locator('#identity-proximity-start').click();
          if (held) {
            await page.waitForFunction((c) => window.__nativeUiTest.calls.includes(c), held);
            await page.locator('#identity-proximity-cancel').click();
            await page.evaluate((c) => window.__nativeUiTest.release(c), held);
            await page.waitForFunction(
              () => !document.querySelector('#identity-wallet-restore')?.hasAttribute('disabled'),
            );
            assert.equal(await page.locator('#identity-proximity-consent').isVisible(), false);
          } else {
            await page.locator('#identity-proximity-consent').waitFor({ state: 'visible' });
            assert.match(
              (await page.locator('#identity-proximity-target').textContent()) ?? '',
              /試験読み手/,
            );
            assert.match(
              (await page.locator('#identity-proximity-values').textContent()) ?? '',
              /保存予定/,
            );
            assert.equal(
              await page.evaluate(() =>
                window.__nativeUiTest.calls.includes('confirm_identity_proximity'),
              ),
              false,
            );
            if (action === 'nfc_negotiated_data') {
              assert.equal(await page.locator('#identity-proximity-qr').textContent(), '');
              assert.match(
                (await page.locator('#identity-proximity-status').textContent()) ?? '',
                /かざしたまま/,
              );
            }
            if (action === 'disconnect') {
              await page.evaluate(() =>
                window.__nativeUiTest.emit('identity-proximity-ended', 'stale-session'),
              );
              assert.equal(await page.locator('#identity-proximity-consent').isVisible(), true);
              await page.evaluate(() =>
                window.__nativeUiTest.emit('identity-proximity-ended', 'fixture-proximity'),
              );
            } else if (action === 'navigate')
              await page.locator('#diagnostics [data-back]').click();
            else
              await page
                .locator(
                  '#identity-proximity-' +
                    (action === 'nfc' ||
                    action === 'qr_nfc' ||
                    action === 'nfc_negotiated' ||
                    action === 'nfc_negotiated_data'
                      ? 'approve'
                      : action),
                )
                .click();
          }
          await page.waitForFunction(() =>
            window.__nativeUiTest.calls.includes('cancel_identity_proximity'),
          );
          const confirmations = await page.evaluate(() =>
            window.__nativeUiTest.arguments
              .filter((c) => c.command === 'confirm_identity_proximity')
              .map((c) => c.args),
          );
          assert.deepEqual(
            confirmations,
            action === 'approve' ||
              action === 'nfc' ||
              action === 'qr_nfc' ||
              action === 'nfc_negotiated' ||
              action === 'nfc_negotiated_data'
              ? [
                  {
                    sessionId: 'fixture-proximity',
                    reviewId: 'fixture-proximity-review',
                    approve: true,
                  },
                ]
              : [],
          );
          assert.equal(await page.locator('#identity-proximity-values').textContent(), '');
          assert.equal(await page.locator('#identity-proximity-qr').textContent(), '');
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      });
    }
  } finally {
    await browser.close();
    await server.close();
  }
});

test('native same-device invocations use consent and discard requests after leaving the screen', async (t) => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch({ headless: true });
  try {
    for (const approve of [false, true])
      await t.test(
        `mixed credential consent is grouped and ${approve ? 'approved' : 'denied'} once`,
        async () => {
          const { page, errors } = await createNativeUiPage(browser, server.url, {
            identityReader: true,
            identityInvocation: true,
            identityBatch: true,
          });
          try {
            await page.locator('#identity-vp-consent').waitFor({ state: 'visible' });
            const text = await page.locator('#identity-vp-values').innerText();
            assert.match(text, /証明書 1（SD-JWT）/);
            assert.match(text, /証明書 2（mdoc）/);
            assert.match(text, /試験 太郎/);
            assert.match(text, /生年月日（提示先が保存予定）/);
            assert.doesNotMatch(text, /氏名（提示先が保存予定）/);
            assert.doesNotMatch(text, /東京都/);
            assert.equal(
              await page.evaluate(() =>
                window.__nativeUiTest.calls.includes('confirm_identity_presentation'),
              ),
              false,
            );
            await page.locator(approve ? '#identity-vp-approve' : '#identity-vp-deny').click();
            await page.waitForFunction(() =>
              window.__nativeUiTest.calls.includes('confirm_identity_presentation'),
            );
            assert.equal(
              await page.evaluate(
                () =>
                  window.__nativeUiTest.calls.filter((c) => c === 'confirm_identity_presentation')
                    .length,
              ),
              1,
            );
            assert.equal(
              await page.evaluate(
                () =>
                  window.__nativeUiTest.arguments.find(
                    (c) => c.command === 'confirm_identity_presentation',
                  )?.args?.approve,
              ),
              approve,
            );
            assert.equal(await page.locator('#identity-vp-values').textContent(), '');
            assert.deepEqual(errors, []);
          } finally {
            await page.close();
          }
        },
      );
    await t.test(
      'type-only request still requires explicit consent to send proof information',
      async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          identityReader: true,
          identityInvocation: true,
          identityNoClaims: true,
        });
        try {
          await page.locator('#identity-vp-consent').waitFor({ state: 'visible' });
          assert.equal(await page.locator('#identity-vp-values').textContent(), '');
          assert.match(
            (await page.locator('#identity-vp-status').textContent()) ?? '',
            /選択開示する属性はありません/,
          );
          assert.match((await page.locator('#identity-vp-status').textContent()) ?? '', /所持証明/);
          assert.equal(
            await page.evaluate(() =>
              window.__nativeUiTest.calls.includes('confirm_identity_presentation'),
            ),
            false,
          );
          await page.locator('#identity-vp-deny').click();
          await page.waitForFunction(() =>
            window.__nativeUiTest.calls.includes('confirm_identity_presentation'),
          );
          assert.equal(
            await page.evaluate(
              () =>
                window.__nativeUiTest.arguments.find(
                  (a) => a.command === 'confirm_identity_presentation',
                )?.args?.approve,
            ),
            false,
          );
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      },
    );
    for (const mode of ['cold-start', 'event', 'late'] as const) {
      await t.test(mode, async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          identityReader: true,
          identityInvocation: mode === 'cold-start',
          identityFormat: 'mso_mdoc',
        });
        try {
          if (mode !== 'cold-start') {
            if (mode === 'late')
              await page.evaluate(() => window.__nativeUiTest.hold('review_identity_invocation'));
            await page.evaluate(() =>
              window.__nativeUiTest.emit('identity-presentation-ready', 'fixture-invocation'),
            );
          }
          await page.waitForFunction(() =>
            window.__nativeUiTest.calls.includes('review_identity_invocation'),
          );
          if (mode === 'late') {
            await page.locator('#diagnostics [data-back]').click();
            await page.evaluate(() => window.__nativeUiTest.release('review_identity_invocation'));
            await page.waitForFunction(() =>
              window.__nativeUiTest.calls.includes('confirm_identity_presentation'),
            );
            assert.equal(await page.locator('#identity-vp-consent').isVisible(), false);
            assert.equal(await page.locator('#identity-vp-values').innerText(), '');
            assert.equal(
              await page.evaluate(() =>
                window.__nativeUiTest.calls.includes('cancel_identity_presentation'),
              ),
              true,
            );
          } else {
            await page.locator('#identity-vp-consent').waitFor({ state: 'visible' });
            assert.match(await page.locator('#identity-vp-values').innerText(), /試験 太郎/);
            assert.equal(
              await page.evaluate(() =>
                window.__nativeUiTest.calls.includes('confirm_identity_presentation'),
              ),
              false,
            );
            await page.locator('#identity-vp-approve').click();
            await page.waitForFunction(() =>
              window.__nativeUiTest.calls.includes('confirm_identity_presentation'),
            );
          }
          assert.deepEqual(
            await page.evaluate(
              () =>
                window.__nativeUiTest.arguments.find(
                  (c) => c.command === 'review_identity_invocation',
                )?.args,
            ),
            { invocationId: 'fixture-invocation' },
          );
          assert.equal(await page.locator('#identity-vp-request').inputValue(), '');
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      });
    }
  } finally {
    await browser.close();
    await server.close();
  }
});

test('verifier browser completion reports sent credentials without triggering another submission', async (t) => {
  const server = await startNativeUiServer();
  const browser = await chromium.launch({ headless: true });
  try {
    for (const completion of [
      'opened',
      'rejected',
      'invalid_response',
      'browser_unavailable',
      'late',
    ] as const) {
      await t.test(completion, async () => {
        const { page, errors } = await createNativeUiPage(browser, server.url, {
          identityReader: true,
          identityInvocation: true,
          identityCompletion: completion === 'late' ? 'cancelled' : completion,
        });
        try {
          await page.locator('#identity-vp-consent').waitFor({ state: 'visible' });
          if (completion === 'late')
            await page.evaluate(() => window.__nativeUiTest.hold('confirm_identity_presentation'));
          await page.locator('#identity-vp-approve').click();
          await page.waitForFunction(() =>
            window.__nativeUiTest.calls.includes('confirm_identity_presentation'),
          );
          if (completion === 'late') {
            await page.locator('#diagnostics [data-back]').click();
            await page.evaluate(() =>
              window.__nativeUiTest.release('confirm_identity_presentation'),
            );
            await page.waitForFunction(() =>
              window.__nativeUiTest.calls.includes('cancel_identity_presentation'),
            );
            assert.equal(await page.locator('#identity-vp-status').innerText(), '');
          } else {
            await page.waitForFunction(
              () =>
                !!document.querySelector('#identity-vp-status')?.textContent?.includes('提示先'),
            );
            const message = await page.locator('#identity-vp-status').innerText();
            assert.match(message, completion === 'opened' ? /画面を開きました/ : /送信済み/);
            if (completion === 'invalid_response') assert.match(message, /再送せず/);
          }
          assert.equal(await page.locator('#identity-vp-values').innerText(), '');
          assert.equal(
            await page.evaluate(
              () =>
                window.__nativeUiTest.arguments.filter(
                  (c) => c.command === 'confirm_identity_presentation',
                ).length,
            ),
            1,
          );
          assert.deepEqual(errors, []);
        } finally {
          await page.close();
        }
      });
    }
  } finally {
    await browser.close();
    await server.close();
  }
});
