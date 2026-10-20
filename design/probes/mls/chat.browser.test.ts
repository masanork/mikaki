import { qualificationTimeout } from './test-timeout.ts';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, firefox, webkit, expect } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { invitationCode } from './chat-view.ts';
import type { InvitationOffer } from './delivery-types.ts';
import { Client, trust, descriptor, admit, successor } from './vault-browser-support.ts';
import { fixture } from './server-support.ts';

async function idle(c: Client) {
  await expect(c.page.getByRole('region', { name: '暗号化チャット', exact: true })).toHaveAttribute(
    'aria-busy',
    'false',
  );
}
async function click(c: Client, name: string) {
  await c.page.getByRole('button', { name, exact: true }).click();
  await idle(c);
}
async function approve(c: Client, rejoin = false) {
  const approve = c.page.getByRole('button', {
    name: rejoin ? 'このコードで再参加を承認' : 'この招待を承認',
    exact: true,
  });
  await expect(approve).toBeDisabled();
  await c.page.getByRole('checkbox').check();
  await approve.click();
  await idle(c);
}
async function send(c: Client, text: string) {
  await c.page.getByRole('textbox', { name: 'メッセージ', exact: true }).fill(text);
  await click(c, '送信');
}
async function stop(c: Client, active = true) {
  await click(c, active ? '会話を停止する' : '招待を中止する');
  await expect(c.page.getByRole('heading', { name: 'この会話を停止しますか' })).toBeVisible();
  await click(c, '停止を確定');
}
async function importOffer(c: Client, code: string) {
  await c.page.getByRole('textbox', { name: '受け取った招待コード' }).fill(code);
  await click(c, 'コードを確認');
}
async function pair(
  f: Awaited<ReturnType<typeof fixture>>,
  browser: Awaited<ReturnType<typeof chromium.launch>>,
) {
  const a = new Client(f, browser, await f.seed()),
    b = new Client(f, browser, await f.seed());
  await a.init();
  await b.init();
  await a.create();
  await b.create();
  return { a, b };
}

for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: foreground chat UI with real Vault, MLS and mailbox`,
    { timeout: qualificationTimeout(180_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        await t.test(
          'explicit invitation approval, bounded text, exact retries, safe rendering and durable bidirectional history',
          async () => {
            const { a, b } = await pair(f, browser);
            try {
              await trust(a, b);
              const channel = await descriptor(a, b);
              const scope = (await a.page.evaluate(() => custodyDevice.chatSnapshot())).own.scope;
              const offer: InvitationOffer = { channel, inviter_scope: scope };
              await a.chat(offer);
              await b.chat();
              await expect(
                a.page.getByRole('button', { name: '送信', exact: true }),
              ).toBeDisabled();
              assert.equal(
                a.requests.filter((r) => r.path.endsWith('/invitation') && r.method === 'POST')
                  .length,
                0,
              );
              await importOffer(b, invitationCode(offer));
              a.loss = { path: `/messaging/channels/${channel.id}/invitation`, method: 'POST' };
              await approve(a);
              await approve(b);
              await click(a, '同期');
              await click(b, '同期');
              await click(a, '同期');
              await expect(a.page.getByRole('button', { name: '送信', exact: true })).toBeEnabled();
              await send(a, 'あ'.repeat(1366));
              await expect(a.page.getByRole('alert')).toContainText('4,096バイト');
              assert.equal(a.requests.filter((r) => r.path.endsWith('/messages')).length, 0);

              // Lose the actual witness PUT response after it committed. The UI
              // must retry its original operation, even though its refresh can now
              // see the reconciled encrypted text and outbox.
              a.loss = { path: `/messaging/heads/${scope}`, method: 'PUT' };
              const text = 'こんにちは\n<img src=x onerror="window.chatInjected=true">';
              await send(a, text);
              await expect(a.page.getByRole('button', { name: '同じ送信を再試行' })).toBeEnabled();
              await expect(
                a.page.getByRole('textbox', { name: 'メッセージ', exact: true }),
              ).toBeDisabled();
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).sent.length,
                1,
              );
              await click(a, '同じ送信を再試行');
              await click(b, '同期');
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).sent.length,
                1,
              );
              await expect(b.page.getByRole('region', { name: 'メッセージ履歴' })).toContainText(
                text,
              );
              assert.equal(await b.page.locator('img').count(), 0);
              assert.equal(
                await b.page.evaluate(() => Object.hasOwn(window, 'chatInjected')),
                false,
              );
              assert.equal(
                a.requests.filter((r) => r.path.endsWith('/messages') && r.method === 'POST')
                  .length,
                1,
              );
              assert.ok(
                a.requests
                  .filter((r) => r.path.endsWith('/messages'))
                  .every((r) => !r.body!.includes('こんにちは')),
              );

              a.loss = { path: `/messaging/channels/${channel.id}/messages`, method: 'POST' };
              await send(a, '配送結果を再確認するメッセージ');
              await expect(a.page.getByRole('region', { name: 'メッセージ履歴' })).toContainText(
                '送信待ち',
              );
              await click(a, '同期');
              const posts = a.requests.filter(
                (r) => r.path.endsWith('/messages') && r.method === 'POST',
              );
              assert.equal(posts.length, 3);
              assert.equal(posts[1].body, posts[2].body);
              await click(b, '同期');
              await send(b, '返信も暗号化して届けます');
              await click(a, '同期');
              await a.restart();
              await a.open();
              await a.chat();
              await expect(a.page.getByRole('region', { name: 'メッセージ履歴' })).toContainText(
                text,
              );
              await expect(a.page.getByRole('region', { name: 'メッセージ履歴' })).toContainText(
                '返信も暗号化して届けます',
              );
              await expect(a.page.getByRole('region', { name: 'メッセージ履歴' })).toContainText(
                'サーバー受理済み（既読ではありません）',
              );
              assert.equal(
                (await b.page.evaluate(() => custodyDevice.chatSnapshot())).received.length,
                2,
              );

              const violations = (await new AxeBuilder({ page: a.page }).analyze()).violations;
              assert.deepEqual(
                violations.map((v) => v.id),
                [],
              );
              if (name === 'chromium') {
                const out = new URL('../../../local/generated/mls-chat/', import.meta.url);
                await mkdir(out, { recursive: true });
                await a.page.setViewportSize({ width: 1000, height: 900 });
                await a.page.screenshot({
                  path: new URL('conversation-desktop.png', out).pathname,
                  fullPage: true,
                });
                await a.page.setViewportSize({ width: 390, height: 844 });
                assert.equal(
                  await a.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
                  true,
                );
                await a.page.screenshot({
                  path: new URL('conversation-mobile.png', out).pathname,
                  fullPage: true,
                });
              }
            } finally {
              await a.close();
              await b.close();
            }
          },
        );

        await t.test(
          'actual simultaneous update forks, lost close receipt, explicit code review and fresh-group rejoin preserve history and isolate old pending text',
          async () => {
            const { a, b } = await pair(f, browser);
            try {
              const offer = await admit(a, b);
              await a.chat();
              await b.chat();
              await send(b, '復旧前から残す受信履歴');
              await click(a, '同期');
              await a.run({ kind: 'update' });
              await b.run({ kind: 'update' });
              await click(a, '同期');
              await click(b, '同期');
              await click(a, '同期');
              const rejected = await a.page.evaluate(async (channel) => {
                try {
                  await custodyDevice.syncDelivery(channel);
                  return 'unexpected_success';
                } catch (error) {
                  return error instanceof Error ? error.message : String(error);
                }
              }, offer.channel);
              assert.equal(rejected, 'message_rejected');
              await expect(a.page.getByRole('alert')).toContainText('メッセージを検証できず');
              await expect(b.page.getByRole('alert')).toContainText('メッセージを検証できず');
              await expect(
                a.page.getByRole('button', { name: '送信', exact: true }),
              ).toBeDisabled();
              await a.restart();
              await a.open();
              await a.chat();
              await expect(
                a.page.getByRole('button', { name: '送信', exact: true }),
              ).toBeDisabled();
              const queued = await a.page.evaluate(
                ({ channel, id }) => custodyDevice.sendText(id, channel, '停止前の送信待ち本文'),
                { channel: offer.channel, id: randomUUID() },
              );
              assert.equal(queued.ok, true);
              a.loss = { path: `/messaging/channels/${offer.channel.id}/close`, method: 'POST' };
              await stop(a);
              await expect(
                a.page.getByRole('heading', { name: '会話は停止しています', exact: true }),
              ).toBeVisible();
              await expect(
                a.page.getByRole('button', { name: '送信', exact: true }),
              ).toBeDisabled();
              await a.restart();
              await a.open();
              await a.chat();
              await click(a, '停止の確認を再試行');
              await stop(b);
              await click(a, '再参加コードを作る');
              const code = await a.page
                .getByRole('textbox', { name: '共有する招待コード' })
                .inputValue();
              await approve(a, true);
              const count = a.requests.filter((r) => r.path.endsWith('/rejoin')).length;
              await importOffer(a, invitationCode(successor(offer)));
              await expect(a.page.getByRole('alert')).toContainText(
                '承認済みの再参加コードと異なります',
              );
              assert.equal(a.requests.filter((r) => r.path.endsWith('/rejoin')).length, count);
              assert.equal(
                await a.page.getByRole('textbox', { name: '共有する招待コード' }).inputValue(),
                code,
              );
              await importOffer(b, code);
              await approve(b, true);
              await click(a, '同期');
              await click(b, '同期');
              await click(a, '同期');
              await expect(a.page.getByRole('button', { name: '送信', exact: true })).toBeEnabled();
              const history = a.page.getByRole('region', { name: 'メッセージ履歴' });
              await expect(history).toContainText('復旧前から残す受信履歴');
              await expect(history).toContainText('停止した会話で保留・自動転送なし');
              await expect(history).toContainText('以前の会話');
              await send(a, '新しい会話から送信');
              await click(b, '同期');
              await expect(b.page.getByRole('region', { name: 'メッセージ履歴' })).toContainText(
                '新しい会話から送信',
              );
              await expect(
                b.page.getByRole('region', { name: 'メッセージ履歴' }),
              ).not.toContainText('停止前の送信待ち本文');
              const current = (await a.page.evaluate(() => custodyDevice.chatSnapshot()))
                .invitation!.offer;
              assert.notEqual(current.channel.id, offer.channel.id);
              assert.equal(
                a.requests.filter(
                  (r) =>
                    r.path === `/messaging/channels/${current.channel.id}/messages` &&
                    r.method === 'POST',
                ).length,
                1,
              );
            } finally {
              await a.close();
              await b.close();
            }
          },
        );

        await t.test(
          'failed send persistence can retry once; Vault invalidation during a witnessed send clears all text and prevents late repaint',
          async () => {
            const { a, b } = await pair(f, browser);
            let release: (() => void) | undefined;
            try {
              await admit(a, b);
              await a.chat();
              await b.chat();
              await a.abortCommand('send_chat');
              await send(a, '保存失敗から同じ送信を再試行');
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).sent.length,
                0,
              );
              assert.equal(a.requests.filter((r) => r.path.endsWith('/messages')).length, 0);
              await click(a, '同じ送信を再試行');
              await click(b, '同期');
              assert.equal(
                (await b.page.evaluate(() => custodyDevice.chatSnapshot())).received.length,
                1,
              );
              await a.page.evaluate(() => {
                const original = custodyDevice.sendText.bind(custodyDevice);
                Object.assign(globalThis, { chatSendFinished: false });
                custodyDevice.sendText = async (...args) => {
                  try {
                    return await original(...args);
                  } finally {
                    Object.assign(globalThis, { chatSendFinished: true });
                  }
                };
              });
              const held = new Promise<void>((resolve) => {
                a.pauseHead = {
                  reached: resolve,
                  release: new Promise<void>((r) => {
                    release = r;
                  }),
                };
              });
              await a.page
                .getByRole('textbox', { name: 'メッセージ', exact: true })
                .fill('ロック時に消す下書き');
              await a.page.getByRole('button', { name: '送信', exact: true }).click();
              await held;
              await a.page.evaluate(() => custodyOwner.lock());
              await expect(
                a.page.getByText('チャットをロックしました。Vaultを開き直してください。', {
                  exact: true,
                }),
              ).toBeVisible();
              assert.equal(await a.page.getByRole('textbox').count(), 0);
              await expect(a.page.locator('body')).not.toContainText('保存失敗から');
              await expect(a.page.locator('body')).not.toContainText('ロック時に消す');
              release!();
              await expect
                .poll(() => a.page.evaluate(() => Reflect.get(globalThis, 'chatSendFinished')))
                .toBe(true);
              await expect
                .poll(async () =>
                  a.page.evaluate(() => document.querySelector('.mls-chat') === null),
                )
                .toBe(true);
              assert.equal(
                a.requests.filter((r) => r.path.endsWith('/messages') && r.method === 'POST')
                  .length,
                1,
              );
            } finally {
              release?.();
              await a.close();
              await b.close();
            }
          },
        );

        await t.test(
          'cancel before admission and reject a code for another device without recording consent',
          async () => {
            const { a, b } = await pair(f, browser);
            try {
              await trust(a, b);
              const channel = await descriptor(a, b);
              const own = (await a.page.evaluate(() => custodyDevice.chatSnapshot())).own.scope;
              const offer: InvitationOffer = { channel, inviter_scope: own };
              await a.chat();
              const wrong = structuredClone(offer);
              (wrong.channel.a.scope === own ? wrong.channel.a : wrong.channel.b).fingerprint =
                'A'.repeat(43);
              await importOffer(a, invitationCode(wrong));
              await expect(a.page.getByRole('alert')).toContainText(
                'この端末に宛てた招待ではありません',
              );
              assert.equal(a.requests.filter((r) => r.path.endsWith('/invitation')).length, 0);
              await importOffer(a, invitationCode(offer));
              a.dropRequest = {
                path: `/messaging/channels/${channel.id}/invitation`,
                method: 'POST',
              };
              await approve(a);
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT channel_id FROM messaging_channel WHERE channel_id=?',
                )
                  .bind(channel.id)
                  .first(),
                null,
              );
              await stop(a, false);
              await expect(
                a.page.getByRole('heading', { name: '会話は停止しています', exact: true }),
              ).toBeVisible();
              const saved = await a.page.evaluate(() => custodyDevice.chatSnapshot());
              assert.equal(saved.recoveries.at(-1)!.reason, 'cancel_invitation');
              assert.equal(saved.recoveries.at(-1)!.phase, 'closed');
              assert.equal(
                a.requests.filter((r) => r.path.endsWith('/invitation/packets')).length,
                0,
              );
            } finally {
              await a.close();
              await b.close();
            }
          },
        );
      } finally {
        await browser.close();
        await f.close();
      }
    },
  );
}
