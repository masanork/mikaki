import { qualificationTimeout } from './test-timeout.ts';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, firefox, webkit, expect, type Browser } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { Client } from './vault-browser-support.ts';
import { fixture } from './server-support.ts';
import { setup, prepare, approve, complete, click } from './replacement-browser-support.ts';
import { replacementCode, parseReplacementCode } from './replacement-types.ts';
import type { InvitationOffer } from './delivery-types.ts';
async function ready(f: Awaited<ReturnType<typeof fixture>>, browser: Browser) {
  const p = await setup(f, browser);
  const receipt = await p.a.page.evaluate(
    ({ previous, id }) =>
      custodyDevice.sendText(id, previous.channel, '中止しても再送しない旧本文'),
    { previous: p.previous, id: randomUUID() },
  );
  assert.equal(receipt.ok, true, receipt.error ?? 'send failed');
  await p.c.init();
  await p.c.manager();
  await p.c.page.evaluate((old) => custodyDevice.createReplacement(old), p.predecessor);
  const proposal = await prepare(p.a, p.c);
  return { ...p, ...proposal };
}
async function importCode(c: Client, previous: InvitationOffer, next: InvitationOffer) {
  await c.page
    .getByRole('textbox', { name: '受け取った鍵切り替えコード', exact: true })
    .fill(replacementCode(previous, next));
  await click(c, '鍵切り替えコードを確認');
}
async function stop(c: Client) {
  await c.page
    .getByRole('checkbox', {
      name: 'この切り替え案を中止し、旧会話を停止したままにします',
      exact: true,
    })
    .check();
  await click(c, 'この切り替え案を中止');
}
async function latest(c: Client) {
  return (await c.page.evaluate(() => custodyDevice.chatSnapshot())).replacements.at(-1)!;
}
async function fresh(c: Client) {
  await click(c, '鍵切り替えコードを作る');
  const code = await c.page
    .getByRole('textbox', { name: '共有する鍵切り替えコード', exact: true })
    .inputValue();
  return parseReplacementCode(code);
}
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: explicit replacement proposal cancellation and conflict recovery`,
    { timeout: qualificationTimeout(180_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        await t.test(
          'competing approved proposals require an explicit veto and fresh peer-code consent, retain quarantined history and complete a real reversed-role group',
          async () => {
            const { a, b, c, previous, next } = await ready(f, browser);
            try {
              const y: InvitationOffer = {
                channel: {
                  ...next.channel,
                  id: randomUUID(),
                  group: randomBytes(16).toString('base64url'),
                },
                inviter_scope: (await c.page.evaluate(() => custodyDevice.chatSnapshot())).own
                  .scope,
              };
              await importCode(c, previous, y);
              await approve(a);
              await approve(c);
              await expect(
                a.page.getByRole('textbox', { name: 'メッセージ', exact: true }),
              ).toBeDisabled();
              await expect(
                c.page.getByRole('textbox', { name: 'メッセージ', exact: true }),
              ).toBeDisabled();
              await assert.rejects(
                () =>
                  a.page.evaluate(
                    ({ previous, next }) => custodyDevice.approveReplacement(previous, next),
                    { previous, next: y },
                  ),
                /replacement_intent_conflict/,
              );
              assert.equal(
                (await f.env.DB.prepare(
                  'SELECT count(*) AS n FROM messaging_invitation_packet WHERE channel_id IN(?,?)',
                )
                  .bind(next.channel.id, y.channel.id)
                  .first<{ n: number }>())!.n,
                0,
              );
              await expect(
                a.page.getByRole('button', { name: 'この切り替え案を中止', exact: true }),
              ).toBeDisabled();
              await a.page.setViewportSize({ width: 390, height: 844 });
              assert.equal(
                await a.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
                true,
              );
              assert.deepEqual((await new AxeBuilder({ page: a.page }).analyze()).violations, []);
              if (name === 'chromium') {
                await mkdir('local/generated/mls', { recursive: true });
                await a.page.screenshot({
                  path: 'local/generated/mls/replacement-cancellation-chromium.png',
                  fullPage: true,
                });
              }
              await stop(a);
              assert.equal((await latest(a)).phase, 'cancelled');
              assert.equal((await latest(a)).abandoned.length, 1);
              const abandoned = (await latest(a)).abandoned[0].id;
              await a.restart();
              await a.open();
              await a.chat();
              await expect(
                a.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).toContainText('停止した会話で保留・自動転送なし');
              await importCode(a, previous, y);
              await approve(a);
              await complete(a, c);
              const entries = (await a.page.evaluate(() => custodyDevice.chatSnapshot()))
                .replacements;
              assert.equal(entries.length, 2);
              assert.deepEqual(
                entries.map((r) => r.phase),
                ['cancelled', 'active'],
              );
              assert.equal(entries[0].abandoned[0].id, abandoned);
              await a.page
                .getByRole('textbox', { name: 'メッセージ', exact: true })
                .fill('競合を解消した新しい会話');
              await click(a, '送信');
              await click(c, '同期');
              await expect(
                c.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).toContainText('競合を解消した新しい会話');
              await expect(
                c.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).not.toContainText('中止しても再送しない旧本文');
              await assert.rejects(
                () =>
                  a.page.evaluate(
                    ({ previous, next }) => custodyDevice.approveReplacement(previous, next),
                    { previous, next },
                  ),
                /replacement_cancelled/,
              );
              assert.equal(
                (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
                  .bind(previous.channel.id)
                  .first<{ blocked: number }>())!.blocked,
                1,
              );
              assert.equal(
                await f.env.DB.prepare('SELECT message_id FROM messaging_mail WHERE message_id=?')
                  .bind(abandoned)
                  .first(),
                null,
              );
            } finally {
              await a.close();
              await b.close();
              await c.close();
            }
          },
        );
        await t.test(
          'unpublished veto, aborted begin/finish, lost cancellation reply, reload, peer observation and lock retain exact cancellation identity without late publication',
          async () => {
            const { a, b, c, previous, next } = await ready(f, browser);
            try {
              a.dropRequest = {
                path: `/messaging/channels/${next.channel.id}/replace`,
                method: 'POST',
              };
              await approve(a);
              assert.equal((await latest(a)).phase, 'prepared');
              await a.abortCommand('begin_cancel_replacement');
              await stop(a);
              assert.equal((await latest(a)).phase, 'prepared');
              assert.equal(a.requests.filter((r) => r.path.endsWith('/replace/cancel')).length, 0);
              await a.abortCommand('finish_cancel_replacement');
              await stop(a);
              const first = await latest(a);
              assert.equal(first.phase, 'cancelling');
              await a.restart();
              await a.open();
              await a.chat();
              assert.equal((await latest(a)).phase, 'cancelled');
              assert.equal(
                (await latest(a)).cancellation!.operation_id,
                first.cancellation!.operation_id,
              );
              const proposal = await fresh(a);
              await approve(a);
              a.loss = {
                path: `/messaging/channels/${proposal.next.channel.id}/replace/cancel`,
                method: 'POST',
              };
              await stop(a);
              const lost = await latest(a);
              assert.equal(lost.phase, 'cancelling');
              await expect(
                a.page.getByRole('textbox', { name: 'メッセージ', exact: true }),
              ).toBeDisabled();
              await a.restart();
              await a.open();
              await a.chat();
              assert.equal((await latest(a)).phase, 'cancelled');
              assert.equal(
                (await latest(a)).cancellation!.operation_id,
                lost.cancellation!.operation_id,
              );
              await approve(c);
              assert.equal((await latest(c)).phase, 'cancelled');
              await expect(
                c.page.getByRole('heading', { name: '切り替え案は中止済みです', exact: true }),
              ).toBeVisible();
              const third = await fresh(a);
              await approve(a);
              let release!: () => void;
              const reached = new Promise<void>((resolve) => {
                a.pauseHead = {
                  reached: resolve,
                  release: new Promise<void>((r) => {
                    release = r;
                  }),
                };
              });
              await a.page
                .getByRole('checkbox', {
                  name: 'この切り替え案を中止し、旧会話を停止したままにします',
                  exact: true,
                })
                .check();
              const pending = click(a, 'この切り替え案を中止').catch(() => {});
              await reached;
              await a.page.evaluate(() => custodyOwner.lock());
              release();
              await pending;
              assert.equal(
                a.requests.filter(
                  (r) => r.path === `/messaging/channels/${third.next.channel.id}/replace/cancel`,
                ).length,
                0,
              );
              await expect(
                a.page.getByText('チャットをロックしました。Vaultを開き直してください。', {
                  exact: true,
                }),
              ).toBeVisible();
              assert.equal(await a.page.locator('textarea').count(), 0);
              await a.restart();
              await a.open();
              await a.chat();
              assert.equal((await latest(a)).phase, 'cancelled');
              assert.equal(
                (await f.env.DB.prepare(
                  'SELECT count(*) AS n FROM messaging_replacement_cancellation WHERE owner_id=?',
                )
                  .bind(a.who.owner)
                  .first<{ n: number }>())!.n,
                3,
              );
              for (const offer of [next, proposal.next, third.next])
                assert.equal(
                  await f.env.DB.prepare(
                    'SELECT message_id FROM messaging_invitation_packet WHERE channel_id=?',
                  )
                    .bind(offer.channel.id)
                    .first(),
                  null,
                );
            } finally {
              await a.close();
              await b.close();
              await c.close();
            }
          },
        );
        await t.test(
          'a bilateral admitted proposal cannot report cancellation; the UI completes joining before explicit conversation termination',
          async () => {
            const { a, b, c, previous, next } = await ready(f, browser);
            try {
              await approve(a);
              await approve(c);
              assert.equal((await latest(a)).phase, 'consented');
              await stop(a);
              assert.equal((await latest(a)).phase, 'consented');
              assert.equal((await latest(a)).cancellation!.outcome, 'admitted');
              await expect(
                a.page.getByText(
                  '双方の承認後でも、参加が完了しない場合はこの招待を停止してやり直せます。旧会話は再開しません。再参加には新しいコードへの双方の承認が必要です。',
                  { exact: true },
                ),
              ).toBeVisible();
              assert.equal(
                (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
                  .bind(next.channel.id)
                  .first<{ blocked: number }>())!.blocked,
                0,
              );
              await complete(a, c);
              await click(a, '会話を停止する');
              await click(a, '停止を確定');
              await expect(
                a.page.getByRole('textbox', { name: 'メッセージ', exact: true }),
              ).toBeDisabled();
              assert.equal(
                (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
                  .bind(next.channel.id)
                  .first<{ blocked: number }>())!.blocked,
                1,
              );
              assert.equal(
                (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
                  .bind(previous.channel.id)
                  .first<{ blocked: number }>())!.blocked,
                1,
              );
            } finally {
              await a.close();
              await b.close();
              await c.close();
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
