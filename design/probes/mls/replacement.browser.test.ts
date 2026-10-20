import { qualificationTimeout } from './test-timeout.ts';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, firefox, webkit, expect } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { stored, successor } from './vault-browser-support.ts';
import { fixture } from './server-support.ts';
import type { InvitationOffer } from './delivery-types.ts';

import { setup, prepare, approve, complete, click } from './replacement-browser-support.ts';
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: real replacement enrollment and bilateral changed-key admission`,
    { timeout: qualificationTimeout(180_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        await t.test(
          'new custody, independent fingerprint review, explicit bilateral consent and fresh group retain old history only on the unchanged device',
          async () => {
            const { a, b, c, previous, predecessor } = await setup(f, browser);
            try {
              const received = '変更前に受信した履歴',
                queued = '旧会話で保留した本文';
              await b.page.evaluate(
                async ({ previous, id, text }) => {
                  await custodyDevice.sendText(id, previous.channel, text);
                  await custodyDevice.syncDelivery(previous.channel);
                },
                { previous, id: randomUUID(), text: received },
              );
              await a.sync(previous.channel);
              await a.page.evaluate(
                ({ previous, id, text }) => custodyDevice.sendText(id, previous.channel, text),
                { previous, id: randomUUID(), text: queued },
              );
              const oldWire = (await a.box()).ready.map((v) => v.id);
              assert.equal(oldWire.length, 1);
              await a.stop(previous, 'leave');
              await b.stop(previous, 'leave');
              await c.init();
              await c.manager();
              await c.page.evaluate((old) => custodyDevice.createReplacement(old), predecessor);
              assert.equal(
                ((await stored(c.page)) as { scope: { device: { generation: number } } }).scope
                  .device.generation,
                2,
              );
              const { next } = await prepare(a, c);
              await expect(
                a.page.getByRole('button', { name: '新しい鍵での会話を承認', exact: true }),
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
                  path: 'local/generated/mls/device-replacement-chromium.png',
                  fullPage: true,
                });
              }
              await approve(a);
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).replacements.at(-1)!
                  .phase,
                'consented',
              );
              await expect(
                a.page.getByRole('textbox', { name: 'メッセージ', exact: true }),
              ).toBeDisabled();
              await approve(c);
              await complete(a, c);
              const snap = await a.page.evaluate(() => custodyDevice.chatSnapshot());
              assert.deepEqual(
                snap.replacements.at(-1)!.abandoned.map((v) => v.id),
                oldWire,
              );
              await expect(
                a.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).toContainText(received);
              await expect(
                a.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).toContainText('停止した会話で保留・自動転送なし');
              await expect(
                c.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).not.toContainText(received);
              assert.equal(
                await f.env.DB.prepare(
                  "SELECT message_id FROM messaging_mail WHERE channel_id=? AND kind='application'",
                )
                  .bind(next.channel.id)
                  .first(),
                null,
              );
              await a.page
                .getByRole('textbox', { name: 'メッセージ', exact: true })
                .fill('新しい鍵での会話');
              await click(a, '送信');
              await click(c, '同期');
              await expect(
                c.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).toContainText('新しい鍵での会話');
              await assert.rejects(() => b.sync(previous.channel));
              await a.restart();
              await a.open();
              await a.chat();
              await expect(
                a.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).toContainText(received);
              await expect(
                a.page.getByRole('textbox', { name: 'メッセージ', exact: true }),
              ).toBeEnabled();
              // A's old close tombstone is shadowed by the admitted replacement,
              // and must stay valid when a later close/rejoin adds another entry.
              await a.stop(next, 'leave');
              await c.stop(next, 'leave');
              await a.restart();
              await a.open();
              const again = successor(next);
              assert.equal(await a.approveRejoin(next, again), false);
              assert.equal(await c.approveRejoin(next, again), true);
              await c.syncRejoin(next, again);
              await a.syncRejoin(next, again);
              assert.equal((await c.syncRejoin(next, again)).phase, 'active');
              assert.equal((await a.syncRejoin(next, again)).phase, 'active');
              await a.chat();
              await a.page
                .getByRole('textbox', { name: 'メッセージ', exact: true })
                .fill('切り替え後の再参加');
              await click(a, '送信');
              assert.equal((await c.sync(again.channel)).received, 1);
              const scan = await new AxeBuilder({ page: a.page }).analyze();
              assert.deepEqual(scan.violations, []);
            } finally {
              await a.close();
              await b.close();
              await c.close();
            }
          },
        );
        await t.test(
          'saved predecessor resumes after enrollment interruption; lost approval, aborted activation and reload reuse exact consent without releasing old ciphertext',
          async () => {
            const { a, b, c, previous, predecessor } = await setup(f, browser);
            try {
              await c.init();
              await c.manager(c.page, 'after_challenge_prepare');
              const reached = c.phase('after_challenge_prepare');
              const creating = c.page
                .evaluate((old) => custodyDevice.createReplacement(old), predecessor)
                .catch(() => {});
              await reached;
              const prepared = await stored(c.page);
              await f.env.DB.prepare(
                'UPDATE messaging_enrollment SET expires_at=unixepoch()-1 WHERE device_id=?',
              )
                .bind(c.id)
                .run();
              await c.restart();
              await creating;
              await c.manager(c.page, 'after_challenge_prepare');
              const renewed = c.phase('after_challenge_prepare');
              const opening = c.page.evaluate(() => custodyDevice.open()).catch(() => {});
              await renewed;
              const ticket = await f.env.DB.prepare(
                'SELECT enrollment_id FROM messaging_enrollment WHERE device_id=? AND consumed_proof IS NULL ORDER BY expires_at DESC LIMIT 1',
              )
                .bind(c.id)
                .first<{ enrollment_id: string }>();
              assert.ok(ticket);
              await c.restart();
              await opening;
              c.loss = {
                path: `/messaging/enrollments/${ticket.enrollment_id}/complete`,
                method: 'POST',
              };
              await assert.rejects(() => c.open());
              await c.restart();
              await c.open();
              assert.equal(
                ((await stored(c.page)) as { scope: { device: { generation: number } } }).scope
                  .device.generation,
                2,
              );
              assert.ok(prepared);
              const { next } = await prepare(a, c);
              a.loss = { path: `/messaging/channels/${next.channel.id}/replace`, method: 'POST' };
              await approve(a);
              const before = (
                await a.page.evaluate(() => custodyDevice.chatSnapshot())
              ).replacements.at(-1)!;
              assert.equal(before.phase, 'prepared');
              await a.restart();
              await a.open();
              await a.chat();
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).replacements.at(-1)!
                  .operation_id,
                before.operation_id,
              );
              await c.abortCommand('activate_replacement');
              await approve(c);
              assert.equal(
                (await c.page.evaluate(() => custodyDevice.chatSnapshot())).replacements.at(-1)!
                  .phase,
                'consented',
              );
              await c.restart();
              await c.open();
              await c.chat();
              await click(c, '同期');
              await click(a, '同期');
              const welcome = await f.env.DB.prepare(
                "SELECT message_id FROM messaging_invitation_packet WHERE channel_id=? AND kind='welcome'",
              )
                .bind(next.channel.id)
                .first<{ message_id: string }>();
              assert.ok(welcome);
              c.loss = {
                path: `/messaging/channels/${next.channel.id}/invitation/packets/${welcome.message_id}/consume`,
                method: 'POST',
              };
              await click(c, '同期');
              assert.equal(
                (await c.page.evaluate(() => custodyDevice.chatSnapshot())).invitation!.phase,
                'joined',
              );
              await c.restart();
              await c.open();
              await c.chat();
              await complete(a, c);
              const approvals = await f.env.DB.prepare(
                'SELECT operation_id FROM messaging_replacement_approval WHERE channel_id=?',
              )
                .bind(next.channel.id)
                .all<{ operation_id: string }>();
              assert.equal(approvals.results.length, 2);
              assert.ok(approvals.results.some((v) => v.operation_id === before.operation_id));
              const competing: InvitationOffer = {
                ...next,
                channel: { ...next.channel, id: randomUUID() },
              };
              await assert.rejects(() =>
                a.page.evaluate(
                  ({ previous, next }) => custodyDevice.approveReplacement(previous, next),
                  { previous, next: competing },
                ),
              );
              await a.page.getByRole('button', { name: 'チャットをロック', exact: true }).click();
              await expect(
                a.page.getByText('チャットをロックしました。Vaultを開き直してください。', {
                  exact: true,
                }),
              ).toBeVisible();
            } finally {
              await a.close();
              await b.close();
              await c.close();
            }
          },
        );
        await t.test(
          'locking during witnessed replacement preparation prevents late code, history and wire publication',
          async () => {
            const { a, b, c, predecessor } = await setup(f, browser);
            try {
              await c.init();
              await c.manager();
              await c.page.evaluate((old) => custodyDevice.createReplacement(old), predecessor);
              const { next } = await prepare(a, c);
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
                  name: '確認した新しい指紋とコードが一致し、旧会話を閉じることに同意します',
                  exact: true,
                })
                .check();
              const pending = click(a, '新しい鍵での会話を承認').catch(() => {});
              await reached;
              await a.page.evaluate(() => custodyOwner.lock());
              release();
              await pending;
              await expect(
                a.page.getByText('チャットをロックしました。Vaultを開き直してください。', {
                  exact: true,
                }),
              ).toBeVisible();
              assert.equal(await a.page.locator('textarea').count(), 0);
              assert.equal(
                a.requests.filter(
                  (r) => r.path === `/messaging/channels/${next.channel.id}/replace`,
                ).length,
                0,
              );
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT channel_id FROM messaging_channel WHERE channel_id=?',
                )
                  .bind(next.channel.id)
                  .first(),
                null,
              );
              await a.restart();
              await a.open();
              const saved = (
                await a.page.evaluate(() => custodyDevice.chatSnapshot())
              ).replacements.at(-1)!;
              assert.equal(saved.next.channel.id, next.channel.id);
              assert.equal(saved.phase, 'prepared');
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
