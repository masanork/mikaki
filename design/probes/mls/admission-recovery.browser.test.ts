import { qualificationTimeout } from './test-timeout.ts';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { chromium, firefox, webkit, expect, type Browser } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { Client, trust, invitation, successor } from './vault-browser-support.ts';
import { setup, prepare, approve, complete, click } from './replacement-browser-support.ts';
import { fixture } from './server-support.ts';
import { invitationCode } from './chat-view.ts';
import type { InvitationOffer } from './delivery-types.ts';
async function ready(f: Awaited<ReturnType<typeof fixture>>, browser: Browser, reverse = false) {
  const p = await setup(f, browser);
  const receipt = await p.a.page.evaluate(
    ({ previous, id }) => custodyDevice.sendText(id, previous.channel, '旧会話の未送信本文'),
    { previous: p.previous, id: randomUUID() },
  );
  assert.equal(receipt.ok, true);
  await p.c.init();
  await p.c.manager();
  await p.c.page.evaluate((old) => custodyDevice.createReplacement(old), p.predecessor);
  const proposal = await prepare(p.a, p.c);
  await approve(reverse ? p.c : p.a);
  await approve(reverse ? p.a : p.c);
  return { ...p, ...proposal };
}
async function recover(c: Client, previous: InvitationOffer, next: InvitationOffer) {
  return c.page.evaluate(({ previous, next }) => custodyDevice.recoverReplacement(previous, next), {
    previous,
    next,
  });
}
async function snapshot(c: Client) {
  return c.page.evaluate(() => custodyDevice.chatSnapshot());
}
async function resumed(a: Client, b: Client, old: InvitationOffer, fresh = successor(old, true)) {
  assert.equal(await a.approveRejoin(old, fresh), false);
  assert.equal(await b.approveRejoin(old, fresh), true);
  for (let n = 0; n < 3; n++) {
    await a.syncRejoin(old, fresh);
    await b.syncRejoin(old, fresh);
  }
  await a.chat();
  await b.chat();
  await complete(a, b);
  return fresh;
}
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: recovery after bilateral admission`,
    // Four complete recovery scenarios share this parent budget. CI Firefox
    // completed the first three before the old 180s limit cancelled the fourth.
    { timeout: qualificationTimeout(300_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        await t.test(
          'peer closes before local key replacement: explicit UI recovery, durable close retry and fresh consent retire both abandoned groups',
          async () => {
            const { a, b, c, previous, next } = await ready(f, browser);
            try {
              assert.equal((await snapshot(a)).replacements.at(-1)!.phase, 'consented');
              await c.stop(next, 'cancel_invitation');
              await click(a, '同期');
              assert.equal((await snapshot(a)).replacements.at(-1)!.phase, 'recovery_required');
              assert.deepEqual((await snapshot(a)).invitation!.offer, previous);
              assert.equal(
                a.requests.filter(
                  (r) => r.path === `/messaging/channels/${next.channel.id}/invitation/packets`,
                ).length,
                0,
              );
              const stop = a.page.getByRole('button', {
                name: '参加を停止してやり直す',
                exact: true,
              });
              await expect(stop).toBeDisabled();
              assert.deepEqual((await new AxeBuilder({ page: a.page }).analyze()).violations, []);
              await a.abortCommand('begin_replacement_recovery');
              await assert.rejects(() => recover(a, previous, next));
              assert.equal((await snapshot(a)).replacements.at(-1)!.phase, 'recovery_required');
              const path = `/messaging/channels/${next.channel.id}/close`;
              assert.equal(a.requests.filter((r) => r.path === path).length, 0);
              a.loss = { path, method: 'POST' };
              await a.page
                .getByRole('checkbox', {
                  name: 'この招待を停止し、新しい会話への参加をやり直します',
                  exact: true,
                })
                .check();
              await click(a, '参加を停止してやり直す');
              const closing = await a.recovery(next);
              assert.equal(closing.phase, 'closing');
              await a.restart();
              await a.open();
              await a.chat();
              await a.abortCommand('complete_close');
              await click(a, '停止の確認を再試行');
              assert.equal((await a.recovery(next)).phase, 'closing');
              await a.restart();
              await a.open();
              await a.chat();
              await click(a, '停止の確認を再試行');
              assert.equal((await a.recovery(next)).operation_id, closing.operation_id);
              assert.equal((await a.recovery(next)).phase, 'closed');
              assert.equal((await snapshot(a)).replacements.at(-1)!.phase, 'abandoned');
              const attempts = a.requests.filter((r) => r.path === path && r.method === 'POST');
              assert.equal(attempts.length, 3);
              assert.equal(attempts[1].body, attempts[2].body);
              assert.equal(attempts[0].body, attempts[1].body);
              await assert.rejects(() => a.box(), /conversation_frozen/);
              await assert.rejects(() =>
                a.page.evaluate(
                  ({ previous, next }) => custodyDevice.approveRejoin(previous, next),
                  {
                    previous: next,
                    next: previous,
                  },
                ),
              );
              // Fresh public code is inspected and independently approved by each UI.
              await c.chat();
              await click(a, '再参加コードを作る');
              const code = await a.page
                .getByRole('textbox', { name: '共有する招待コード', exact: true })
                .inputValue();
              await c.page
                .getByRole('textbox', { name: '受け取った招待コード', exact: true })
                .fill(code);
              await click(c, 'コードを確認');
              for (const client of [a, c]) {
                await expect(
                  client.page.getByRole('button', {
                    name: 'このコードで再参加を承認',
                    exact: true,
                  }),
                ).toBeDisabled();
                await client.page
                  .getByRole('checkbox', {
                    name: '別の連絡手段で確認した相手の指紋と、この会話のコードが一致しています',
                    exact: true,
                  })
                  .check();
                await click(client, 'このコードで再参加を承認');
              }
              const fresh = (await a.recovery(next)).next!;
              assert.equal(invitationCode(fresh), code);
              a.loss = { path: `/messaging/channels/${fresh.channel.id}/rejoin`, method: 'POST' };
              await assert.rejects(() => a.syncRejoin(next, fresh));
              assert.equal((await snapshot(a)).replacements.at(-1)!.phase, 'abandoned');
              await a.abortCommand('activate_rejoin');
              await assert.rejects(() => a.syncRejoin(next, fresh));
              assert.equal((await a.recovery(next)).phase, 'closed');
              assert.equal((await snapshot(a)).replacements.at(-1)!.phase, 'abandoned');
              await a.restart();
              await a.open();
              await a.chat();
              await complete(a, c);
              assert.equal((await a.recovery(next)).phase, 'rejoined');
              assert.equal((await snapshot(a)).replacements.at(-1)!.phase, 'active');
              assert.equal((await a.recovery(next)).abandoned.length, 1);
              await expect(
                a.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).toContainText('停止した会話で保留・自動転送なし');
              await a.page
                .getByRole('textbox', { name: 'メッセージ', exact: true })
                .fill('再承認した新しい会話');
              await click(a, '送信');
              await click(c, '同期');
              await expect(
                c.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).toContainText('再承認した新しい会話');
              await expect(
                c.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).not.toContainText('旧会話の未送信本文');
              for (const old of [previous, next]) {
                const rejected = await a.page.evaluate(
                  (group) =>
                    custodyDevice.request(crypto.randomUUID(), { kind: 'create_group', group }),
                  Array.from(Buffer.from(old.channel.group, 'base64url')),
                );
                assert.equal(rejected.ok, false);
                assert.equal(
                  (await f.env.DB.prepare(
                    'SELECT blocked FROM messaging_channel WHERE channel_id=?',
                  )
                    .bind(old.channel.id)
                    .first<{ blocked: number }>())!.blocked,
                  1,
                );
              }
            } finally {
              await a.close();
              await b.close();
              await c.close();
            }
          },
        );
        await t.test(
          'Welcome joined but consumption never sent: expiry survives reload, freezes wire, then a fresh reversed-role invitation delivers real text',
          async () => {
            const a = new Client(f, browser, await f.seed()),
              b = new Client(f, browser, await f.seed());
            try {
              await a.init();
              await b.init();
              await a.create();
              await b.create();
              await trust(a, b);
              const offer = await invitation(a, b);
              await b.syncInvite(offer);
              await a.syncInvite(offer);
              const welcome = await f.env.DB.prepare(
                "SELECT message_id FROM messaging_invitation_packet WHERE channel_id=? AND kind='welcome'",
              )
                .bind(offer.channel.id)
                .first<{ message_id: string }>();
              assert.ok(welcome);
              b.dropRequest = {
                path: `/messaging/channels/${offer.channel.id}/invitation/packets/${welcome.message_id}/consume`,
                method: 'POST',
              };
              await assert.rejects(() => b.syncInvite(offer));
              assert.equal((await snapshot(b)).invitation!.phase, 'joined');
              await f.env.DB.prepare(
                'UPDATE messaging_invitation_packet SET expires_at=unixepoch()-1 WHERE channel_id=?',
              )
                .bind(offer.channel.id)
                .run();
              assert.equal((await b.syncInvite(offer)).phase, 'recovery_required');
              assert.equal((await a.syncInvite(offer)).phase, 'recovery_required');
              await b.restart();
              await b.open();
              assert.equal((await b.syncInvite(offer)).phase, 'recovery_required');
              await assert.rejects(() => b.box(), /conversation_frozen/);
              await a.stop(offer, 'cancel_invitation');
              await b.stop(offer, 'cancel_invitation');
              const fresh = await resumed(a, b, offer);
              await a.page.evaluate(
                (route) => custodyDevice.sendText(crypto.randomUUID(), route, '期限切れからの復旧'),
                fresh.channel,
              );
              await a.sync(fresh.channel);
              await b.sync(fresh.channel);
              assert.ok(
                (await snapshot(b)).received.some((r) =>
                  JSON.stringify(r.event).includes('期限切れからの復旧'),
                ),
              );
            } finally {
              await a.close();
              await b.close();
            }
          },
        );
        await t.test(
          'replacement Commit publication interrupted after local preparation: expired consumed KP quarantines Commit and Welcome before fresh admission',
          async () => {
            const { a, b, c, previous, next } = await ready(f, browser);
            try {
              a.dropRequest = {
                path: `/messaging/channels/${next.channel.id}/invitation/packets`,
                method: 'POST',
              };
              await assert.rejects(() =>
                a.page.evaluate(
                  ({ previous, next }) => custodyDevice.syncReplacement(previous, next),
                  { previous, next },
                ),
              );
              assert.equal((await snapshot(a)).replacements.at(-1)!.phase, 'active');
              assert.equal((await snapshot(a)).invitation!.phase, 'invited');
              await f.env.DB.prepare(
                'UPDATE messaging_invitation_packet SET expires_at=unixepoch()-1 WHERE channel_id=?',
              )
                .bind(next.channel.id)
                .run();
              for (const client of [a, c]) {
                const result = await client.page.evaluate(
                  ({ previous, next }) => custodyDevice.syncReplacement(previous, next),
                  { previous, next },
                );
                assert.equal(result.phase, 'recovery_required');
                await assert.rejects(() => client.box(), /conversation_frozen/);
                await client.stop(next, 'cancel_invitation');
              }
              const failed = (await a.recovery(next)).abandoned;
              assert.deepEqual(
                failed.map((r) => r.kind),
                ['commit', 'welcome'],
              );
              const fresh = await resumed(a, c, next);
              assert.deepEqual((await a.recovery(next)).abandoned, failed);
              for (const entry of failed)
                assert.equal(
                  await f.env.DB.prepare(
                    'SELECT message_id FROM messaging_invitation_packet WHERE message_id=?',
                  )
                    .bind(entry.id)
                    .first(),
                  null,
                );
              const sent = await c.page.evaluate(
                (route) =>
                  custodyDevice.sendText(
                    crypto.randomUUID(),
                    route,
                    '途中のCommitを破棄して再参加',
                  ),
                fresh.channel,
              );
              assert.equal(sent.ok, true);
              await c.sync(fresh.channel);
              await a.sync(fresh.channel);
              assert.ok(
                (await snapshot(a)).received.some((r) =>
                  JSON.stringify(r.event).includes('途中のCommitを破棄して再参加'),
                ),
              );
            } finally {
              await a.close();
              await b.close();
              await c.close();
            }
          },
        );
        await t.test(
          'Vault lock during the recovery witness releases no late close or admission wire; the exact saved recovery resumes after unlock',
          async () => {
            const { a: c, b, c: a, previous, next } = await ready(f, browser, true);
            try {
              await c.stop(next, 'cancel_invitation');
              let release!: () => void, reached!: () => void;
              const arrived = new Promise<void>((r) => {
                reached = r;
              });
              a.pauseHead = {
                reached,
                release: new Promise<void>((r) => {
                  release = r;
                }),
              };
              const pending = recover(a, previous, next).then(
                () => 'unexpected_success',
                () => 'locked',
              );
              await arrived;
              await a.page.evaluate(() => custodyOwner.lock());
              release();
              assert.equal(await pending, 'locked');
              const path = `/messaging/channels/${next.channel.id}/close`;
              assert.equal(a.requests.filter((r) => r.path === path).length, 0);
              await a.restart();
              await a.open();
              assert.equal((await recover(a, previous, next)).phase, 'closed');
              await resumed(a, c, next);
              assert.equal(a.requests.filter((r) => r.path === path).length, 1);
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
