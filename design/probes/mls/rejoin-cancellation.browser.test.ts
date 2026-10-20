import { qualificationTimeout } from './test-timeout.ts';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, firefox, webkit, expect, type Browser } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { Client, admit, successor } from './vault-browser-support.ts';
import { click, complete } from './replacement-browser-support.ts';
import { invitationCode } from './chat-view.ts';
import { fixture } from './server-support.ts';
import type { InvitationOffer } from './delivery-types.ts';
async function snapshot(c: Client) {
  return c.page.evaluate(() => custodyDevice.chatSnapshot());
}
async function pair(f: Awaited<ReturnType<typeof fixture>>, browser: Browser) {
  const a = new Client(f, browser, await f.seed()),
    b = new Client(f, browser, await f.seed());
  await a.init();
  await b.init();
  await a.create();
  await b.create();
  const previous = await admit(a, b);
  const sent = await a.page.evaluate(
    ({ previous, id }) =>
      custodyDevice.sendText(id, previous.channel, '取り消しても再送しない元の本文'),
    { previous, id: randomUUID() },
  );
  assert.equal(sent.ok, true);
  await a.stop(previous, 'leave');
  await b.stop(previous, 'leave');
  return { a, b, previous };
}
function cancel(c: Client, previous: InvitationOffer, next: InvitationOffer) {
  return c.page.evaluate(({ previous, next }) => custodyDevice.cancelRejoin(previous, next), {
    previous,
    next,
  });
}
async function veto(c: Client) {
  await c.page
    .getByRole('checkbox', {
      name: 'この再参加案を取り消し、元の会話を停止したままにします',
      exact: true,
    })
    .check();
  await click(c, 'この再参加案を取り消す');
}
async function importCode(c: Client, next: InvitationOffer) {
  await c.page
    .getByRole('textbox', { name: '受け取った招待コード', exact: true })
    .fill(invitationCode(next));
  await click(c, 'コードを確認');
}
async function approve(c: Client) {
  const button = c.page.getByRole('button', { name: 'このコードで再参加を承認', exact: true });
  await expect(button).toBeDisabled();
  await c.page
    .getByRole('checkbox', {
      name: '別の連絡手段で確認した相手の指紋と、この会話のコードが一致しています',
      exact: true,
    })
    .check();
  await click(c, 'このコードで再参加を承認');
  await expect(c.page.getByRole('alert')).toHaveText('');
}
async function text(a: Client, b: Client, offer: InvitationOffer) {
  const sent = await a.page.evaluate(
    (route) => custodyDevice.sendText(crypto.randomUUID(), route, '選び直した会話の本文'),
    offer.channel,
  );
  assert.equal(sent.ok, true);
  await a.sync(offer.channel);
  await b.sync(offer.channel);
  const peer = await snapshot(b);
  assert.ok(peer.received.some((r) => JSON.stringify(r.event).includes('選び直した会話の本文')));
  assert.ok(
    !peer.received.some((r) => JSON.stringify(r.event).includes('取り消しても再送しない元の本文')),
  );
  assert.equal((await snapshot(a)).sent[0].status, 'isolated');
}
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: same-key proposal cancellation and reselection`,
    { timeout: qualificationTimeout(300_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        await t.test(
          'conflicting proposals require explicit veto and fresh consent to the peer code under the original parent, then exchange real MLS text',
          async () => {
            const { a, b, previous } = await pair(f, browser);
            try {
              const x = successor(previous),
                y = successor(previous, true);
              assert.equal(await a.approveRejoin(previous, x), false);
              assert.equal(await b.approveRejoin(previous, y), false);
              await a.chat();
              await b.chat();
              await assert.rejects(() => a.approveRejoin(previous, y), /rejoin_intent_conflict/);
              await expect(
                a.page.getByRole('button', { name: 'この再参加案を取り消す', exact: true }),
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
                  path: 'local/generated/mls/rejoin-cancellation-chromium.png',
                  fullPage: true,
                });
              }
              await veto(a);
              const entry = await a.recovery(previous);
              assert.equal(entry.next, null);
              assert.equal(entry.phase, 'closed');
              assert.equal(entry.cancellations![0].outcome, 'cancelled');
              assert.equal(entry.abandoned.length, 1);
              assert.deepEqual((await snapshot(a)).invitation!.offer, previous);
              await assert.rejects(() => a.box(), /conversation_frozen/);
              const before = a.requests.length;
              await assert.rejects(
                () => a.approveRejoin(previous, x),
                /retired_or_unexpected_group/,
              );
              await assert.rejects(
                () =>
                  a.approveRejoin(previous, {
                    ...y,
                    channel: { ...y.channel, group: x.channel.group },
                  }),
                /retired_or_unexpected_group/,
              );
              assert.ok(!a.requests.slice(before).some((r) => r.path.endsWith('/rejoin')));
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT message_id FROM messaging_invitation_packet WHERE channel_id IN(?,?)',
                )
                  .bind(x.channel.id, y.channel.id)
                  .first(),
                null,
              );
              await importCode(a, y);
              await approve(a);
              await complete(a, b);
              assert.deepEqual((await a.recovery(previous)).next, y);
              assert.equal((await a.recovery(previous)).cancellations![0].outcome, 'cancelled');
              await text(a, b, y);
              await a.restart();
              await a.open();
              assert.equal((await a.recovery(previous)).cancellations![0].outcome, 'cancelled');
            } finally {
              await a.close();
              await b.close();
            }
          },
        );
        await t.test(
          'unpublished approval, actual IndexedDB aborts, lost cancellation reply and reload retain the same veto UUID and never release invitation wire',
          async () => {
            const { a, b, previous } = await pair(f, browser);
            try {
              const next = successor(previous),
                path = `/messaging/channels/${next.channel.id}/rejoin/cancel`;
              a.dropRequest = {
                path: `/messaging/channels/${next.channel.id}/rejoin`,
                method: 'POST',
              };
              await assert.rejects(() => a.approveRejoin(previous, next));
              await a.chat();
              await a.abortCommand('begin_cancel_rejoin');
              await assert.rejects(() => cancel(a, previous, next));
              assert.equal((await a.recovery(previous)).cancellations, undefined);
              assert.equal(a.requests.filter((r) => r.path === path).length, 0);
              a.loss = { path, method: 'POST' };
              await veto(a);
              const pending = (await a.recovery(previous)).cancellations![0];
              assert.equal(pending.outcome, 'pending');
              await assert.rejects(
                () => a.syncRejoin(previous, next),
                /rejoin_cancellation_pending/,
              );
              await a.restart();
              await a.open();
              await a.chat();
              await a.abortCommand('finish_cancel_rejoin');
              await click(a, '取り消しの確認を再試行');
              assert.equal((await a.recovery(previous)).cancellations![0].outcome, 'pending');
              await a.restart();
              await a.open();
              await a.chat();
              await click(a, '取り消しの確認を再試行');
              const saved = (await a.recovery(previous)).cancellations![0];
              assert.equal(saved.outcome, 'cancelled');
              assert.equal(saved.operation_id, pending.operation_id);
              const attempts = a.requests.filter((r) => r.path === path);
              assert.equal(attempts.length, 3);
              assert.equal(attempts[0].body, attempts[1].body);
              assert.equal(attempts[1].body, attempts[2].body);
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT message_id FROM messaging_invitation_packet WHERE channel_id=?',
                )
                  .bind(next.channel.id)
                  .first(),
                null,
              );
              const scope = (await snapshot(a)).own.scope;
              await f.response(
                await f.request(
                  `/messaging/channels/${next.channel.id}/rejoin`,
                  'POST',
                  { previous, next },
                  a.who,
                ),
                409,
              );
              assert.equal(
                (
                  await f.response<{ state: string }>(
                    await f.request(
                      `/messaging/channels/${next.channel.id}/rejoin/status`,
                      'POST',
                      { previous, next, scope },
                      a.who,
                    ),
                  )
                ).state,
                'cancelled',
              );
            } finally {
              await a.close();
              await b.close();
            }
          },
        );
        await t.test(
          'final peer approval wins the race: stable admitted receipt preserves the proposal and UI explicitly stops it before fresh recovery',
          async () => {
            const { a, b, previous } = await pair(f, browser);
            try {
              const next = successor(previous);
              assert.equal(await a.approveRejoin(previous, next), false);
              assert.equal(await b.approveRejoin(previous, next), true);
              await a.chat();
              await a.abortCommand('finish_cancel_rejoin');
              await veto(a);
              assert.equal((await a.recovery(previous)).cancellations![0].outcome, 'pending');
              await a.restart();
              await a.open();
              await a.chat();
              await click(a, '取り消しの確認を再試行');
              const admitted = await a.recovery(previous);
              assert.equal(admitted.cancellations![0].outcome, 'admitted');
              assert.deepEqual(admitted.next, next);
              assert.equal(
                (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
                  .bind(next.channel.id)
                  .first<{ blocked: number }>())!.blocked,
                0,
              );
              await expect(
                a.page.getByRole('button', { name: '再参加先を停止してやり直す', exact: true }),
              ).toBeDisabled();
              await a.page
                .getByRole('checkbox', {
                  name: '双方が承認した再参加先を停止し、新しい会話への参加をやり直します',
                  exact: true,
                })
                .check();
              await click(a, '再参加先を停止してやり直す');
              assert.equal((await a.recovery(next)).deferred_from, previous.channel.id);
              await b.stop(next, 'cancel_invitation');
              const vetoed = successor(next);
              assert.equal(await a.approveRejoin(next, vetoed), false);
              assert.equal(await cancel(a, next, vetoed), 'cancelled');
              assert.deepEqual((await a.recovery(previous)).next, next);
              assert.equal((await a.recovery(next)).next, null);
              const fresh = successor(next, true);
              assert.equal(await a.approveRejoin(next, fresh), false);
              assert.equal(await b.approveRejoin(next, fresh), true);
              await a.chat();
              await b.chat();
              await complete(a, b);
              await text(a, b, fresh);
              assert.equal((await a.recovery(previous)).cancellations![0].outcome, 'admitted');
            } finally {
              await a.close();
              await b.close();
            }
          },
        );
        await t.test(
          'peer veto is reported without reapproval; locking during the witnessed local intent prevents HTTP and retry keeps the original UUID',
          async () => {
            const { a, b, previous } = await pair(f, browser);
            try {
              const next = successor(previous);
              a.dropRequest = {
                path: `/messaging/channels/${next.channel.id}/rejoin`,
                method: 'POST',
              };
              await assert.rejects(() => a.approveRejoin(previous, next));
              assert.equal(await b.approveRejoin(previous, next), false);
              assert.equal(await cancel(b, previous, next), 'cancelled');
              assert.equal((await a.syncRejoin(previous, next)).phase, 'proposal_cancelled');
              await assert.rejects(
                () =>
                  a.page.evaluate(
                    ({ previous, next }) => custodyDevice.recoverRejoin(previous, next),
                    { previous, next },
                  ),
                /rejoin_cancelled/,
              );
              assert.equal((await snapshot(a)).recoveries.length, 1);
              await a.chat();
              let release!: () => void;
              const reached = new Promise<void>((resolve) => {
                a.pauseHead = {
                  reached: resolve,
                  release: new Promise<void>((r) => {
                    release = r;
                  }),
                };
              });
              const pending = veto(a).catch(() => {});
              await reached;
              await a.page.evaluate(() => custodyOwner.lock());
              release();
              await pending;
              const path = `/messaging/channels/${next.channel.id}/rejoin/cancel`;
              assert.equal(a.requests.filter((r) => r.path === path).length, 0);
              await expect(
                a.page.getByText('チャットをロックしました。Vaultを開き直してください。', {
                  exact: true,
                }),
              ).toBeVisible();
              assert.equal(await a.page.locator('textarea').count(), 0);
              await a.restart();
              await a.open();
              await a.chat();
              const saved = (await a.recovery(previous)).cancellations![0];
              assert.equal(saved.outcome, 'pending');
              await click(a, '取り消しの確認を再試行');
              assert.equal(
                (await a.recovery(previous)).cancellations![0].operation_id,
                saved.operation_id,
              );
              assert.equal((await a.recovery(previous)).next, null);
              assert.equal(
                JSON.parse(a.requests.find((r) => r.path === path)!.body!).operation_id,
                saved.operation_id,
              );
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT message_id FROM messaging_invitation_packet WHERE channel_id=?',
                )
                  .bind(next.channel.id)
                  .first(),
                null,
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
