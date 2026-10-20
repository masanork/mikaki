import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, firefox, webkit, expect, type Browser } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { fixture } from './server-support.ts';
import { Client, successor } from './vault-browser-support.ts';
import { setup, prepare, pin, click, complete, approve } from './replacement-browser-support.ts';
import { replacementCode, parseReplacementCode } from './replacement-types.ts';
import { qualificationTimeout } from './test-timeout.ts';
import type { InvitationOffer, RecoveryInfo } from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
const snapshot = (c: Client) => c.page.evaluate(() => custodyDevice.chatSnapshot());
const closeRoot = (c: Client, previous: InvitationOffer, next: InvitationOffer) =>
  c.page.evaluate(({ previous, next }) => custodyDevice.recoverReplacement(previous, next), {
    previous,
    next,
  });
const recover = (c: Client, previous: InvitationOffer, next: InvitationOffer) =>
  c.page.evaluate(({ previous, next }) => custodyDevice.recoverRejoin(previous, next), {
    previous,
    next,
  });
const receipt = ({ abandoned: _quarantine, ...r }: RecoveryInfo) => r;
async function admitted(f: Server, browser: Browser) {
  const p = await setup(f, browser);
  await p.c.init();
  await p.c.manager();
  await p.c.page.evaluate((old) => custodyDevice.createReplacement(old), p.predecessor);
  assert.equal(
    (
      await p.a.page.evaluate(
        ({ id, route }) => custodyDevice.sendText(id, route, '途中の参加先へ転送しない旧本文'),
        { id: randomUUID(), route: p.previous.channel },
      )
    ).ok,
    true,
  );
  const failed = await prepare(p.a, p.c);
  await approve(p.a);
  await approve(p.c);
  await closeRoot(p.a, p.previous, failed.next);
  return { ...p, failed };
}
async function rotate(f: Server, browser: Browser, p: Awaited<ReturnType<typeof admitted>>) {
  const d = new Client(f, browser, p.b.who, p.b.id);
  d.prf.splice(0, d.prf.length, ...p.b.prf);
  await d.init();
  await d.manager();
  await d.page.evaluate(
    (old) => custodyDevice.createReplacement(old),
    (await snapshot(p.a)).trust.peer!.accepted,
  );
  await p.a.chat();
  await d.chat();
  await pin(p.a, d, true);
  await pin(d, p.a);
  return d;
}
async function stop(c: Client) {
  const b = c.page.getByRole('button', { name: '承認済みの参加先を停止', exact: true });
  await expect(b).toBeDisabled();
  await c.page
    .getByRole('checkbox', {
      name: '承認済みの参加先を停止し、最新の鍵で承認し直します',
      exact: true,
    })
    .check();
  await click(c, '承認済みの参加先を停止');
}
async function importStop(c: Client, previous: InvitationOffer, next: InvitationOffer) {
  await c.page
    .getByRole('textbox', { name: '停止する承認済みの鍵切り替えコード', exact: true })
    .fill(replacementCode(previous, next));
  await click(c, '停止対象のコードを確認');
  await stop(c);
  await expect(c.page.getByRole('alert')).toHaveText('');
}
async function fresh(a: Client, b: Client) {
  await click(a, '鍵切り替えコードを作る');
  const code = await a.page
    .getByRole('textbox', { name: '共有する鍵切り替えコード', exact: true })
    .inputValue();
  await b.page.getByRole('textbox', { name: '受け取った鍵切り替えコード', exact: true }).fill(code);
  await click(b, '鍵切り替えコードを確認');
  for (const c of [a, b])
    await expect(
      c.page.getByRole('button', { name: '新しい鍵での会話を承認', exact: true }),
    ).toBeDisabled();
  return parseReplacementCode(code);
}
async function text(a: Client, b: Client, body: string) {
  await a.page.getByRole('textbox', { name: 'メッセージ', exact: true }).fill(body);
  await click(a, '送信');
  await click(b, '同期');
  const h = b.page.getByRole('region', { name: 'メッセージ履歴', exact: true });
  await expect(h).toContainText(body);
  await expect(h).not.toContainText('途中の参加先へ転送しない旧本文');
  assert.equal((await snapshot(a)).sent[0].status, 'isolated');
}
async function veto(c: Client) {
  const b = c.page.getByRole('button', { name: 'この再参加案を取り消す', exact: true });
  await expect(b).toBeDisabled();
  await c.page
    .getByRole('checkbox', {
      name: 'この再参加案を取り消し、元の会話を停止したままにします',
      exact: true,
    })
    .check();
  await click(c, 'この再参加案を取り消す');
}
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: latest-key recovery through unresolved same-key proposals and deferred closes`,
    { timeout: qualificationTimeout(480_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        for (const unpublished of [true, false])
          await t.test(
            `${unpublished ? 'an unpublished' : 'a unilateral'} same-key proposal is explicitly vetoed after peer rotation before a distinct stop and new bilateral approval`,
            async () => {
              const p = await admitted(f, browser),
                clients = [p.a, p.b, p.c];
              try {
                const next = successor(p.failed.next),
                  path = `/messaging/channels/${next.channel.id}/rejoin`;
                if (unpublished) {
                  p.a.dropRequest = { path, method: 'POST' };
                  await assert.rejects(() => p.a.approveRejoin(p.failed.next, next));
                  assert.equal(
                    await f.env.DB.prepare(
                      'SELECT channel_id FROM messaging_channel WHERE channel_id=?',
                    )
                      .bind(next.channel.id)
                      .first(),
                    null,
                  );
                } else {
                  assert.equal(await p.a.approveRejoin(p.failed.next, next), false);
                  const row = await f.env.DB.prepare(
                    'SELECT a_consent,b_consent FROM messaging_channel WHERE channel_id=?',
                  )
                    .bind(next.channel.id)
                    .first<{ a_consent: number; b_consent: number }>();
                  assert.equal(row!.a_consent + row!.b_consent, 1);
                }
                const d = await rotate(f, browser, p);
                clients.push(d);
                await expect(
                  p.a.page.getByRole('button', { name: '承認済みの参加先を停止', exact: true }),
                ).toHaveCount(0);
                const cancelPath = `${path}/cancel`;
                p.a.loss = { path: cancelPath, method: 'POST' };
                await veto(p.a);
                assert.equal(
                  (await p.a.recovery(p.failed.next)).cancellations!.at(-1)!.outcome,
                  'pending',
                );
                await p.a.restart();
                await p.a.open();
                await p.a.chat();
                await click(p.a, '取り消しの確認を再試行');
                const root = await p.a.recovery(p.failed.next);
                assert.equal(root.next, null);
                assert.equal(root.cancellations!.at(-1)!.outcome, 'cancelled');
                const attempts = p.a.requests.filter((r) => r.path === cancelPath);
                assert.equal(attempts.length, 2);
                assert.equal(attempts[0].body, attempts[1].body);
                await stop(p.a);
                await expect(p.a.page.getByRole('alert')).toHaveText('');
                await importStop(d, p.previous, p.failed.next);
                assert.equal((await snapshot(p.a)).replacement_stops[0].recovery_chain, undefined);
                await fresh(p.a, d);
                await approve(p.a);
                await approve(d);
                await complete(p.a, d);
                await text(p.a, d, '再参加案を取り消した後の本文');
                assert.deepEqual(receipt(await p.a.recovery(p.failed.next)), receipt(root));
                assert.equal(
                  (await f.env.DB.prepare(
                    'SELECT blocked FROM messaging_channel WHERE channel_id=?',
                  )
                    .bind(next.channel.id)
                    .first<{ blocked: number }>())!.blocked,
                  1,
                );
              } finally {
                for (const c of clients) await c.close();
              }
            },
          );
        await t.test(
          'every admitted descendant closes explicitly before a witnessed chain stop; lock, lost replies, aborted activation and another generation retain exact fences and the shared retirement budget',
          async () => {
            const p = await admitted(f, browser),
              clients = [p.a, p.b, p.c];
            try {
              const first = successor(p.failed.next),
                second = successor(first, true);
              await p.c.stop(p.failed.next, 'cancel_invitation');
              assert.equal(await p.a.approveRejoin(p.failed.next, first), false);
              assert.equal(await p.c.approveRejoin(p.failed.next, first), true);
              await p.c.stop(first, 'cancel_invitation');
              await recover(p.a, p.failed.next, first);
              assert.equal(await p.a.approveRejoin(first, second), false);
              assert.equal(await p.c.approveRejoin(first, second), true);
              let d = await rotate(f, browser, p);
              clients.push(d);
              await veto(p.a);
              assert.equal((await p.a.recovery(first)).cancellations!.at(-1)!.outcome, 'admitted');
              await expect(
                p.a.page.getByRole('button', { name: '承認済みの参加先を停止', exact: true }),
              ).toHaveCount(0);
              const closePath = `/messaging/channels/${second.channel.id}/close`,
                stopPath = `/messaging/channels/${p.failed.next.channel.id}/replace/stop`;
              p.a.loss = { path: closePath, method: 'POST' };
              const button = p.a.page.getByRole('button', {
                name: '再参加先を停止してやり直す',
                exact: true,
              });
              await expect(button).toBeDisabled();
              await p.a.page
                .getByRole('checkbox', {
                  name: '双方が承認した再参加先を停止し、新しい会話への参加をやり直します',
                  exact: true,
                })
                .check();
              await click(p.a, '再参加先を停止してやり直す');
              const closing = await p.a.recovery(second);
              assert.equal(closing.phase, 'closing');
              await assert.rejects(() =>
                p.a.page.evaluate(
                  ({ previous, next }) => custodyDevice.stopReplacement(previous, next),
                  p.failed,
                ),
              );
              assert.equal(p.a.requests.filter((r) => r.path === stopPath).length, 0);
              await p.a.restart();
              await p.a.open();
              await p.a.chat();
              await p.a.abortCommand('complete_close');
              await click(p.a, '停止の確認を再試行');
              assert.equal((await p.a.recovery(second)).phase, 'closing');
              await click(p.a, '停止の確認を再試行');
              const closes = p.a.requests.filter((r) => r.path === closePath);
              assert.equal(closes.length, 3);
              assert.equal(new Set(closes.map((r) => r.body)).size, 1);
              const before = (await snapshot(p.a)).recoveries,
                ids = before.map((r) => r.operation_id);
              await expect(
                p.a.page.getByText('停止を確認した参加先: 3件', { exact: true }),
              ).toBeVisible();
              await p.a.abortCommand('begin_stop_replacement');
              await stop(p.a);
              assert.equal((await snapshot(p.a)).replacement_stops.length, 0);
              let release!: () => void;
              const reached = new Promise<void>((resolve) => {
                p.a.pauseHead = {
                  reached: resolve,
                  release: new Promise<void>((r) => {
                    release = r;
                  }),
                };
              });
              const operation = p.a.page.evaluate(
                ({ previous, next }) => custodyDevice.stopReplacement(previous, next),
                p.failed,
              );
              await Promise.race([
                reached,
                operation.then(() => {
                  throw new Error('stop finished before witness');
                }),
              ]);
              await p.a.page.evaluate(() => custodyOwner.lock());
              release();
              await assert.rejects(() => operation);
              await expect(
                p.a.page.getByText('チャットをロックしました。Vaultを開き直してください。', {
                  exact: true,
                }),
              ).toBeVisible();
              assert.equal(p.a.requests.filter((r) => r.path === stopPath).length, 0);
              await p.a.restart();
              await p.a.open();
              await p.a.chat();
              const pending = (await snapshot(p.a)).replacement_stops[0];
              assert.equal(pending.phase, 'stopping');
              assert.deepEqual(pending.recovery_chain, ids);
              p.a.loss = { path: stopPath, method: 'POST' };
              await click(p.a, '同期');
              await p.a.abortCommand('complete_stop_replacement');
              await click(p.a, '同期');
              await click(p.a, '同期');
              assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'stopped');
              await expect(
                p.a.page.getByText('停止を確認した参加先: 3件', { exact: true }),
              ).toBeVisible();
              const stops = p.a.requests.filter((r) => r.path === stopPath);
              assert.equal(stops.length, 3);
              assert.equal(new Set(stops.map((r) => r.body)).size, 1);
              await p.a.page.setViewportSize({ width: 390, height: 844 });
              assert.equal(
                await p.a.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
                true,
              );
              assert.deepEqual((await new AxeBuilder({ page: p.a.page }).analyze()).violations, []);
              if (name === 'chromium') {
                await mkdir('local/generated/mls', { recursive: true });
                await p.a.page.screenshot({
                  path: 'local/generated/mls/replacement-stop-chain-chromium.png',
                  fullPage: true,
                });
              }
              await importStop(d, p.previous, p.failed.next);
              let proposal = await fresh(p.a, d);
              await approve(p.a);
              await approve(d);
              await p.a.abortCommand('activate_replacement');
              await click(p.a, '同期');
              assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'stopped');
              const additional = proposal.next;
              d = await rotate(f, browser, p);
              clients.push(d);
              await stop(p.a);
              await expect(p.a.page.getByRole('alert')).toHaveText('');
              await importStop(d, p.previous, additional);
              proposal = await fresh(p.a, d);
              await approve(p.a);
              await approve(d);
              await complete(p.a, d);
              assert.deepEqual(
                (await snapshot(p.a)).replacement_stops.map((s) => s.phase),
                ['retired', 'retired'],
              );
              assert.deepEqual((await snapshot(p.a)).recoveries.map(receipt), before.map(receipt));
              assert.equal((await p.a.recovery(p.failed.next)).abandoned.length, 1);
              for (const offer of [first, second])
                assert.deepEqual((await p.a.recovery(offer)).abandoned, []);
              await text(p.a, d, '複数の停止を確認して最新の鍵で届いた本文');
              for (const offer of [p.previous, p.failed.next, first, second, additional]) {
                const result = await p.a.page.evaluate(
                  (group) =>
                    custodyDevice.request(crypto.randomUUID(), { kind: 'create_group', group }),
                  Array.from(Buffer.from(offer.channel.group, 'base64url')),
                );
                assert.equal(result.ok, false);
                assert.equal(result.error, 'retired_or_unexpected_group');
                assert.equal(
                  (await f.env.DB.prepare(
                    'SELECT blocked FROM messaging_channel WHERE channel_id=?',
                  )
                    .bind(offer.channel.id)
                    .first<{ blocked: number }>())!.blocked,
                  1,
                );
              }
              for (const offer of [p.failed.next, first, second, additional])
                assert.equal(
                  p.a.requests.filter(
                    (r) => r.path === `/messaging/channels/${offer.channel.id}/invitation/packets`,
                  ).length,
                  0,
                );
              const denied = await p.a.page.evaluate(
                ({ offer, next }) =>
                  custodyDevice.request(crypto.randomUUID(), {
                    kind: 'begin_cancel_rejoin',
                    offer: JSON.stringify(offer),
                    next: JSON.stringify(next),
                    cancel_id: crypto.randomUUID(),
                  }),
                { offer: p.failed.next, next: first },
              );
              assert.equal(denied.ok, false);
              assert.equal(denied.error, 'conversation_frozen');
              for (const c of [p.a, d]) {
                await c.restart();
                await c.open();
                await c.chat();
              }
              await text(p.a, d, '再読み込み後も届いた本文');
              let current = proposal.next;
              for (let i = 0; i < 3; i++) {
                await p.a.stop(current, 'leave');
                await d.stop(current, 'leave');
                const next = successor(current, i % 2 === 0);
                assert.equal(await p.a.approveRejoin(current, next), false);
                assert.equal(await d.approveRejoin(current, next), true);
                for (let n = 0; n < 3; n++) {
                  await p.a.syncRejoin(current, next);
                  await d.syncRejoin(current, next);
                }
                current = next;
              }
              await p.a.chat();
              await d.chat();
              await complete(p.a, d);
              await text(p.a, d, '共有の廃止上限まで再参加した後の本文');
              await p.a.stop(current, 'leave');
              const next = successor(current),
                path = `/messaging/channels/${next.channel.id}/rejoin`;
              await assert.rejects(() => p.a.approveRejoin(current, next), /recovery_ledger_full/);
              assert.equal(p.a.requests.filter((r) => r.path === path).length, 0);
              for (const c of [p.a, d]) {
                await c.restart();
                await c.open();
              }
              assert.deepEqual((await snapshot(p.a)).replacement_stops[0].recovery_chain, ids);
              assert.equal(
                (await snapshot(d)).recoveries.some((r) => ids.includes(r.operation_id)),
                false,
              );
            } finally {
              for (const c of clients) await c.close();
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
