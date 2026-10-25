import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, firefox, webkit, expect, type Browser } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { fixture } from './server-support.ts';
import { Client, successor } from './vault-browser-support.ts';
import {
  setup,
  prepare,
  pin,
  click,
  complete,
  approve as approveUI,
} from './replacement-browser-support.ts';
import { replacementCode, parseReplacementCode } from './replacement-types.ts';
import { qualificationTimeout } from './test-timeout.ts';
import type { InvitationOffer } from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
const snapshot = (c: Client) => c.page.evaluate(() => custodyDevice.chatSnapshot());
async function approve(c: Client) {
  await approveUI(c);
  await expect(c.page.getByRole('alert')).toHaveText('');
}
async function rotate(f: Server, browser: Browser, original: Client, a: Client) {
  const c = new Client(f, browser, original.who, original.id);
  c.prf.splice(0, c.prf.length, ...original.prf);
  await c.init();
  await c.manager();
  await c.page.evaluate(
    (old) => custodyDevice.createReplacement(old),
    (await snapshot(a)).trust.peer!.accepted,
  );
  await c.chat();
  await pin(a, c, true);
  await pin(c, a);
  return c;
}
async function admitted(f: Server, browser: Browser) {
  const p = await setup(f, browser);
  await p.c.init();
  await p.c.manager();
  await p.c.page.evaluate((old) => custodyDevice.createReplacement(old), p.predecessor);
  const result = await p.a.page.evaluate(
    ({ id, offer }) => custodyDevice.sendText(id, offer.channel, '停止前の送信待ち本文'),
    { id: randomUUID(), offer: p.previous },
  );
  assert.equal(result.ok, true);
  const failed = await prepare(p.a, p.c);
  await approve(p.a);
  await approve(p.c);
  assert.equal((await snapshot(p.a)).replacements.at(-1)!.phase, 'consented');
  return { ...p, failed };
}
async function stop(c: Client) {
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
  await expect(
    c.page.getByRole('button', { name: '承認済みの参加先を停止', exact: true }),
  ).toBeDisabled();
}
async function fresh(a: Client, b: Client) {
  await click(a, '鍵切り替えコードを作る');
  const text = await a.page
    .getByRole('textbox', { name: '共有する鍵切り替えコード', exact: true })
    .inputValue();
  await b.page.getByRole('textbox', { name: '受け取った鍵切り替えコード', exact: true }).fill(text);
  await click(b, '鍵切り替えコードを確認');
  for (const c of [a, b])
    await expect(
      c.page.getByRole('button', { name: '新しい鍵での会話を承認', exact: true }),
    ).toBeDisabled();
  return parseReplacementCode(text);
}
async function text(a: Client, b: Client) {
  await a.page
    .getByRole('textbox', { name: 'メッセージ', exact: true })
    .fill('停止後に最新の鍵で再承認した本文');
  await click(a, '送信');
  await click(b, '同期');
  await expect(b.page.getByRole('region', { name: 'メッセージ履歴', exact: true })).toContainText(
    '停止後に最新の鍵で再承認した本文',
  );
  await expect(
    b.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
  ).not.toContainText('停止前の送信待ち本文');
  assert.equal((await snapshot(a)).sent[0].status, 'isolated');
}
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: witnessed stop after bilateral admission and another device-key update`,
    // Five sequential journeys, including six rejoin cycles, share this deadline.
    { timeout: qualificationTimeout(600_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        await t.test(
          'both owners explicitly stop the failed target before latest-key approval, retire both old groups, retain quarantine and exchange real text across reload',
          async () => {
            const p = await admitted(f, browser),
              clients = [p.a, p.b, p.c];
            try {
              const d = await rotate(f, browser, p.b, p.a);
              clients.push(d);
              await p.a.page
                .getByRole('checkbox', {
                  name: 'この切り替え案を中止し、旧会話を停止したままにします',
                  exact: true,
                })
                .check();
              await click(p.a, 'この切り替え案を中止');
              assert.equal(
                (await snapshot(p.a)).replacements.at(-1)!.cancellation!.outcome,
                'admitted',
              );
              await expect(
                p.a.page.getByRole('button', { name: '参加を停止してやり直す', exact: true }),
              ).toHaveCount(0);
              await stop(p.a);
              await expect(p.a.page.getByRole('alert')).toHaveText('');
              await importStop(d, p.previous, p.failed.next);
              await stop(d);
              await expect(d.page.getByRole('alert')).toHaveText('');
              const stopped = (await snapshot(p.a)).replacement_stops[0];
              assert.equal(stopped.phase, 'stopped');
              assert.equal(stopped.abandoned.length, 1);
              await assert.rejects(() => p.a.box(), /conversation_frozen/);
              await expect(
                p.a.page.getByRole('textbox', { name: 'メッセージ', exact: true }),
              ).toBeDisabled();
              await p.a.page.setViewportSize({ width: 390, height: 844 });
              assert.equal(
                await p.a.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
                true,
              );
              assert.deepEqual((await new AxeBuilder({ page: p.a.page }).analyze()).violations, []);
              if (name === 'chromium') {
                await mkdir('local/generated/mls', { recursive: true });
                await p.a.page.screenshot({
                  path: 'local/generated/mls/replacement-stop-chromium.png',
                  fullPage: true,
                });
              }
              for (const c of [p.a, d]) {
                await c.restart();
                await c.open();
                await c.chat();
              }
              const next = await fresh(p.a, d);
              await approve(p.a);
              await approve(d);
              await complete(p.a, d);
              assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'retired');
              assert.equal((await snapshot(d)).replacement_stops[0].phase, 'retired');
              assert.equal(
                (await snapshot(p.a)).invitation!.offer.channel.id,
                next.next.channel.id,
              );
              await assert.rejects(() => p.c.syncInvite(p.failed.next));
              const before = (await snapshot(p.a)).invitation;
              await p.a.page.evaluate(
                ({ previous, next }) => custodyDevice.stopReplacement(previous, next),
                p.failed,
              );
              assert.deepEqual((await snapshot(p.a)).invitation, before);
              await text(p.a, d);
              for (const c of [p.a, d]) {
                await c.restart();
                await c.open();
                await c.chat();
              }
              assert.equal(
                (await snapshot(p.a)).replacement_stops[0].abandoned[0].id,
                stopped.abandoned[0].id,
              );
              assert.equal((await snapshot(d)).received.length, 1);
            } finally {
              for (const c of clients) await c.close();
            }
          },
        );
        await t.test(
          'lost committed stop replies and actual begin/complete IndexedDB aborts keep the same frozen intent without premature consent or wire',
          async () => {
            const p = await admitted(f, browser),
              clients = [p.a, p.b, p.c];
            try {
              const d = await rotate(f, browser, p.b, p.a);
              clients.push(d);
              const path = `/messaging/channels/${p.failed.next.channel.id}/replace/stop`;
              p.a.loss = { path, method: 'POST' };
              await stop(p.a);
              const saved = (await snapshot(p.a)).replacement_stops[0];
              assert.equal(saved.phase, 'stopping');
              await assert.rejects(() => p.a.box(), /conversation_frozen/);
              await p.a.restart();
              await p.a.open();
              await p.a.chat();
              assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'stopped');
              const writes = p.a.requests.filter((r) => r.path === path);
              assert.equal(writes.length, 2);
              assert.equal(writes[0].body, writes[1].body);
              await importStop(d, p.previous, p.failed.next);
              await d.abortCommand('begin_stop_replacement');
              await stop(d);
              assert.equal((await snapshot(d)).replacement_stops.length, 0);
              assert.equal(d.requests.filter((r) => r.path === path).length, 0);
              d.forgedStopReceipt = true;
              await stop(d);
              await expect(d.page.getByRole('alert')).toContainText(
                '停止の応答が保存した対象と一致しません',
              );
              const pending = (await snapshot(d)).replacement_stops[0];
              assert.equal(pending.phase, 'stopping');
              await d.abortCommand('complete_stop_replacement');
              await click(d, '同期');
              assert.equal((await snapshot(d)).replacement_stops[0].phase, 'stopping');
              await d.restart();
              await d.open();
              await d.chat();
              await click(d, '同期');
              assert.equal(
                (await snapshot(d)).replacement_stops[0].operation_id,
                pending.operation_id,
              );
              assert.equal((await snapshot(d)).replacement_stops[0].phase, 'stopped');
              const retries = d.requests.filter((r) => r.path === path);
              assert.equal(retries.length, 3);
              assert.ok(retries.every((r) => r.body === retries[0].body));
              const next = await fresh(p.a, d);
              await approve(p.a);
              await d.abortCommand('activate_replacement');
              await approveUI(d);
              assert.equal((await snapshot(d)).replacement_stops[0].phase, 'stopped');
              assert.equal((await snapshot(d)).replacements.at(-1)!.phase, 'consented');
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT message_id FROM messaging_invitation_packet WHERE channel_id=?',
                )
                  .bind(next.next.channel.id)
                  .first(),
                null,
              );
              await d.restart();
              await d.open();
              await d.chat();
              await complete(p.a, d);
              await text(p.a, d);
            } finally {
              for (const c of clients) await c.close();
            }
          },
        );
        await t.test(
          'another post-admission generation update retains every stopped target and emits only final native admission wire',
          async () => {
            const p = await admitted(f, browser),
              clients = [p.a, p.b, p.c];
            try {
              const d = await rotate(f, browser, p.b, p.a);
              clients.push(d);
              await stop(p.a);
              await importStop(d, p.previous, p.failed.next);
              await stop(d);
              const intermediate = await fresh(p.a, d);
              await approve(p.a);
              await approve(d);
              const e = await rotate(f, browser, p.b, p.a);
              clients.push(e);
              await stop(p.a);
              await importStop(e, p.previous, intermediate.next);
              await stop(e);
              const pending = (await snapshot(p.a)).replacement_stops;
              assert.equal(pending.length, 2);
              assert.ok(pending.every((s) => s.phase === 'stopped'));
              const next = await fresh(p.a, e);
              await approve(p.a);
              await approve(e);
              await complete(p.a, e);
              const done = await snapshot(p.a);
              assert.ok(done.replacement_stops.every((s) => s.phase === 'retired'));
              assert.equal(done.replacements.at(-1)!.restart_from, intermediate.next.channel.id);
              assert.equal(done.invitation!.offer.channel.id, next.next.channel.id);
              for (const failed of [p.failed.next, intermediate.next]) {
                const packets = (
                  await f.env.DB.prepare(
                    'SELECT sender_scope,kind FROM messaging_invitation_packet WHERE channel_id=?',
                  )
                    .bind(failed.channel.id)
                    .all()
                ).results;
                assert.equal(packets.length, 1);
                assert.equal(packets[0].kind, 'key_package');
                assert.notEqual(packets[0].sender_scope, done.own.scope);
              }
              await text(p.a, e);
              await assert.rejects(() => d.syncInvite(intermediate.next));
            } finally {
              for (const c of clients) await c.close();
            }
          },
        );
        await t.test(
          'Vault lock at the committed stop-intent witness clears the UI, sends no stop write and resumes the exact saved intent after unlock',
          async () => {
            const p = await admitted(f, browser),
              clients = [p.a, p.b, p.c];
            try {
              const d = await rotate(f, browser, p.b, p.a);
              clients.push(d);
              let release!: () => void;
              const reached = new Promise<void>((resolve) => {
                p.a.pauseHead = {
                  reached: resolve,
                  release: new Promise<void>((r) => {
                    release = r;
                  }),
                };
              });
              const operation = stop(p.a);
              await Promise.race([
                reached,
                operation.then(() => {
                  throw new Error('stop_finished_before_witness');
                }),
              ]);
              await p.a.page.evaluate(() => custodyOwner.lock());
              release();
              await operation.catch(() => {});
              await expect(
                p.a.page.getByText('チャットをロックしました。Vaultを開き直してください。', {
                  exact: true,
                }),
              ).toBeVisible();
              assert.equal(await p.a.page.locator('textarea').count(), 0);
              const path = `/messaging/channels/${p.failed.next.channel.id}/replace/stop`;
              assert.equal(p.a.requests.filter((r) => r.path === path).length, 0);
              await p.a.restart();
              await p.a.open();
              await p.a.chat();
              const saved = (await snapshot(p.a)).replacement_stops[0];
              assert.equal(saved.phase, 'stopped');
              assert.equal(
                JSON.parse(p.a.requests.find((r) => r.path === path)!.body!).operation_id,
                saved.operation_id,
              );
              await importStop(d, p.previous, p.failed.next);
              await stop(d);
              await fresh(p.a, d);
              await approve(p.a);
              await approve(d);
              await complete(p.a, d);
              await text(p.a, d);
            } finally {
              for (const c of clients) await c.close();
            }
          },
        );
        await t.test(
          'a veto releases only the unused historical marker; reversed-role admission accounts for both retirements before subsequent rejoin consent',
          async () => {
            const p = await admitted(f, browser),
              clients = [p.a, p.b, p.c];
            try {
              const d = await rotate(f, browser, p.b, p.a);
              clients.push(d);
              await assert.rejects(
                () =>
                  d.page.evaluate(
                    ({ previous, next }) =>
                      custodyDevice.stopReplacement(previous, {
                        ...next,
                        inviter_scope:
                          next.inviter_scope === next.channel.a.scope
                            ? next.channel.b.scope
                            : next.channel.a.scope,
                      }),
                    p.failed,
                  ),
                /replacement_stop_unavailable/,
              );
              assert.equal((await snapshot(d)).replacement_stops.length, 0);
              await stop(p.a);
              await importStop(d, p.previous, p.failed.next);
              await stop(d);
              const cancelled = await fresh(p.a, d);
              await approve(d);
              await d.page
                .getByRole('checkbox', {
                  name: 'この切り替え案を中止し、旧会話を停止したままにします',
                  exact: true,
                })
                .check();
              await click(d, 'この切り替え案を中止');
              assert.equal((await snapshot(d)).replacements.at(-1)!.phase, 'cancelled');
              assert.equal((await snapshot(d)).replacement_stops[0].phase, 'stopped');
              const next = await fresh(d, p.a);
              await approve(d);
              await approve(p.a);
              await complete(p.a, d);
              await text(p.a, d);
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT message_id FROM messaging_invitation_packet WHERE channel_id=?',
                )
                  .bind(cancelled.next.channel.id)
                  .first(),
                null,
              );
              const stopPath = `/messaging/channels/${next.next.channel.id}/replace/stop`,
                beforeStop = p.a.requests.filter((r) => r.path === stopPath).length;
              await assert.rejects(
                () =>
                  p.a.page.evaluate(
                    ({ previous, next }) => custodyDevice.stopReplacement(previous, next),
                    next,
                  ),
                /replacement_origin_advanced/,
              );
              assert.equal(p.a.requests.filter((r) => r.path === stopPath).length, beforeStop);
              assert.equal((await snapshot(p.a)).replacement_stops.length, 1);
              let current = next.next;
              for (let i = 0; i < 6; i++) {
                await p.a.stop(current, 'leave');
                await d.stop(current, 'leave');
                const rejoin = successor(current, i % 2 === 0);
                assert.equal(await p.a.approveRejoin(current, rejoin), false);
                assert.equal(await d.approveRejoin(current, rejoin), true);
                for (let n = 0; n < 3; n++) {
                  await p.a.syncRejoin(current, rejoin);
                  await d.syncRejoin(current, rejoin);
                }
                assert.equal((await snapshot(p.a)).invitation!.phase, 'active');
                current = rejoin;
              }
              await p.a.stop(current, 'leave');
              await d.stop(current, 'leave');
              const impossible = successor(current),
                requests = p.a.requests.filter((r) => r.path.endsWith('/rejoin')).length;
              await assert.rejects(
                () => p.a.approveRejoin(current, impossible),
                /recovery_ledger_full/,
              );
              assert.equal(p.a.requests.filter((r) => r.path.endsWith('/rejoin')).length, requests);
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT channel_id FROM messaging_channel WHERE channel_id=?',
                )
                  .bind(impossible.channel.id)
                  .first(),
                null,
              );
              assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'retired');
              assert.equal(
                (await snapshot(p.a)).recoveries.filter((r) => r.phase === 'rejoined').length,
                6,
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
