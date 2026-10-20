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
import type { InvitationOffer } from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
const snapshot = (c: Client) => c.page.evaluate(() => custodyDevice.chatSnapshot());
const recover = (c: Client, previous: InvitationOffer, next: InvitationOffer) =>
  c.page.evaluate(({ previous, next }) => custodyDevice.recoverReplacement(previous, next), {
    previous,
    next,
  });
async function admitted(f: Server, browser: Browser) {
  const p = await setup(f, browser);
  await p.c.init();
  await p.c.manager();
  await p.c.page.evaluate((old) => custodyDevice.createReplacement(old), p.predecessor);
  assert.equal(
    (
      await p.a.page.evaluate(
        ({ id, route }) => custodyDevice.sendText(id, route, '復旧前の未送信本文'),
        { id: randomUUID(), route: p.previous.channel },
      )
    ).ok,
    true,
  );
  const failed = await prepare(p.a, p.c);
  await approve(p.a);
  await approve(p.c);
  assert.equal((await snapshot(p.a)).replacements.at(-1)!.phase, 'consented');
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
  await d.chat();
  await p.a.chat();
  await pin(p.a, d, true);
  await pin(d, p.a);
  return d;
}
async function stop(c: Client) {
  const button = c.page.getByRole('button', { name: '承認済みの参加先を停止', exact: true });
  await expect(button).toBeDisabled();
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
async function fresh(a: Client, d: Client) {
  await click(a, '鍵切り替えコードを作る');
  const code = await a.page
    .getByRole('textbox', { name: '共有する鍵切り替えコード', exact: true })
    .inputValue();
  await d.page.getByRole('textbox', { name: '受け取った鍵切り替えコード', exact: true }).fill(code);
  await click(d, '鍵切り替えコードを確認');
  for (const c of [a, d])
    await expect(
      c.page.getByRole('button', { name: '新しい鍵での会話を承認', exact: true }),
    ).toBeDisabled();
  return parseReplacementCode(code);
}
async function text(a: Client, d: Client, body: string) {
  await a.page.getByRole('textbox', { name: 'メッセージ', exact: true }).fill(body);
  await click(a, '送信');
  await click(d, '同期');
  const history = d.page.getByRole('region', { name: 'メッセージ履歴', exact: true });
  await expect(history).toContainText(body);
  await expect(history).not.toContainText('復旧前の未送信本文');
  assert.equal((await snapshot(a)).sent[0].status, 'isolated');
}
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: latest-key stop from a deferred ordinary admission recovery`,
    { timeout: qualificationTimeout(360_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        await t.test(
          'closed root retains its close receipt, veto tombstones and quarantine through stop/activation aborts, reload and subsequent ordinary rejoin',
          async () => {
            const p = await admitted(f, browser),
              clients = [p.a, p.b, p.c];
            try {
              await recover(p.a, p.previous, p.failed.next);
              const veto = successor(p.failed.next);
              assert.equal(await p.a.approveRejoin(p.failed.next, veto), false);
              assert.equal(
                await p.a.page.evaluate(
                  ({ previous, next }) => custodyDevice.cancelRejoin(previous, next),
                  { previous: p.failed.next, next: veto },
                ),
                'cancelled',
              );
              const root = await p.a.recovery(p.failed.next);
              assert.equal(root.phase, 'closed');
              let d = await rotate(f, browser, p);
              clients.push(d);
              await expect(
                p.a.page.getByRole('button', { name: '再参加コードを作る', exact: true }),
              ).toHaveCount(0);
              const path = `/messaging/channels/${p.failed.next.channel.id}/replace/stop`;
              await p.a.abortCommand('begin_stop_replacement');
              await stop(p.a);
              assert.equal((await snapshot(p.a)).replacement_stops.length, 0);
              assert.equal(p.a.requests.filter((r) => r.path === path).length, 0);
              p.a.loss = { path, method: 'POST' };
              await stop(p.a);
              const stopped = (await snapshot(p.a)).replacement_stops[0];
              assert.equal(stopped.phase, 'stopping');
              assert.equal(stopped.recovery_id, root.operation_id);
              assert.deepEqual((await snapshot(p.a)).invitation!.offer, p.failed.next);
              assert.deepEqual(await p.a.recovery(p.failed.next), root);
              await assert.rejects(() => p.a.box(), /conversation_frozen/);
              await p.a.restart();
              await p.a.open();
              await p.a.chat();
              await p.a.abortCommand('complete_stop_replacement');
              await click(p.a, '同期');
              assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'stopping');
              await click(p.a, '同期');
              assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'stopped');
              const writes = p.a.requests.filter((r) => r.path === path);
              assert.equal(writes.length, 3);
              assert.equal(new Set(writes.map((r) => r.body)).size, 1);
              await p.a.page.setViewportSize({ width: 390, height: 844 });
              assert.equal(
                await p.a.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
                true,
              );
              assert.deepEqual((await new AxeBuilder({ page: p.a.page }).analyze()).violations, []);
              if (name === 'chromium') {
                await mkdir('local/generated/mls', { recursive: true });
                await p.a.page.screenshot({
                  path: 'local/generated/mls/replacement-stop-recovery-chromium.png',
                  fullPage: true,
                });
              }
              await importStop(d, p.previous, p.failed.next);
              let next = await fresh(p.a, d);
              const consentWrites = p.a.requests.filter((r) => r.path.endsWith('/replace')).length;
              await assert.rejects(
                () =>
                  p.a.page.evaluate(
                    ({ previous, next }) => custodyDevice.approveReplacement(previous, next),
                    {
                      previous: next.previous,
                      next: {
                        ...next.next,
                        channel: {
                          ...next.next.channel,
                          id: veto.channel.id,
                          group: veto.channel.group,
                        },
                      },
                    },
                  ),
                /retired_or_unexpected_group/,
              );
              assert.equal(
                p.a.requests.filter((r) => r.path.endsWith('/replace')).length,
                consentWrites,
              );
              await approve(p.a);
              await approve(d);
              await p.a.abortCommand('activate_replacement');
              await click(p.a, '同期');
              assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'stopped');
              assert.deepEqual((await snapshot(p.a)).invitation!.offer, p.failed.next);
              // Another registration after admission must retain the linked
              // root rather than requiring managed metadata to point back to O.
              const secondFailed = next.next;
              d = await rotate(f, browser, p);
              clients.push(d);
              await stop(p.a);
              await expect(p.a.page.getByRole('alert')).toHaveText('');
              assert.equal((await snapshot(p.a)).replacement_stops.length, 2);
              assert.deepEqual(await p.a.recovery(p.failed.next), root);
              await importStop(d, p.previous, secondFailed);
              next = await fresh(p.a, d);
              await approve(p.a);
              await approve(d);
              await p.a.restart();
              await p.a.open();
              await p.a.chat();
              await complete(p.a, d);
              assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'retired');
              assert.equal((await snapshot(p.a)).replacement_stops[1].phase, 'retired');
              assert.deepEqual(await p.a.recovery(p.failed.next), root);
              await text(p.a, d, '以前の復旧待ちから最新の鍵で届いた本文');
              for (const old of [p.previous, p.failed.next, secondFailed]) {
                const result = await p.a.page.evaluate(
                  (group) =>
                    custodyDevice.request(crypto.randomUUID(), { kind: 'create_group', group }),
                  Array.from(Buffer.from(old.channel.group, 'base64url')),
                );
                assert.equal(result.ok, false);
                assert.equal(
                  (await f.env.DB.prepare(
                    'SELECT blocked FROM messaging_channel WHERE channel_id=?',
                  )
                    .bind(old.channel.id)
                    .first<{ blocked: number }>())!.blocked,
                  1,
                );
              }
              const rejoinWrites = p.a.requests.filter((r) => r.path.endsWith('/rejoin')).length;
              await assert.rejects(
                () => p.a.approveRejoin(p.failed.next, successor(p.failed.next)),
                /conversation_frozen/,
              );
              assert.equal(
                p.a.requests.filter((r) => r.path.endsWith('/rejoin')).length,
                rejoinWrites,
              );
              // The retained closed root must not freeze a later, unrelated recovery.
              await p.a.stop(next.next, 'leave');
              await d.stop(next.next, 'leave');
              const rejoined = successor(next.next, true);
              assert.equal(await p.a.approveRejoin(next.next, rejoined), false);
              assert.equal(await d.approveRejoin(next.next, rejoined), true);
              for (let i = 0; i < 3; i++) {
                await p.a.syncRejoin(next.next, rejoined);
                await d.syncRejoin(next.next, rejoined);
              }
              for (const c of [p.a, d]) {
                await c.restart();
                await c.open();
                await c.chat();
              }
              await complete(p.a, d);
              await text(p.a, d, '通常の再参加後にも届いた本文');
              assert.deepEqual(await p.a.recovery(p.failed.next), root);
              assert.equal(
                (await snapshot(d)).recoveries.some((r) => r.operation_id === root.operation_id),
                false,
              );
            } finally {
              for (const c of clients) await c.close();
            }
          },
        );
        await t.test(
          'an unconfirmed ordinary close must finish with its saved UUID before a distinct latest-key stop can commit',
          async () => {
            const p = await admitted(f, browser),
              clients = [p.a, p.b, p.c];
            try {
              const closePath = `/messaging/channels/${p.failed.next.channel.id}/close`,
                stopPath = `/messaging/channels/${p.failed.next.channel.id}/replace/stop`;
              p.a.loss = { path: closePath, method: 'POST' };
              await assert.rejects(() => recover(p.a, p.previous, p.failed.next));
              const root = await p.a.recovery(p.failed.next);
              assert.equal(root.phase, 'closing');
              const d = await rotate(f, browser, p);
              clients.push(d);
              await assert.rejects(() =>
                p.a.page.evaluate(
                  ({ previous, next }) => custodyDevice.stopReplacement(previous, next),
                  p.failed,
                ),
              );
              assert.equal(p.a.requests.filter((r) => r.path === stopPath).length, 0);
              assert.equal((await snapshot(p.a)).replacement_stops.length, 0);
              await p.a.abortCommand('complete_close');
              await click(p.a, '停止の確認を再試行');
              assert.equal((await p.a.recovery(p.failed.next)).phase, 'closing');
              await p.a.restart();
              await p.a.open();
              await p.a.chat();
              await click(p.a, '停止の確認を再試行');
              assert.equal((await p.a.recovery(p.failed.next)).phase, 'closed');
              const closes = p.a.requests.filter((r) => r.path === closePath);
              assert.equal(closes.length, 3);
              assert.equal(new Set(closes.map((r) => r.body)).size, 1);
              await stop(p.a);
              assert.equal(
                (await snapshot(p.a)).replacement_stops[0].recovery_id,
                root.operation_id,
              );
              assert.notEqual(
                (await snapshot(p.a)).replacement_stops[0].operation_id,
                root.operation_id,
              );
              await importStop(d, p.previous, p.failed.next);
              await fresh(p.a, d);
              await approve(p.a);
              await approve(d);
              await complete(p.a, d);
              await text(p.a, d, '停止応答の再確認後に届いた本文');
            } finally {
              for (const c of clients) await c.close();
            }
          },
        );
        await t.test(
          'a witnessed pending stop blocks saved-consent synchronization and raw native activation even while both old endpoints remain current',
          async () => {
            const p = await admitted(f, browser),
              clients = [p.a, p.b, p.c];
            try {
              const path = `/messaging/channels/${p.failed.next.channel.id}/replace/stop`;
              p.a.dropRequest = { path, method: 'POST' };
              await assert.rejects(() =>
                p.a.page.evaluate(
                  ({ previous, next }) => custodyDevice.stopReplacement(previous, next),
                  p.failed,
                ),
              );
              const stopped = (await snapshot(p.a)).replacement_stops[0];
              assert.equal(stopped.phase, 'stopping');
              assert.equal((await snapshot(p.a)).replacements.at(-1)!.phase, 'consented');
              assert.equal(
                (await f.env.DB.prepare('SELECT blocked FROM messaging_channel WHERE channel_id=?')
                  .bind(p.failed.next.channel.id)
                  .first<{ blocked: number }>())!.blocked,
                0,
              );
              const channelRequests = () =>
                p.a.requests.filter((r) => r.path.startsWith('/messaging/channels/')).length;
              const before = channelRequests();
              assert.equal(
                (
                  await p.a.page.evaluate(
                    ({ previous, next }) => custodyDevice.syncReplacement(previous, next),
                    p.failed,
                  )
                ).phase,
                'recovery_required',
              );
              assert.equal(channelRequests(), before);
              for (const kind of ['consent_replacement', 'activate_replacement'] as const) {
                const result = await p.a.page.evaluate(
                  ({ kind, previous, next }) =>
                    custodyDevice.request(crypto.randomUUID(), {
                      kind,
                      previous: JSON.stringify(previous),
                      next: JSON.stringify(next),
                    }),
                  { kind, ...p.failed },
                );
                assert.equal(result.ok, false);
                assert.equal(result.error, 'conversation_frozen');
              }
              assert.equal((await snapshot(p.a)).replacements.at(-1)!.phase, 'consented');
              assert.deepEqual((await snapshot(p.a)).invitation!.offer, p.previous);
              await p.a.page.evaluate(
                ({ previous, next }) => custodyDevice.stopReplacement(previous, next),
                p.failed,
              );
              assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'stopped');
              const writes = p.a.requests.filter((r) => r.path === path);
              assert.equal(writes.length, 2);
              assert.equal(writes[0].body, writes[1].body);
              assert.equal(
                p.a.requests.filter(
                  (r) =>
                    r.path === `/messaging/channels/${p.failed.next.channel.id}/invitation/packets`,
                ).length,
                0,
              );
              await assert.rejects(() => p.a.box(), /conversation_frozen/);
            } finally {
              for (const c of clients) await c.close();
            }
          },
        );
        await t.test(
          'pending same-key successors cannot be skipped; their exact confirmed deferred closes can link to a root stop',
          async () => {
            const p = await admitted(f, browser),
              clients = [p.a, p.b, p.c];
            try {
              await recover(p.a, p.previous, p.failed.next);
              const next = successor(p.failed.next);
              assert.equal(await p.a.approveRejoin(p.failed.next, next), false);
              await p.c.stop(p.failed.next, 'cancel_invitation');
              assert.equal(await p.c.approveRejoin(p.failed.next, next), true);
              const d = await rotate(f, browser, p);
              clients.push(d);
              const before = await p.a.recovery(p.failed.next),
                path = `/messaging/channels/${p.failed.next.channel.id}/replace/stop`;
              await expect(
                p.a.page.getByRole('button', { name: '承認済みの参加先を停止', exact: true }),
              ).toHaveCount(0);
              await assert.rejects(() =>
                p.a.page.evaluate(
                  ({ previous, next }) => custodyDevice.stopReplacement(previous, next),
                  p.failed,
                ),
              );
              assert.deepEqual(await p.a.recovery(p.failed.next), before);
              assert.equal((await snapshot(p.a)).replacement_stops.length, 0);
              assert.equal(p.a.requests.filter((r) => r.path === path).length, 0);
              await p.a.page.evaluate(
                ({ previous, next }) => custodyDevice.recoverRejoin(previous, next),
                { previous: p.failed.next, next },
              );
              const child = await p.a.recovery(next);
              assert.equal(child.phase, 'closed');
              assert.equal(child.deferred_from, p.failed.next.channel.id);
              await p.a.page.evaluate(
                ({ previous, next }) => custodyDevice.stopReplacement(previous, next),
                p.failed,
              );
              assert.equal((await p.a.recovery(next)).operation_id, child.operation_id);
              assert.deepEqual((await p.a.recovery(next)).abandoned, []);
              assert.deepEqual((await snapshot(p.a)).replacement_stops[0].recovery_chain, [
                before.operation_id,
                child.operation_id,
              ]);
              assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'stopped');
              assert.equal(p.a.requests.filter((r) => r.path === path).length, 1);
              await assert.rejects(() => p.a.box(), /conversation_frozen/);
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
