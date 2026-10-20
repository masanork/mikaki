import { qualificationTimeout } from './test-timeout.ts';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, firefox, webkit, expect, type Browser } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { Client, successor, stored } from './vault-browser-support.ts';
import {
  setup,
  pin,
  approve as approveReplacement,
  complete,
  click,
} from './replacement-browser-support.ts';
import { parseReplacementCode, replacementCode } from './replacement-types.ts';
import type { InvitationOffer } from './delivery-types.ts';
import type { VerifiedDevice } from './peer-review.ts';
import { fixture } from './server-support.ts';
async function snapshot(c: Client) {
  return c.page.evaluate(() => custodyDevice.chatSnapshot());
}
async function approve(c: Client) {
  await approveReplacement(c);
  await expect(c.page.getByRole('alert')).toHaveText('');
}
async function rotate(
  f: Awaited<ReturnType<typeof fixture>>,
  browser: Browser,
  original: Client,
  old: VerifiedDevice,
) {
  const c = new Client(f, browser, original.who, original.id);
  c.prf.splice(0, c.prf.length, ...original.prf);
  await c.init();
  await c.manager();
  await c.page.evaluate((old) => custodyDevice.createReplacement(old), old);
  return c;
}
async function code(a: Client, b: Client) {
  await click(a, '鍵切り替えコードを作る');
  const text = await a.page
    .getByRole('textbox', { name: '共有する鍵切り替えコード', exact: true })
    .inputValue();
  await b.page.getByRole('textbox', { name: '受け取った鍵切り替えコード', exact: true }).fill(text);
  await click(b, '鍵切り替えコードを確認');
  await expect(
    a.page.getByRole('button', { name: '新しい鍵での会話を承認', exact: true }),
  ).toBeDisabled();
  await expect(
    b.page.getByRole('button', { name: '新しい鍵での会話を承認', exact: true }),
  ).toBeDisabled();
  return parseReplacementCode(text);
}
async function veto(c: Client) {
  await c.page
    .getByRole('checkbox', {
      name: 'この切り替え案を中止し、旧会話を停止したままにします',
      exact: true,
    })
    .check();
  await click(c, 'この切り替え案を中止');
}
async function pendingText(a: Client, old: InvitationOffer) {
  const result = await a.page.evaluate(
    ({ old, id }) => custodyDevice.sendText(id, old.channel, '更新前の会話で保留した本文'),
    { old, id: randomUUID() },
  );
  assert.equal(result.ok, true);
}
async function text(a: Client, b: Client, next: InvitationOffer) {
  await a.page
    .getByRole('textbox', { name: 'メッセージ', exact: true })
    .fill('最後に確認した鍵での会話');
  await click(a, '送信');
  await click(b, '同期');
  await expect(b.page.getByRole('region', { name: 'メッセージ履歴', exact: true })).toContainText(
    '最後に確認した鍵での会話',
  );
  await expect(
    b.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
  ).not.toContainText('更新前の会話で保留した本文');
  assert.equal((await snapshot(a)).sent[0].status, 'isolated');
  assert.equal((await snapshot(b)).invitation!.offer.channel.id, next.channel.id);
}
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: repeated device generations during pending negotiation`,
    { timeout: qualificationTimeout(300_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        await t.test(
          'two further key changes require explicit stale-proposal vetoes, independently reviewed latest keys and fresh bilateral consent without adopting old wire',
          async () => {
            const { a, b, c, previous, predecessor } = await setup(f, browser);
            const clients = [a, b, c];
            try {
              await pendingText(a, previous);
              await c.init();
              await c.manager();
              await c.page.evaluate((old) => custodyDevice.createReplacement(old), predecessor);
              await a.chat();
              await c.chat();
              await pin(a, c, true);
              await pin(c, a);
              let proposal = await code(a, c);
              await approve(a);
              const stale: InvitationOffer[] = [];
              for (let n = 0; n < 2; n++) {
                const latest = await rotate(
                  f,
                  browser,
                  b,
                  (await snapshot(a)).trust.peer!.accepted,
                );
                clients.push(latest);
                await latest.chat();
                await pin(a, latest, true);
                await pin(latest, a);
                await expect(
                  a.page.getByText(
                    '相手の鍵が更新されています。承認待ちの古い案を中止し、最新の指紋と新しいコードを双方で確認してください。',
                    { exact: true },
                  ),
                ).toBeVisible();
                if (n === 0) {
                  await a.page.setViewportSize({ width: 390, height: 844 });
                  assert.equal(
                    await a.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
                    true,
                  );
                  assert.deepEqual(
                    (await new AxeBuilder({ page: a.page }).analyze()).violations,
                    [],
                  );
                  if (name === 'chromium') {
                    await mkdir('local/generated/mls', { recursive: true });
                    await a.page.screenshot({
                      path: 'local/generated/mls/generation-negotiation-chromium.png',
                      fullPage: true,
                    });
                  }
                }
                await veto(a);
                stale.push(proposal.next);
                assert.equal((await snapshot(a)).replacements.at(-1)!.phase, 'cancelled');
                await assert.rejects(() => a.box(), /conversation_frozen/);
                proposal = await code(a, latest);
                await approve(a);
                if (n === 1) {
                  await approve(latest);
                  await complete(a, latest);
                  await text(a, latest, proposal.next);
                  assert.equal(
                    ((await stored(latest.page)) as { scope: { device: { generation: number } } })
                      .scope.device.generation,
                    4,
                  );
                  assert.equal(
                    (await snapshot(latest)).replacements.at(-1)!.predecessor_confirmed,
                    true,
                  );
                  await latest.restart();
                  await latest.open();
                  await latest.chat();
                  assert.equal((await snapshot(latest)).replacements.at(-1)!.phase, 'active');
                }
              }
              for (const offer of stale) {
                assert.equal(
                  (await f.env.DB.prepare(
                    'SELECT blocked FROM messaging_channel WHERE channel_id=?',
                  )
                    .bind(offer.channel.id)
                    .first<{ blocked: number }>())!.blocked,
                  1,
                );
                assert.equal(
                  await f.env.DB.prepare(
                    'SELECT message_id FROM messaging_invitation_packet WHERE channel_id=?',
                  )
                    .bind(offer.channel.id)
                    .first(),
                  null,
                );
              }
              assert.equal((await snapshot(a)).replacements[0].abandoned.length, 1);
              for (const old of clients.slice(1, -1))
                await assert.rejects(() => old.sync(previous.channel));
            } finally {
              for (const c of clients) await c.close();
            }
          },
        );
        await t.test(
          'a same-key rejoin interrupted by two registry generations is vetoed under its original parent before explicit changed-key admission',
          async () => {
            const { a, b, c, previous, predecessor } = await setup(f, browser);
            let latest: Client | undefined;
            try {
              await pendingText(a, previous);
              await a.stop(previous, 'leave');
              await b.stop(previous, 'leave');
              const abandoned = successor(previous);
              assert.equal(await a.approveRejoin(previous, abandoned), false);
              await c.init();
              await c.manager();
              await c.page.evaluate((old) => custodyDevice.createReplacement(old), predecessor);
              await a.chat();
              await c.chat();
              await pin(a, c, true);
              latest = await rotate(f, browser, b, (await snapshot(a)).trust.peer!.accepted);
              await latest.chat();
              await pin(a, latest, true);
              await pin(latest, a);
              await expect(
                a.page.getByRole('button', { name: '鍵切り替えコードを作る', exact: true }),
              ).toHaveCount(0);
              await a.page
                .getByRole('checkbox', {
                  name: 'この再参加案を取り消し、元の会話を停止したままにします',
                  exact: true,
                })
                .check();
              await click(a, 'この再参加案を取り消す');
              assert.equal((await a.recovery(previous)).next, null);
              await expect(
                a.page.getByRole('button', { name: '再参加コードを作る', exact: true }),
              ).toHaveCount(0);
              const proposal = await code(a, latest);
              await approve(a);
              await approve(latest);
              await complete(a, latest);
              await text(a, latest, proposal.next);
              assert.equal((await a.recovery(previous)).cancellations![0].outcome, 'cancelled');
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT message_id FROM messaging_invitation_packet WHERE channel_id=?',
                )
                  .bind(abandoned.channel.id)
                  .first(),
                null,
              );
              await assert.rejects(() => b.sync(previous.channel));
            } finally {
              await a.close();
              await b.close();
              await c.close();
              await latest?.close();
            }
          },
        );
        await t.test(
          'changed endpoint veto releases its unused historical marker before selecting a fresh peer code',
          async () => {
            const { a, b, c, previous, predecessor } = await setup(f, browser);
            let latest: Client | undefined;
            try {
              await c.init();
              await c.manager();
              await c.page.evaluate((old) => custodyDevice.createReplacement(old), predecessor);
              await a.chat();
              await c.chat();
              await pin(a, c, true);
              latest = await rotate(f, browser, b, (await snapshot(a)).trust.peer!.accepted);
              await latest.chat();
              await pin(a, latest, true);
              await pin(latest, a);
              const first = await code(a, latest);
              await approve(latest);
              assert.equal(
                (await snapshot(latest)).replacements.at(-1)!.predecessor_confirmed,
                true,
              );
              await veto(latest);
              assert.equal((await snapshot(latest)).replacements.at(-1)!.phase, 'cancelled');
              await latest.restart();
              await latest.open();
              await latest.chat();
              const peerVeto = await code(a, latest);
              await approve(latest);
              a.dropRequest = {
                path: `/messaging/channels/${peerVeto.next.channel.id}/replace`,
                method: 'POST',
              };
              await approveWithoutSuccess(a);
              await veto(a);
              await click(latest, '同期');
              assert.equal((await snapshot(latest)).replacements.at(-1)!.phase, 'cancelled');
              const fresh = await code(a, latest);
              await approve(a);
              await approve(latest);
              await complete(a, latest);
              assert.equal(
                await latest.page.evaluate(
                  ({ previous, next }) => custodyDevice.cancelReplacement(previous, next),
                  first,
                ),
                'cancelled',
              );
              assert.equal((await snapshot(latest)).replacements[0].phase, 'cancelled');
              assert.equal(
                (await snapshot(latest)).replacements.at(-1)!.predecessor_confirmed,
                true,
              );
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT message_id FROM messaging_invitation_packet WHERE channel_id=?',
                )
                  .bind(first.next.channel.id)
                  .first(),
                null,
              );
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT message_id FROM messaging_invitation_packet WHERE channel_id=?',
                )
                  .bind(peerVeto.next.channel.id)
                  .first(),
                null,
              );
              await a.page
                .getByRole('textbox', { name: 'メッセージ', exact: true })
                .fill('取り消し後に選び直した会話');
              await click(a, '送信');
              await click(latest, '同期');
              await expect(
                latest.page.getByRole('region', { name: 'メッセージ履歴', exact: true }),
              ).toContainText('取り消し後に選び直した会話');
              assert.equal(
                (await snapshot(latest)).invitation!.offer.channel.id,
                fresh.next.channel.id,
              );
            } finally {
              await a.close();
              await b.close();
              await c.close();
              await latest?.close();
            }
          },
        );
        await t.test(
          'lost historical proof, aborted native attestation, Vault lock at its witness and failed activation retry the same intent without premature approval or wire',
          async () => {
            const { a, b, c, previous, predecessor } = await setup(f, browser);
            let latest: Client | undefined;
            try {
              await pendingText(a, previous);
              await c.init();
              await c.manager();
              await c.page.evaluate((old) => custodyDevice.createReplacement(old), predecessor);
              await a.chat();
              await c.chat();
              await pin(a, c, true);
              latest = await rotate(f, browser, b, (await snapshot(a)).trust.peer!.accepted);
              await latest.chat();
              await pin(a, latest, true);
              await pin(latest, a);
              const proposal = await code(a, latest);
              await approve(a);
              const path = `/messaging/channels/${proposal.next.channel.id}/replace/predecessor`,
                approvalPath = `/messaging/channels/${proposal.next.channel.id}/replace`;
              latest.loss = { path, method: 'POST' };
              await approveWithoutSuccess(latest);
              const prepared = (await snapshot(latest)).replacements.at(-1)!;
              assert.equal(prepared.phase, 'prepared');
              assert.equal(prepared.predecessor_confirmed, undefined);
              await latest.restart();
              await latest.open();
              await latest.chat();
              await latest.abortCommand('attest_replacement_predecessor');
              await click(latest, '同期');
              assert.equal(
                (await snapshot(latest)).replacements.at(-1)!.predecessor_confirmed,
                undefined,
              );
              assert.equal(latest.requests.filter((r) => r.path === approvalPath).length, 0);
              await latest.restart();
              await latest.open();
              await latest.chat();
              let release!: () => void;
              const reached = new Promise<void>((resolve) => {
                latest!.pauseHead = {
                  reached: resolve,
                  release: new Promise<void>((r) => {
                    release = r;
                  }),
                };
              });
              const pending = click(latest, '同期').catch(() => {});
              await reached;
              await latest.page.evaluate(() => custodyOwner.lock());
              release();
              await pending;
              await expect(
                latest.page.getByText('チャットをロックしました。Vaultを開き直してください。', {
                  exact: true,
                }),
              ).toBeVisible();
              assert.equal(await latest.page.locator('textarea').count(), 0);
              assert.equal(latest.requests.filter((r) => r.path === approvalPath).length, 0);
              await latest.restart();
              await latest.open();
              await latest.chat();
              assert.equal(
                (await snapshot(latest)).replacements.at(-1)!.predecessor_confirmed,
                true,
              );
              await latest.abortCommand('activate_replacement');
              await click(latest, '同期');
              assert.equal((await snapshot(latest)).replacements.at(-1)!.phase, 'consented');
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT message_id FROM messaging_invitation_packet WHERE channel_id=?',
                )
                  .bind(proposal.next.channel.id)
                  .first(),
                null,
              );
              await latest.restart();
              await latest.open();
              await latest.chat();
              await complete(a, latest);
              await text(a, latest, proposal.next);
              const proofs = latest.requests.filter((r) => r.path === path);
              assert.equal(proofs.length, 3);
              assert.equal(proofs[0].body, proofs[1].body);
              assert.equal(proofs[1].body, proofs[2].body);
              assert.equal(
                (await snapshot(latest)).replacements.at(-1)!.operation_id,
                prepared.operation_id,
              );
              for (const r of latest.requests.filter((r) => r.path === approvalPath))
                assert.equal(JSON.parse(r.body!).operation_id, prepared.operation_id);
              assert.equal(
                replacementCode(proposal.previous, proposal.next).startsWith('mikaki-replace-v1:'),
                true,
              );
            } finally {
              await a.close();
              await b.close();
              await c.close();
              await latest?.close();
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
async function approveWithoutSuccess(c: Client) {
  await c.page
    .getByRole('checkbox', {
      name: '確認した新しい指紋とコードが一致し、旧会話を閉じることに同意します',
      exact: true,
    })
    .check();
  await click(c, '新しい鍵での会話を承認');
  await expect(c.page.getByRole('alert')).not.toHaveText('');
}
