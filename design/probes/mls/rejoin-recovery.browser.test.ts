import { qualificationTimeout } from './test-timeout.ts';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, firefox, webkit, expect, type Browser } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { Client, admit, successor } from './vault-browser-support.ts';
import { setup, prepare, approve, complete, click } from './replacement-browser-support.ts';
import { fixture, ORIGIN } from './server-support.ts';
import type { InvitationOffer } from './delivery-types.ts';
async function snapshot(c: Client) {
  return c.page.evaluate(() => custodyDevice.chatSnapshot());
}
async function recover(c: Client, previous: InvitationOffer, next: InvitationOffer) {
  return c.page.evaluate(({ previous, next }) => custodyDevice.recoverRejoin(previous, next), {
    previous,
    next,
  });
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
    ({ previous, id }) => custodyDevice.sendText(id, previous.channel, '元の会話の未送信本文'),
    { previous, id: randomUUID() },
  );
  assert.equal(sent.ok, true);
  await a.stop(previous, 'leave');
  await b.stop(previous, 'leave');
  return { a, b, previous };
}
async function stalled(a: Client, b: Client, previous: InvitationOffer) {
  const next = successor(previous);
  assert.equal(await a.approveRejoin(previous, next), false);
  assert.equal(await b.approveRejoin(previous, next), true);
  await b.syncRejoin(previous, next);
  await b.stop(next, 'cancel_invitation');
  assert.equal((await a.syncRejoin(previous, next)).phase, 'recovery_required');
  return next;
}
async function finish(
  a: Client,
  b: Client,
  previous: InvitationOffer,
  next = successor(previous, true),
) {
  assert.equal(await a.approveRejoin(previous, next), false);
  assert.equal(await b.approveRejoin(previous, next), true);
  for (let n = 0; n < 3; n++) {
    await a.syncRejoin(previous, next);
    await b.syncRejoin(previous, next);
  }
  assert.equal((await snapshot(a)).invitation!.phase, 'active');
  assert.equal((await snapshot(b)).invitation!.phase, 'active');
  return next;
}
async function text(a: Client, b: Client, offer: InvitationOffer) {
  const sent = await a.page.evaluate(
    (route) => custodyDevice.sendText(crypto.randomUUID(), route, '新しく承認した再参加先'),
    offer.channel,
  );
  assert.equal(sent.ok, true);
  await a.sync(offer.channel);
  await b.sync(offer.channel);
  assert.ok(
    (await snapshot(b)).received.some((r) =>
      JSON.stringify(r.event).includes('新しく承認した再参加先'),
    ),
  );
  assert.ok(
    !(await snapshot(b)).received.some((r) =>
      JSON.stringify(r.event).includes('元の会話の未送信本文'),
    ),
  );
}
async function uiApprove(c: Client) {
  const approve = c.page.getByRole('button', { name: 'このコードで再参加を承認', exact: true });
  await expect(approve).toBeDisabled();
  await c.page
    .getByRole('checkbox', {
      name: '別の連絡手段で確認した相手の指紋と、この会話のコードが一致しています',
      exact: true,
    })
    .check();
  await click(c, 'このコードで再参加を承認');
  await expect(c.page.getByRole('alert')).toHaveText('');
}
async function uiProposal(a: Client, b: Client) {
  await a.chat();
  await b.chat();
  await click(a, '再参加コードを作る');
  const code = await a.page
    .getByRole('textbox', { name: '共有する招待コード', exact: true })
    .inputValue();
  await b.page.getByRole('textbox', { name: '受け取った招待コード', exact: true }).fill(code);
  await click(b, 'コードを確認');
  await uiApprove(a);
  await uiApprove(b);
}
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: same-key rejoin failure recovery`,
    { timeout: qualificationTimeout(300_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        await t.test(
          'peer closes before local restart: explicit recovery, stable close/rejoin retries, atomic retirement and independently approved fresh UI code',
          async () => {
            const { a, b, previous } = await pair(f, browser);
            try {
              const failed = successor(previous);
              assert.equal(await a.approveRejoin(previous, failed), false);
              assert.equal(await b.approveRejoin(previous, failed), true);
              await b.syncRejoin(previous, failed);
              const rejoinPath = `${ORIGIN}/messaging/channels/${failed.channel.id}/rejoin`;
              let closed = false;
              await a.page.route(rejoinPath, async (route) => {
                if (!closed) {
                  closed = true;
                  await b.stop(failed, 'cancel_invitation');
                }
                await route.fallback();
              });
              assert.equal((await a.syncRejoin(previous, failed)).phase, 'recovery_required');
              await a.page.unroute(rejoinPath);
              assert.equal((await a.recovery(previous)).successor_failed, true);
              assert.deepEqual((await snapshot(a)).invitation!.offer, previous);
              await a.chat();
              await expect(
                a.page.getByRole('button', { name: '再参加先を停止してやり直す', exact: true }),
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
                  path: 'local/generated/mls/rejoin-recovery-chromium.png',
                  fullPage: true,
                });
              }
              await a.abortCommand('begin_rejoin_recovery');
              await assert.rejects(() => recover(a, previous, failed));
              assert.equal((await snapshot(a)).recoveries.length, 1);
              const path = `/messaging/channels/${failed.channel.id}/close`;
              assert.equal(a.requests.filter((r) => r.path === path).length, 0);
              a.loss = { path, method: 'POST' };
              await a.page
                .getByRole('checkbox', {
                  name: 'この再参加先を停止し、新しい会話への参加をやり直します',
                  exact: true,
                })
                .check();
              await click(a, '再参加先を停止してやり直す');
              const closing = await a.recovery(failed);
              assert.equal(closing.phase, 'closing');
              assert.equal(closing.deferred_from, previous.channel.id);
              await a.restart();
              await a.open();
              await a.chat();
              await a.abortCommand('complete_close');
              await click(a, '停止の確認を再試行');
              assert.equal((await a.recovery(failed)).phase, 'closing');
              await a.restart();
              await a.open();
              await a.chat();
              await click(a, '停止の確認を再試行');
              assert.equal((await a.recovery(failed)).operation_id, closing.operation_id);
              const attempts = a.requests.filter((r) => r.path === path);
              assert.equal(attempts.length, 3);
              assert.equal(attempts[0].body, attempts[1].body);
              assert.equal(attempts[1].body, attempts[2].body);
              await assert.rejects(() => a.box(), /conversation_frozen/);
              await assert.rejects(
                () => a.approveRejoin(previous, successor(previous)),
                /rejoin_intent_conflict|rejoin_recovery_required/,
              );
              await uiProposal(a, b);
              const fresh = (await a.recovery(failed)).next!;
              a.loss = { path: `/messaging/channels/${fresh.channel.id}/rejoin`, method: 'POST' };
              await assert.rejects(() => a.syncRejoin(failed, fresh));
              await a.abortCommand('activate_rejoin');
              await assert.rejects(() => a.syncRejoin(failed, fresh));
              assert.equal((await a.recovery(previous)).phase, 'closed');
              assert.equal((await a.recovery(failed)).phase, 'closed');
              await a.restart();
              await a.open();
              await a.chat();
              await complete(a, b);
              assert.equal((await a.recovery(previous)).phase, 'rejoined');
              assert.equal((await a.recovery(failed)).phase, 'rejoined');
              assert.equal((await a.recovery(previous)).abandoned.length, 1);
              assert.equal((await a.recovery(failed)).abandoned.length, 0);
              await text(a, b, fresh);
              for (const old of [previous, failed]) {
                const result = await a.page.evaluate(
                  (group) =>
                    custodyDevice.request(crypto.randomUUID(), { kind: 'create_group', group }),
                  Array.from(Buffer.from(old.channel.group, 'base64url')),
                );
                assert.equal(result.ok, false);
              }
            } finally {
              await a.close();
              await b.close();
            }
          },
        );
        await t.test(
          'repeated pre-activation closures retain every immutable proposal and consume exactly the shared eight retirement slots',
          async () => {
            const { a, b, previous } = await pair(f, browser);
            try {
              let current = previous;
              const abandoned: InvitationOffer[] = [previous];
              for (let n = 0; n < 7; n++) {
                const failed = await stalled(a, b, current);
                await recover(a, current, failed);
                abandoned.push(failed);
                current = failed;
                assert.equal((await a.recovery(current)).phase, 'closed');
                assert.equal(
                  (await a.recovery(current)).deferred_from,
                  abandoned.at(-2)!.channel.id,
                );
              }
              await a.restart();
              await a.open();
              const fresh = await finish(a, b, current);
              await text(a, b, fresh);
              const history = (await snapshot(a)).recoveries;
              assert.equal(history.length, 8);
              assert.ok(history.every((r) => r.phase === 'rejoined'));
              assert.equal(history[0].abandoned.length, 1);
              assert.ok(history.slice(1).every((r) => r.abandoned.length === 0));
              for (const old of abandoned) {
                const result = await a.page.evaluate(
                  (group) =>
                    custodyDevice.request(crypto.randomUUID(), { kind: 'create_group', group }),
                  Array.from(Buffer.from(old.channel.group, 'base64url')),
                );
                assert.equal(result.ok, false);
              }
              await a.stop(fresh, 'leave');
              await b.stop(fresh, 'leave');
              const impossible = successor(fresh);
              const before = a.requests.filter((r) => r.path.endsWith('/rejoin')).length;
              await assert.rejects(
                () => a.approveRejoin(fresh, impossible),
                /recovery_ledger_full/,
              );
              assert.equal(a.requests.filter((r) => r.path.endsWith('/rejoin')).length, before);
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT channel_id FROM messaging_channel WHERE channel_id=?',
                )
                  .bind(impossible.channel.id)
                  .first(),
                null,
              );
              await assert.rejects(() => a.box(), /conversation_frozen/);
            } finally {
              await a.close();
              await b.close();
            }
          },
        );
        await t.test(
          'lost successful approval/status replies do not imply failure; expired KeyPackage before local restart persists recovery across reload',
          async () => {
            const { a, b, previous } = await pair(f, browser);
            try {
              const failed = successor(previous),
                path = `/messaging/channels/${failed.channel.id}/rejoin`;
              a.loss = { path, method: 'POST' };
              await assert.rejects(() => a.approveRejoin(previous, failed));
              assert.equal((await a.syncRejoin(previous, failed)).phase, 'waiting_peer');
              assert.equal((await a.recovery(previous)).successor_failed, undefined);
              assert.equal(await b.approveRejoin(previous, failed), true);
              await b.syncRejoin(previous, failed);
              await f.env.DB.prepare(
                'UPDATE messaging_invitation_packet SET expires_at=unixepoch()-1 WHERE channel_id=?',
              )
                .bind(failed.channel.id)
                .run();
              a.loss = { path: `${path}/status`, method: 'POST' };
              await assert.rejects(() => a.syncRejoin(previous, failed));
              assert.equal((await a.recovery(previous)).successor_failed, undefined);
              assert.equal((await a.syncRejoin(previous, failed)).phase, 'recovery_required');
              await a.restart();
              await a.open();
              assert.equal((await a.recovery(previous)).successor_failed, true);
              assert.equal((await b.syncRejoin(previous, failed)).phase, 'recovery_required');
              await b.stop(failed, 'cancel_invitation');
              await recover(a, previous, failed);
              const fresh = await finish(a, b, failed);
              await text(a, b, fresh);
            } finally {
              await a.close();
              await b.close();
            }
          },
        );
        await t.test(
          'a lost unpublished approval cannot stop an absent candidate; after the peer explicitly approves then stops it, both endpoints can confirm closure without publishing a KP',
          async () => {
            const { a, b, previous } = await pair(f, browser);
            try {
              const failed = successor(previous),
                path = `/messaging/channels/${failed.channel.id}/rejoin`;
              a.dropRequest = { path, method: 'POST' };
              await assert.rejects(() => a.approveRejoin(previous, failed));
              await assert.rejects(() => recover(a, previous, failed), /rejoin_unconfirmed/);
              assert.equal(
                await f.env.DB.prepare(
                  'SELECT channel_id FROM messaging_channel WHERE channel_id=?',
                )
                  .bind(failed.channel.id)
                  .first(),
                null,
              );
              assert.equal(await b.approveRejoin(previous, failed), false);
              assert.equal((await recover(b, previous, failed)).phase, 'closed');
              assert.equal((await a.syncRejoin(previous, failed)).phase, 'recovery_required');
              assert.equal((await recover(a, previous, failed)).phase, 'closed');
              assert.equal(
                (await f.env.DB.prepare(
                  'SELECT count(*) AS n FROM messaging_invitation_packet WHERE channel_id=?',
                )
                  .bind(failed.channel.id)
                  .first<{ n: number }>())!.n,
                0,
              );
              const fresh = await finish(a, b, failed);
              await text(a, b, fresh);
            } finally {
              await a.close();
              await b.close();
            }
          },
        );
        await t.test(
          'a deferred changed-key recovery can itself abandon a rejoin; Vault lock at its witness releases no late close and fresh UI consent normalizes the whole chain',
          async () => {
            const { a, b, c, previous, predecessor } = await setup(f, browser);
            try {
              await c.init();
              await c.manager();
              await c.page.evaluate((old) => custodyDevice.createReplacement(old), predecessor);
              const { next } = await prepare(a, c);
              await approve(a);
              await approve(c);
              await c.stop(next, 'cancel_invitation');
              await a.page.evaluate(
                ({ previous, next }) => custodyDevice.syncReplacement(previous, next),
                { previous, next },
              );
              await a.page.evaluate(
                ({ previous, next }) => custodyDevice.recoverReplacement(previous, next),
                { previous, next },
              );
              const failed = await stalled(a, c, next);
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
              const pending = recover(a, next, failed).then(
                () => 'unexpected_success',
                () => 'locked',
              );
              await arrived;
              await a.page.evaluate(() => custodyOwner.lock());
              release();
              assert.equal(await pending, 'locked');
              const path = `/messaging/channels/${failed.channel.id}/close`;
              assert.equal(a.requests.filter((r) => r.path === path).length, 0);
              await a.restart();
              await a.open();
              assert.equal((await recover(a, next, failed)).phase, 'closed');
              assert.equal((await snapshot(a)).replacements.at(-1)!.phase, 'abandoned');
              const vetoed = successor(failed);
              assert.equal(await a.approveRejoin(failed, vetoed), false);
              assert.equal(
                await a.page.evaluate(
                  ({ failed, vetoed }) => custodyDevice.cancelRejoin(failed, vetoed),
                  { failed, vetoed },
                ),
                'cancelled',
              );
              assert.equal((await a.recovery(failed)).next, null);
              await uiProposal(a, c);
              await complete(a, c);
              assert.equal((await snapshot(a)).replacements.at(-1)!.phase, 'active');
              assert.equal((await a.recovery(next)).phase, 'rejoined');
              assert.equal((await a.recovery(failed)).phase, 'rejoined');
              await text(a, c, (await snapshot(a)).invitation!.offer);
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
