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
import type { DeviceEngine } from './device-store.ts';
import type { InvitationOffer } from './delivery-types.ts';
type Server = Awaited<ReturnType<typeof fixture>>;
declare global {
  var stopNativeModes: string[];
}
const snapshot = (c: Client) => c.page.evaluate(() => custodyDevice.chatSnapshot());
async function observeNative(c: Client) {
  await c.page.evaluate(() => {
    stopNativeModes = [];
    const prototype = (custodyWasm.BoundMlsClient as unknown as { prototype: DeviceEngine })
      .prototype;
    const original = prototype.check_activated_replacement_origin;
    prototype.check_activated_replacement_origin = function (...args) {
      const mode = original.apply(this, args);
      stopNativeModes.push(mode);
      return mode;
    };
  });
}
async function advanced(f: Server, browser: Browser, mode: string) {
  const p = await setup(f, browser);
  await p.c.init();
  await p.c.manager();
  await p.c.page.evaluate((old) => custodyDevice.createReplacement(old), p.predecessor);
  assert.equal(
    (
      await p.a.page.evaluate(
        ({ id, route }) => custodyDevice.sendText(id, route, '元の会話で隔離する本文'),
        { id: randomUUID(), route: p.previous.channel },
      )
    ).ok,
    true,
  );
  const failed = await prepare(p.a, p.c);
  await approve(p.a);
  await approve(p.c);
  const s = await snapshot(p.a);
  if (mode === 'unjoined')
    p.a.dropRequest = {
      path: `/messaging/channels/${failed.next.channel.id}/invitation/${s.own.scope}`,
      method: 'GET',
    };
  if (mode === 'forming') {
    const packet = (await snapshot(p.c)).invitation!;
    assert.equal(packet.phase, 'prepared');
    const kp = p.c.requests.find(
      (r) => r.path === `/messaging/channels/${failed.next.channel.id}/invitation/packets`,
    )!;
    p.a.loss = {
      path: `/messaging/channels/${failed.next.channel.id}/invitation/packets/${JSON.parse(kp.body!).message_id}/consume`,
      method: 'POST',
    };
  }
  await click(p.a, '同期');
  if (mode === 'joined') await complete(p.a, p.c);
  else await expect(p.a.page.getByRole('alert')).not.toHaveText('');
  const current = await snapshot(p.a);
  assert.equal(current.replacements.at(-1)!.phase, 'active');
  assert.equal(
    current.invitation!.phase,
    mode === 'joined' ? 'active' : mode === 'forming' ? 'invited' : 'prepared',
  );
  if (mode === 'forming') {
    await p.c.stop(failed.next, 'cancel_invitation');
    assert.equal((await p.a.syncInvite(failed.next)).phase, 'recovery_required');
    assert.equal((await snapshot(p.a)).invitation!.phase, 'recovery_required');
    assert.deepEqual((await snapshot(p.a)).recoveries, []);
  }
  return { ...p, failed };
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
  await a.chat();
  await c.chat();
  await pin(a, c, true);
  await pin(c, a);
  return c;
}
async function stop(c: Client) {
  await expect(
    c.page.getByRole('button', { name: '承認済みの参加先を停止', exact: true }),
  ).toBeDisabled();
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
async function assertFences(c: Client, offers: InvitationOffer[]) {
  for (const offer of offers) {
    const result = await c.page.evaluate(
      (group) => custodyDevice.request(crypto.randomUUID(), { kind: 'create_group', group }),
      Array.from(Buffer.from(offer.channel.group, 'base64url')),
    );
    assert.equal(result.ok, false);
    assert.equal(result.error, 'retired_or_unexpected_group');
  }
}
async function text(a: Client, b: Client) {
  await a.page
    .getByRole('textbox', { name: 'メッセージ', exact: true })
    .fill('進んだ参加先から最新鍵へ復旧した本文');
  await click(a, '送信');
  await click(b, '同期');
  const h = b.page.getByRole('region', { name: 'メッセージ履歴', exact: true });
  await expect(h).toContainText('進んだ参加先から最新鍵へ復旧した本文');
  for (const old of ['元の会話で隔離する本文', '参加済みの会話で隔離する本文'])
    await expect(h).not.toContainText(old);
  for (const sent of (await snapshot(a)).sent.filter(
    (s) => s.text !== '進んだ参加先から最新鍵へ復旧した本文',
  ))
    assert.equal(sent.status, 'isolated');
}
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: latest-key recovery after native replacement activation`,
    { timeout: qualificationTimeout(600_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        for (const mode of ['unjoined', 'forming', 'joined'])
          await t.test(
            `${mode}: exact native origin survives witnessed stop and fresh bilateral approval`,
            async () => {
              const p = await advanced(f, browser, mode),
                clients = [p.a, p.b, p.c];
              const originalQuarantine = (await snapshot(p.a)).replacements[0].abandoned;
              assert.equal(originalQuarantine.length, 1);
              try {
                if (mode === 'joined')
                  assert.equal(
                    (
                      await p.a.page.evaluate(
                        ({ id, route }) =>
                          custodyDevice.sendText(id, route, '参加済みの会話で隔離する本文'),
                        { id: randomUUID(), route: p.failed.next.channel },
                      )
                    ).ok,
                    true,
                  );
                let d = await rotate(f, browser, p.b, p.a);
                clients.push(d);
                await observeNative(p.a);
                const stopPath = `/messaging/channels/${p.failed.next.channel.id}/replace/stop`;
                if (mode === 'unjoined') p.a.loss = { path: stopPath, method: 'POST' };
                if (mode === 'forming') await p.a.abortCommand('begin_stop_replacement');
                await stop(p.a);
                const nativeModes = await p.a.page.evaluate(() => stopNativeModes);
                assert.equal(nativeModes.length > 0, true);
                assert.equal(
                  nativeModes.every((m) => m === mode),
                  true,
                );
                if (mode === 'forming') {
                  assert.equal((await snapshot(p.a)).replacement_stops.length, 0);
                  assert.equal(p.a.requests.filter((r) => r.path === stopPath).length, 0);
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
                  assert.equal((await snapshot(p.a)).replacement_stops[0].native_origin, true);
                  p.a.forgedStopReceipt = true;
                  await click(p.a, '同期');
                  assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'stopping');
                }
                if (mode !== 'joined') {
                  assert.equal((await snapshot(p.a)).replacement_stops[0].native_origin, true);
                  await p.a.restart();
                  await p.a.open();
                  await p.a.chat();
                  if (mode === 'unjoined') {
                    await p.a.abortCommand('complete_stop_replacement');
                    await click(p.a, '同期');
                    assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'stopping');
                  }
                  await click(p.a, '同期');
                }
                await expect(p.a.page.getByRole('alert')).toHaveText('');
                const stopped = (await snapshot(p.a)).replacement_stops[0];
                assert.equal(stopped.phase, 'stopped');
                assert.equal(stopped.native_origin, true);
                assert.equal(
                  stopped.abandoned.length,
                  mode === 'forming' ? 2 : mode === 'joined' ? 1 : 0,
                );
                const requests = p.a.requests.filter((r) =>
                  r.path.startsWith('/messaging/channels/'),
                ).length;
                assert.equal(
                  (
                    await p.a.page.evaluate(
                      ({ previous, next }) => custodyDevice.syncReplacement(previous, next),
                      p.failed,
                    )
                  ).phase,
                  'recovery_required',
                );
                assert.equal(
                  p.a.requests.filter((r) => r.path.startsWith('/messaging/channels/')).length,
                  requests,
                );
                const blocked = await p.a.page.evaluate(
                  ({ previous, next }) =>
                    custodyDevice.request(crypto.randomUUID(), {
                      kind: 'activate_replacement',
                      previous: JSON.stringify(previous),
                      next: JSON.stringify(next),
                    }),
                  p.failed,
                );
                assert.equal(blocked.ok, false);
                assert.equal(blocked.error, 'conversation_frozen');

                assert.equal((await snapshot(p.a)).replacements[0].phase, 'active');
                assert.deepEqual(
                  (await snapshot(p.a)).replacements[0].abandoned,
                  originalQuarantine,
                );
                const writes = p.a.requests.filter((r) => r.path === stopPath);
                assert.equal(new Set(writes.map((r) => r.body)).size, 1);
                await assert.rejects(() => p.a.box(), /conversation_frozen/);
                await importStop(d, p.previous, p.failed.next);
                if (mode === 'joined') {
                  await p.a.page.setViewportSize({ width: 390, height: 844 });
                  assert.equal(
                    await p.a.page.evaluate(
                      () => document.documentElement.scrollWidth <= innerWidth,
                    ),
                    true,
                  );
                  assert.deepEqual(
                    (await new AxeBuilder({ page: p.a.page }).analyze()).violations,
                    [],
                  );
                  if (name === 'chromium') {
                    await mkdir('local/generated/mls', { recursive: true });
                    await p.a.page.screenshot({
                      path: 'local/generated/mls/replacement-stop-advanced-chromium.png',
                      fullPage: true,
                    });
                  }
                }
                let proposal = await fresh(p.a, d);
                await approve(p.a);
                await approve(d);
                await p.a.abortCommand('activate_replacement');
                await click(p.a, '同期');
                assert.equal((await snapshot(p.a)).replacement_stops[0].phase, 'stopped');
                assert.equal(
                  (await snapshot(p.a)).invitation!.offer.channel.id,
                  p.failed.next.channel.id,
                );
                const retired = [p.previous, p.failed.next];
                if (mode === 'joined') {
                  retired.push(proposal.next);
                  d = await rotate(f, browser, p.b, p.a);
                  clients.push(d);
                  await stop(p.a);
                  await expect(p.a.page.getByRole('alert')).toHaveText('');
                  assert.deepEqual(
                    (await snapshot(p.a)).replacement_stops.map((s) => s.native_origin),
                    [true, undefined],
                  );
                  await importStop(d, p.previous, proposal.next);
                  proposal = await fresh(p.a, d);
                  await approve(p.a);
                  await approve(d);
                } else {
                  await p.a.restart();
                  await p.a.open();
                  await p.a.chat();
                }
                await complete(p.a, d);
                await expect(p.a.page.getByRole('alert')).toHaveText('');
                const final = await snapshot(p.a);
                assert.equal(final.invitation!.offer.channel.id, proposal.next.channel.id);
                assert.equal(final.replacements[0].phase, 'active');
                assert.deepEqual(final.replacements[0].abandoned, originalQuarantine);
                assert.equal(final.replacements.at(-1)!.phase, 'active');
                assert.equal(
                  final.replacement_stops.every((s) => s.phase === 'retired'),
                  true,
                );
                await text(p.a, d);
                await assertFences(p.a, retired);
                await assertFences(d, retired);
                await p.a.restart();
                await p.a.open();
                await p.a.chat();
                await assertFences(p.a, retired);
                if (mode === 'joined') {
                  let current = proposal.next;
                  for (let i = retired.length; i < 8; i++) {
                    await p.a.stop(current, 'leave');
                    await d.stop(current, 'leave');
                    const next = successor(current);
                    assert.equal(await p.a.approveRejoin(current, next), false);
                    assert.equal(await d.approveRejoin(current, next), true);
                    for (let j = 0; j < 3; j++) {
                      await p.a.syncRejoin(current, next);
                      await d.syncRejoin(current, next);
                    }
                    assert.equal((await snapshot(p.a)).invitation!.phase, 'active');
                    current = next;
                  }
                  await p.a.stop(current, 'leave');
                  await d.stop(current, 'leave');
                  const count = p.a.requests.filter((r) => r.path.endsWith('/rejoin')).length;
                  await assert.rejects(
                    () => p.a.approveRejoin(current, successor(current)),
                    /recovery_ledger_full/,
                  );
                  assert.equal(
                    p.a.requests.filter((r) => r.path.endsWith('/rejoin')).length,
                    count,
                  );
                }
              } finally {
                for (const c of clients) await c.close();
              }
            },
          );
        await t.test(
          'alternating endpoint key changes keep using the completed current conversation; the changed endpoint cannot freeze it through the old anchor',
          async () => {
            const p = await advanced(f, browser, 'joined'),
              clients = [p.a, p.b, p.c];
            try {
              assert.equal(
                (
                  await p.c.page.evaluate(
                    ({ id, route }) =>
                      custodyDevice.sendText(id, route, '参加済みの会話で隔離する本文'),
                    { id: randomUUID(), route: p.failed.next.channel },
                  )
                ).ok,
                true,
              );
              const nextAlice = await rotate(f, browser, p.a, p.c);
              clients.push(nextAlice);
              await expect(
                p.c.page.getByRole('button', { name: '承認済みの参加先を停止', exact: true }),
              ).toHaveCount(0);
              const stopPath = `/messaging/channels/${p.failed.next.channel.id}/replace/stop`;
              await assert.rejects(
                () =>
                  p.c.page.evaluate(
                    ({ previous, next }) => custodyDevice.stopReplacement(previous, next),
                    p.failed,
                  ),
                /replacement_origin_advanced/,
              );
              assert.equal(p.c.requests.filter((r) => r.path === stopPath).length, 0);
              assert.deepEqual((await snapshot(p.c)).replacement_stops, []);
              const proposal = await fresh(p.c, nextAlice);
              assert.deepEqual(proposal.previous, p.failed.next);
              await approve(p.c);
              await approve(nextAlice);
              await complete(p.c, nextAlice);
              await expect(p.c.page.getByRole('alert')).toHaveText('');
              assert.deepEqual((await snapshot(p.c)).replacement_stops, []);
              assert.deepEqual((await snapshot(nextAlice)).replacement_stops, []);
              await text(p.c, nextAlice);
              await p.c.restart();
              await p.c.open();
              await p.c.chat();
              await assertFences(p.c, [p.previous, p.failed.next]);
              assert.equal(
                (await snapshot(p.c)).invitation!.offer.channel.id,
                proposal.next.channel.id,
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
