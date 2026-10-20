import { qualificationTimeout } from './test-timeout.ts';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { chromium, firefox, webkit } from '@playwright/test';
import type { Command } from './device-store.js';
import { envelopeHash, type DeliveryEnvelope } from './delivery-types.ts';
import { fixture, digest } from './server-support.ts';
import {
  Client,
  stored,
  trust,
  join,
  descriptor,
  delivery,
  invitation,
  successor,
  admit,
} from './vault-browser-support.ts';

const engines = { chromium, firefox, webkit };
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = engines[name as keyof typeof engines];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: Vault-owned MLS custody and enrollment recovery`,
    { timeout: qualificationTimeout(240_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        await t.test(
          'explicit invitation cancellation freezes before HTTP, resumes lost close/rejoin replies and quarantines the old KeyPackage',
          async () => {
            const a = new Client(f, browser, await f.seed()),
              b = new Client(f, browser, await f.seed());
            await a.init();
            await b.init();
            await a.create();
            await b.create();
            await trust(a, b);
            const old = await invitation(a, b),
              queued = (await b.box()).ready[0];
            assert.equal(queued.kind, 'key_package');
            b.loss = { path: `/messaging/channels/${old.channel.id}/close`, method: 'POST' };
            await assert.rejects(b.stop(old, 'cancel_invitation'));
            assert.equal((await b.recovery(old)).phase, 'closing');
            await assert.rejects(b.box(), /conversation_frozen/);
            await b.restart();
            await b.open();
            const closed = await b.stop(old, 'cancel_invitation');
            assert.equal(closed.phase, 'closed');
            assert.equal(closed.abandoned[0].id, queued.id);
            await a.stop(old, 'cancel_invitation');
            const next = successor(old);
            await assert.rejects(
              a.approveRejoin(old, {
                ...next,
                channel: { ...next.channel, group: old.channel.group },
              }),
              /invalid_channel_successor/,
            );
            a.loss = { path: `/messaging/channels/${next.channel.id}/rejoin`, method: 'POST' };
            await assert.rejects(a.approveRejoin(old, next));
            await a.restart();
            await a.open();
            assert.equal((await a.syncRejoin(old, next)).phase, 'waiting_peer');
            assert.equal((await a.recovery(old)).phase, 'closed');
            assert.equal(await b.approveRejoin(old, next), true);
            await b.syncRejoin(old, next);
            await a.syncRejoin(old, next);
            assert.equal((await b.syncRejoin(old, next)).phase, 'active');
            assert.equal((await a.syncRejoin(old, next)).phase, 'active');
            assert.equal((await b.recovery(old)).abandoned[0].id, queued.id);
            const ids = await f.env.DB.prepare(
              'SELECT message_id FROM messaging_invitation_packet WHERE channel_id=?',
            )
              .bind(next.channel.id)
              .all<{ message_id: string }>();
            assert.equal(
              ids.results.some((r) => r.message_id === queued.id),
              false,
            );
            await a.run({ kind: 'send', text: '中止した招待を再利用せず、新しい会話へ' });
            await a.sync(next.channel);
            assert.equal((await b.sync(next.channel)).received, 1);
            assert.equal(
              (await f.env.DB.prepare(
                'SELECT count(*) AS n FROM messaging_generation WHERE device_id IN(?,?)',
              )
                .bind(a.id, b.id)
                .first<{ n: number }>())!.n,
              2,
            );
            await a.close();
            await b.close();
          },
        );
        await t.test(
          'simultaneous update forks stop consumption and explicitly rejoin a new group while retaining history and unsent ciphertext',
          async () => {
            const a = new Client(f, browser, await f.seed()),
              b = new Client(f, browser, await f.seed());
            await a.init();
            await b.init();
            await a.create();
            await b.create();
            const old = await admit(a, b);
            await a.run({ kind: 'send', text: '復旧前に受信済みの履歴' });
            await a.sync(old.channel);
            await b.sync(old.channel);
            const history = await b.page.evaluate(() => custodyDevice.inbox());
            assert.equal(history.length, 1);
            await a.run({ kind: 'update' });
            await b.run({ kind: 'update' });
            await a.sync(old.channel);
            await assert.rejects(b.sync(old.channel));
            await assert.rejects(a.sync(old.channel));
            const oldWire = await f.env.DB.prepare(
              'SELECT wire FROM messaging_mail WHERE channel_id=? AND consumed=0 ORDER BY sequence LIMIT 1',
            )
              .bind(old.channel.id)
              .first<{ wire: string }>();
            assert.ok(oldWire);
            await a.run({ kind: 'send', text: '古い会話の未送信文は自動転送しない' });
            const abandoned = (await a.box()).ready[0];
            await a.stop(old, 'epoch_conflict');
            await b.stop(old, 'epoch_conflict');
            const denied = await a.page.evaluate(() =>
              custodyDevice.request(crypto.randomUUID(), { kind: 'send', text: 'frozen' }),
            );
            assert.equal(denied.error, 'conversation_frozen');
            const next = successor(old, true);
            assert.equal(await a.approveRejoin(old, next), false);
            await b.abortCommand('activate_rejoin');
            await assert.rejects(b.approveRejoin(old, next), /storage_|transaction/i);
            assert.equal((await b.recovery(old)).phase, 'closed');
            await assert.rejects(b.box(), /conversation_frozen/);
            await b.restart();
            await b.open();
            // A is the new joiner; B explicitly assumes the inviter role.
            await a.syncRejoin(old, next);
            await b.syncRejoin(old, next);
            assert.equal((await a.syncRejoin(old, next)).phase, 'active');
            assert.equal((await b.syncRejoin(old, next)).phase, 'active');
            assert.ok((await a.recovery(old)).abandoned.some((r) => r.id === abandoned.id));
            assert.deepEqual((await b.recovery(old)).inbox_ids, [history[0].id]);
            const replay = await b.page.evaluate(
              ({ route, wire }) =>
                custodyDevice.request(crypto.randomUUID(), {
                  kind: 'receive_delivery',
                  message_id: crypto.randomUUID(),
                  wire,
                  route: JSON.stringify(route),
                }),
              { route: next.channel, wire: [...Buffer.from(oldWire!.wire, 'base64url')] },
            );
            assert.equal(replay.ok, false);
            await a.run({ kind: 'send', text: '明示的な再参加後の新しい暗号文' });
            await a.sync(next.channel);
            assert.equal((await b.sync(next.channel)).received, 1);
            const inbox = await b.page.evaluate(() => custodyDevice.inbox());
            assert.equal(inbox.length, 2);
            assert.equal(inbox[0].id, history[0].id);
            assert.equal(inbox[1].channel_id, next.channel.id);
            assert.equal(
              (await f.env.DB.prepare(
                'SELECT count(*) AS n FROM messaging_mail WHERE channel_id=? AND message_id=?',
              )
                .bind(next.channel.id, abandoned.id)
                .first<{ n: number }>())!.n,
              0,
            );
            await a.close();
            await b.close();
          },
        );
        await t.test(
          'initial admission survives lost KeyPackage, consumption, Commit, Welcome and activation replies with no harness wire relay',
          async () => {
            const a = new Client(f, browser, await f.seed()),
              b = new Client(f, browser, await f.seed());
            await a.init();
            await b.init();
            await a.create();
            await b.create();
            await trust(a, b);
            const offer = await invitation(a, b),
              base = `/messaging/channels/${offer.channel.id}/invitation`;
            await assert.rejects(
              a.approveInvite({
                ...offer,
                inviter_scope:
                  offer.inviter_scope === offer.channel.a.scope
                    ? offer.channel.b.scope
                    : offer.channel.a.scope,
              }),
              /invitation_conflict/,
            );
            b.loss = { path: `${base}/packets`, method: 'POST' };
            await assert.rejects(b.syncInvite(offer));
            await b.restart();
            await b.open();
            assert.equal((await b.syncInvite(offer)).phase, 'waiting_welcome');
            const kp = await f.env.DB.prepare(
              "SELECT message_id FROM messaging_invitation_packet WHERE channel_id=? AND kind='key_package'",
            )
              .bind(offer.channel.id)
              .first<{ message_id: string }>();
            a.loss = { path: `${base}/packets/${kp!.message_id}/consume`, method: 'POST' };
            await assert.rejects(a.syncInvite(offer));
            await a.restart();
            await a.open();
            a.loss = { path: `${base}/packets`, method: 'POST' };
            await assert.rejects(a.syncInvite(offer));
            await a.restart();
            await a.open();
            // Retry the Commit successfully, then lose Welcome's stored response.
            a.loss = { path: `${base}/packets`, method: 'POST', skip: 1 };
            await assert.rejects(a.syncInvite(offer));
            const welcome = await f.env.DB.prepare(
              "SELECT message_id FROM messaging_invitation_packet WHERE channel_id=? AND kind='welcome'",
            )
              .bind(offer.channel.id)
              .first<{ message_id: string }>();
            b.loss = { path: `${base}/packets/${welcome!.message_id}/consume`, method: 'POST' };
            await assert.rejects(b.syncInvite(offer));
            await b.restart();
            await b.open();
            assert.equal((await b.syncInvite(offer)).phase, 'active');
            await a.restart();
            await a.open();
            assert.equal((await a.syncInvite(offer)).phase, 'active');
            const sends = [...a.requests, ...b.requests].filter(
              (r) => r.path === `${base}/packets` && r.method === 'POST',
            );
            const originals = new Map<string, string>();
            for (const request of sends) {
              const packet = JSON.parse(request.body!);
              const old = originals.get(packet.message_id);
              if (old) assert.equal(request.body, old);
              else originals.set(packet.message_id, request.body!);
            }
            assert.equal(originals.size, 3);
            assert.equal(
              (await f.env.DB.prepare(
                'SELECT count(*) AS n FROM messaging_invitation_packet WHERE channel_id=? AND finished=1 AND wire IS NULL',
              )
                .bind(offer.channel.id)
                .first<{ n: number }>())!.n,
              3,
            );
            await a.run({ kind: 'send', text: '招待の配送だけで参加し、再開後に復号する' });
            await a.sync(offer.channel);
            assert.equal((await b.sync(offer.channel)).received, 1);
            assert.equal((await b.page.evaluate(() => custodyDevice.inbox())).length, 1);
            await a.close();
            await b.close();
          },
        );
        await t.test(
          'rejected or unpersisted Welcome cannot activate the channel or burn its original KeyPackage',
          async () => {
            const a = new Client(f, browser, await f.seed()),
              b = new Client(f, browser, await f.seed());
            await a.init();
            await b.init();
            await a.create();
            await b.create();
            await trust(a, b);
            const offer = await invitation(a, b);
            await b.syncInvite(offer);
            assert.equal((await a.syncInvite(offer)).phase, 'waiting_activation');
            await a.run({ kind: 'send', text: '参加確認前にキューへ置いた文章' });
            await assert.rejects(a.sync(offer.channel), /delivery_unconfirmed_or_denied/);
            const original = await f.env.DB.prepare(
              "SELECT * FROM messaging_invitation_packet WHERE channel_id=? AND kind='welcome'",
            )
              .bind(offer.channel.id)
              .first<DeliveryEnvelope & { envelope_hash: string }>();
            assert.ok(original);
            const bad = Buffer.from(original.wire, 'base64url');
            bad[bad.length - 1] ^= 1;
            const forged = { ...original, wire: bad.toString('base64url'), digest: digest(bad) };
            await f.env.DB.prepare(
              "UPDATE messaging_invitation_packet SET wire=?,digest=?,envelope_hash=? WHERE channel_id=? AND kind='welcome'",
            )
              .bind(forged.wire, forged.digest, await envelopeHash(forged), offer.channel.id)
              .run();
            await assert.rejects(b.syncInvite(offer));
            await f.env.DB.prepare(
              "UPDATE messaging_invitation_packet SET wire=?,digest=?,envelope_hash=? WHERE channel_id=? AND kind='welcome'",
            )
              .bind(original.wire, original.digest, original.envelope_hash, offer.channel.id)
              .run();
            await b.abortCommand('join_from_delivery');
            await assert.rejects(b.syncInvite(offer), /storage_|transaction/i);
            assert.equal(
              (await f.env.DB.prepare(
                'SELECT bootstrap_complete FROM messaging_channel WHERE channel_id=?',
              )
                .bind(offer.channel.id)
                .first<{ bootstrap_complete: number }>())!.bootstrap_complete,
              0,
            );
            assert.equal(
              b.requests.some((r) => r.path.endsWith(`/packets/${original.message_id}/consume`)),
              false,
            );
            await b.restart();
            await b.open();
            assert.equal((await b.syncInvite(offer)).phase, 'active');
            assert.equal((await a.syncInvite(offer)).phase, 'active');
            await a.sync(offer.channel);
            assert.equal((await b.sync(offer.channel)).received, 1);
            assert.equal((await b.page.evaluate(() => custodyDevice.inbox())).length, 1);
            await a.close();
            await b.close();
          },
        );
        await t.test(
          'authenticated mailbox catches up after closed pages and lost send/consume responses without duplicate events',
          async () => {
            const a = new Client(f, browser, await f.seed()),
              b = new Client(f, browser, await f.seed());
            await a.init();
            await b.init();
            await a.create();
            await b.create();
            await join(a, b);
            const route = await delivery(a, b),
              base = `/messaging/channels/${route.id}`;
            await assert.rejects(
              a.approve({ ...route, group: Buffer.alloc(16, 4).toString('base64url') }),
              /delivery_context_mismatch/,
            );
            await b.page.close();
            await a.run({ kind: 'send', text: 'オフラインの相手へ、同じ暗号文を一度だけ表示' });
            a.loss = { path: `${base}/messages`, method: 'POST' };
            await assert.rejects(a.sync(route));
            assert.equal((await a.box()).ready.length, 1);
            assert.equal(
              (await f.env.DB.prepare(
                'SELECT count(*) AS n FROM messaging_mail WHERE channel_id=? AND consumed=0',
              )
                .bind(route.id)
                .first<{ n: number }>())!.n,
              1,
            );
            await a.restart();
            await a.open();
            assert.deepEqual(await a.sync(route), { sent: 1, received: 0 });
            const sends = a.requests.filter((r) => r.path === `${base}/messages`);
            assert.equal(sends.length, 2);
            assert.equal(sends[0].body, sends[1].body);
            b.page = await b.newPage();
            await b.open();
            const queued = await f.env.DB.prepare(
              'SELECT message_id FROM messaging_mail WHERE channel_id=?',
            )
              .bind(route.id)
              .first<{ message_id: string }>();
            b.loss = { path: `${base}/messages/${queued!.message_id}/consume`, method: 'POST' };
            await assert.rejects(b.sync(route));
            assert.equal((await b.page.evaluate(() => custodyDevice.inbox())).length, 1);
            await b.restart();
            await b.open();
            assert.deepEqual(await b.sync(route), { sent: 0, received: 0 });
            assert.equal((await b.page.evaluate(() => custodyDevice.inbox())).length, 1);
            const mail = await f.env.DB.prepare(
              'SELECT wire,consumed FROM messaging_mail WHERE channel_id=?',
            )
              .bind(route.id)
              .first();
            assert.deepEqual(mail, { wire: null, consumed: 1 });
            await b.run({ kind: 'send', text: '再開して返信' });
            assert.equal((await b.sync(route)).sent, 1);
            assert.equal((await a.sync(route)).received, 1);
            await a.close();
            await b.close();
          },
        );
        await t.test(
          'forged transport receipts and failed local persistence never acknowledge or discard a message',
          async () => {
            const a = new Client(f, browser, await f.seed()),
              b = new Client(f, browser, await f.seed());
            await a.init();
            await b.init();
            await a.create();
            await b.create();
            await join(a, b);
            const route = await delivery(a, b);
            await a.run({ kind: 'send', text: '保存に成功するまで受信確認しない' });
            a.forgedReceipt = true;
            await assert.rejects(a.sync(route), /delivery_receipt_mismatch/);
            assert.equal((await a.box()).ready.length, 1);
            await a.sync(route);
            const original = await f.env.DB.prepare(
              'SELECT * FROM messaging_mail WHERE channel_id=?',
            )
              .bind(route.id)
              .first<DeliveryEnvelope & { envelope_hash: string }>();
            assert.ok(original);
            const damaged = Buffer.from(original.wire, 'base64url');
            damaged[damaged.length - 1] ^= 1;
            const forged = {
              ...original,
              wire: damaged.toString('base64url'),
              digest: digest(damaged),
            };
            await f.env.DB.prepare(
              'UPDATE messaging_mail SET wire=?,digest=?,envelope_hash=? WHERE channel_id=?',
            )
              .bind(forged.wire, forged.digest, await envelopeHash(forged), route.id)
              .run();
            // Even internally consistent transport metadata cannot make a
            // modified MLS ciphertext authentic or consume the original key.
            await assert.rejects(b.sync(route));
            assert.equal((await b.page.evaluate(() => custodyDevice.inbox())).length, 0);
            assert.equal(
              b.requests.some((r) => r.path.endsWith('/consume')),
              false,
            );
            await f.env.DB.prepare(
              'UPDATE messaging_mail SET wire=?,digest=?,envelope_hash=? WHERE channel_id=?',
            )
              .bind(original.wire, original.digest, original.envelope_hash, route.id)
              .run();
            await b.abortCommand('receive_delivery');
            await assert.rejects(b.sync(route), /storage_|transaction/i);
            const row = await f.env.DB.prepare(
              'SELECT consumed,wire FROM messaging_mail WHERE channel_id=?',
            )
              .bind(route.id)
              .first<{ consumed: number; wire: string }>();
            assert.equal(row!.consumed, 0);
            assert.ok(row!.wire);
            assert.equal(
              b.requests.some((r) => r.path.endsWith('/consume')),
              false,
            );
            await b.restart();
            await b.open();
            assert.equal((await b.sync(route)).received, 1);
            assert.equal((await b.page.evaluate(() => custodyDevice.inbox())).length, 1);
            await a.close();
            await b.close();
          },
        );
        await t.test(
          'lost commit acceptance resumes the same update, then ordered catch-up opens the next epoch',
          async () => {
            const a = new Client(f, browser, await f.seed()),
              b = new Client(f, browser, await f.seed());
            await a.init();
            await b.init();
            await a.create();
            await b.create();
            await join(a, b);
            const route = await delivery(a, b),
              base = `/messaging/channels/${route.id}`;
            await a.run({ kind: 'update' });
            a.loss = { path: `${base}/messages`, method: 'POST' };
            await assert.rejects(a.sync(route));
            await a.restart();
            await a.open();
            assert.equal((await a.sync(route)).sent, 1);
            await a.run({ kind: 'send', text: '更新後のepochで復号する' });
            await a.sync(route);
            assert.equal((await b.sync(route)).received, 2);
            assert.equal((await b.page.evaluate(() => custodyDevice.inbox())).length, 1);
            assert.equal(
              (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_mail WHERE channel_id=?')
                .bind(route.id)
                .first<{ n: number }>())!.n,
              2,
            );
            const wrong = { ...route, id: randomUUID() };
            // The server does not permit a second route for this same group/pair.
            await assert.rejects(a.approve(wrong));
            await f.response(await f.request(`${base}/block`, 'POST', {}, b.who));
            await a.run({ kind: 'send', text: 'ブロック後は配送しない' });
            await assert.rejects(a.sync(route), /channel_unavailable/);
            assert.equal((await a.box()).ready.length, 1);
            await a.close();
            await b.close();
          },
        );
        await t.test(
          'real Owner Vault unlock wraps the state key; reload resumes messages without harness checkpoints or state keys',
          async () => {
            const a = new Client(f, browser, await f.seed()),
              b = new Client(f, browser, await f.seed());
            await a.init();
            await b.init();
            await a.create();
            await b.create();
            await join(a, b);
            await a.run({ kind: 'send', text: 'Vaultの鍵から端末だけを開く秘密のメッセージ' });
            const message = (await a.box()).ready[0];
            const original = (await stored(a.page)) as { scope: unknown };
            const dump = JSON.stringify(original);
            for (const secret of [
              'checkpoint',
              'proof_body',
              'private_key',
              'Vaultの鍵から端末だけを開く秘密のメッセージ',
            ])
              assert.equal(dump.includes(secret), false);
            assert.equal(await a.page.evaluate(() => custodyCalls), 1);
            const prf = Buffer.from(a.prf).toString('base64url');
            assert.equal(JSON.stringify(a.requests).includes(prf), false);
            assert.equal(dump.includes(prf), false);
            await a.restart();
            await a.open();
            assert.deepEqual((await a.box()).ready, [message]);
            assert.deepEqual(((await stored(a.page)) as { scope: unknown }).scope, original.scope);
            await b.run({ kind: 'receive', message_id: message.id, wire: message.wire });
            assert.equal((await b.page.evaluate(() => custodyDevice.inbox())).length, 1);
            await a.page.evaluate(() => custodyOwner.lock());
            await assert.rejects(a.box(), /device_locked/);
            assert.equal(
              await a.page.evaluate(() => localStorage.length + sessionStorage.length),
              0,
            );
            await a.close();
            await b.close();
          },
        );
        await t.test(
          'aborted custody writes cannot publish a proof; pending challenge recovery retains the same scope',
          async () => {
            const before = new Client(f, browser, await f.seed());
            await before.init();
            await before.manager();
            await before.page.evaluate(() => {
              const original = IDBObjectStore.prototype.put;
              IDBObjectStore.prototype.put = function (...args: Parameters<typeof original>) {
                IDBObjectStore.prototype.put = original;
                const result = original.apply(this, args);
                this.transaction.abort();
                return result;
              };
            });
            await assert.rejects(
              before.page.evaluate(() => custodyDevice.create()),
              /custody_commit_failed/,
            );
            assert.equal(
              before.requests.filter(
                (r) => r.path === '/messaging/enrollments' && r.method === 'POST',
              ).length,
              0,
            );
            await before.restart();
            await assert.rejects(before.open(), /device_custody_missing/);
            await before.create();
            const pending = new Client(f, browser, await f.seed());
            await pending.init();
            await pending.page.evaluate((id) => {
              globalThis.custodyDevice = new custodyModule.VaultMlsDevice(
                custodyOwner,
                custodyWasm,
                custodyRoot,
                id,
                {
                  onPhase: (p) => {
                    if (p !== 'after_custody_prepare') return;
                    const original = IDBObjectStore.prototype.put;
                    IDBObjectStore.prototype.put = function (...args: Parameters<typeof original>) {
                      IDBObjectStore.prototype.put = original;
                      const result = original.apply(this, args);
                      this.transaction.abort();
                      return result;
                    };
                  },
                },
              );
            }, pending.id);
            await assert.rejects(
              pending.page.evaluate(() => custodyDevice.create()),
              /custody_commit_failed/,
            );
            const initial = (await stored(pending.page)) as { scope: unknown };
            assert.equal(pending.requests.filter((r) => r.path.endsWith('/complete')).length, 0);
            await pending.restart();
            await pending.open();
            assert.deepEqual(
              ((await stored(pending.page)) as { scope: unknown }).scope,
              initial.scope,
            );
            assert.equal(
              (await f.env.DB.prepare(
                'SELECT count(*) AS n FROM messaging_enrollment WHERE device_id=?',
              )
                .bind(pending.id)
                .first<{ n: number }>())!.n,
              1,
            );
            await before.close();
            await pending.close();
          },
        );
        await t.test(
          'separate unlocked tabs share one journal; disposing during a witnessed write releases no late result',
          async () => {
            const client = new Client(f, browser, await f.seed());
            await client.init();
            await client.create();
            const tab = await client.newPage();
            await client.manager(tab);
            await tab.evaluate(() => custodyDevice.open());
            const id = randomUUID();
            const results = await Promise.all([
              client.run({ kind: 'key_package' }, client.page, id),
              client.run({ kind: 'key_package' }, tab, id),
              client.run({ kind: 'key_package' }),
              client.run({ kind: 'key_package' }, tab),
            ]);
            assert.deepEqual(results[0], results[1]);
            assert.equal((await client.box()).ready.length, 3);
            await tab.close();
            let release!: () => void, reached!: () => void;
            const arrived = new Promise<void>((resolve) => {
                reached = resolve;
              }),
              paused = new Promise<void>((resolve) => {
                release = resolve;
              });
            client.pauseHead = { reached, release: paused };
            const command = { kind: 'key_package' } as const,
              operation = randomUUID();
            const pending = client.run(command, client.page, operation).then(
              () => false,
              () => true,
            );
            await arrived;
            await client.page.evaluate(() => custodyOwner.dispose());
            release();
            assert.equal(
              await pending,
              true,
              'no late success can escape the disposed owner lease',
            );
            await assert.rejects(client.box(), /device_locked/);
            await client.restart();
            await client.open();
            await client.run(command, client.page, operation);
            assert.equal(
              (await client.box()).ready.length,
              4,
              'the exact prepared KeyPackage survived lock and retry',
            );
            await client.close();
          },
        );
        await t.test(
          'termination at every enrollment boundary resumes the same signing key and scope',
          async () => {
            for (const phase of [
              'after_custody_prepare',
              'after_challenge_prepare',
              'after_binding_prepare',
              'after_journal_bootstrap',
              'after_activation',
            ] as const) {
              const client = new Client(f, browser, await f.seed());
              await client.init();
              await client.manager(client.page, phase);
              const reached = client.phase(phase),
                pending = client.page.evaluate(() => custodyDevice.create()).catch(() => undefined);
              await reached;
              const original = (await stored(client.page)) as {
                scope: { fingerprint: string };
                public_key: string;
              };
              if (phase === 'after_custody_prepare' || phase === 'after_challenge_prepare')
                assert.equal(
                  (await f.env.DB.prepare(
                    'SELECT count(*) AS n FROM messaging_generation WHERE device_id=?',
                  )
                    .bind(client.id)
                    .first<{ n: number }>())!.n,
                  0,
                );
              await client.restart();
              await pending;
              await client.open();
              const resumed = (await stored(client.page)) as { scope: unknown; public_key: string };
              assert.deepEqual(resumed.scope, original.scope);
              assert.equal(resumed.public_key, original.public_key);
              assert.equal(
                (await f.env.DB.prepare(
                  'SELECT count(*) AS n FROM messaging_generation WHERE device_id=?',
                )
                  .bind(client.id)
                  .first<{ n: number }>())!.n,
                1,
              );
              assert.equal((await client.box()).ready.length, 0);
              await client.close();
            }
          },
        );
        await t.test(
          'lost registration replies, expired tickets and a new owner session reconcile without changing keys',
          async () => {
            const client = new Client(f, browser, await f.seed());
            await client.init();
            await client.manager(client.page, 'after_challenge_prepare');
            const reached = client.phase('after_challenge_prepare'),
              pending = client.page.evaluate(() => custodyDevice.create()).catch(() => undefined);
            await reached;
            const initial = (await stored(client.page)) as { scope: unknown; public_key: string };
            await client.restart();
            await pending;
            // Change the authenticated SSO context while preserving the same owner,
            // credential and PRF-backed root. The old challenge cannot be consumed.
            const secret = randomBytes(32).toString('base64url'),
              session = randomUUID();
            const { createHash } = await import('node:crypto');
            await f.env.DB.batch([
              f.env.DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,unixepoch()+3600,0)').bind(
                session,
                client.who.owner,
                client.who.credential,
              ),
              f.env.DB.prepare('INSERT INTO sso_context VALUES(?,?,unixepoch())').bind(
                session,
                createHash('sha256').update(secret).digest('base64url'),
              ),
            ]);
            client.who = { ...client.who, secret, session };
            await client.cookies();
            await client.restart();
            await client.open();
            assert.deepEqual(
              ((await stored(client.page)) as { scope: unknown }).scope,
              initial.scope,
            );
            const retry = new Client(f, browser, await f.seed());
            await retry.init();
            await retry.manager(retry.page, 'after_challenge_prepare');
            const point = retry.phase('after_challenge_prepare'),
              creation = retry.page.evaluate(() => custodyDevice.create()).catch(() => undefined);
            await point;
            const prepared = (await stored(retry.page)) as { scope: unknown; public_key: string };
            await retry.restart();
            await creation;
            await f.env.DB.prepare(
              'UPDATE messaging_enrollment SET expires_at=unixepoch()-1 WHERE device_id=?',
            )
              .bind(retry.id)
              .run();
            // The old locally cached expiry is still in the future: the actual
            // server 410 must renew only this pre-MLS key, never allocate a new key.
            await retry.open();
            assert.deepEqual(
              ((await stored(retry.page)) as { scope: unknown }).scope,
              prepared.scope,
            );
            const lost = new Client(f, browser, await f.seed());
            await lost.init();
            await lost.manager(lost.page, 'after_challenge_prepare');
            const point2 = lost.phase('after_challenge_prepare'),
              creating = lost.page.evaluate(() => custodyDevice.create()).catch(() => undefined);
            await point2;
            const before = (await stored(lost.page)) as { scope: unknown };
            await lost.restart();
            await creating;
            const ticket = (await f.env.DB.prepare(
              'SELECT enrollment_id FROM messaging_enrollment WHERE device_id=?',
            )
              .bind(lost.id)
              .first<{ enrollment_id: string }>())!;
            lost.loss = {
              path: `/messaging/enrollments/${ticket.enrollment_id}/complete`,
              method: 'POST',
            };
            await assert.rejects(lost.open(), /fetch|network|Network|Failed|Load/i);
            await lost.restart();
            await lost.open();
            assert.deepEqual(((await stored(lost.page)) as { scope: unknown }).scope, before.scope);
            assert.equal(
              lost.requests.filter((r) => r.path.endsWith('/complete') && r.method === 'POST')
                .length,
              1,
              'fresh binding lookup reconciles an already committed registration',
            );
            await client.close();
            await retry.close();
            await lost.close();
          },
        );
        await t.test(
          'suspension, disposal, root authority loss and late completions invalidate retained child handles',
          async () => {
            const client = new Client(f, browser, await f.seed());
            await client.init();
            await client.create();
            await client.page.evaluate(() => custodyOwner.suspend());
            await assert.rejects(client.box(), /device_locked/);
            await client.page.evaluate(() => custodyOwner.resume());
            await client.open();
            assert.equal((await client.box()).ready.length, 0);
            // Dispose does not end VaultScope itself; the explicit child capability
            // notification must still make the state key unusable immediately.
            await client.page.evaluate(() => custodyOwner.dispose());
            await assert.rejects(client.box(), /device_locked/);
            await client.restart();
            await client.open();
            await f.env.DB.prepare(
              'UPDATE vault_owner_key_head SET revision=revision+1 WHERE account_id=?',
            )
              .bind(client.who.owner)
              .run();
            await assert.rejects(client.box(), /owner_key_changed|unavailable|locked/i);
            await assert.rejects(client.box(), /device_locked/);
            const late = new Client(f, browser, await f.seed());
            await late.init();
            await late.manager(late.page, 'after_custody_prepare');
            // A synchronous close at the prepared boundary rejects the factory and
            // leaves an encrypted, resumable candidate without enrollment traffic.
            await late.page.evaluate((id) => {
              globalThis.custodyDevice = new custodyModule.VaultMlsDevice(
                custodyOwner,
                custodyWasm,
                custodyRoot,
                id,
                {
                  onPhase: (p) => {
                    if (p === 'after_custody_prepare') custodyOwner.dispose();
                  },
                },
              );
            }, late.id);
            await assert.rejects(
              late.page.evaluate(() => custodyDevice.create()),
              /device_locked|unavailable/i,
            );
            assert.equal(
              late.requests.filter(
                (r) => r.path === '/messaging/enrollments' && r.method === 'POST',
              ).length,
              0,
            );
            await late.restart();
            await late.open();
            await client.close();
            await late.close();
          },
        );
        await t.test(
          'missing journal, corrupted custody and account changes cannot silently regenerate or reactivate the device',
          async () => {
            const client = new Client(f, browser, await f.seed());
            await client.init();
            await client.manager(client.page, 'after_custody_prepare');
            const reached = client.phase('after_custody_prepare'),
              pending = client.page.evaluate(() => custodyDevice.create()).catch(() => undefined);
            await reached;
            const prepared = await stored(client.page);
            await client.restart();
            await pending;
            await client.open();
            const current = await stored(client.page);
            const corrupted = structuredClone(current) as { custody: { ciphertext: string } };
            corrupted.custody.ciphertext =
              corrupted.custody.ciphertext.slice(0, -1) +
              (corrupted.custody.ciphertext.endsWith('A') ? 'E' : 'A');
            await stored(client.page, corrupted);
            await client.restart();
            await assert.rejects(client.open());
            await assert.rejects(client.create(), /device_already_initialized/);
            await stored(client.page, prepared, true);
            await client.restart();
            await assert.rejects(client.open(), /rollback_or_state_loss/);
            const generations = (await f.env.DB.prepare(
              'SELECT count(*) AS n FROM messaging_generation WHERE device_id=?',
            )
              .bind(client.id)
              .first<{ n: number }>())!.n;
            assert.equal(generations, 1);
            await stored(client.page, current);
            client.who = await f.seed();
            await client.cookies();
            await client.restart();
            await assert.rejects(client.open(), /device_custody_missing/);
            assert.equal(
              (await f.env.DB.prepare(
                'SELECT count(*) AS n FROM messaging_generation WHERE device_id=?',
              )
                .bind(client.id)
                .first<{ n: number }>())!.n,
              1,
            );
            await client.close();
          },
        );
      } finally {
        await browser.close();
        await f.close();
      }
    },
  );
}
