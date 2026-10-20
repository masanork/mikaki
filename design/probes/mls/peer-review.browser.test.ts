import { qualificationTimeout } from './test-timeout.ts';
import assert from 'node:assert/strict';
import { randomUUID, sign } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium, firefox, webkit, expect, type Browser } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { Client, descriptor, admit } from './vault-browser-support.ts';
import { fixture, keys, pub } from './server-support.ts';
import { contactCode, parseContactCode } from './peer-review.ts';
import { invitationCode } from './chat-view.ts';

async function idle(c: Client) {
  await expect(c.page.getByRole('region', { name: '暗号化チャット', exact: true })).toHaveAttribute(
    'aria-busy',
    'false',
  );
}
async function click(c: Client, name: string) {
  await c.page.getByRole('button', { name, exact: true }).click();
  await idle(c);
}
async function importContact(c: Client, value: string) {
  const field = c.page.getByRole('textbox', { name: '相手の端末コード', exact: true });
  // The trusted state folds this panel; opening it is a review action, not consent.
  const details = c.page.locator('details').filter({ hasText: '相手の端末・鍵：' });
  if ((await details.getAttribute('open')) === null) await details.locator('summary').click();
  await field.fill(value);
  await click(c, '署名を検証して確認内容を表示');
}
async function confirm(c: Client, fingerprint: string, changed = false) {
  await c.page
    .getByRole('textbox', { name: '別の連絡手段で確認した相手の指紋', exact: true })
    .fill(fingerprint);
  await click(c, changed ? '新しい指紋を確認して承認' : '指紋を確認して承認');
}
async function pair(f: Awaited<ReturnType<typeof fixture>>, browser: Browser) {
  const a = new Client(f, browser, await f.seed()),
    b = new Client(f, browser, await f.seed());
  await a.init();
  await b.init();
  await a.create();
  await b.create();
  return { a, b };
}
function signed(
  f: Awaited<ReturnType<typeof fixture>>,
  token: string,
  patch: Record<string, unknown>,
) {
  const [header, payload] = token.split('.');
  const claims = { ...JSON.parse(Buffer.from(payload, 'base64url').toString()), ...patch };
  const input = `${header}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}`;
  return `${input}.${sign(null, Buffer.from(input), f.issuer.privateKey).toString('base64url')}`;
}
for (const name of (process.env.MIKAKI_MLS_BROWSERS ?? 'chromium').split(',')) {
  const engine = { chromium, firefox, webkit }[name as 'chromium' | 'firefox' | 'webkit'];
  if (!engine) throw new Error(`Unknown browser ${name}`);
  test(
    `${name}: explicit first-contact and changed-key review UI`,
    { timeout: qualificationTimeout(180_000) },
    async (t) => {
      const f = await fixture(),
        browser = await engine.launch();
      try {
        await t.test(
          'first trust enforces native form constraints and independently entered fingerprints, survives reload and enables real initial invitation and text delivery',
          async () => {
            const { a, b } = await pair(f, browser);
            try {
              const channel = await descriptor(a, b);
              const own = (await a.page.evaluate(() => custodyDevice.chatSnapshot())).own;
              const bob = (await b.page.evaluate(() => custodyDevice.chatSnapshot())).own;
              const offer = { channel, inviter_scope: own.scope };
              await a.chat(offer);
              await b.chat();
              await click(a, '自分の端末コードを表示');
              await click(b, '自分の端末コードを表示');
              const codeA = await a.page
                .getByRole('textbox', { name: '自分の端末コード', exact: true })
                .inputValue();
              const codeB = await b.page
                .getByRole('textbox', { name: '自分の端末コード', exact: true })
                .inputValue();
              await importContact(a, codeB);
              const fingerprintInput = a.page.getByRole('textbox', {
                name: '別の連絡手段で確認した相手の指紋',
              });
              await fingerprintInput.fill('!'.repeat(43));
              assert.equal(
                await fingerprintInput.evaluate((field) =>
                  (field as HTMLInputElement).checkValidity(),
                ),
                false,
              );
              await fingerprintInput.fill('');
              await expect(
                a.page.getByRole('textbox', { name: '別の連絡手段で確認した相手の指紋' }),
              ).toHaveValue('');
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).trust.peer,
                null,
              );
              await a.page.getByRole('checkbox').check();
              await expect(
                a.page.getByRole('button', { name: 'この招待を承認', exact: true }),
              ).toBeDisabled();
              await confirm(a, 'A'.repeat(43));
              await expect(a.page.getByRole('alert')).toContainText('入力した指紋が一致しません');
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).trust.peer,
                null,
              );
              await a.restart();
              await a.open();
              await a.chat(offer);
              await expect(
                a.page.getByRole('textbox', { name: '別の連絡手段で確認した相手の指紋' }),
              ).toHaveValue('');
              const violations = (await new AxeBuilder({ page: a.page }).analyze()).violations;
              assert.deepEqual(
                violations.map((v) => v.id),
                [],
              );
              if (name === 'chromium') {
                const out = new URL('../../../local/generated/mls-chat/', import.meta.url);
                await mkdir(out, { recursive: true });
                await a.page.setViewportSize({ width: 390, height: 844 });
                assert.equal(
                  await a.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
                  true,
                );
                await a.page.screenshot({
                  path: new URL('peer-first-review.png', out).pathname,
                  fullPage: true,
                });
              }
              // These expected fingerprints are obtained independently from each
              // device's own handle, never from its candidate/directory display.
              await confirm(a, bob.fingerprint);
              await importContact(b, codeA);
              await confirm(b, own.fingerprint);
              await b.page
                .getByRole('textbox', { name: '受け取った招待コード' })
                .fill(invitationCode(offer));
              await click(b, 'コードを確認');
              for (const c of [a, b]) {
                await c.page.getByRole('checkbox').check();
                await click(c, 'この招待を承認');
              }
              await click(a, '同期');
              await click(b, '同期');
              await click(a, '同期');
              await a.page
                .getByRole('textbox', { name: 'メッセージ', exact: true })
                .fill('指紋の初回確認から始めた会話');
              await click(a, '送信');
              await click(b, '同期');
              await expect(b.page.getByRole('region', { name: 'メッセージ履歴' })).toContainText(
                '指紋の初回確認から始めた会話',
              );
            } finally {
              await a.close();
              await b.close();
            }
          },
        );

        await t.test(
          'signed generation replacement freezes persisted old mail, requires exact review and does not authorize the old group; revocation survives reload',
          async () => {
            const { a, b } = await pair(f, browser);
            try {
              const offer = await admit(a, b);
              await a.chat();
              const original = (await b.page.evaluate(() => custodyDevice.chatSnapshot())).own;
              const queued = await a.page.evaluate(
                ({ id, channel }) =>
                  custodyDevice.sendText(id, channel, '古い鍵で準備した送信待ち本文'),
                { id: randomUUID(), channel: offer.channel },
              );
              assert.equal(queued.ok, true);
              const next = await f.start(keys(), b.id, 1, b.who),
                binding = (await f.complete(next)).binding;
              const code = contactCode({ scope: f.scope(next.c), binding });
              await importContact(a, code);
              await expect(
                a.page.getByRole('button', { name: '送信', exact: true }),
              ).toBeDisabled();
              let snapshot = await a.page.evaluate(() => custodyDevice.chatSnapshot());
              assert.equal(snapshot.trust.peer!.state, 'key_changed');
              assert.equal(snapshot.trust.peer!.accepted.fingerprint, original.fingerprint);
              assert.equal(snapshot.peer_review!.verified.device.generation, 2);
              await a.restart();
              await a.open();
              await a.chat();
              await expect(
                a.page.getByRole('button', { name: '送信', exact: true }),
              ).toBeDisabled();
              await confirm(a, original.fingerprint, true);
              await expect(a.page.getByRole('alert')).toContainText('入力した指紋が一致しません');
              const scope = (await a.page.evaluate(() => custodyDevice.chatSnapshot())).own.scope;
              a.loss = { path: `/messaging/heads/${scope}`, method: 'PUT' };
              await confirm(a, next.c.scope.fingerprint, true);
              snapshot = await a.page.evaluate(() => custodyDevice.chatSnapshot());
              assert.equal(snapshot.trust.peer!.accepted.fingerprint, next.c.scope.fingerprint);
              assert.equal(snapshot.trust.group_usable, false);
              await expect(
                a.page.getByRole('button', { name: '送信', exact: true }),
              ).toBeDisabled();
              await expect(a.page.locator('body')).toContainText(
                '新しい鍵は確認済みですが、古い会話には送信できません',
              );
              await assert.rejects(a.sync(offer.channel));
              assert.equal(
                a.requests.filter((r) => r.path.endsWith('/messages') && r.method === 'POST')
                  .length,
                0,
              );
              const box = await a.box();
              assert.equal(box.ready.length, 0);
              assert.equal(box.blocked.length, 1);
              const revoked = await f.response<{ binding: string }>(
                await f.request(
                  `/messaging/devices/${b.id}/revoke`,
                  'POST',
                  { expected_revision: 2 },
                  b.who,
                ),
              );
              await importContact(
                a,
                contactCode({ scope: f.scope(next.c), binding: revoked.binding }),
              );
              await a.restart();
              await a.open();
              await a.chat();
              snapshot = await a.page.evaluate(() => custodyDevice.chatSnapshot());
              assert.equal(snapshot.trust.peer!.state, 'revoked');
              await expect(
                a.page.getByRole('button', { name: '送信', exact: true }),
              ).toBeDisabled();
              assert.equal(
                await a.page.getByRole('button', { name: '新しい指紋を確認して承認' }).count(),
                0,
              );
            } finally {
              await a.close();
              await b.close();
            }
          },
        );

        await t.test(
          'invalid signatures and expired codes do not establish trust; signed registry conflicts persist without a confirmation override',
          async () => {
            const { a, b } = await pair(f, browser);
            try {
              await admit(a, b);
              await a.chat();
              const contact = await b.page.evaluate(() => custodyDevice.ownContact());
              const bad = structuredClone(contact),
                parts = bad.binding.split('.');
              parts[2] = Buffer.alloc(64).toString('base64url');
              bad.binding = parts.join('.');
              await importContact(a, contactCode(bad));
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).peer_review,
                null,
              );
              const now = Math.floor(Date.now() / 1000);
              await importContact(
                a,
                contactCode({
                  ...contact,
                  binding: signed(f, contact.binding, { iat: now - 301, exp: now - 1 }),
                }),
              );
              await expect(a.page.getByRole('alert')).toContainText('有効期限');
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).peer_review,
                null,
              );
              await importContact(
                a,
                contactCode({
                  ...contact,
                  binding: signed(f, contact.binding, { public_key: pub(keys().publicKey) }),
                }),
              );
              const state = await a.page.evaluate(() => custodyDevice.chatSnapshot());
              assert.equal(state.peer_review!.observation, 'registry_conflict');
              assert.equal(state.trust.peer!.state, 'registry_conflict');
              await expect(
                a.page.getByRole('button', { name: '送信', exact: true }),
              ).toBeDisabled();
              assert.equal(
                await a.page.getByRole('button', { name: '新しい指紋を確認して承認' }).count(),
                0,
              );
              await a.restart();
              await a.open();
              await a.chat();
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).trust.peer!.state,
                'registry_conflict',
              );
              const issued = Math.floor(Date.now() / 1000);
              await importContact(
                a,
                contactCode({
                  ...contact,
                  binding: signed(f, contact.binding, {
                    revision: 2,
                    iat: issued,
                    exp: issued + 300,
                    public_key: pub(keys().publicKey),
                  }),
                }),
              );
              await expect(a.page.locator('body')).toContainText(
                '同じ世代の異なる鍵は承認できません',
              );
              assert.equal(
                await a.page.getByRole('button', { name: '新しい指紋を確認して承認' }).count(),
                0,
              );
            } finally {
              await a.close();
              await b.close();
            }
          },
        );

        await t.test(
          'another tab invalidates stale review; aborted approval does not pin, and lock during retry prevents all late display',
          async () => {
            const { a, b } = await pair(f, browser);
            let release: (() => void) | undefined;
            try {
              await a.chat();
              const contact = await b.page.evaluate(() => custodyDevice.ownContact());
              const fp = (await b.page.evaluate(() => custodyDevice.chatSnapshot())).own
                .fingerprint;
              await importContact(a, contactCode(contact));
              const tab = await a.newPage();
              await a.manager(tab);
              await tab.evaluate(() => custodyDevice.open());
              await tab.evaluate((contact) => custodyDevice.stagePeer(contact), contact);
              await confirm(a, fp);
              await expect(a.page.getByRole('alert')).toContainText('確認内容が別の操作で更新');
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).trust.peer,
                null,
              );
              await tab.close();
              await a.abortCommand('approve_peer');
              await confirm(a, fp);
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).trust.peer,
                null,
              );
              await expect(
                a.page.getByRole('button', { name: '同じ鍵確認を再試行' }),
              ).toBeEnabled();
              await a.page.evaluate(() => {
                const original = custodyDevice.approvePeerReview.bind(custodyDevice);
                Object.assign(globalThis, { peerReviewFinished: false });
                custodyDevice.approvePeerReview = async (...args) => {
                  try {
                    return await original(...args);
                  } finally {
                    Object.assign(globalThis, { peerReviewFinished: true });
                  }
                };
              });
              const reached = new Promise<void>((resolve) => {
                a.pauseHead = {
                  reached: resolve,
                  release: new Promise<void>((r) => {
                    release = r;
                  }),
                };
              });
              await a.page.getByRole('button', { name: '同じ鍵確認を再試行' }).click();
              await reached;
              await a.page.evaluate(() => custodyOwner.lock());
              await expect(a.page.locator('body')).toContainText('チャットをロックしました');
              assert.equal(await a.page.getByRole('textbox').count(), 0);
              await expect(a.page.locator('body')).not.toContainText(fp);
              release!();
              await expect
                .poll(() => a.page.evaluate(() => Reflect.get(globalThis, 'peerReviewFinished')))
                .toBe(true);
              await a.restart();
              await a.open();
              await a.chat();
              assert.equal(
                (await a.page.evaluate(() => custodyDevice.chatSnapshot())).trust.peer!.accepted
                  .fingerprint,
                fp,
              );
              assert.equal(
                a.requests.filter((r) => r.path.endsWith('/invitation/packets')).length,
                0,
              );
            } finally {
              release?.();
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
