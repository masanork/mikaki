import assert from 'node:assert/strict';
import { expect, type Browser } from '@playwright/test';
import { Client, admit } from './vault-browser-support.ts';
import type { fixture } from './server-support.ts';
import { contactCode } from './peer-review.ts';
import { parseReplacementCode, replacementCode } from './replacement-types.ts';
export async function idle(c: Client) {
  // A recovery click can span several witnessed writes and MLS transitions.
  // Playwright's 5s default is shorter than a valid operation on CI Firefox.
  // Keep waiting for actual completion; do not retry the action or change any
  // protocol/lease deadline. A stuck operation still fails this bounded wait.
  await expect(c.page.getByRole('region', { name: '暗号化チャット', exact: true })).toHaveAttribute(
    'aria-busy',
    'false',
    { timeout: 30_000 },
  );
}
export async function click(c: Client, name: string) {
  await c.page.getByRole('button', { name, exact: true }).click();
  await idle(c);
}
export async function pin(c: Client, peer: Client, changed = false) {
  const contact = await peer.page.evaluate(() => custodyDevice.ownContact());
  const details = c.page.locator('details').filter({ hasText: '相手の端末・鍵：' });
  if ((await details.getAttribute('open')) === null) await details.locator('summary').click();
  await c.page
    .getByRole('textbox', { name: '相手の端末コード', exact: true })
    .fill(contactCode(contact));
  await click(c, '署名を検証して確認内容を表示');
  const fingerprint = (await peer.page.evaluate(() => custodyDevice.chatSnapshot())).own
    .fingerprint;
  await c.page
    .getByRole('textbox', { name: '別の連絡手段で確認した相手の指紋', exact: true })
    .fill(fingerprint);
  await click(c, changed ? '新しい指紋を確認して承認' : '指紋を確認して承認');
  await expect(c.page.getByRole('alert')).toHaveText('');
}
export async function setup(f: Awaited<ReturnType<typeof fixture>>, browser: Browser) {
  const a = new Client(f, browser, await f.seed()),
    b = new Client(f, browser, await f.seed());
  await a.init();
  await b.init();
  await a.create();
  await b.create();
  const previous = await admit(a, b);
  const predecessor = (await a.page.evaluate(() => custodyDevice.chatSnapshot())).trust.peer!
    .accepted;
  const c = new Client(f, browser, b.who, b.id);
  // The synthetic authenticator returns the same PRF for the same account/credential.
  // No owner/state key, raw engine or private checkpoint is copied to the new device.
  c.prf.splice(0, c.prf.length, ...b.prf);
  return { a, b, c, previous, predecessor };
}
export async function approve(c: Client) {
  await c.page
    .getByRole('checkbox', {
      name: '確認した新しい指紋とコードが一致し、旧会話を閉じることに同意します',
      exact: true,
    })
    .check();
  await click(c, '新しい鍵での会話を承認');
}
export async function prepare(a: Client, c: Client) {
  await a.chat();
  await c.chat();
  await pin(a, c, true);
  await pin(c, a);
  await click(a, '鍵切り替えコードを作る');
  const code = await a.page
    .getByRole('textbox', { name: '共有する鍵切り替えコード', exact: true })
    .inputValue();
  assert.equal(
    replacementCode(parseReplacementCode(code).previous, parseReplacementCode(code).next),
    code,
  );
  await c.page.getByRole('textbox', { name: '受け取った鍵切り替えコード', exact: true }).fill(code);
  await click(c, '鍵切り替えコードを確認');
  return parseReplacementCode(code);
}
export async function complete(a: Client, c: Client) {
  for (let n = 0; n < 4; n++) {
    await click(a, '同期');
    await click(c, '同期');
  }
  await expect(a.page.getByRole('textbox', { name: 'メッセージ', exact: true })).toBeEnabled();
  await expect(c.page.getByRole('textbox', { name: 'メッセージ', exact: true })).toBeEnabled();
}
