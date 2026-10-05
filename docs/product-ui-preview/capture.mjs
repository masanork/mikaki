import { chromium, expect } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import {
  createOwnerKey,
  sealOwnerRecord,
  OWNER_KEY_SUITE,
} from '../../crates/worker/ui/vault-owner-crypto.ts';
import { newOwnerNote, encodeOwnerNote } from '../../crates/worker/ui/vault-note.ts';

const root = fileURLToPath(new URL('../..', import.meta.url));
const origin = 'https://auth.mikaki.org';
const harness = createTestHarness({
  root,
  workers: [
    {
      configPath: `${root}/crates/worker/wrangler.jsonc`,
      vars: { MIKAKI_ISSUER: origin },
    },
  ],
});
let browser;
try {
  await harness.listen();
  const worker = harness.getWorker('mikaki-op-worker');
  await worker.applyD1Migrations('DB');
  const { DB } = await worker.getEnv();
  const policy = JSON.parse(await readFile(`${root}/local/generated/worker-policy.json`, 'utf8'));
  await activateWorkerPolicy(DB, policy, { actor: 'preview', reason: 'Product UI preview' });
  const credential = new Uint8Array(randomBytes(32));
  const id = Buffer.from(credential).toString('base64url');
  const cookie = randomBytes(32).toString('base64url');
  const prf = new Uint8Array(32).fill(0x71);
  const context = { origin, ownerId: 'preview', vaultId: 'vault', keyGeneration: 1 };
  const credentialBytes = new Uint8Array(credential);
  const prfInput = new Uint8Array(32).fill(0x29);
  // Synthetic PRF output and browser credential are preview fixtures only.
  const created = await createOwnerKey(context, credentialBytes, prfInput, new Uint8Array(prf));
  const now = Math.floor(Date.now() / 1000);
  await DB.batch([
    DB.prepare("INSERT INTO account_security VALUES('preview',1,1)"),
    DB.prepare("INSERT INTO credential VALUES(?,'preview',1)").bind(id),
    DB.prepare(
      "INSERT INTO passkey_credential VALUES(?,'preview-key','preview-user',0,0,0,1)",
    ).bind(id),
    DB.prepare("INSERT INTO account_role VALUES('preview','admin',1)"),
    DB.prepare("INSERT INTO sso_session VALUES('preview','preview',?,1,?,0)").bind(id, now + 3600),
    DB.prepare("INSERT INTO sso_context VALUES('preview',?,?)").bind(
      createHash('sha256').update(cookie).digest('base64url'),
      now,
    ),
  ]);
  const ownerKeyResponse = await worker.fetch(`${origin}/vault/owner-key`, {
    method: 'PUT',
    headers: {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: origin,
      'Content-Type': 'application/json',
      'X-Operation-ID': randomBytes(32).toString('base64url'),
      'If-None-Match': '*',
    },
    body: JSON.stringify({
      format_version: 2,
      suite: OWNER_KEY_SUITE,
      vault_id: context.vaultId,
      key_generation: context.keyGeneration,
      owner_envelope: created.envelope,
    }),
  });
  if (ownerKeyResponse.status !== 200) throw new Error(await ownerKeyResponse.text());
  for (const [recordId, kind, bytes] of [
    ['name', 'name', new TextEncoder().encode('山田 太郎')],
    [
      'owner_note',
      'owner_note',
      encodeOwnerNote(
        newOwnerNote(
          '次のプロジェクトに向けて',
          'アイデアや大切な情報を、自分のために。\n\n必要なときに、必要な相手へ共有します。',
        ),
      ),
    ],
  ]) {
    const sealed = await sealOwnerRecord(bytes, created.key, context, {
      collectionId: 'personal',
      recordId,
      kind,
      revision: 1,
    });
    const response = await worker.fetch(`${origin}/vault/records/personal/${recordId}`, {
      method: 'PUT',
      headers: {
        cookie: `__Host-op-sso=${cookie}`,
        Origin: origin,
        'Content-Type': 'application/json',
        'X-Operation-ID': randomBytes(32).toString('base64url'),
        'If-None-Match': '*',
      },
      body: JSON.stringify({
        ...sealed,
        vault_id: context.vaultId,
        key_generation: context.keyGeneration,
        owner_key_revision: 1,
        kind,
        revision: 1,
      }),
    });
    if (response.status !== 200) throw new Error(await response.text());
  }
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.addInitScript(
    ({ credential, prf }) => {
      class MockCredential {
        rawId = Uint8Array.from(credential).buffer;
        getClientExtensionResults() {
          return { prf: { results: { first: Uint8Array.from(prf).buffer } } };
        }
      }
      Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
      Object.defineProperty(navigator, 'credentials', {
        value: { get: async () => new MockCredential() },
      });
    },
    { credential: [...credential], prf: [...prf] },
  );
  await page.route(`${origin}/**`, async (route) => {
    const request = route.request();
    const requestHeaders = await request.allHeaders();
    const response = await worker.fetch(request.url(), {
      method: request.method(),
      headers: {
        ...requestHeaders,
        cookie: `__Host-op-sso=${cookie}${requestHeaders['cookie'] ? '; ' + requestHeaders['cookie'] : ''}`,
      },
      ...(request.postData() ? { body: request.postData() } : {}),
    });
    // Route fulfillment flattens repeated Set-Cookie headers. Preserve the
    // HttpOnly confirmation cookie explicitly in the preview browser.
    const confirmation = /__Host-op-logout=([^;, ]+)/.exec(
      response.headers.get('set-cookie') ?? '',
    );
    if (confirmation)
      await page.context().addCookies([
        {
          name: '__Host-op-logout',
          value: confirmation[1],
          url: origin,
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
        },
      ]);
    await route.fulfill({
      status: response.status,
      headers: Object.fromEntries(response.headers),
      body: Buffer.from(await response.arrayBuffer()),
    });
  });
  async function capture(name, fullPage = false) {
    if (await page.locator('.product-material').count())
      await page.locator('.gate-background[data-renderer="canvas"]').waitFor();
    await page.evaluate(() => document.fonts.ready);
    if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth))
      throw new Error(`Horizontal overflow: ${name}`);
    await page.screenshot({
      path: fileURLToPath(new URL(`./${name}.png`, import.meta.url)),
      fullPage,
      animations: 'disabled',
    });
  }
  await page.goto(`${origin}/vault`);
  await expect(page.locator('#unlock')).toBeEnabled();
  await capture('vault-locked');
  await page.locator('#unlock').click();
  await expect(page.locator('#name')).toHaveValue('山田 太郎');
  await page.getByRole('link', { name: '本人用メモ', exact: true }).click();
  await expect(page.getByLabel('メモのタイトル', { exact: true })).toHaveValue(
    '次のプロジェクトに向けて',
  );
  await capture('vault');
  await capture('vault-full', true);
  await capture('vault-owner-note');
  await page.getByRole('link', { name: 'プロフィール', exact: true }).click();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.setViewportSize({ width: 375, height: 812 });
  await capture('vault-mobile');
  await capture('vault-mobile-full', true);
  await page.getByRole('link', { name: '本人用メモ', exact: true }).click();
  await expect(page.locator('#owner-note-title')).toHaveValue('次のプロジェクトに向けて');
  await capture('vault-owner-note-mobile');
  await page.getByRole('link', { name: 'プロフィール', exact: true }).click();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.locator('#name').fill('山田 太郎（編集中）');
  await expect(page.locator('.product-draft-status')).toBeVisible();
  await capture('vault-draft-mobile', true);
  await page.locator('#name').fill('山田 太郎');
  await expect(page.locator('.product-draft-status')).toHaveCount(0);
  await page.getByRole('button', { name: 'Vaultをロック', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Vaultをロックしました', exact: true }),
  ).toBeVisible();
  await capture('vault-session-locked-mobile');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(`${origin}/vault?lang=en`);
  await expect(page.locator('#unlock')).toBeEnabled();
  await capture('vault-en');
  await page.goto(`${origin}/admin`);
  await expect(page.getByRole('button', { name: 'Passkeyで招待を発行' })).toBeVisible();
  await capture('admin');
  await page.setViewportSize({ width: 375, height: 812 });
  await capture('admin-mobile');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(`${origin}/enroll/complete`);
  await expect(page.getByRole('heading', { name: '登録が完了しました' })).toBeVisible();
  await capture('complete');
  await page.setViewportSize({ width: 375, height: 812 });
  await capture('complete-mobile');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(`${origin}/logout?lang=ja`);
  await expect(page.getByRole('button', { name: 'ログアウト', exact: true })).toBeVisible();
  await capture('logout');
  await page.setViewportSize({ width: 375, height: 812 });
  await capture('logout-mobile');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('button', { name: 'ログアウト', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'ログアウトしました' })).toBeVisible();
  await capture('logout-complete');
  await page.setViewportSize({ width: 375, height: 812 });
  await capture('logout-complete-mobile');
  if (errors.length) throw new Error(errors.join('\n'));
  console.log(
    'Product previews verified: ja/en, desktop/mobile, unlock, completion, logout; no page errors or horizontal overflow.',
  );
} finally {
  await browser?.close();
  await harness.close();
}
