/** Product host qualification: real main Worker, usual SSO/Vault and native MLS.
 * Only WebAuthn PRF and the upstream authenticated session are test fixtures. */
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { parse } from 'jsonc-parser';
import { createTestHarness } from 'wrangler';
import { gzipSync } from 'node:zlib';
import { chromium, expect, type Page } from '@playwright/test';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { auditAccessibility } from './support/accessibility-audit.ts';
import { trackMessagingCoverage } from './support/messaging-coverage.ts';

const root = new URL('../../', import.meta.url).pathname;
const origin = 'https://mikaki.test';
async function fixture(enabled: boolean, defaultBuild = false) {
  const config = parse(await readFile(`${root}crates/worker/wrangler.jsonc`, 'utf8'));
  config.main = `${root}crates/worker/${defaultBuild ? 'build' : 'build-messaging-beta'}/worker/service.mjs`;
  config.assets.directory = `${root}assets`;
  config.d1_databases[0].migrations_dir = `${root}crates/worker/migrations`;
  config.vars = { MIKAKI_ISSUER: origin, MESSAGING_BETA_ENABLED: String(enabled || defaultBuild) };
  if (enabled) {
    const jwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
    config.vars.MESSAGING_ISSUER_KEY = JSON.stringify({
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      d: jwk.d,
    });
  }
  const harness = createTestHarness({ root, workers: [{ config }] });
  await harness.listen();
  try {
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const policy = JSON.parse(await readFile(`${root}local/generated/worker-policy.json`, 'utf8'));
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Messaging product host' });
    // Exercise the product limiter, with a local budget large enough for the
    // sequential fixture's journal witnesses. Deployment tuning remains separate.
    await DB.prepare(
      'UPDATE auth_resource_policy SET source_per_minute=2000,deployment_per_minute=4000 WHERE id=1',
    ).run();
    if (enabled) {
      for (const name of ['0001_messaging.sql', '0002_beta_profile.sql']) {
        const sql = (
          await readFile(`${root}crates/worker/messaging-migrations/${name}`, 'utf8')
        ).replace(/^--.*$/gm, '');
        await DB.batch(
          sql
            .split(';')
            .map((s: string) => s.trim())
            .filter(Boolean)
            .map((s: string) => DB.prepare(s)),
        );
      }
    }
    const seed = async () => {
      const account = randomUUID(),
        credential = randomBytes(32),
        id = credential.toString('base64url'),
        secret = randomBytes(32).toString('base64url'),
        session = randomUUID();
      await DB.batch([
        DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(account),
        DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(id, account),
        DB.prepare(
          "INSERT INTO passkey_credential VALUES(?,'fixture-public-key','fixture-user',0,0,0,1)",
        ).bind(id),
        DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,unixepoch()+3600,0)').bind(
          session,
          account,
          id,
        ),
        DB.prepare('INSERT INTO sso_context VALUES(?,?,unixepoch())').bind(
          session,
          createHash('sha256').update(secret).digest('base64url'),
        ),
      ]);
      return { account, credential: [...credential], secret, session };
    };
    return { harness, worker, DB, seed };
  } catch (error) {
    await harness.close();
    throw error;
  }
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
type Actor = Awaited<ReturnType<Fixture['seed']>>;
async function client(
  f: Fixture,
  browser: Awaited<ReturnType<typeof chromium.launch>>,
  actor: Actor,
) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  let ceremonies = 0;
  const requests: { path: string; method: string; body: string | null }[] = [],
    errors: string[] = [];
  await context.exposeFunction('recordChatCeremony', () => {
    ceremonies++;
  });
  await context.addInitScript(
    ({ credential }) => {
      class FixtureCredential {
        rawId = Uint8Array.from(credential).buffer;
        getClientExtensionResults() {
          return { prf: { results: { first: new Uint8Array(32).fill(0x71).buffer } } };
        }
      }
      Object.defineProperty(window, 'PublicKeyCredential', { value: FixtureCredential });
      Object.defineProperty(navigator, 'credentials', {
        value: {
          get: async (options: CredentialRequestOptions) => {
            await (
              window as unknown as { recordChatCeremony(): Promise<void> }
            ).recordChatCeremony();
            const requested = options.publicKey?.allowCredentials?.[0]?.id;
            if (!requested || !BufferSourceEqual(requested, credential))
              throw new Error('Pinned credential required');
            return new FixtureCredential();
          },
        },
      });
      function BufferSourceEqual(value: BufferSource, expected: number[]) {
        const bytes =
          value instanceof ArrayBuffer
            ? new Uint8Array(value)
            : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        return bytes.length === expected.length && bytes.every((b, i) => b === expected[i]);
      }
    },
    { credential: actor.credential },
  );
  await context.route(`${origin}/**`, async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    requests.push({ path, method: request.method(), body: request.postData() });
    const response = await f.worker.fetch(request.url(), {
      method: request.method(),
      headers: { ...(await request.allHeaders()), cookie: `__Host-op-sso=${actor.secret}` },
      ...(request.postData() ? { body: request.postData()! } : {}),
    });
    const headers = new Headers(Object.fromEntries(response.headers));
    const etag = headers.get('etag');
    if (etag && !headers.get('cache-control')?.includes('no-transform'))
      headers.set('etag', `W/${etag}`);
    await route.fulfill({
      status: response.status,
      headers: Object.fromEntries(headers),
      body: Buffer.from(await response.arrayBuffer()),
    });
  });
  const page = await context.newPage();
  await trackMessagingCoverage(page);
  page.setDefaultTimeout(10_000);
  page.on('pageerror', (e) => errors.push(e.message));
  const openVault = async () => {
    await page.goto(`${origin}/vault?lang=ja`);
    await expect(page.getByRole('link', { name: 'Walletアプリで開く', exact: true })).toBeVisible();
    assert.equal(
      await page.locator('#name,#owner-note,#owner-agent-grants,#archive-file').count(),
      0,
    );
  };
  const openChat = async () => {
    await page.getByRole('button', { name: 'Chat', exact: true }).click();
    await page.locator('#unlock').click();
    await ready(page);
  };
  return { context, page, requests, errors, ceremonies: () => ceremonies, openVault, openChat };
}
async function ready(page: Page) {
  await expect(page.getByRole('region', { name: 'Chat', exact: true })).toHaveAttribute(
    'aria-busy',
    'false',
  );
  await expect(
    page.getByText('Chatを開けませんでした。接続を確認し、画面を開き直してください。', {
      exact: true,
    }),
  ).toHaveCount(0);
}
const chat = (page: Page) => page.getByRole('region', { name: '暗号化チャット', exact: true });
async function idle(page: Page) {
  await expect(chat(page)).toHaveAttribute('aria-busy', 'false');
}
async function click(page: Page, name: string) {
  await page.getByRole('button', { name, exact: true }).click();
  await idle(page);
}
async function own(page: Page) {
  await click(page, '自分の端末コードを表示');
  const code = await page
    .getByRole('textbox', { name: '自分の端末コード', exact: true })
    .inputValue();
  const fingerprint = await page
    .locator('details p')
    .filter({ hasText: /^あなたの指紋：/ })
    .textContent();
  assert.ok(fingerprint);
  return { code, fingerprint: fingerprint.replace('あなたの指紋：', '') };
}
async function trust(page: Page, peer: { code: string; fingerprint: string }) {
  await page.getByRole('textbox', { name: '相手の端末コード', exact: true }).fill(peer.code);
  await click(page, '署名を検証して確認内容を表示');
  const field = page.getByRole('textbox', {
    name: '別の連絡手段で確認した相手の指紋',
    exact: true,
  });
  await expect(field).toHaveValue('');
  // The test conveys the other device's own fingerprint, independently of the
  // contact being reviewed. The product never fills this field itself.
  await field.fill(peer.fingerprint);
  await click(page, '指紋を確認して承認');
}
async function approve(page: Page) {
  const button = page.getByRole('button', { name: 'この招待を承認', exact: true });
  await expect(button).toBeDisabled();
  await page
    .getByRole('checkbox', {
      name: '別の連絡手段で確認した相手の指紋と、この会話のコードが一致しています',
      exact: true,
    })
    .check();
  await button.click();
  await idle(page);
}

test(
  'disabled product beta is absent before any messaging schema or issuer key exists',
  { timeout: 60_000 },
  async () => {
    const f = await fixture(false),
      browser = await chromium.launch();
    try {
      const actor = await f.seed(),
        c = await client(f, browser, actor);
      await c.openVault();
      await c.openChat();
      await expect(c.page.getByRole('status')).toContainText('まだ利用できません');
      assert.equal(
        await c.page.getByRole('button', { name: 'チャットを開く', exact: true }).count(),
        0,
      );
      const config = await f.worker.fetch(`${origin}/vault/messaging-config`, {
        headers: { cookie: `__Host-op-sso=${actor.secret}` },
      });
      assert.equal(config.status, 200);
      assert.deepEqual(await config.json(), { enabled: false });
      for (const path of [
        '/messaging/account',
        '/messaging/client.js',
        '/messaging/crypto.wasm',
        '/messaging/chat.css',
        '/chat/client.js',
        '/chat/crypto.wasm',
      ])
        assert.equal((await f.worker.fetch(`${origin}${path}`)).status, 404, path);
      assert.equal(c.requests.filter((r) => r.path.startsWith('/messaging/')).length, 0);
      const page = await f.worker.fetch(`${origin}/vault`, {
        headers: { cookie: `__Host-op-sso=${actor.secret}` },
      });
      assert.doesNotMatch(page.headers.get('Content-Security-Policy')!, /wasm-unsafe-eval/);
      assert.deepEqual(c.errors, []);
    } finally {
      await browser.close();
      await f.harness.close();
    }
  },
);

test(
  'default product build ignores the runtime beta flag without a messaging schema or key',
  { timeout: 60_000 },
  async () => {
    const f = await fixture(false, true);
    try {
      const actor = await f.seed();
      const response = await f.worker.fetch(`${origin}/vault/messaging-config`, {
        headers: { cookie: `__Host-op-sso=${actor.secret}` },
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { enabled: false });
      assert.equal((await f.worker.fetch(`${origin}/messaging/account`)).status, 404);
      assert.equal((await f.worker.fetch(`${origin}/messaging/client.js`)).status, 404);
      const page = await f.worker.fetch(`${origin}/vault`, {
        headers: { cookie: `__Host-op-sso=${actor.secret}` },
      });
      assert.doesNotMatch(page.headers.get('Content-Security-Policy')!, /wasm-unsafe-eval/);
    } finally {
      await f.harness.close();
    }
  },
);

test(
  'two owners use the normal Vault product UI for native encrypted chat; reload preserves custody and lock clears text',
  { timeout: 180_000 },
  async () => {
    const f = await fixture(true),
      browser = await chromium.launch();
    try {
      assert.equal((await f.worker.fetch(`${origin}/vault/messaging-config`)).status, 401);
      assert.equal((await f.worker.fetch(`${origin}/messaging/account`)).status, 401);
      const actorA = await f.seed(),
        actorB = await f.seed(),
        a = await client(f, browser, actorA),
        b = await client(f, browser, actorB);
      for (const c of [a, b]) {
        await c.openVault();
        assert.equal(c.ceremonies(), 0);
        assert.equal(c.requests.filter((r) => r.path.startsWith('/messaging/')).length, 0);
        await c.openChat();
        const enroll = c.page.getByRole('button', {
          name: 'この端末でチャットを有効にする',
          exact: true,
        });
        await expect(enroll).toBeEnabled();
        assert.equal(
          c.requests.filter((r) => r.path === '/messaging/account' && r.method === 'POST').length,
          0,
        );
        await enroll.click();
        await idle(c.page);
        // No second PRF ceremony or separate owner controller is needed for chat.
        assert.equal(c.ceremonies(), 1);
      }
      const publicA = await own(a.page),
        publicB = await own(b.page);
      await trust(a.page, publicB);
      await trust(b.page, publicA);
      await click(a.page, '招待コードを作る');
      const invitation = await a.page
        .getByRole('textbox', { name: '共有する招待コード', exact: true })
        .inputValue();
      await b.page
        .getByRole('textbox', { name: '受け取った招待コード', exact: true })
        .fill(invitation);
      await click(b.page, 'コードを確認');
      await approve(a.page);
      await approve(b.page);
      await click(a.page, '同期');
      await click(b.page, '同期');
      await click(a.page, '同期');
      await a.page
        .getByRole('textbox', { name: 'メッセージ', exact: true })
        .fill('Vaultから始める暗号化チャット');
      await click(a.page, '送信');
      await click(b.page, '同期');
      await expect(b.page.getByRole('region', { name: 'メッセージ履歴' })).toContainText(
        'Vaultから始める暗号化チャット',
      );
      await b.page
        .getByRole('textbox', { name: 'メッセージ', exact: true })
        .fill('同じ画面から返信します');
      await click(b.page, '送信');
      await click(a.page, '同期');
      await expect(a.page.getByRole('region', { name: 'メッセージ履歴' })).toContainText(
        '同じ画面から返信します',
      );
      for (const c of [a, b])
        assert.ok(
          c.requests
            .filter((r) => r.path.startsWith('/messaging/') && r.body)
            .every(
              (r) => !r.body!.includes('Vaultから始める') && !r.body!.includes('同じ画面から返信'),
            ),
        );
      const request =
        'openid4vp:?client_id=verifier&request_uri=https%3A%2F%2Fverifier.example%2Frequest%3Fid%3Done';
      await a.page.getByRole('textbox', { name: 'メッセージ', exact: true }).fill(request);
      await click(a.page, '送信');
      await click(b.page, '同期');
      await expect(
        b.page.getByRole('link', { name: 'Walletで提示内容を確認', exact: true }),
      ).toHaveAttribute('href', request);
      const ceremonies = b.ceremonies();
      await b.page.getByRole('textbox', { name: 'メッセージ', exact: true }).fill('未送信の下書き');
      b.page.once('dialog', (dialog) => dialog.dismiss());
      await b.page.getByRole('button', { name: 'Wallet', exact: true }).click();
      await expect(b.page.getByRole('textbox', { name: 'メッセージ', exact: true })).toHaveValue(
        '未送信の下書き',
      );
      b.page.once('dialog', (dialog) => dialog.dismiss());
      await b.page.getByRole('button', { name: '設定', exact: true }).click();
      await expect(b.page.getByRole('textbox', { name: 'メッセージ', exact: true })).toHaveValue(
        '未送信の下書き',
      );
      b.page.once('dialog', (dialog) => dialog.accept());
      await b.page.getByRole('button', { name: 'Wallet', exact: true }).click();
      await expect(b.page.getByRole('region', { name: 'メッセージ履歴' })).toHaveCount(0);
      await b.page.getByRole('button', { name: 'Chat', exact: true }).click();
      await ready(b.page);
      await expect(b.page.getByRole('region', { name: 'メッセージ履歴' })).toContainText(
        '同じ画面から返信します',
      );
      assert.equal(b.ceremonies(), ceremonies, 'tab navigation reuses the owner unlock');
      const before = await f.DB.prepare(
        'SELECT account_id,device_id,generation,revision FROM messaging_device_head ORDER BY account_id',
      ).all();
      assert.equal(before.results.length, 2);
      await a.openVault();
      await a.openChat();
      await idle(a.page);
      await expect(a.page.getByRole('region', { name: 'メッセージ履歴' })).toContainText(
        '同じ画面から返信します',
      );
      assert.deepEqual(
        (
          await f.DB.prepare(
            'SELECT account_id,device_id,generation,revision FROM messaging_device_head ORDER BY account_id',
          ).all()
        ).results,
        before.results,
      );
      await auditAccessibility(a.page, 'messaging-beta-chat');
      assert.equal(
        await a.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        true,
      );
      await mkdir(`${root}local/generated/messaging-beta`, { recursive: true });
      await a.page.screenshot({
        path: `${root}local/generated/messaging-beta/chat-mobile.png`,
        fullPage: true,
      });
      const preview =
        process.env['MIKAKI_WALLET_CHAT_PREVIEW'] === '1'
          ? 'docs/wallet-chat-mvp-preview'
          : 'local/generated/wallet-chat-mvp-preview';
      await mkdir(`${root}${preview}`, { recursive: true });
      await b.page.screenshot({ path: `${root}${preview}/chat-390.png`, fullPage: true });
      await a.page.getByRole('button', { name: 'ロック', exact: true }).click();
      await expect(a.page.getByText('同じ画面から返信します', { exact: true })).toHaveCount(0);
      await expect(a.page.locator('.messaging-host')).toHaveCount(0);
      // Same authenticated owner, a new browser with no local profile: never
      // substitute a new identity for the registered device or lose old history.
      const fresh = await client(f, browser, actorA);
      await fresh.openVault();
      await fresh.openChat();
      await expect(fresh.page.locator('.messaging-host [role=alert]')).toContainText(
        '保存データを確認できない',
      );
      assert.equal(
        await fresh.page
          .getByRole('button', { name: 'この端末でチャットを有効にする', exact: true })
          .count(),
        0,
      );
      assert.equal(
        fresh.requests.filter((r) => r.path === '/messaging/account' && r.method === 'POST').length,
        0,
      );
      assert.deepEqual(
        (
          await f.DB.prepare(
            'SELECT account_id,device_id,generation,revision FROM messaging_device_head ORDER BY account_id',
          ).all()
        ).results,
        before.results,
      );
      await f.DB.prepare('UPDATE sso_session SET revoked=1 WHERE sso_id=?')
        .bind(actorB.session)
        .run();
      assert.equal(
        (
          await f.worker.fetch(`${origin}/vault/messaging-config`, {
            headers: { cookie: `__Host-op-sso=${actorB.secret}` },
          })
        ).status,
        401,
      );
      assert.equal(
        (
          await f.worker.fetch(`${origin}/messaging/account`, {
            headers: { cookie: `__Host-op-sso=${actorB.secret}` },
          })
        ).status,
        401,
      );
      assert.deepEqual([...a.errors, ...b.errors, ...fresh.errors], []);
    } finally {
      await browser.close();
      await f.harness.close();
    }
  },
);

// The beta ships the browser engine as static assets, without increasing the
// ordinary product's server Wasm budget.
test('enabled Chat beta stays within the existing server size cap and bounded lazy assets', async () => {
  const f = await fixture(true);
  try {
    const budgets = {
      '/messaging/client.js': [262144, 65536],
      '/messaging/crypto.wasm': [2097152, 786432],
      '/messaging/chat.css': [8192, 3072],
    };
    for (const [path, [raw, gzip]] of Object.entries(budgets)) {
      const response = await f.worker.fetch(`${origin}${path}`);
      assert.equal(response.status, 200);
      const bytes = Buffer.from(await response.arrayBuffer());
      assert.ok(bytes.length > 0 && bytes.length <= raw, `${path}: ${bytes.length} > ${raw}`);
      assert.ok(gzipSync(bytes).length <= gzip, `${path} gzip budget`);
    }
    const wasm = await readFile(`${root}crates/worker/build-messaging-beta/index_bg.wasm`);
    assert.ok(wasm.length <= 8388608, `beta server Wasm: ${wasm.length} > 8 MiB`);
    assert.ok(gzipSync(wasm).length <= 3145728, 'beta server Wasm gzip budget');
  } finally {
    await f.harness.close();
  }
});
