import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { chromium, expect } from '@playwright/test';
import { createTestHarness } from 'wrangler';

// Run manually with a built, isolated checkout of the publicly active OP commit.
// All mutations target the disposable local Worker; public requests are GET only.
const repository = fileURLToPath(new URL('..', import.meta.url));
const source = resolve(process.env.MIKAKI_SCREENSHOT_SOURCE_ROOT ?? repository);
const destination = new URL('screenshots/onboarding/', import.meta.url);
const issuer = 'https://auth.mikaki.org';
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const versionResponse = await fetch(`${issuer}/version`);
assert.equal(versionResponse.status, 200);
const version = await versionResponse.json();
assert.equal(version.worker, 'mikaki-op');
assert.equal(version.source_clean, true);
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: source, encoding: 'utf8' }).trim();
assert.equal(commit, version.source_commit, 'Use a checkout of the active public OP commit');
const { activateWorkerPolicy } = await import(
  pathToFileURL(resolve(source, 'scripts/worker-policy-store.ts')).href
);
const harness = createTestHarness({
  root: source,
  workers: [
    {
      configPath: resolve(source, 'crates/worker/wrangler.jsonc'),
      vars: { MIKAKI_ISSUER: issuer },
    },
  ],
});
let browser;
const publicAssets = new Map();
const record = {
  checked_at: new Date().toISOString(),
  issuer,
  source_commit: commit,
  version_id: version.version_id,
  assets: {},
  images: [],
  scope:
    'Public enrollment/sign-in GET screens; downloaded deployed UI assets with disposable local Vault data and mocked PRF. No production registration, save or physical-device qualification.',
};
try {
  await harness.listen();
  const worker = harness.getWorker('mikaki-op-worker');
  for (const path of [
    '/login/login.js',
    '/login/login.css',
    '/vault/vault.js',
    '/ui/product.css',
  ]) {
    const local = await worker.fetch(`${issuer}${path}`);
    const publicResponse = await fetch(`${issuer}${path}`);
    assert.equal(local.status, 200, path);
    assert.equal(publicResponse.status, 200, path);
    const bytes = Buffer.from(await publicResponse.arrayBuffer());
    publicAssets.set(path, {
      body: bytes,
      contentType: publicResponse.headers.get('content-type'),
    });
    record.assets[path] = {
      public_sha256: digest(bytes),
      local_sha256: digest(Buffer.from(await local.arrayBuffer())),
    };
  }
  await mkdir(destination, { recursive: true });
  browser = await chromium.launch({ headless: true });
  const errors = [];
  async function capture(page, name, target, kind) {
    await page.evaluate(() => document.fonts.ready);
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),
      false,
      name,
    );
    const buffer = await target.screenshot({ animations: 'disabled' });
    await writeFile(new URL(`${name}.png`, destination), buffer);
    record.images.push({ file: `${name}.png`, sha256: digest(buffer), kind });
  }
  // Own fresh browser contexts: do not read or change the owner's browser/session.
  for (const lang of ['ja', 'en']) {
    const context = await browser.newContext({
      viewport: { width: 375, height: 812 },
      reducedMotion: 'reduce',
    });
    const page = await context.newPage();
    page.on('pageerror', (error) => errors.push(error.message));
    await page.goto(`${issuer}/enroll?lang=${lang}`);
    await expect(
      page.getByRole('heading', {
        name: lang === 'ja' ? 'アカウントを登録' : 'Create an account',
        exact: true,
      }),
    ).toBeVisible();
    await capture(page, `enroll-${lang}`, page.locator('.auth-shell'), 'public-get');
    await page.goto(`${issuer}/signin?lang=${lang}`);
    await expect(
      page.getByRole('button', {
        name: lang === 'ja' ? 'Passkeyでサインイン' : 'Sign in with passkey',
        exact: true,
      }),
    ).toBeVisible();
    await capture(page, `signin-${lang}`, page.locator('.auth-shell'), 'public-get');
    await context.close();
  }
  await worker.applyD1Migrations('DB');
  const { DB } = await worker.getEnv();
  const policy = JSON.parse(
    await readFile(resolve(source, 'local/generated/worker-policy.json'), 'utf8'),
  );
  await activateWorkerPolicy(DB, policy, {
    actor: 'website-preview',
    reason: 'Synthetic onboarding images',
  });
  const credential = new Uint8Array(randomBytes(32));
  const id = Buffer.from(credential).toString('base64url');
  const cookie = randomBytes(32).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  await DB.batch([
    DB.prepare("INSERT INTO account_security VALUES('website-demo',1,1)"),
    DB.prepare("INSERT INTO credential VALUES(?,'website-demo',1)").bind(id),
    DB.prepare("INSERT INTO passkey_credential VALUES(?,'demo-key','demo-user',0,0,0,1)").bind(id),
    DB.prepare("INSERT INTO sso_session VALUES('website-demo','website-demo',?,1,?,0)").bind(
      id,
      now + 3600,
    ),
    DB.prepare("INSERT INTO sso_context VALUES('website-demo',?,?)").bind(
      createHash('sha256').update(cookie).digest('base64url'),
      now,
    ),
  ]);
  for (const lang of ['ja', 'en']) {
    // The single disposable account contains only our sample note.
    const context = await browser.newContext({
      viewport: { width: 900, height: 900 },
      reducedMotion: 'reduce',
    });
    const page = await context.newPage();
    page.on('pageerror', (error) => errors.push(error.message));
    await page.addInitScript(
      ({ credential }) => {
        class MockCredential {
          rawId = Uint8Array.from(credential).buffer;
          getClientExtensionResults() {
            return { prf: { results: { first: new Uint8Array(32).fill(0x71).buffer } } };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: { get: async () => new MockCredential() },
        });
      },
      { credential: [...credential] },
    );
    await page.route(`${issuer}/**`, async (route) => {
      const request = route.request();
      const asset = publicAssets.get(new URL(request.url()).pathname);
      if (asset) {
        await route.fulfill(asset);
        return;
      }
      const headers = await request.allHeaders();
      const response = await worker.fetch(request.url(), {
        method: request.method(),
        headers: {
          ...headers,
          cookie: `__Host-op-sso=${cookie}${headers.cookie ? '; ' + headers.cookie : ''}`,
        },
        ...(request.postData() ? { body: request.postData() } : {}),
      });
      const body = Buffer.from(await response.arrayBuffer());
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body,
      });
    });
    await page.goto(`${issuer}/vault?lang=${lang}`);
    const note = page.locator('#notes > section');
    const open = page.locator('#note-unlock');
    await expect(open).toBeEnabled();
    await capture(page, `vault-locked-${lang}`, page.locator('.vault-shell'), 'local-synthetic');
    await open.click();
    const title = page.getByLabel(lang === 'ja' ? 'メモのタイトル' : 'Note title', { exact: true });
    const text = page.getByLabel(lang === 'ja' ? 'メモの本文' : 'Note text', { exact: true });
    const exampleTitle = lang === 'ja' ? 'はじめてのメモ' : 'My first note';
    const exampleText =
      lang === 'ja'
        ? 'これは操作を試すためのサンプルです。'
        : 'This is sample text for trying the controls.';
    await expect(title).toBeEnabled();
    await title.fill(exampleTitle);
    await text.fill(exampleText);
    await capture(page, `note-edit-${lang}`, note, 'local-synthetic');
    await page.locator('#note-save').click();
    await expect(note.getByRole('status')).toHaveText(
      lang === 'ja' ? 'メモを暗号化して保存しました。' : 'Note encrypted and saved.',
    );
    await expect(title).toBeDisabled();
    await capture(page, `note-saved-${lang}`, note, 'local-synthetic');
    await open.click();
    await expect(title).toHaveValue(exampleTitle);
    await expect(text).toHaveValue(exampleText);
    await capture(page, `note-reopened-${lang}`, note, 'local-synthetic');
    await page.unrouteAll({ behavior: 'wait' });
    await context.close();
  }
  assert.deepEqual(errors, []);
  // Check deployment identity again: do not publish a mixed-version capture.
  const after = await (await fetch(`${issuer}/version`)).json();
  assert.equal(after.version_id, version.version_id);
  assert.equal(after.source_commit, commit);
  await writeFile(new URL('provenance.json', destination), JSON.stringify(record, null, 2) + '\n');
  console.log(
    `Captured ${record.images.length} localized onboarding images; four UI assets are pinned to the public deployment; synthetic save/reopen verified.`,
  );
} finally {
  await browser?.close();
  await harness.close();
}
