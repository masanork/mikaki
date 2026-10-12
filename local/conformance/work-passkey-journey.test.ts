/** Disposable HTTPS journey through the product OP and its SQLite checkpoint.
 * Browser credentials/cookies are created only by real virtual WebAuthn ceremonies.
 * Operator setup supplies a verified Git snapshot; no provider or AI is contacted.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { chromium, expect } from '@playwright/test';
import type { D1Database } from '@cloudflare/workers-types';
import { createTestHarness } from 'wrangler';
import { issueBootstrapInvite } from '../../scripts/enrollment-store.ts';
import { gitFixture } from '../../scripts/work-git-fixture.ts';
import { prepareWorkCodeCopy } from '../../scripts/prepare-work-code-copy.ts';
import {
  prepareWorkCodeSource,
  verifyWorkCodeSource,
} from '../../scripts/prepare-work-code-source.ts';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { startBrowserEvidence } from './support/browser-evidence.ts';
import { journeyServer } from './support/journey-server.ts';
import { applyWorkMigrations } from './support/work-migrations.ts';

for (const lang of ['ja', 'en'] as const) {
  test(`Work HTTPS journey (${lang}): virtual Passkey enrollment/login, preparation, explicit consent and logout refusal`, async () => {
    let dispatch: Parameters<typeof journeyServer>[0] = async () => {
      throw new Error('Work journey not ready');
    };
    const server = await journeyServer((url, init) => dispatch(url, init));
    const directory = await mkdtemp(join(tmpdir(), 'mikaki-work-passkey-journey-'));
    let harness: ReturnType<typeof createTestHarness> | undefined;
    let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
    let evidence: Awaited<ReturnType<typeof startBrowserEvidence>> | undefined;
    let failure: unknown;
    try {
      const root = new URL('../..', import.meta.url).pathname;
      const issuer = `https://mikaki.test:${server.port}`;
      const authority = 'work-passkey-journey';
      const checkpointBinding = {
        binding: 'WORK_AUTHORITY_CHECKPOINT',
        service: 'journey-checkpoint',
        entrypoint: 'WorkCheckpointService',
      };
      const base = JSON.parse(await readFile(join(root, 'crates/worker/wrangler.jsonc'), 'utf8'));
      const config = {
        ...base,
        name: 'work-journey-op',
        main: join(root, 'crates/worker/service/entrypoint.ts'),
        d1_databases: base.d1_databases.map((db: Record<string, unknown>) => ({
          ...db,
          migrations_dir: join(root, 'crates/worker/migrations'),
        })),
        services: [checkpointBinding],
        vars: {
          ...base.vars,
          MIKAKI_ISSUER: issuer,
          WORK_OWNER_API_ENABLED: 'true',
          WORK_SOURCE_API_ENABLED: 'true',
          WORK_PREPARATION_REVIEW_ENABLED: 'true',
          WORK_PREPARATION_COMPOSE_ENABLED: 'true',
          WORK_COPY_CONSENT_ENABLED: 'true',
          WORK_COPY_EXECUTION_ENABLED: 'false',
          WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
          WORK_ARTIFACTS_NAMESPACE: 'mikaki-dev',
          WORK_COPY_RECIPIENT: 'mikaki-work-test',
          WORK_COPY_WORKLOAD: 'mikaki-work-test',
        },
        // Logout has no RP delivery in this code-only journey.
        queues: { ...base.queues, consumers: [] },
        triggers: { crons: [] },
      };
      harness = createTestHarness({
        root,
        workers: [
          { config },
          {
            config: {
              ...config,
              name: 'work-journey-operator',
              main: join(root, 'local/generated/work-store-main/worker.mjs'),
              vars: { LOCAL_WORK_QUALIFICATION: 'true' },
              services: [
                checkpointBinding,
                {
                  binding: 'CHECKPOINT_ADMIN',
                  service: 'journey-checkpoint',
                  entrypoint: 'WorkCheckpointAdmin',
                },
                {
                  binding: 'OP_AUTHORITY_ADMIN',
                  service: config.name,
                  entrypoint: 'OpAuthorityAdmin',
                },
              ],
            },
          },
          {
            config: {
              name: 'journey-checkpoint',
              main: join(root, 'crates/work-checkpoint-worker/worker.ts'),
              compatibility_date: '2026-10-08',
              vars: { WORK_AUTHORITY_ID: authority },
              durable_objects: {
                bindings: [{ name: 'CHECKPOINTS', class_name: 'WorkCheckpoint' }],
              },
              migrations: [{ tag: 'journey-v1', new_sqlite_classes: ['WorkCheckpoint'] }],
            },
          },
        ],
      });
      await harness.listen();
      const worker = harness.getWorker(config.name);
      const operator = harness.getWorker('work-journey-operator');
      await worker.applyD1Migrations('DB');
      const { DB } = (await worker.getEnv()) as { DB: D1Database };
      await applyWorkMigrations(DB, 14);
      await activateWorkerPolicy(
        DB,
        JSON.parse(await readFile(join(root, 'local/generated/worker-policy.json'), 'utf8')),
        { actor: 'test', reason: 'Virtual Passkey to Work journey' },
      );
      const { invitation } = await issueBootstrapInvite(DB, 'test', 'Disposable Work owner');
      const checkpoint = async (input: Record<string, unknown>) => {
        const response = await operator.fetch('https://private.invalid/checkpoint-fixture', {
          method: 'POST',
          body: JSON.stringify(input),
        });
        assert.equal(response.status, 200);
        return response.json();
      };
      const initial = { authority, epoch: 'a'.repeat(64), sequence: 0, tip: 'b'.repeat(64) };
      await checkpoint({ action: 'bootstrap', checkpoint: initial, floor: 1 });
      await DB.prepare('INSERT INTO work_authority_checkpoint VALUES(1,?,?,?,?)')
        .bind(initial.authority, initial.epoch, initial.sequence, initial.tip)
        .run();
      const git = await gitFixture(
        directory,
        'code',
        { 'README.md': 'Disposable Work E2E code\n' },
        'Excluded history\n',
      );
      const packet = await prepareWorkCodeSource(
        git.dir,
        git.commit,
        directory,
        'journey-code',
        'journey-code',
        'Work E2E code snapshot',
      );
      const verified = await verifyWorkCodeSource(packet.directory, git.dir);
      dispatch = async (url, init) => {
        assert.equal(new URL(url).origin, issuer);
        return worker.fetch(url, { ...init, redirect: 'manual' });
      };

      browser = await chromium.launch({
        headless: true,
        args: ['--host-resolver-rules=MAP mikaki.test 127.0.0.1', '--no-proxy-server'],
      });
      const context = await browser.newContext({
        ignoreHTTPSErrors: true,
        viewport: lang === 'en' ? { width: 375, height: 900 } : { width: 1280, height: 1000 },
      });
      evidence = await startBrowserEvidence(context, `work-passkey-journey-${lang}`);
      const page = await context.newPage();
      page.setDefaultTimeout(10_000);
      const errors: string[] = [];
      page.on('pageerror', (error) => errors.push(error.message));
      const cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable', { enableUI: false });
      let assertions = 0,
        registrations = 0;
      cdp.on('WebAuthn.credentialAsserted', () => assertions++);
      cdp.on('WebAuthn.credentialAdded', () => registrations++);
      await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          ctap2Version: 'ctap2_1',
          transport: 'internal',
          hasResidentKey: true,
          hasUserVerification: true,
          hasPrf: true,
          automaticPresenceSimulation: true,
          isUserVerified: true,
        },
      });
      const count = async (table: string) =>
        Number(await DB.prepare(`SELECT count(*) AS n FROM ${table}`).first('n'));
      const noEffects = async () => {
        for (const table of [
          'work_copy_job',
          'work_credential_attempt',
          'work_task_repository',
          'work_grant',
          'work_run',
        ])
          assert.equal(await count(table), 0, table);
      };
      const words =
        lang === 'ja'
          ? {
              register: '招待で登録する',
              registered: '登録が完了しました',
              invitation: '招待コード',
              logout: 'ログアウト',
              loggedOut: 'ログアウトしました',
              prepare: '準備を作成',
              review: '準備を確認する',
              inspect: '開示対象のファイル内容を確認',
              approve: 'このコピーを承認',
              withdraw: 'コピーの承認を取り消す',
              integrity: '照合用の記録',
              save: '開示記録を保存',
            }
          : {
              register: 'Register with invitation',
              registered: 'Registration complete',
              invitation: 'Invitation code',
              logout: 'Log out',
              loggedOut: 'You have logged out',
              prepare: 'Prepare copy',
              review: 'Review preparation',
              inspect: 'Inspect disclosed file contents',
              approve: 'Approve this copy',
              withdraw: 'Withdraw copy consent',
              integrity: 'Integrity records',
              save: 'Save disclosure record',
            };
      assert.equal((await page.goto(`${issuer}/work/source-review?lang=${lang}`))?.status(), 401);
      assert.equal(await count('account_security'), 0);
      assert.equal(await count('sso_session'), 0);
      await page.goto(`${issuer}/enroll?lang=${lang}`);
      await page.getByLabel(words.invitation, { exact: true }).fill(invitation);
      await page.getByRole('button', { name: words.register, exact: true }).click();
      await expect(
        page.getByRole('heading', { name: words.registered, exact: true }),
      ).toBeVisible();
      assert.equal(registrations, 1);
      assert.equal(await count('passkey_credential'), 1);
      const owner = await DB.prepare(
        'SELECT account_id,epoch FROM account_security WHERE active=1',
      ).first<{ account_id: string; epoch: number }>();
      assert.ok(owner);
      const registered = await operator.fetch('https://private.invalid/authority-fixture', {
        method: 'POST',
        body: JSON.stringify({
          action: 'register-source',
          source: verified.source,
          account: owner.account_id,
          expected_epoch: owner.epoch,
          actor: 'verified-local-git',
          reason: 'Independent Git snapshot verification',
        }),
      });
      assert.equal(registered.status, 200, await registered.clone().text());
      assert.equal(await count('work_preparation'), 0);
      assert.equal(await count('work_copy_consent'), 0);

      // Revoke the enrollment SSO, then authenticate normally with its virtual Passkey.
      await page.goto(`${issuer}/logout?lang=${lang}`);
      await page.getByRole('button', { name: words.logout, exact: true }).click();
      await expect(page.getByRole('heading', { name: words.loggedOut, exact: true })).toBeVisible();
      assert.equal((await page.goto(`${issuer}/work/source-review?lang=${lang}`))?.status(), 401);
      const beforeLogin = assertions;
      await page.goto(`${issuer}/signin?lang=${lang}`);
      await page.waitForURL(`${issuer}/vault?lang=${lang}`);
      assert.ok(assertions > beforeLogin, 'Login must perform a virtual WebAuthn assertion');
      const sso = (await context.cookies(issuer)).find((cookie) => cookie.name === '__Host-op-sso');
      assert.ok(sso, 'SSO must come from the product login response');
      const sessionHash = createHash('sha256').update(sso.value).digest('base64url');
      const beforeUnlock = assertions;
      await page.locator('#unlock').click();
      await expect(page.locator('#name')).toHaveValue('');
      assert.ok(assertions > beforeUnlock, 'Vault must perform real virtual PRF authentication');

      await page.goto(`${issuer}/work/source-review?lang=${lang}`);
      await expect(page.locator('html')).toHaveAttribute('lang', lang);
      const prepare = page.getByRole('button', { name: words.prepare, exact: true });
      await expect(prepare).toBeDisabled();
      await page.getByRole('radio', { name: /Work E2E code snapshot/ }).check();
      await expect(prepare).toBeEnabled();
      const createdResponse = page.waitForResponse(
        (response) =>
          new URL(response.url()).pathname === '/work/preparations' &&
          response.request().method() === 'POST',
      );
      await prepare.click();
      const created = await createdResponse;
      assert.equal(created.status(), 200);
      const preparation = (await created.json()).record;
      assert.equal(await count('work_preparation'), 1);
      assert.equal(await count('work_copy_consent'), 0, 'Preparation is not copy consent');
      await noEffects();
      await page.getByRole('link', { name: words.review, exact: true }).click();
      const reviewUrl = `${issuer}/work/preparation-review?lang=${lang}#${preparation.preparation_id}`;
      await expect(page).toHaveURL(reviewUrl);
      const approve = page.getByRole('button', { name: words.approve, exact: true });
      await expect(approve).toBeDisabled();
      await expect(page.getByRole('checkbox')).toBeDisabled();
      await page.getByText(words.integrity, { exact: true }).click();
      const downloadEvent = page.waitForEvent('download');
      await page.getByRole('button', { name: words.save, exact: true }).click();
      const download = await downloadEvent;
      assert.equal(await download.failure(), null);
      const record = JSON.parse(await readFile((await download.path())!, 'utf8'));
      assert.equal(download.suggestedFilename(), `mikaki-work-disclosure-${record.digest}.json`);
      assert.equal(record.digest, preparation.disclosure_digest);
      assert.equal(record.manifest.owner, owner.account_id);
      assert.equal(record.manifest.code.commit, packet.source.commit);
      assert.deepEqual(record.manifest.contexts, []);
      const host = await prepareWorkCodeCopy(
        record,
        packet.directory,
        git.dir,
        join(directory, 'copy-host'),
      );
      assert.equal(host.codeCopyReceipt.disclosure_digest, record.digest);
      assert.equal(host.codeCopyReceipt.owner_consent_recorded, false);
      assert.equal(await count('work_copy_consent'), 0, 'Saving metadata is not consent');
      await noEffects();
      await page.getByRole('button', { name: words.inspect, exact: true }).click();
      await expect(page.getByRole('checkbox')).toBeEnabled();
      await expect(approve).toBeDisabled();
      assert.equal(await count('work_copy_consent'), 0, 'Inspection is not consent');
      await page.getByRole('checkbox').check();
      await approve.click();
      await expect(page.getByRole('button', { name: words.withdraw, exact: true })).toBeVisible();
      const consent = await DB.prepare(
        'SELECT c.owner_id,c.session_hash,c.active,c.revision,c.preparation_digest=p.digest AS exact_digest FROM work_copy_consent c JOIN work_preparation p ON p.operation_id=c.preparation_id',
      ).first();
      assert.deepEqual(consent, {
        owner_id: owner.account_id,
        session_hash: sessionHash,
        active: 1,
        revision: 1,
        exact_digest: 1,
      });
      assert.equal(await count('work_copy_consent_current'), 1);
      const consentDigest = await DB.prepare(
        'SELECT review_digest FROM work_copy_consent',
      ).first<string>('review_digest');
      assert.ok(consentDigest);
      await page.reload();
      await expect(page.getByRole('button', { name: words.withdraw, exact: true })).toBeVisible();
      assert.equal(await count('work_copy_consent'), 1, 'Reload must not resubmit approval');
      assert.equal(
        Number(
          await DB.prepare(
            "SELECT count(*) AS n FROM work_audit WHERE action='copy.approve'",
          ).first('n'),
        ),
        1,
      );
      await noEffects();

      await page.goto(`${issuer}/logout?lang=${lang}`);
      await page.getByRole('button', { name: words.logout, exact: true }).click();
      await expect(page.getByRole('heading', { name: words.loggedOut, exact: true })).toBeVisible();
      assert.equal(
        await count('work_copy_consent_current'),
        0,
        'Logout invalidates the real consenting SSO',
      );
      assert.equal(await count('work_copy_consent'), 1, 'Historical consent is retained');
      const replay = await worker.fetch(
        `${issuer}/work/preparations/${preparation.preparation_id}/copy-consent`,
        {
          method: 'POST',
          headers: {
            cookie: `__Host-op-sso=${sso.value}`,
            origin: issuer,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ format_version: 1, review_digest: consentDigest }),
        },
      );
      assert.equal(replay.status, 401, 'Revoked SSO cannot approve or replay a consent');
      assert.equal((await page.goto(reviewUrl))?.status(), 401);
      await expect(page.getByRole('button', { name: words.approve, exact: true })).toHaveCount(0);
      await noEffects();
      const state = (await checkpoint({ action: 'status', release: 1 })) as {
        checkpoint: typeof initial;
        pending: unknown;
        frozen: boolean;
      };
      const marker = await DB.prepare(
        'SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1',
      ).first();
      assert.deepEqual(state.checkpoint, marker);
      assert.ok(state.checkpoint.sequence > initial.sequence);
      assert.equal(state.pending, null);
      assert.equal(state.frozen, false);
      assert.deepEqual(errors, []);
    } catch (error) {
      failure = error;
      throw error;
    } finally {
      await evidence?.finish(failure);
      await browser?.close();
      await server.close();
      await harness?.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
}
