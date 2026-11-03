import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { chromium, expect } from '@playwright/test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { issueBootstrapInvite } from '../../scripts/enrollment-store.ts';
import { journeyServer } from './support/journey-server.ts';
import { journeyRp } from './support/journey-rp.ts';
import { applyWorkMigrations } from './support/work-migrations.ts';

test(
  'DBSC real Chromium: passkey login registers and refreshes a bound session',
  { timeout: 120000 },
  async () => {
    let dispatch: Parameters<typeof journeyServer>[0] = async () => {
      throw new Error('not ready');
    };
    const server = await journeyServer((url, init) => dispatch(url, init));
    let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
    let harness: ReturnType<typeof createTestHarness> | undefined;
    try {
      const issuer = `https://mikaki.test:${server.port}`,
        rpOrigin = `https://journey-rp.test:${server.port}`,
        clientId = 'journey-rp';
      const opKeys = await generateKeyPair('ES256', { extractable: true });
      const rpKeys = await generateKeyPair('ES256', { extractable: true });
      const publicJwk = {
        ...(await exportJWK(opKeys.publicKey)),
        kid: 'journey-op',
        alg: 'ES256',
        use: 'sig',
      };
      const privateJwk = {
        ...(await exportJWK(opKeys.privateKey)),
        kid: 'journey-op',
        alg: 'ES256',
        use: 'sig',
      };
      const rpJwk = await exportJWK(rpKeys.publicKey);
      const sec1 = Buffer.concat([
        Buffer.from([4]),
        Buffer.from(rpJwk.x!, 'base64url'),
        Buffer.from(rpJwk.y!, 'base64url'),
      ]);
      const root = new URL('../..', import.meta.url).pathname;
      const authority = 'dbsc-journey';
      const base = JSON.parse(await readFile(join(root, 'crates/worker/wrangler.jsonc'), 'utf8'));
      base.assets.directory = join(root, 'assets');
      const config = {
        ...base,
        main: join(root, 'crates/worker/service/entrypoint.ts'),
        d1_databases: base.d1_databases.map((db: Record<string, unknown>) => ({
          ...db,
          migrations_dir: join(root, 'crates/worker/migrations'),
        })),
        services: [
          {
            binding: 'WORK_AUTHORITY_CHECKPOINT',
            service: 'dbsc-checkpoint',
            entrypoint: 'WorkCheckpointService',
          },
        ],
        vars: { ...base.vars, MIKAKI_ISSUER: issuer },
        queues: { ...base.queues, consumers: [] },
        triggers: { crons: [] },
      };
      harness = createTestHarness({
        root,
        workers: [
          { config, secrets: { OP_PRIVATE_JWK: JSON.stringify(privateJwk) } },
          {
            config: {
              name: 'dbsc-checkpoint',
              main: join(root, 'crates/work-checkpoint-worker/worker.ts'),
              compatibility_date: '2026-10-08',
              vars: { WORK_AUTHORITY_ID: authority },
              durable_objects: {
                bindings: [{ name: 'CHECKPOINTS', class_name: 'WorkCheckpoint' }],
              },
              migrations: [{ tag: 'dbsc-v1', new_sqlite_classes: ['WorkCheckpoint'] }],
            },
          },
        ],
      });
      await harness.listen();
      const worker = harness.getWorker('mikaki-op-worker');
      await worker.applyD1Migrations('DB');
      const { DB } = await worker.getEnv();
      await applyWorkMigrations(DB, 14);
      const policy = JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      );
      await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'DBSC browser journey' });
      await DB.batch([
        DB.prepare(
          "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES(?,1,1,'journey-rp.test')",
        ).bind(clientId),
        DB.prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)').bind(
          clientId,
          `${rpOrigin}/callback`,
        ),
        DB.prepare("INSERT INTO client_key VALUES(?,'journey-rp',1,1,'ES256',?)").bind(
          clientId,
          sec1,
        ),
        DB.prepare("INSERT INTO signing_key VALUES('journey-op',1,1,'ES256',?)").bind(
          JSON.stringify(publicJwk),
        ),
      ]);
      const { invitation } = await issueBootstrapInvite(DB, 'test', 'Disposable DBSC owner');
      const { CHECKPOINTS } = await harness.getWorker('dbsc-checkpoint').getEnv();
      const checkpoint = CHECKPOINTS.getByName(authority);
      const initial = { authority, epoch: 'a'.repeat(64), sequence: 0, tip: 'b'.repeat(64) };
      await checkpoint.bootstrap(initial, 1);
      await DB.prepare('INSERT INTO work_authority_checkpoint VALUES(1,?,?,?,?)')
        .bind(initial.authority, initial.epoch, initial.sequence, initial.tip)
        .run();
      const rp = await journeyRp(
        issuer,
        rpOrigin,
        clientId,
        rpKeys.privateKey,
        publicJwk,
        (url, init) => worker.fetch(url, init),
      );
      let refreshHeaders: Record<string, string> | undefined;
      const requests: Array<{
        path: string;
        status: number;
        registration: boolean;
        response: boolean;
      }> = [];
      dispatch = async (url, init) => {
        const target = new URL(url);
        if (target.origin === rpOrigin) return rp.handle(new Request(url, init));
        if (target.origin !== issuer) throw new Error('Unexpected origin');
        if (target.pathname === '/__test/expire')
          return new Response('expiry fixture', {
            headers: {
              'Set-Cookie': '__Host-op-sso=x; Max-Age=1; Path=/; Secure; HttpOnly; SameSite=Lax',
            },
          });
        const response = await worker.fetch(url, { ...init, redirect: 'manual' });
        if (target.pathname === '/dbsc/refresh' && init.headers['secure-session-response'])
          refreshHeaders = init.headers;
        if (target.pathname.startsWith('/dbsc/') || target.pathname === '/login/finish') {
          requests.push({
            path: target.pathname,
            status: response.status,
            registration: !!response.headers.get('Secure-Session-Registration'),
            response: !!init.headers['secure-session-response'],
          });
        }
        return response;
      };
      browser = await chromium.launch({
        ...(process.env.DBSC_CHROME_PATH
          ? { executablePath: process.env.DBSC_CHROME_PATH }
          : { channel: 'chromium' }),
        headless: true,
        args: [
          '--host-resolver-rules=MAP mikaki.test 127.0.0.1, MAP journey-rp.test 127.0.0.1',
          '--no-proxy-server',
          `--ignore-certificate-errors-spki-list=${server.spki}`,
          '--enable-features=DeviceBoundSessions:RequireOriginTrialTokens/false/RefreshQuota/false/CheckSubdomainRegistration/false/OriginTrialFeedback/true/SchemaVersion/2,DeviceBoundSessionsIncludeAudienceClaim,EnableBoundSessionCredentialsSoftwareKeysForManualTesting',
        ],
      });
      const context = await browser.newContext({ locale: 'en-US', ignoreHTTPSErrors: true });
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable', { enableUI: false });
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
      await page.goto(`${issuer}/?lang=en`);
      await page.getByRole('link', { name: 'Register with an invitation', exact: true }).click();
      await page.getByLabel('Invitation code', { exact: true }).fill(invitation);
      await page.getByRole('button', { name: 'Register with invitation', exact: true }).click();
      await expect(
        page.getByRole('heading', { name: 'Registration complete', exact: true }),
      ).toBeVisible();
      await page.goto(rpOrigin);
      await page.getByRole('link', { name: 'Sign in', exact: true }).click();
      await page.getByRole('button', { name: 'Continue this connection', exact: true }).click();
      await expect(
        page.getByRole('heading', { name: 'Signed-in application', exact: true }),
      ).toBeVisible();
      await new Promise((resolve) => setTimeout(resolve, 5000));
      console.log('DBSC_E2E_OBSERVED', JSON.stringify(requests));
      assert.ok(
        requests.some((r) => r.path === '/dbsc/register' && r.response && r.status === 200),
        'Chromium must register a bound session with a signed proof',
      );
      const before = (await context.cookies(issuer)).find((c) => c.name === '__Host-op-sso')?.value;
      assert.ok(before);
      await page.goto(`${issuer}/__test/expire`);
      await new Promise((resolve) => setTimeout(resolve, 2200));
      await page.goto(`${issuer}/?lang=en`);
      console.log('DBSC_REFRESH_OBSERVED', JSON.stringify(requests));
      await expect
        .poll(() => requests.filter((r) => r.path === '/dbsc/refresh' && r.status === 200).length, {
          timeout: 3000,
        })
        .toBeGreaterThan(0);
      const after = (await context.cookies(issuer)).find((c) => c.name === '__Host-op-sso')?.value;
      assert.ok(after);
      assert.notEqual(after, before);
      assert.ok(refreshHeaders);
      const replay = await worker.fetch(`${issuer}/dbsc/refresh`, {
        method: 'POST',
        headers: refreshHeaders,
      });
      assert.equal(replay.status, 403, 'replayed proof cannot refresh');
      assert.ok(replay.headers.get('Secure-Session-Challenge'));
      assert.equal(replay.headers.get('set-cookie'), null);
      await DB.prepare('UPDATE dbsc_challenge SET expires_at=? WHERE session_id IS NOT NULL')
        .bind(Math.floor(Date.now() / 1000) - 1)
        .run();
      await page.goto(`${issuer}/__test/expire`);
      await new Promise((resolve) => setTimeout(resolve, 2200));
      await page.goto(`${issuer}/?lang=en`);
      await expect
        .poll(() => requests.filter((r) => r.path === '/dbsc/refresh' && r.status === 200).length, {
          timeout: 10000,
        })
        .toBe(2);
      assert.ok(
        requests.filter((r) => r.path === '/dbsc/refresh' && r.status === 403).length >= 2,
        'expired cached challenge prompts a new challenge',
      );
      console.log('DBSC_BROWSER_REFRESH', JSON.stringify(requests));
      assert.equal((await DB.prepare('SELECT COUNT(*) AS n FROM dbsc_session').first()).n, 1);
      const row = (await DB.prepare('SELECT session_id, sso_id FROM dbsc_session').first()) as {
        session_id: string;
        sso_id: string;
      };
      const challengeResponse = await worker.fetch(`${issuer}/dbsc/refresh`, {
        method: 'POST',
        headers: { 'Sec-Secure-Session-Id': `"${row.session_id}"` },
      });
      assert.equal(challengeResponse.status, 403);
      const challenge = /^"([^"]+)";id=/.exec(
        challengeResponse.headers.get('Secure-Session-Challenge') ?? '',
      )?.[1];
      assert.ok(challenge);
      const attacker = await generateKeyPair('ES256');
      const forged = await new SignJWT({
        jti: challenge,
        sub: row.session_id,
        aud: `${issuer}/dbsc/refresh`,
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dbsc+jwt' })
        .setIssuedAt()
        .sign(attacker.privateKey);
      const invalid = await worker.fetch(`${issuer}/dbsc/refresh`, {
        method: 'POST',
        headers: {
          'Sec-Secure-Session-Id': `"${row.session_id}"`,
          'Secure-Session-Response': `"${forged}"`,
        },
      });
      assert.equal(invalid.status, 400, 'wrong signing key is rejected');
      // Exercise the same guard that protects production sessions before using
      // a checkpointed fixture transaction to model revocation.
      await assert.rejects(
        DB.prepare('UPDATE sso_session SET revoked=1 WHERE sso_id=?').bind(row.sso_id).run(),
      );
      const state = await checkpoint.status(1);
      const permit = await checkpoint.begin(state.checkpoint, randomUUID(), 1);
      await DB.batch([
        DB.prepare(
          'UPDATE work_authority_checkpoint SET sequence=?,tip=? WHERE id=1 AND authority=? AND epoch=? AND sequence=? AND tip=?',
        ).bind(
          permit.next.sequence,
          permit.next.tip,
          permit.previous.authority,
          permit.previous.epoch,
          permit.previous.sequence,
          permit.previous.tip,
        ),
        DB.prepare('INSERT INTO work_authority_frame VALUES(1,?,?,1)').bind(
          permit.next.sequence,
          permit.next.tip,
        ),
        DB.prepare('UPDATE sso_session SET revoked=1 WHERE sso_id=?').bind(row.sso_id),
        DB.prepare('DELETE FROM work_authority_frame WHERE id=1'),
      ]);
      await checkpoint.commit(permit, permit.next, 1);
      const revoked = await worker.fetch(`${issuer}/dbsc/refresh`, {
        method: 'POST',
        headers: { 'Sec-Secure-Session-Id': `"${row.session_id}"` },
      });
      assert.equal(revoked.status, 401, 'revoked parent cannot refresh');
    } catch (error) {
      console.error('DBSC_E2E_FAILURE', error);
      throw error;
    } finally {
      await browser?.close();
      await harness?.close();
      await server.close();
    }
  },
);
