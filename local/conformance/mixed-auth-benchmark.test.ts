import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { chromium, expect } from '@playwright/test';
import { exportJWK, generateKeyPair } from 'jose';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { issueBootstrapInvite } from '../../scripts/enrollment-store.ts';
import { journeyServer } from './support/journey-server.ts';
import { journeyRp } from './support/journey-rp.ts';

type RequestSample = {
  cycle: number | null;
  kind: 'setup' | 'warmup' | 'sample';
  phase: string;
  method: string;
  path: string;
  status: number;
  duration_ms: number;
  outcome:
    | 'success'
    | 'expected_rejection'
    | 'expected_absence'
    | 'unexpected_http_error'
    | 'transport_error';
  transport_error?: string;
};

const enabled = process.env.MIKAKI_MIXED_BENCHMARK === '1';
test(
  'local-only mixed auth benchmark: Passkey/PRF, PKCE, UserInfo, protected session, and logout',
  { skip: !enabled, timeout: 180_000 },
  async () => {
    const warmups = 1;
    const samples = 3;
    const concurrency = 2;
    const deadlineMs = 150_000;
    const startedAt = Date.now();
    const startedPerformance = performance.now();
    const requests: RequestSample[] = [];
    const outcomes: Array<Record<string, unknown>> = [];
    const phaseLatency: Record<string, number[]> = {};
    const failures: string[] = [];
    let cycleNumber: number | null = null;
    let cycleKind: RequestSample['kind'] = 'setup';
    let setupMs = 0;
    const percentile = (values: number[], fraction: number) => {
      const sorted = [...values].sort((a, b) => a - b);
      return sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] ?? null;
    };
    const summary = (values: number[]) => ({
      count: values.length,
      min_ms: values.length ? Math.round(Math.min(...values) * 1000) / 1000 : null,
      median_ms: percentile(values, 0.5),
      p95_ms: percentile(values, 0.95),
      p99_ms: percentile(values, 0.99),
      max_ms: values.length ? Math.round(Math.max(...values) * 1000) / 1000 : null,
    });

    let phase = 'setup';
    const recordRequest = (
      method: string,
      path: string,
      status: number,
      durationMs: number,
      started: { cycle: number | null; kind: RequestSample['kind']; phase: string },
      transportError?: string,
    ) => {
      const expectedRejection =
        status === 401 &&
        method === 'GET' &&
        path === '/protected' &&
        started.phase === 'post_logout_check';
      const expectedAbsence =
        status === 404 &&
        method === 'GET' &&
        ((started.phase === 'setup' &&
          [
            '/vault/owner-key',
            '/vault/records/personal/name',
            '/vault/records/personal/owner_note',
          ].includes(path)) ||
          (started.phase === 'owner-prf' && path === '/vault/records/personal/owner_note'));
      requests.push({
        ...started,
        method,
        path,
        status,
        duration_ms: Math.round(durationMs * 1000) / 1000,
        outcome:
          status === 0
            ? 'transport_error'
            : expectedRejection
              ? 'expected_rejection'
              : expectedAbsence
                ? 'expected_absence'
                : status >= 400
                  ? 'unexpected_http_error'
                  : 'success',
        ...(transportError ? { transport_error: transportError } : {}),
      });
    };
    let dispatch: Parameters<typeof journeyServer>[0] = async () => {
      throw new Error('Mixed benchmark bridge is not ready');
    };
    const server = await journeyServer((url, init) => dispatch(url, init));
    let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
    let harness: ReturnType<typeof createTestHarness> | undefined;
    let failure: unknown;
    let runFailed = false;
    try {
      const issuer = `https://mikaki.test:${server.port}`;
      const rpOrigin = `https://journey-rp.test:${server.port}`;
      const clientId = 'mixed-benchmark-rp';
      const opKeys = await generateKeyPair('ES256', { extractable: true });
      const rpKeys = await generateKeyPair('ES256', { extractable: true });
      const publicJwk = {
        ...(await exportJWK(opKeys.publicKey)),
        kid: 'mixed-benchmark-op',
        alg: 'ES256',
        use: 'sig',
      };
      const privateJwk = {
        ...(await exportJWK(opKeys.privateKey)),
        kid: 'mixed-benchmark-op',
        alg: 'ES256',
        use: 'sig',
      };
      const rpJwk = await exportJWK(rpKeys.publicKey);
      assert.ok(rpJwk.x && rpJwk.y);
      const sec1 = Buffer.concat([
        Buffer.from([4]),
        Buffer.from(rpJwk.x, 'base64url'),
        Buffer.from(rpJwk.y, 'base64url'),
      ]);
      harness = createTestHarness({
        root: new URL('../..', import.meta.url).pathname,
        workers: [
          {
            configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
            vars: { MIKAKI_ISSUER: issuer },
            secrets: { OP_PRIVATE_JWK: JSON.stringify(privateJwk) },
          },
        ],
      });
      await harness.listen();
      const worker = harness.getWorker('mikaki-op-worker');
      await worker.applyD1Migrations('DB');
      const { DB } = await worker.getEnv();
      const policy = JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      );
      await activateWorkerPolicy(DB, policy, {
        actor: 'test',
        reason: 'Opt-in local mixed authentication benchmark',
      });
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
        DB.prepare("INSERT INTO signing_key VALUES('mixed-benchmark-op',1,1,'ES256',?)").bind(
          JSON.stringify(publicJwk),
        ),
      ]);
      const { invitation } = await issueBootstrapInvite(DB, 'test', 'Disposable benchmark owner');
      const timedFetch = async (
        url: string,
        init?: {
          method?: string;
          headers?: Record<string, string>;
          body?: string | URLSearchParams;
          redirect?: 'manual' | 'follow';
        },
      ) => {
        const target = new URL(url);
        const before = performance.now();
        const started = { cycle: cycleNumber, kind: cycleKind, phase };
        try {
          const response = await worker.fetch(url, init);
          recordRequest(
            init?.method ?? 'GET',
            target.pathname,
            response.status,
            performance.now() - before,
            started,
          );
          return response;
        } catch (error) {
          recordRequest(
            init?.method ?? 'GET',
            target.pathname,
            0,
            performance.now() - before,
            started,
            error instanceof Error ? error.name : 'UnknownError',
          );
          throw error;
        }
      };
      const rp = await journeyRp(
        issuer,
        rpOrigin,
        clientId,
        rpKeys.privateKey,
        publicJwk,
        (url, init) => timedFetch(url, init),
      );
      dispatch = async (url, init) => {
        const target = new URL(url);
        if (target.origin === issuer)
          return timedFetch(url, {
            method: init.method,
            headers: init.headers,
            ...(init.body ? { body: init.body } : {}),
            redirect: 'manual',
          });
        if (target.origin === rpOrigin) {
          const before = performance.now();
          const started = { cycle: cycleNumber, kind: cycleKind, phase };
          try {
            const response = await rp.handle(new Request(url, init));
            recordRequest(
              init.method,
              target.pathname,
              response.status,
              performance.now() - before,
              started,
            );
            return response;
          } catch (error) {
            recordRequest(
              init.method,
              target.pathname,
              0,
              performance.now() - before,
              started,
              error instanceof Error ? error.name : 'UnknownError',
            );
            throw error;
          }
        }
        throw new Error('Unexpected benchmark origin');
      };
      browser = await chromium.launch({
        headless: true,
        args: [
          '--host-resolver-rules=MAP mikaki.test 127.0.0.1, MAP journey-rp.test 127.0.0.1',
          '--no-proxy-server',
        ],
      });
      const context = await browser.newContext({ locale: 'en-US', ignoreHTTPSErrors: true });
      const page = await context.newPage();
      page.setDefaultTimeout(10_000);
      const protectedPages = await Promise.all([context.newPage(), context.newPage()]);
      for (const protectedPage of protectedPages) protectedPage.setDefaultTimeout(10_000);
      const cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable', { enableUI: false });
      let assertions = 0;
      cdp.on('WebAuthn.credentialAsserted', () => assertions++);
      const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
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
      await expect(page.getByRole('heading', { name: 'Registration complete' })).toBeVisible();
      await page.goto(`${issuer}/vault?lang=en`);
      await page.locator('#unlock').click();
      await expect(page.locator('#name')).toHaveValue('');
      await page.locator('#name').fill('Local mixed benchmark owner');
      await page.locator('#save').click();
      await expect(page.locator('#status')).toHaveText('Saved.');
      const setupSso = (await context.cookies(issuer)).some(
        (cookie) => cookie.name === '__Host-op-sso',
      );
      if (setupSso) {
        phase = 'setup-reset';
        await page.goto(`${issuer}/logout?lang=en`);
        await page.getByRole('button', { name: 'Log out', exact: true }).click();
        await expect(page.getByRole('heading', { name: 'You have logged out' })).toBeVisible();
      }
      setupMs = performance.now() - startedPerformance;

      const runCycle = async (index: number, warmup: boolean) => {
        if (Date.now() - startedAt > deadlineMs) throw new Error('Benchmark deadline exceeded');
        assert.equal(
          (await context.cookies(issuer)).some((cookie) => cookie.name === '__Host-op-sso'),
          false,
          'Each measured authentication cycle must start without an existing OP SSO session',
        );
        cycleNumber = index;
        cycleKind = warmup ? 'warmup' : 'sample';
        const before = performance.now();
        const row: Record<string, unknown> = {
          index,
          kind: warmup ? 'warmup' : 'sample',
          outcome: 'in_progress',
          auth_ms: null,
          prf_ms: null,
          userinfo_ms: null,
          protected_ms: null,
          logout_ms: null,
          post_logout_status: null,
          passkey_assertions: null,
        };
        outcomes.push(row);
        try {
          phase = 'login';
          const assertionStart = assertions;
          const authStart = performance.now();
          await page.goto(rpOrigin);
          await page.getByRole('link', { name: 'Sign in', exact: true }).click();
          await expect(page.getByRole('heading', { name: 'Signed-in application' })).toBeVisible();
          const authMs = performance.now() - authStart;
          row.auth_ms = Math.round(authMs * 1000) / 1000;
          row.passkey_assertions = assertions - assertionStart;
          assert.equal(
            row.passkey_assertions,
            1,
            'Each measured login must use one Passkey assertion',
          );
          assert.ok(rp.lastExchange, 'The login must complete a PKCE code exchange');

          phase = 'owner-prf';
          const prfStart = performance.now();
          const prfAssertionStart = assertions;
          await page.goto(`${issuer}/vault?lang=en`);
          await page.locator('#unlock').click();
          await expect(page.locator('#name')).toHaveValue('Local mixed benchmark owner');
          row.owner_prf_assertions = assertions - prfAssertionStart;
          assert.equal(
            row.owner_prf_assertions,
            1,
            'Each owner PRF unlock must use one Passkey assertion',
          );
          const prfMs = performance.now() - prfStart;
          row.prf_ms = Math.round(prfMs * 1000) / 1000;

          phase = 'userinfo';
          const userinfoStart = performance.now();
          const userinfo = await rp.userinfo();
          const userinfoMs = performance.now() - userinfoStart;
          row.userinfo_ms = Math.round(userinfoMs * 1000) / 1000;
          assert.equal(userinfo.status, 200, 'The local openid-only UserInfo request must succeed');
          assert.equal((userinfo.body as { sub?: unknown }).sub, rp.lastSubject);
          assert.ok(
            (userinfo.body as { name?: unknown }).name == null,
            'openid-only UserInfo is sub-only in this fixture; it does not benchmark profile/name',
          );

          phase = 'protected';
          const protectedStart = performance.now();
          const protectedResponses = await Promise.all(
            protectedPages.map((protectedPage) => protectedPage.goto(`${rpOrigin}/protected`)),
          );
          for (const response of protectedResponses) assert.equal(response?.status(), 200);
          row.protected_ms = Math.round((performance.now() - protectedStart) * 1000) / 1000;
          row.protected_concurrency = concurrency;

          phase = 'logout';
          const logoutStart = performance.now();
          await page.goto(`${issuer}/logout?lang=en`);
          await page.getByRole('button', { name: 'Log out', exact: true }).click();
          await expect(page.getByRole('heading', { name: 'You have logged out' })).toBeVisible();
          row.logout_ms = Math.round((performance.now() - logoutStart) * 1000) / 1000;
          phase = 'post_logout_check';
          const rejected = await protectedPages[0].goto(`${rpOrigin}/protected`);
          assert.ok(rejected);
          row.post_logout_status = rejected.status();
          assert.equal(rejected.status(), 401, 'Protected access must reject the ended OP session');
          const cycleRequests = requests.filter((request) => request.cycle === index);
          const count = (path: string, requestPhase?: string) =>
            cycleRequests.filter(
              (request) =>
                request.path === path && (!requestPhase || request.phase === requestPhase),
            );
          assert.deepEqual(
            count('/authorize').map((request) => request.status),
            [302, 302],
          );
          assert.deepEqual(
            count('/token').map((request) => request.status),
            [200],
          );
          assert.deepEqual(
            count('/userinfo').map((request) => request.status),
            [200],
          );
          assert.deepEqual(
            count('/callback').map((request) => request.status),
            [302],
          );
          assert.deepEqual(
            count('/session/check', 'login').map((request) => request.status),
            [200, 200],
          );
          assert.deepEqual(
            count('/session/check', 'protected').map((request) => request.status),
            [200, 200],
          );
          assert.deepEqual(
            count('/session/check', 'post_logout_check').map((request) => request.status),
            [200],
          );
          assert.deepEqual(
            count('/protected', 'login').map((request) => request.status),
            [200],
          );
          assert.deepEqual(
            count('/protected', 'protected').map((request) => request.status),
            [200, 200],
          );
          assert.deepEqual(
            count('/protected', 'post_logout_check').map((request) => request.status),
            [401],
          );
          assert.equal(count('/logout').length, 2);
          row.outcome = 'success';
          if (!warmup) {
            for (const key of ['auth_ms', 'prf_ms', 'userinfo_ms', 'protected_ms', 'logout_ms']) {
              (phaseLatency[key] ??= []).push(Number(row[key]));
            }
          }
        } catch (error) {
          row.outcome = 'failure';
          const errorType = error instanceof Error ? error.name : 'UnknownError';
          row.failure = {
            phase,
            error_type: errorType,
          };
          failures.push(`cycle ${index}: ${phase}/${errorType}`);
          throw error;
        } finally {
          row.total_ms = Math.round((performance.now() - before) * 1000) / 1000;
        }
      };

      for (let i = 0; i < warmups + samples; i++) await runCycle(i + 1, i < warmups);
      phase = 'complete';
      const perCycle = warmups + samples;
      const expected = { authorize: perCycle * 2, token: perCycle, userinfo: perCycle };
      assert.equal(
        requests.filter((request) => request.path === '/authorize').length,
        expected.authorize,
      );
      assert.equal(requests.filter((request) => request.path === '/token').length, expected.token);
      assert.equal(
        requests.filter((request) => request.path === '/userinfo').length,
        expected.userinfo,
      );
      assert.equal(
        requests.filter((request) => request.path === '/protected').length,
        perCycle * (concurrency + 2),
      );
      assert.equal(
        requests.filter((request) => request.path === '/session/check').length,
        perCycle * (2 + concurrency + 1),
      );
      assert.equal(
        requests.filter((request) => request.path === '/session/check' && request.phase === 'login')
          .length,
        perCycle * 2,
      );
      assert.equal(
        requests.filter(
          (request) => request.path === '/session/check' && request.phase === 'protected',
        ).length,
        (warmups + samples) * concurrency,
      );
      assert.equal(
        requests.filter(
          (request) => request.path === '/session/check' && request.phase === 'post_logout_check',
        ).length,
        warmups + samples,
      );
      assert.equal(
        requests.filter((request) => request.outcome === 'unexpected_http_error').length,
        0,
        'No unexpected HTTP errors may appear in setup or benchmark samples',
      );
      assert.equal(
        requests.filter((request) => request.outcome === 'transport_error').length,
        0,
        'No request transport errors may appear in setup or benchmark samples',
      );
    } catch (error) {
      failure = error;
      runFailed = true;
      failures.push(`run/${phase}/${error instanceof Error ? error.name : 'UnknownError'}`);
      throw error;
    } finally {
      const cleanupResults = await Promise.allSettled([
        browser?.close(),
        server.close(),
        harness?.close(),
      ]);
      for (const result of cleanupResults) {
        if (result.status === 'rejected') {
          failures.push(
            `cleanup/${result.reason instanceof Error ? result.reason.name : 'UnknownError'}`,
          );
          failure ??= result.reason;
        }
      }
      const report = {
        schema: 'mikaki.local-mixed-auth-benchmark.v1',
        scope: 'local-only; no production capacity, CPU, or remote SQL claim',
        generated_at: new Date().toISOString(),
        benchmark_base_commit: 'bb45ce230f2077de32b1c961184eaafe44b027fb',
        measured_source_head: execFileSync('git', ['rev-parse', 'HEAD'], {
          encoding: 'utf8',
        }).trim(),
        tracked_source_clean:
          execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], {
            encoding: 'utf8',
          }).trim() === '',
        warmups,
        samples,
        concurrency,
        authentication_cycles_serial: true,
        deadline_ms: deadlineMs,
        session_check_profile:
          'check on callback and every protected request; 300-second lease not exercised',
        userinfo_profile: 'openid-only sub response; Claims Worker/name profile not exercised',
        logout_profile:
          'front-channel logout plus protected-session rejection; BCL/Queue measured separately',
        outcomes,
        setup_scope:
          'local OP harness, isolated D1, disposable client/owner, virtual authenticator enrollment',
        setup_ms: Math.round(setupMs * 1000) / 1000,
        phase_latency: Object.fromEntries(
          Object.entries(phaseLatency).map(([key, values]) => [key, summary(values)]),
        ),
        request_samples: requests,
        request_outcomes: {
          successful_http: requests.filter((request) => request.outcome === 'success').length,
          expected_rejections: requests.filter(
            (request) => request.outcome === 'expected_rejection',
          ).length,
          expected_absences: requests.filter((request) => request.outcome === 'expected_absence')
            .length,
          unexpected_http_errors: requests.filter(
            (request) => request.outcome === 'unexpected_http_error',
          ).length,
          transport_errors: requests.filter((request) => request.outcome === 'transport_error')
            .length,
        },
        endpoint_latency: Object.fromEntries(
          [
            ...new Set(
              requests.map((request) => `${request.method} ${request.path} ${request.outcome}`),
            ),
          ].map((key) => {
            const [method, path, outcome] = key.split(' ');
            const values = requests
              .filter(
                (request) =>
                  request.kind === 'sample' &&
                  request.method === method &&
                  request.path === path &&
                  request.outcome === outcome,
              )
              .map((request) => request.duration_ms);
            return [key, summary(values)];
          }),
        ),
        request_counts: Object.fromEntries(
          [...new Set(requests.map((request) => request.path))].map((path) => [
            path,
            requests.filter((request) => request.path === path).length,
          ]),
        ),
        endpoint_outcomes: Object.fromEntries(
          [
            ...new Set(
              requests.map((request) => `${request.phase} ${request.method} ${request.path}`),
            ),
          ].map((key) => {
            const [requestPhase, method, path] = key.split(' ');
            return [
              key,
              Object.fromEntries(
                [
                  'success',
                  'expected_rejection',
                  'expected_absence',
                  'unexpected_http_error',
                  'transport_error',
                ].map((outcome) => [
                  outcome,
                  requests.filter(
                    (request) =>
                      request.phase === requestPhase &&
                      request.method === method &&
                      request.path === path &&
                      request.outcome === outcome,
                  ).length,
                ]),
              ),
            ];
          }),
        ),
        failures,
        final: failure ? 'failed' : 'success',
      };
      const outputPath = resolve(
        process.env.MIKAKI_MIXED_BENCHMARK_OUTPUT ??
          `artifacts/local-mixed-auth-${new Date().toISOString().replaceAll(':', '-')}.json`,
      );
      try {
        await mkdir(dirname(outputPath), { recursive: true });
        await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
      } catch (error) {
        failure ??= error;
        throw error;
      }
      if (failure) process.stderr.write(`Local mixed benchmark report saved: ${outputPath}\n`);
      else process.stdout.write(`Local mixed benchmark report saved: ${outputPath}\n`);
      if (!runFailed && failure) throw failure;
    }
  },
);
