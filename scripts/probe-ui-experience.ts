/** Reproducible lab measurements against disposable Rust Worker fixtures over real HTTPS. */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import {
  chromium,
  expect,
  type BrowserContext,
  type Page,
  type CDPSession,
  type Response as BrowserResponse,
} from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from './worker-policy-store.ts';
import { releaseSource } from './release-inventory.ts';
import { journeyServer } from '../local/conformance/support/journey-server.ts';
import { auditAccessibility } from '../local/conformance/support/accessibility-audit.ts';
import { sealAttribute } from '../crates/worker/ui/vault-crypto.ts';

type Probe = {
  fcp: number | null;
  lcp: number | null;
  cls: number;
  shifts: { start: number; value: number }[];
  longTasks: { start: number; duration: number }[];
  events: { name: string; duration: number }[];
  lightUpdates: number;
};
const root = new URL('../', import.meta.url).pathname;
const repeats = Number(process.env['MIKAKI_UI_PROBE_REPEATS'] ?? 3);
assert.ok(Number.isSafeInteger(repeats) && repeats > 0 && repeats <= 5);
let dispatch: Parameters<typeof journeyServer>[0];
const port = Number(process.env['MIKAKI_UI_PROBE_PORT'] ?? 0);
assert.ok(port === 0 || (Number.isInteger(port) && port > 1024 && port <= 65535));
const label = process.env['MIKAKI_UI_PROBE_LABEL'] ?? 'current';
assert.match(label, /^[a-z0-9-]+$/);
const server = await journeyServer((url, init) => dispatch(url, init), port);
const issuer = `https://mikaki.test:${server.port}`;
const harness = createTestHarness({
  root,
  workers: [
    {
      configPath: `${root}/crates/worker/wrangler.jsonc`,
      vars: { MIKAKI_ISSUER: issuer },
    },
  ],
});
let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
const samples: Record<string, unknown>[] = [];
try {
  await harness.listen();
  const worker = harness.getWorker('mikaki-op-worker');
  await worker.applyD1Migrations('DB');
  const { DB } = await worker.getEnv();
  const policy = JSON.parse(await readFile(`${root}/local/generated/worker-policy.json`, 'utf8'));
  await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'UI lab fixture' });
  const credential = new Uint8Array(randomBytes(32)),
    prf = new Uint8Array(32).fill(0x71);
  const credentialId = Buffer.from(credential).toString('base64url');
  const cookie = randomBytes(32).toString('base64url'),
    now = Math.floor(Date.now() / 1000);
  await DB.batch([
    DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
    DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(credentialId),
    DB.prepare(
      "INSERT INTO passkey_credential VALUES(?,'synthetic-key','synthetic-user',0,0,0,1)",
    ).bind(credentialId),
    DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(
      credentialId,
      now + 3600,
    ),
    DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(
      createHash('sha256').update(cookie).digest('base64url'),
      now,
    ),
  ]);
  const sealed = await sealAttribute(
    new TextEncoder().encode('Synthetic owner'),
    prf,
    credential,
    new Uint8Array(32).fill(0x29),
    issuer,
    'name',
    1,
  );
  const written = await worker.fetch(`${issuer}/vault/attributes/name`, {
    method: 'PUT',
    headers: {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: issuer,
      'Content-Type': 'application/json',
      'X-Operation-ID': randomBytes(32).toString('base64url'),
      'If-None-Match': '*',
    },
    body: JSON.stringify(sealed),
  });
  assert.equal(written.status, 200);
  dispatch = async (url, init) => {
    const response = await worker.fetch(url, { ...init, redirect: 'manual' });
    const bytes = Buffer.from(await response.arrayBuffer());
    const headers = new Headers([...response.headers]);
    // A declared lab transport profile, not a claim about Cloudflare's HTTP compression.
    if (bytes.length && /text\/|javascript|json/.test(headers.get('Content-Type') ?? '')) {
      const compressed = gzipSync(bytes, { level: 6 });
      headers.set('Content-Encoding', 'gzip');
      headers.set('Content-Length', String(compressed.length));
      return new Response(compressed, { status: response.status, headers });
    }
    return new Response(bytes.length ? bytes : null, { status: response.status, headers });
  };
  browser = await chromium.launch({
    headless: true,
    args: ['--host-resolver-rules=MAP mikaki.test 127.0.0.1', '--no-proxy-server'],
  });
  const profiles = [
    {
      name: 'desktop',
      width: 1440,
      height: 900,
      cpu: 1,
      latency: 0,
      bytesPerSecond: -1,
      reduced: false,
    },
    {
      name: 'slow-mobile',
      width: 390,
      height: 844,
      cpu: 4,
      latency: 400,
      bytesPerSecond: 50_000,
      reduced: false,
    },
    {
      name: 'slow-mobile-reduced',
      width: 390,
      height: 844,
      cpu: 4,
      latency: 400,
      bytesPerSecond: 50_000,
      reduced: true,
    },
  ];
  for (const profile of profiles)
    for (const screen of ['login', 'vault'])
      for (let sample = 0; sample < repeats; sample++) {
        const context: BrowserContext = await browser.newContext({
          ignoreHTTPSErrors: true,
          locale: 'ja-JP',
          viewport: { width: profile.width, height: profile.height },
          isMobile: profile.width < 500,
          hasTouch: profile.width < 500,
          deviceScaleFactor: profile.width < 500 ? 2 : 1,
          reducedMotion: profile.reduced ? 'reduce' : 'no-preference',
        });
        try {
          if (screen === 'vault')
            await context.addCookies([
              {
                name: '__Host-op-sso',
                value: cookie,
                url: issuer,
                secure: true,
                httpOnly: true,
                sameSite: 'Lax',
              },
            ]);
          await context.addInitScript(
            ({ credential, prf }) => {
              const probe: Probe = {
                fcp: null,
                lcp: null,
                cls: 0,
                shifts: [],
                longTasks: [],
                events: [],
                lightUpdates: 0,
              };
              Object.assign(window, { __uiProbe: probe });
              let sessionStart = 0,
                lastShift = 0,
                sessionScore = 0;
              for (const type of [
                'paint',
                'largest-contentful-paint',
                'layout-shift',
                'longtask',
                'event',
              ]) {
                new PerformanceObserver((list) => {
                  for (const entry of list.getEntries()) {
                    const data = entry.toJSON() as Record<string, number | string | boolean>;
                    if (type === 'paint' && entry.name === 'first-contentful-paint')
                      probe.fcp = entry.startTime;
                    if (type === 'largest-contentful-paint') probe.lcp = entry.startTime;
                    if (type === 'layout-shift' && !data['hadRecentInput']) {
                      if (
                        entry.startTime - lastShift > 1000 ||
                        entry.startTime - sessionStart > 5000
                      ) {
                        sessionStart = entry.startTime;
                        sessionScore = 0;
                      }
                      lastShift = entry.startTime;
                      sessionScore += Number(data['value']);
                      probe.cls = Math.max(probe.cls, sessionScore);
                      probe.shifts.push({ start: entry.startTime, value: Number(data['value']) });
                    }
                    if (type === 'longtask')
                      probe.longTasks.push({ start: entry.startTime, duration: entry.duration });
                    if (type === 'event' && Number(data['interactionId']) > 0)
                      probe.events.push({ name: entry.name, duration: entry.duration });
                  }
                }).observe({
                  type,
                  buffered: true,
                  ...(type === 'event' ? { durationThreshold: 16 } : {}),
                });
              }
              new MutationObserver((records) => {
                probe.lightUpdates += records.length;
              }).observe(document, {
                subtree: true,
                attributes: true,
                attributeFilter: ['data-light-phase'],
              });
              class MockCredential {
                rawId = Uint8Array.from(credential).buffer;
                getClientExtensionResults() {
                  return { prf: { results: { first: Uint8Array.from(prf).buffer } } };
                }
              }
              Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
              Object.defineProperty(navigator, 'credentials', {
                value: {
                  get: async () => {
                    if (location.pathname === '/login')
                      throw new DOMException('Synthetic cancellation', 'NotAllowedError');
                    return new MockCredential();
                  },
                },
              });
            },
            { credential: [...credential], prf: [...prf] },
          );
          const page = await context.newPage(),
            client = await context.newCDPSession(page);
          page.setDefaultTimeout(30_000);
          const errors: string[] = [];
          page.on('pageerror', (error) => errors.push(error.message));
          await client.send('Network.enable');
          await client.send('Network.setCacheDisabled', { cacheDisabled: true });
          await client.send('Network.emulateNetworkConditionsByRule', {
            offline: false,
            matchedNetworkConditions: [
              {
                urlPattern: '',
                latency: profile.latency,
                downloadThroughput: profile.bytesPerSecond,
                uploadThroughput: profile.bytesPerSecond,
              },
            ],
          });
          await client.send('Emulation.setCPUThrottlingRate', { rate: profile.cpu });
          await client.send('Performance.enable');
          const response: BrowserResponse | null = await page.goto(
            `${issuer}/${screen === 'login' ? 'signin' : 'vault'}?lang=ja`,
          );
          assert.equal(response?.status(), 200);
          await expect(page.locator(screen === 'login' ? '#passkey' : '#unlock')).toBeEnabled();
          const readyMs = await page.evaluate(() => performance.now());
          await page.locator('.gate-background[data-renderer="canvas"]').waitFor();
          const metrics = async () =>
            Object.fromEntries(
              (await client.send('Performance.getMetrics')).metrics.map((x) => [x.name, x.value]),
            );
          const lightUpdates = () =>
            page.evaluate(() => (window as unknown as { __uiProbe: Probe }).__uiProbe.lightUpdates);
          const beforeIdle = await metrics(),
            beforeLight = await lightUpdates();
          await page.waitForTimeout(2000);
          const afterIdle = await metrics(),
            afterLight = await lightUpdates();
          const idleScriptMs =
            (afterIdle['ScriptDuration']! - beforeIdle['ScriptDuration']!) * 1000;
          let unlockMs: number | null = null,
            offscreenScriptMs: number | null = null,
            offscreenLightUpdates: number | null = null;
          if (screen === 'vault') {
            await page.locator('#unlock').focus();
            const started = performance.now();
            await page.keyboard.press('Enter');
            await expect(page.locator('#name')).toHaveValue('Synthetic owner');
            await expect(page.locator('#name')).toBeFocused();
            unlockMs = performance.now() - started;
            await page.locator('#notes').scrollIntoViewIfNeeded();
            assert.ok(
              await page
                .locator('.product-header')
                .evaluate((node) => node.getBoundingClientRect().bottom <= 0),
            );
            await page.waitForTimeout(250);
            const before = await metrics(),
              light = await lightUpdates();
            await page.waitForTimeout(2000);
            const after = await metrics();
            offscreenScriptMs = (after['ScriptDuration']! - before['ScriptDuration']!) * 1000;
            offscreenLightUpdates = (await lightUpdates()) - light;
          }
          const observed = await page.evaluate(() => {
            const metrics = (window as unknown as { __uiProbe: Probe }).__uiProbe;
            return {
              ...metrics,
              navigation: performance.getEntriesByType('navigation')[0]?.toJSON(),
              resources: performance.getEntriesByType('resource').map((entry) => {
                const resource = entry as PerformanceResourceTiming;
                return {
                  path: new URL(resource.name).pathname,
                  duration: resource.duration,
                  transferSize: resource.transferSize,
                  encodedBodySize: resource.encodedBodySize,
                  decodedBodySize: resource.decodedBodySize,
                };
              }),
              overflow: document.documentElement.scrollWidth > innerWidth,
            };
          });
          // Store no transaction URL, cookie, challenge, or raw account content.
          delete (observed.navigation as Record<string, unknown>)['name'];
          assert.equal(observed.overflow, false);
          assert.deepEqual(errors, []);
          if (sample === 0) {
            await auditAccessibility(page, `probe-${profile.name}-${screen}`);
            await mkdir('artifacts/ui-experience', { recursive: true });
            await page.screenshot({
              path: `artifacts/ui-experience/${profile.name}-${screen}.png`,
              fullPage: true,
            });
          }
          samples.push({
            profile: profile.name,
            screen,
            sample,
            readyMs,
            idleScriptMs,
            idleLightUpdates: afterLight - beforeLight,
            unlockMs,
            offscreenScriptMs,
            offscreenLightUpdates,
            ...observed,
          });
          console.log(
            `${profile.name}/${screen}/${sample + 1}: ready ${Math.round(readyMs)}ms; idle script ${Math.round(idleScriptMs)}ms; offscreen ${offscreenLightUpdates ?? '-'} light updates`,
          );
        } finally {
          await context.close();
        }
      }
  const assets: Record<string, string> = {};
  for (const path of [
    '/login/login.js',
    '/login/login.css',
    '/vault/vault.js',
    '/ui/product.css',
  ]) {
    const bytes = Buffer.from(await (await worker.fetch(`${issuer}${path}`)).arrayBuffer());
    assets[path] = createHash('sha256').update(bytes).digest('hex');
  }
  await mkdir('artifacts/ui-experience', { recursive: true });
  await writeFile(
    'artifacts/ui-experience/report.json',
    JSON.stringify(
      {
        schema_version: 1,
        label,
        assets,
        fixtureOrigin: issuer,
        source: releaseSource(root),
        browser: browser.version(),
        measuredAt: new Date().toISOString(),
        conditions: {
          profiles,
          repeats,
          transport: 'loopback HTTPS, gzip level 6, disabled cache; actual Rust Worker responses',
          authenticator:
            'synthetic PRF; login automatic ceremony cancelled; no real device latency',
          idleWindowMs: 2000,
          metricScope: 'lab paint/CLS/event samples, not field Web Vitals or INP',
        },
        samples,
      },
      null,
      2,
    ) + '\n',
  );
} finally {
  await browser?.close();
  await harness.close();
  await server.close();
}
