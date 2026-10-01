import { readFile, writeFile } from 'node:fs/promises';
import { chromium } from 'playwright';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const suite = 'https://localhost:8443';
const moduleName = process.argv[2] ?? 'oidcc-server';
const signCount = Number(process.argv[3] ?? '1');
const planName = process.argv[4] ?? 'oidcc-basic-certification-test-plan';
const config = JSON.parse(
  await readFile(new URL('../generated/oidf-local-config.json', import.meta.url), 'utf8'),
);
const passkey = JSON.parse(
  await readFile(new URL('../generated/oidf-passkey.json', import.meta.url), 'utf8'),
);
const variant =
  planName === 'fapi2-security-profile-final-test-plan'
    ? {
        fapi_profile: 'plain_fapi',
        client_auth_type: 'private_key_jwt',
        sender_constrain: 'dpop',
        authorization_request_type: 'simple',
        openid: 'openid_connect',
      }
    : planName === 'oidcc-config-certification-test-plan'
      ? {}
      : planName.includes('logout-certification-test-plan')
        ? { response_type: 'code', client_registration: 'static_client' }
        : { server_metadata: 'discovery', client_registration: 'static_client' };

async function api(path: string, options: RequestInit = {}) {
  const response = await fetch(`${suite}${path}`, options);
  if (!response.ok) {
    const detail = (await response.text()).replace(/[A-Za-z0-9_-]{32,}/g, '[redacted]');
    throw new Error(`${path}: HTTP ${response.status}: ${detail.slice(0, 1200)}`);
  }
  return response.json();
}

function describeUrl(value: string) {
  const url = new URL(value);
  return `${url.origin}${url.pathname} (${[...url.searchParams.keys()].join(',')})`;
}

const plan = await api(
  `/api/plan?${new URLSearchParams({
    planName,
    variant: JSON.stringify(variant),
  })}`,
  { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config) },
);
console.log('plan:', plan.id);
const browser = await chromium.launch({
  headless: true,
  args: [
    '--no-sandbox',
    '--host-rules=MAP host.docker.internal 127.0.0.1,MAP suite-frontend 127.0.0.1',
    '--ignore-certificate-errors',
  ],
});
try {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    ...(planName === 'fapi2-security-profile-final-test-plan'
      ? { locale: 'en-US', extraHTTPHeaders: { 'Accept-Language': 'en-US,en;q=0.9' } }
      : {}),
  });
  const page = await context.newPage();
  page.on('console', (message) => {
    if (message.type() === 'error') console.log('browser console:', message.text());
  });
  page.on('requestfailed', (request) =>
    console.log(
      'browser request failed:',
      request.method(),
      describeUrl(request.url()),
      request.failure()?.errorText,
    ),
  );
  page.on('request', (request) => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === '/logout')
      console.log('logout POST requested');
  });
  page.on('response', (response) => {
    if (new URL(response.url()).pathname === '/logout' && response.request().method() === 'POST') {
      console.log('logout POST:', response.status());
    }
  });
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      automaticPresenceSimulation: false,
      isUserVerified: true,
    },
  });
  await cdp.send('WebAuthn.addCredential', {
    authenticatorId,
    credential: {
      ...passkey,
      isResidentCredential: true,
      signCount,
    },
  });
  page.on('pageerror', (error) => console.error('browser error:', error.message));
  const names =
    moduleName === 'all'
      ? plan.modules.map((item: { testModule: string }) => item.testModule)
      : moduleName.split(',');
  const summary: Array<{ name: string; id: string; status: string; result: string }> = [];
  for (const name of names) {
    await context.clearCookies();
    const run = await api(`/api/runner?${new URLSearchParams({ test: name, plan: plan.id })}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    console.log('module:', name, run.id);
    const seen = new Set<string>();
    let reusedSecondVisit = false;
    let lastReviewScreenshot: Buffer | undefined;
    let reviewSubmitted = false;
    let info;
    try {
      const maxPolls =
        name === 'fapi2-security-profile-final-par-attempt-to-use-expired-request_uri' ? 240 : 60;
      for (let i = 0; i < maxPolls; i++) {
        const [current, state] = await Promise.all([
          api(`/api/info/${run.id}`),
          api(`/api/runner/${run.id}`),
        ]);
        info = current;
        const urls = state.browser?.urls ?? [];
        for (const url of urls) {
          let reportedBeforeNavigation = false;
          if (seen.has(url)) {
            if (reusedSecondVisit) continue;
            const beforeAuthReuse =
              name ===
              'fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds';
            const afterAuthReuse =
              name === 'fapi2-security-profile-final-par-attempt-reuse-request_uri';
            if (!beforeAuthReuse && !afterAuthReuse) continue;
            const entries = await api(`/api/log/${run.id}?pretty=true`);
            const secondBlock = beforeAuthReuse
              ? 'Make second request to authorization endpoint'
              : 'Attempting reuse of request_uri and testing if Authorization server returns error in callback';
            if (!entries.some((entry: { msg?: string }) => entry.msg === secondBlock)) continue;
            reusedSecondVisit = true;
            if (beforeAuthReuse) {
              await fetch(
                `${suite}/api/runner/browser/${run.id}/visit?url=${encodeURIComponent(url)}`,
                { method: 'POST' },
              );
              reportedBeforeNavigation = true;
            }
          } else {
            seen.add(url);
          }
          console.log('visiting:', describeUrl(url));
          const navigation = await page.goto(url, {
            waitUntil: 'domcontentloaded',
            timeout: 30_000,
          });
          if (navigation && navigation.status() >= 400)
            console.log('navigation error:', navigation.status(), new URL(page.url()).pathname);
          lastReviewScreenshot = await page
            .screenshot({ type: 'jpeg', quality: 70, timeout: 5000 })
            .catch(() => undefined);
          if (new URL(page.url()).pathname === '/login') {
            if (navigation && navigation.status() >= 400)
              throw new Error(`Login page returned HTTP ${navigation.status()}`);
            // Hold the virtual authenticator until the actual prompt is captured.
            // Otherwise conditional UI can navigate away before screenshot() finishes.
            await page.locator('#passkey').waitFor({ state: 'visible', timeout: 10_000 });
            lastReviewScreenshot = await page.screenshot({
              type: 'jpeg',
              quality: 70,
              timeout: 5000,
            });
            if (
              name ===
                'fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds' &&
              !reusedSecondVisit
            ) {
              console.log('leaving first login visit unauthenticated');
            } else if (name === 'fapi2-security-profile-final-user-rejects-authentication') {
              // The minimal login UI has no rejection button; exercise the protocol endpoint.
              await page.evaluate(async () => {
                const tx = document.getElementById('app')?.dataset['tx'];
                const result = await fetch('/login/deny', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ tx }),
                });
                if (!result.ok) throw new Error('Authentication rejection failed');
                const body = (await result.json()) as { location: string };
                location.assign(body.location);
              });
              await page.waitForURL((target) => target.pathname !== '/login', { timeout: 30_000 });
            } else {
              await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
                authenticatorId,
                enabled: true,
              });
              if (new URL(page.url()).pathname === '/login') {
                await page
                  .locator('#passkey')
                  .click({ timeout: 5000 })
                  .catch((error) => {
                    if (new URL(page.url()).pathname === '/login') throw error;
                  });
              }
              await page.waitForURL((target) => target.pathname !== '/login', { timeout: 30_000 });
              await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
                authenticatorId,
                enabled: false,
              });
            }
          }
          if (
            new URL(page.url()).pathname === '/logout' &&
            (await page.locator('button[type="submit"]').count())
          ) {
            console.log('logout document origin:', await page.evaluate(() => location.origin));
            await page.locator('button[type="submit"]').click();
            console.log('logout landed:', describeUrl(page.url()));
            lastReviewScreenshot = await page
              .screenshot({ type: 'jpeg', quality: 70, timeout: 5000 })
              .catch(() => lastReviewScreenshot);
          }
          await page.waitForTimeout(1500);
          console.log('landed:', describeUrl(page.url()));
          if (!reportedBeforeNavigation)
            await fetch(
              `${suite}/api/runner/browser/${run.id}/visit?url=${encodeURIComponent(url)}`,
              { method: 'POST' },
            );
        }
        if (info.status === 'WAITING' && lastReviewScreenshot && !reviewSubmitted) {
          const entries = await api(`/api/log/${run.id}?pretty=true`);
          const review = entries.find(
            (entry: { result: string; upload?: string }) =>
              entry.result === 'REVIEW' && entry.upload,
          );
          const logoutVisited = [...seen].some((url) => new URL(url).pathname === '/logout');
          if (
            review &&
            (name !== 'fapi2-security-profile-final-par-attempt-reuse-request_uri' ||
              reusedSecondVisit) &&
            (!name.includes('logout') || logoutVisited) &&
            (!/second|again|reauth/i.test(review.msg ?? '') || seen.size >= 2)
          ) {
            if (lastReviewScreenshot.byteLength > 500 * 1024)
              throw new Error('Screenshot exceeds the local suite 500KB limit');
            await writeFile(
              new URL(`../generated/oidf-review-${run.id}.jpg`, import.meta.url),
              lastReviewScreenshot,
              { mode: 0o600 },
            );
            const response = await fetch(
              `${suite}/api/log/${run.id}/images/${review.upload}?description=${encodeURIComponent(new URL(page.url()).pathname === '/login' ? 'Passkey login prompt' : 'Authorization error page')}`,
              {
                method: 'POST',
                body: `data:image/jpeg;base64,${lastReviewScreenshot.toString('base64')}`,
              },
            );
            console.log('review upload:', response.status);
            if (!response.ok) {
              await writeFile(
                new URL('../generated/oidf-review-upload-error.txt', import.meta.url),
                await response.text(),
                { mode: 0o600 },
              );
              throw new Error(`Review upload rejected: HTTP ${response.status}`);
            }
            reviewSubmitted = response.ok;
          }
        }
        if (['FINISHED', 'INTERRUPTED', 'FAILED', 'SKIPPED'].includes(info.status)) break;
        if (i % 10 === 0) console.log('status:', info.status, info.result, 'urls:', urls.length);
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    } catch (error) {
      console.error('driver error:', error instanceof Error ? error.message : String(error));
    }
    info = await api(`/api/info/${run.id}`);
    const log = await api(`/api/log/${run.id}?pretty=true`);
    await writeFile(
      new URL(`../generated/oidf-passkey-${name}-${run.id}.json`, import.meta.url),
      JSON.stringify({ planId: plan.id, runId: run.id, info, log }, null, 2),
      { mode: 0o600 },
    );
    console.log('result:', name, info.status, info.result);
    const events = log
      .filter((entry: { result: string }) =>
        ['FAILURE', 'FAILED', 'WARNING', 'REVIEW'].includes(entry.result),
      )
      .map((entry: { result: string; msg?: string }) => ({ result: entry.result, msg: entry.msg }))
      .slice(-10);
    if (events.length) console.log('events:', events);
    summary.push({ name, id: run.id, status: info.status, result: info.result });
    if (!['FINISHED', 'INTERRUPTED', 'FAILED', 'SKIPPED'].includes(info.status)) {
      await fetch(`${suite}/api/runner/${run.id}`, { method: 'DELETE' });
    }
  }
  await writeFile(
    new URL(`../generated/oidf-passkey-summary-${plan.id}.json`, import.meta.url),
    JSON.stringify(summary, null, 2),
    { mode: 0o600 },
  );
  console.log('summary:', summary);
  if (
    summary.some(
      (entry) =>
        entry.status !== 'FINISHED' ||
        !['PASSED', 'REVIEW', 'WARNING', 'SKIPPED'].includes(entry.result),
    )
  )
    process.exitCode = 1;
  const credentials = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  console.log('signCount:', credentials.credentials?.[0]?.signCount);
  await context.close();
} finally {
  await browser.close();
}
