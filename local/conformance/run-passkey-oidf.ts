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
  planName === 'oidcc-config-certification-test-plan'
    ? {}
    : { server_metadata: 'discovery', client_registration: 'static_client' };

async function api(path, options = {}) {
  const response = await fetch(`${suite}${path}`, options);
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json();
}

function describeUrl(value) {
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
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
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
    moduleName === 'all' ? plan.modules.map((item) => item.testModule) : moduleName.split(',');
  const summary: Array<{ name: string; id: string; status: string; result: string }> = [];
  for (const name of names) {
    await context.clearCookies();
    const run = await api(`/api/runner?${new URLSearchParams({ test: name, plan: plan.id })}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    console.log('module:', name, run.id);
    const seen = new Set();
    let lastReviewScreenshot;
    let reviewSubmitted = false;
    let info;
    try {
      for (let i = 0; i < 60; i++) {
        const [current, state] = await Promise.all([
          api(`/api/info/${run.id}`),
          api(`/api/runner/${run.id}`),
        ]);
        info = current;
        const urls = state.browser?.urls ?? [];
        for (const url of urls) {
          if (seen.has(url)) continue;
          seen.add(url);
          console.log('visiting:', describeUrl(url));
          await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 });
          lastReviewScreenshot = await page.screenshot({ fullPage: true });
          if (new URL(page.url()).pathname === '/login') {
            await page.locator('#passkey').click();
            await page.waitForURL((target) => target.pathname !== '/login', { timeout: 30_000 });
          }
          await page.waitForTimeout(1500);
          console.log('landed:', describeUrl(page.url()));
          await fetch(
            `${suite}/api/runner/browser/${run.id}/visit?url=${encodeURIComponent(url)}`,
            { method: 'POST' },
          );
        }
        if (info.status === 'WAITING' && lastReviewScreenshot && !reviewSubmitted) {
          const entries = await api(`/api/log/${run.id}?pretty=true`);
          const review = entries.find((entry) => entry.result === 'REVIEW' && entry.upload);
          if (review && (!/second|again|reauth/i.test(review.msg ?? '') || seen.size >= 2)) {
            const response = await fetch(
              `${suite}/api/log/${run.id}/images/${review.upload}?description=${encodeURIComponent('Passkey login prompt')}`,
              {
                method: 'POST',
                body: `data:image/png;base64,${lastReviewScreenshot.toString('base64')}`,
              },
            );
            console.log('review upload:', response.status);
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
      .filter((entry) => ['FAILURE', 'FAILED', 'WARNING', 'REVIEW'].includes(entry.result))
      .map((entry) => ({ result: entry.result, msg: entry.msg }))
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
  const credentials = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  console.log('signCount:', credentials.credentials?.[0]?.signCount);
  await context.close();
} finally {
  await browser.close();
}
