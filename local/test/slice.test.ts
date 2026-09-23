import { revokeAccountSessions } from '../account-admin.ts';
import assert from 'node:assert/strict';
import { after, afterEach, before, test } from 'node:test';
import { chromium } from '@playwright/test';
import { startLocal } from '../runtime.ts';
import {
  OP,
  RP,
  CLIENT,
  CALLBACK,
  ASSERTION_TYPE,
  clientAssertion,
  random,
  hash,
  now,
  p,
  signed,
} from '../shared.ts';

let local, browser, context, page, authenticator, cdp;
const scalar = async (db, sql, ...args) =>
  (
    await db
      .prepare(sql)
      .bind(...args)
      .raw()
  )[0][0];
const clientEnv = () => ({ RP_PRIVATE_JWK: local.rpKeys.private });
// Playwright's API client does not share Chromium's Secure-cookie exception for loopback HTTP.
// Forward the cookies captured from the actual browser for these backend race tests only.
async function browserHeaders(origin, ctx = context) {
  return {
    Origin: origin,
    Cookie: (await ctx.cookies())
      .filter((c) => c.domain === new URL(origin).hostname)
      .map((c) => `${c.name}=${c.value}`)
      .join('; '),
  };
}
async function request(path, fields = {}, assertion = undefined) {
  const token = assertion ?? (await clientAssertion(clientEnv(), `${OP}${path}`));
  return fetch(`${OP}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: CLIENT,
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: token,
      ...fields,
    }),
    redirect: 'manual',
  });
}
async function begin() {
  await page.goto(RP);
  await page.getByRole('button', { name: 'ログイン / Sign in', exact: true }).click();
  await page.waitForURL(`${OP}/login?**`);
  await page.getByLabel('Language').selectOption('en');
  await page.getByRole('checkbox').check();
}
async function loggedIn() {
  await page.waitForURL(`${RP}/`);
  await page.getByTestId('signed-in').waitFor();
}
async function pendingCode() {
  const home = await context.request.get(RP, { headers: await browserHeaders(RP) }),
    csrf = (await home.text()).match(/name="csrf" value="([^"]+)"/)[1];
  const start = await context.request.post(`${RP}/login`, {
    form: { csrf },
    headers: await browserHeaders(RP),
    maxRedirects: 0,
  });
  assert.equal(start.status(), 303);
  const auth = await context.request.get(start.headers().location, {
    headers: await browserHeaders(OP),
    maxRedirects: 0,
  });
  assert.equal(auth.status(), 303);
  const callback = auth.headers().location,
    u = new URL(callback),
    code = u.searchParams.get('code'),
    state = u.searchParams.get('state');
  assert.ok(code);
  const verifier = await scalar(
    local.rpDB,
    'SELECT verifier FROM login WHERE state_hash=?',
    await hash(state),
  );
  const sid = await scalar(
    local.opDB,
    'SELECT sid FROM authorization_code WHERE code_hash=?',
    await hash(code),
  );
  return { code, verifier, sid, callback };
}
const exchange = (c, assertion = undefined, verifier = c.verifier) =>
  request(
    '/token',
    {
      grant_type: 'authorization_code',
      code: c.code,
      redirect_uri: CALLBACK,
      code_verifier: verifier,
    },
    assertion,
  );
before(async () => {
  local = await startLocal();
  const channel = process.env.MIKAKI_BROWSER_CHANNEL;
  browser = await chromium.launch({
    ...(channel ? { channel } : {}),
    headless: true,
  });
  context = await browser.newContext({ locale: 'en-US' });
  page = await context.newPage();
  page.setDefaultTimeout(8000);
  page.setDefaultNavigationTimeout(10000);
  page.on('response', async (r) => {
    if (r.status() >= 400)
      console.log(
        'HTTP failure',
        new URL(r.url()).pathname,
        r.status(),
        (await r.text()).slice(0, 100),
      );
  });
  page.on('pageerror', (e) => console.log('Page error', e.message));
  cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  ({ authenticatorId: authenticator } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  }));
});
after(async () => {
  await browser?.close();
  await local?.close();
});
afterEach(async (t) => {
  if (!t.passed && page) {
    console.log(
      'Page at failure',
      new URL(page.url()).origin,
      new URL(page.url()).pathname,
      [...new URL(page.url()).searchParams.keys()],
      await page.locator('body').innerText(),
    );
    console.log('Worker logs', local.logs());
  }
});

test('registration requires the client discoverable-credential signal without consuming the invitation', async () => {
  await begin();
  await page.getByLabel('Invitation code', { exact: true }).fill(local.invitation);
  for (const output of [{}, { credProps: { rk: false } }]) {
    await page.evaluate((value) => {
      PublicKeyCredential.prototype.getClientExtensionResults = () => value;
    }, output);
    await page.getByRole('button', { name: 'Register with invitation' }).click();
    await page.getByRole('alert').waitFor();
    assert.equal(await scalar(local.opDB, 'SELECT COUNT(*) FROM account_security'), 0);
    assert.equal(
      await scalar(local.opDB, 'SELECT COUNT(*) FROM invitation WHERE used_by IS NOT NULL'),
      0,
    );
    const { credentials } = await cdp.send('WebAuthn.getCredentials', {
      authenticatorId: authenticator,
    });
    for (const credential of credentials)
      await cdp.send('WebAuthn.removeCredential', {
        authenticatorId: authenticator,
        credentialId: credential.credentialId,
      });
  }
  // The next test navigates to a new document, restoring the native browser method.
});

test('invitation + browser Passkey + OIDC exchange creates the first admin and app session', async () => {
  let completions;
  await page.route(`${OP}/ceremony/finish`, async (route) => {
    const req = route.request(),
      data = req.postData();
    const headers = { ...(await browserHeaders(OP)), 'Content-Type': 'application/json' };
    // Distinct internal reasons must produce the same public rejection.
    for (const [field, value] of [
      ['challenge', random()],
      ['origin', 'https://untrusted.example'],
    ]) {
      const changed = JSON.parse(data);
      const client = JSON.parse(Buffer.from(changed.response.client_data, 'base64url').toString());
      client[field] = value;
      changed.response.client_data = Buffer.from(JSON.stringify(client)).toString('base64url');
      const rejected = await context.request.post(`${OP}/ceremony/finish`, {
        data: JSON.stringify(changed),
        headers,
      });
      assert.equal(rejected.status(), 400);
      assert.deepEqual(await rejected.json(), { error: 'invalid_credential' });
    }
    const responses = await Promise.all(
      [0, 1].map(() => context.request.post(`${OP}/ceremony/finish`, { data, headers })),
    );
    completions = responses.map((r) => r.status()).sort();
    await route.fulfill({ response: responses.find((r) => r.ok()) ?? responses[0] });
  });
  await begin();
  await page.getByLabel('Invitation code', { exact: true }).fill(local.invitation);
  await page.getByRole('button', { name: 'Register with invitation' }).click();
  await loggedIn();
  await page.unroute(`${OP}/ceremony/finish`);
  assert.deepEqual(completions, [200, 400]);
  const diagnostics = local.logs().flatMap(({ message }) => {
    try {
      const value = JSON.parse(message);
      return value.event === 'webauthn_rejected' ? [value] : [];
    } catch {
      return [];
    }
  });
  for (const code of ['challenge', 'origin']) {
    const diagnostic = diagnostics.find((value) => value.code === code);
    assert.ok(diagnostic);
    assert.equal(diagnostic.stage, 'client_data');
    assert.match(diagnostic.correlation, /^[0-9a-f-]{36}$/);
    assert.deepEqual(Object.keys(diagnostic).sort(), ['code', 'correlation', 'event', 'stage']);
  }
  assert.equal(await scalar(local.opDB, 'SELECT COUNT(*) FROM account_role'), 1);
  assert.equal(await scalar(local.opDB, 'SELECT closed FROM bootstrap'), 1);
  assert.equal(
    await scalar(local.opDB, 'SELECT COUNT(*) FROM invitation WHERE used_by IS NOT NULL'),
    1,
  );
  assert.equal(await scalar(local.opDB, 'SELECT COUNT(*) FROM token_issue'), 1);
  assert.equal(await scalar(local.rpDB, 'SELECT COUNT(*) FROM app_session'), 1);
  const passkeys = await cdp.send('WebAuthn.getCredentials', { authenticatorId: authenticator });
  assert.equal(passkeys.credentials[0].isResidentCredential, true);
  const cookies = await context.cookies();
  for (const name of ['__Host-op-sso', '__Host-rp-session']) {
    const c = cookies.find((c) => c.name === name);
    assert.ok(c?.secure && c.httpOnly && c.sameSite === 'Lax');
  }
  assert.equal(cookies.find((c) => c.name === '__Host-op-sso').domain, 'localhost');
  assert.equal(cookies.find((c) => c.name === '__Host-rp-session').domain, '127.0.0.1');
});
test('valid SSO reuses consent without another Passkey and keeps pairwise sub', async () => {
  const before = await page.getByTestId('subject').textContent();
  const ceremonies = await scalar(local.opDB, 'SELECT COUNT(*) FROM ceremony');
  await page.getByRole('button', { name: 'SSOを再確認 / Check SSO' }).click();
  await loggedIn();
  assert.equal(await page.getByTestId('subject').textContent(), before);
  assert.equal(await scalar(local.opDB, 'SELECT COUNT(*) FROM ceremony'), ceremonies);
});
test('client assertions are endpoint-bound and single use', async () => {
  const sid = await scalar(local.rpDB, 'SELECT sid FROM app_session LIMIT 1');
  const assertion = await clientAssertion(clientEnv(), `${OP}/session/check`);
  assert.equal((await request('/session/check', { sid }, assertion)).status, 200);
  assert.notEqual((await request('/session/check', { sid }, assertion)).status, 200);
  const wrong = await clientAssertion(clientEnv(), `${OP}/token`);
  assert.notEqual((await request('/session/check', { sid }, wrong)).status, 200);
});
test('unregistered redirect and CSRF are rejected without redirection', async () => {
  const r = await fetch(
    `${OP}/authorize?client_id=local-rp&redirect_uri=https://evil.example/callback`,
    { redirect: 'manual' },
  );
  assert.equal(r.status, 400);
  assert.equal(r.headers.get('location'), null);
  const start = await fetch(`${RP}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: 'https://evil.example',
    },
    body: 'csrf=forged',
    redirect: 'manual',
  });
  assert.equal(start.status, 403);
});
test('logout revokes SSO and all derived sids and delivers persistent backchannel events', async () => {
  await page.getByRole('button', { name: 'ログアウト / Sign out' }).click();
  await page.waitForURL(`${OP}/logout?**`);
  await page.getByRole('button', { name: 'ログアウト / Sign out' }).click();
  await page.waitForURL(`${RP}/`);
  assert.equal(await scalar(local.opDB, 'SELECT COUNT(*) FROM valid_client_session'), 0);
  for (let i = 0; i < 100; i++) {
    if (
      !(await scalar(
        local.opDB,
        "SELECT COUNT(*) FROM logout_delivery WHERE state!='delivered'",
      )) &&
      !(await scalar(local.opDB, 'SELECT COUNT(*) FROM sso_logout_event WHERE expanded=0'))
    )
      break;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(
    await scalar(local.opDB, 'SELECT COUNT(*) FROM sso_logout_event WHERE expanded=0'),
    0,
  );
  assert.equal(await scalar(local.rpDB, 'SELECT COUNT(*) FROM app_session'), 0);
  assert.ok((await scalar(local.rpDB, 'SELECT COUNT(*) FROM tombstone')) >= 2);
  assert.equal(
    await scalar(local.opDB, "SELECT COUNT(*) FROM logout_delivery WHERE state!='delivered'"),
    0,
  );
});
test('existing discoverable Passkey signs in again without an invitation', async () => {
  await begin();
  await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
  await loggedIn();
  assert.equal(await scalar(local.opDB, 'SELECT COUNT(*) FROM account_security'), 1);
  assert.equal(await scalar(local.rpDB, 'SELECT COUNT(*) FROM identity'), 1);
});

test('wrong PKCE consumes assertion but does not consume the code', async () => {
  const c = await pendingCode(),
    assertion = await clientAssertion(clientEnv(), `${OP}/token`);
  assert.notEqual((await exchange(c, assertion, random())).status, 200);
  assert.equal(
    await scalar(
      local.opDB,
      'SELECT consumed_by FROM authorization_code WHERE code_hash=?',
      await hash(c.code),
    ),
    null,
  );
  assert.notEqual((await exchange(c, assertion)).status, 200);
  assert.equal((await exchange(c)).status, 200);
});
test('parallel code exchange succeeds once; a subsequent replay revokes its token', async () => {
  const c = await pendingCode(),
    responses = await Promise.all([exchange(c), exchange(c)]);
  assert.equal(responses.filter((r) => r.status === 200).length, 1);
  assert.equal(
    await scalar(
      local.opDB,
      'SELECT COUNT(*) FROM token_issue WHERE code_hash=?',
      await hash(c.code),
    ),
    1,
  );
  assert.notEqual((await exchange(c)).status, 200);
  assert.equal(
    await scalar(
      local.opDB,
      'SELECT revoked FROM token_issue WHERE code_hash=?',
      await hash(c.code),
    ),
    1,
  );
  assert.deepEqual(await (await request('/session/check', { sid: c.sid })).json(), {
    active: false,
  });
});
test('UserInfo accepts only issued unexpired opaque bearer tokens; expiry does not end app sid', async () => {
  const c = await pendingCode(),
    tokens = await (await exchange(c)).json();
  const profile = await fetch(`${OP}/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  assert.equal(profile.status, 200);
  assert.deepEqual(Object.keys(await profile.json()), ['sub']);
  assert.equal(
    (await fetch(`${OP}/userinfo`, { headers: { Authorization: `Bearer ${tokens.id_token}` } }))
      .status,
    401,
  );
  await local.opDB
    .prepare('UPDATE token_issue SET access_expires_at=? WHERE code_hash=?')
    .bind(now(), await hash(c.code))
    .run();
  assert.equal(
    (await fetch(`${OP}/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } }))
      .status,
    401,
  );
  assert.equal((await (await request('/session/check', { sid: c.sid })).json()).active, true);
});
test('code expiry and stopped signing key fail without committing an issue', async () => {
  const expired = await pendingCode();
  await local.opDB
    .prepare('UPDATE authorization_code SET expires_at=? WHERE code_hash=?')
    .bind(now(), await hash(expired.code))
    .run();
  assert.notEqual((await exchange(expired)).status, 200);
  const stopped = await pendingCode();
  await local.opDB.prepare('UPDATE signing_key SET active=0').run();
  try {
    assert.notEqual((await exchange(stopped)).status, 200);
    assert.equal(
      await scalar(
        local.opDB,
        'SELECT consumed_by FROM authorization_code WHERE code_hash=?',
        await hash(stopped.code),
      ),
      null,
    );
  } finally {
    await local.opDB.prepare('UPDATE signing_key SET active=1').run();
  }
});
test('foreign-browser callback fails before code exchange', async () => {
  const c = await pendingCode();
  const r = await fetch(c.callback, { redirect: 'manual' });
  assert.equal(r.status, 400);
  assert.equal(
    await scalar(
      local.opDB,
      'SELECT consumed_by FROM authorization_code WHERE code_hash=?',
      await hash(c.code),
    ),
    null,
  );
});
test('backchannel arriving before callback leaves a tombstone and prevents session revival', async () => {
  const c = await pendingCode();
  const token = await signed(
    { OP_PRIVATE_JWK: local.opKeys.private },
    'op',
    {
      sid: c.sid,
      jti: random(),
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
    },
    CLIENT,
    p('oidc_logout.token_ttl'),
    'logout+jwt',
  );
  const r = await fetch(`${RP}/backchannel`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ logout_token: token }),
  });
  assert.equal(r.status, 200);
  const callback = await context.request.get(c.callback, {
    headers: await browserHeaders(RP),
    maxRedirects: 0,
  });
  assert.notEqual(callback.status(), 303);
  assert.equal(await scalar(local.rpDB, 'SELECT COUNT(*) FROM app_session WHERE sid=?', c.sid), 0);
});
test('expired lease fails closed after parent epoch changes', async () => {
  const active = await scalar(local.opDB, 'SELECT account_id FROM account_security LIMIT 1');
  const epoch = await scalar(
    local.opDB,
    'SELECT epoch FROM account_security WHERE account_id=?',
    active,
  );
  await revokeAccountSessions(local.opDB, {
    account: active,
    epoch,
    actor: 'test-operator',
    reason: 'session_reset',
  });
  await local.rpDB.prepare('UPDATE app_session SET lease_until=?').bind(now()).run();
  const r = await context.request.get(`${RP}/me`, { headers: await browserHeaders(RP) });
  assert.equal(r.status(), 503);
  assert.ok((await scalar(local.rpDB, 'SELECT MAX(lease_until) FROM app_session')) <= now());
});

test('fresh Passkey login survives delivery of the old account epoch revocation', async () => {
  // A fresh RP login must not reuse the deliberately expired lease from the prior test.
  await context.clearCookies({ name: '__Host-rp-session' });
  await begin();
  await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
  await loggedIn();
  const before = await context.request.get(`${RP}/me`, { headers: await browserHeaders(RP) });
  const identity = await before.json();
  assert.ok(identity.sid);
  for (let i = 0; i < 5; i++)
    await local.op.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
  const after = await context.request.get(`${RP}/me`, { headers: await browserHeaders(RP) });
  assert.equal(after.status(), 200);
  assert.equal((await after.json()).sid, identity.sid);
  assert.equal(
    await scalar(local.opDB, 'SELECT COUNT(*) FROM logout_delivery WHERE sid=?', identity.sid),
    0,
  );
  assert.equal(
    await scalar(local.opDB, 'SELECT COUNT(*) FROM revocation_event WHERE expanded=0'),
    0,
  );
});

test('consumed bootstrap invitation cannot register another account; malformed JSON and missing CSRF fail', async () => {
  const other = await browser.newContext({ locale: 'en-US' }),
    tab = await other.newPage();
  try {
    const auth = new URL(`${OP}/authorize`);
    auth.search = new URLSearchParams({
      client_id: CLIENT,
      redirect_uri: CALLBACK,
      response_type: 'code',
      scope: 'openid',
      state: random(),
      nonce: random(),
      code_challenge: await hash(random()),
      code_challenge_method: 'S256',
    }).toString();
    await tab.goto(auth.href);
    const tx = new URL(tab.url()).searchParams.get('tx');
    const headers = await browserHeaders(OP, other);
    const ctx = await (await other.request.get(`${OP}/login/context?tx=${tx}`, { headers })).json();
    const start = await other.request.post(`${OP}/ceremony/start`, {
      data: { ...ctx, purpose: 'register', invitation: local.invitation },
      headers,
    });
    assert.equal(start.status(), 400);
    const csrf = await other.request.post(`${OP}/ceremony/start`, {
      data: { tx, purpose: 'authenticate' },
      headers,
    });
    assert.equal(csrf.status(), 400);
    for (const data of ['{"tx":"a","tx":"b"}', '['.repeat(9) + ']'.repeat(9)]) {
      const r = await other.request.post(`${OP}/ceremony/start`, {
        data,
        headers: { Origin: OP, 'Content-Type': 'application/json' },
      });
      assert.equal(r.status(), 400);
    }
    assert.equal(await scalar(local.opDB, 'SELECT COUNT(*) FROM account_security'), 1);
  } finally {
    await other.close();
  }
});
