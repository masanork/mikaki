import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { exportJWK, jwtVerify, generateKeyPair } from 'jose';
import { chromium, type BrowserContext, type Page } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import type { D1Database, Queue } from '@cloudflare/workers-types';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
import { journeyServer } from './support/journey-server.ts';

const root = new URL('../..', import.meta.url).pathname;
const defaultIssuer = 'https://mikaki.test';
const opaque = () => randomBytes(32).toString('base64url');
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
async function within<T>(promise: Promise<T>, label: string, ms = 5000): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      promise.then((value) => ({ value })),
      new Promise<{ timeout: true }>((resolve) => {
        timeout = setTimeout(() => resolve({ timeout: true }), ms);
      }),
    ]);
    assert.ok('value' in result, `Timed out waiting for ${label}`);
    return result.value;
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

type CapturedLogout = { token: string; jti: string; aud: unknown; sid: unknown };
async function startInstance(options: {
  queue: boolean;
  backchannel: (request: Request, logout: CapturedLogout) => Promise<Response>;
  recipientCount?: number;
  recipientClients?: string[];
  sessionCount?: number;
  issuer?: string;
  ackLoss?: boolean;
}) {
  const issuer = options.issuer ?? defaultIssuer;
  const sourceConfig = JSON.parse(
    await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
  );
  sourceConfig.main = new URL(
    '../../crates/worker/build/worker/shim.mjs',
    import.meta.url,
  ).pathname;
  sourceConfig.d1_databases[0].migrations_dir = new URL(
    '../../crates/worker/migrations',
    import.meta.url,
  ).pathname;
  if (options.ackLoss) {
    sourceConfig.main = new URL('./support/logout-queue-ack-loss.mjs', import.meta.url).pathname;
    const mainConsumer = sourceConfig.queues.consumers[0];
    mainConsumer.max_batch_timeout = 0;
    mainConsumer.max_retries = 1;
    mainConsumer.retry_delay = 0;
    sourceConfig.queues.consumers.push({
      queue: mainConsumer.dead_letter_queue,
      max_batch_size: 1,
      max_batch_timeout: 1,
      max_retries: 1,
    });
  }
  if (!options.queue) delete sourceConfig.queues;

  const key = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = {
    ...(await exportJWK(key.publicKey)),
    kid: 'logout-queue-op',
    alg: 'ES256',
    use: 'sig',
  };
  const privateJwk = {
    ...(await exportJWK(key.privateKey)),
    kid: 'logout-queue-op',
    alg: 'ES256',
    use: 'sig',
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    if (new URL(request.url).hostname === 'rp.example.test') {
      assert.equal(request.method, 'POST');
      assert.match(
        request.headers.get('content-type') ?? '',
        /^application\/x-www-form-urlencoded/i,
      );
      const form = new URLSearchParams(await request.clone().text());
      const token = form.get('logout_token');
      assert.ok(token, 'the real Worker must POST a logout_token to the RP');
      const expectedClient = new URL(request.url).pathname.split('/')[1];
      const { payload: claims } = await jwtVerify(token, key.publicKey, {
        issuer,
        audience: expectedClient,
        algorithms: ['ES256'],
      });
      assert.equal(claims.iss, issuer);
      assert.equal(claims.aud, expectedClient);
      assert.equal(typeof claims.events, 'object');
      const event = claims.events as Record<string, unknown>;
      assert.deepEqual(Object.keys(event), ['http://schemas.openid.net/event/backchannel-logout']);
      assert.deepEqual(event['http://schemas.openid.net/event/backchannel-logout'], {});
      assert.equal('nonce' in claims, false);
      const captured = {
        token,
        jti: String(claims.jti),
        aud: claims.aud,
        sid: claims.sid,
      };
      return options.backchannel(request, captured);
    }
    return originalFetch(input, init);
  };

  const harness = createTestHarness({
    root,
    workers: [
      {
        config: sourceConfig,
        vars: { MIKAKI_ISSUER: issuer },
        secrets: { OP_PRIVATE_JWK: JSON.stringify(privateJwk) },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const env = await worker.getEnv();
    const DB = env.DB as D1Database;
    const now = Math.floor(Date.now() / 1000);
    const recipientCount = options.recipientCount ?? 1;
    const sessions = Array.from({ length: options.sessionCount ?? 1 }, (_, index) => ({
      sso: index === 0 ? 'logout-queue-sso' : `logout-queue-sso-${index}`,
      cookie: opaque(),
    }));
    const account = 'logout-queue-account';
    const credential = 'logout-queue-credential';
    const policy = JSON.parse(
      await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
    );
    await activateWorkerPolicy(DB, policy, {
      actor: 'logout-queue-test',
      reason: 'exercise real Rust logout delivery through workerd',
    });
    const statements = [
      DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(account),
      DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(credential, account),
      DB.prepare("INSERT INTO signing_key VALUES('logout-queue-op',1,1,'ES256',?)").bind(
        JSON.stringify(publicJwk),
      ),
    ];
    for (const [sessionIndex, session] of sessions.entries()) {
      statements.push(
        DB.prepare('INSERT INTO sso_session VALUES(?,?,?,?,?,0)').bind(
          session.sso,
          account,
          credential,
          1,
          now + 3600,
        ),
        DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(
          session.sso,
          digest(session.cookie),
          now,
        ),
      );
      for (let i = 0; i < recipientCount; i++) {
        const clientId =
          options.recipientClients?.[i] ?? (i % 2 === 0 ? 'logout-rp-a' : 'logout-rp-b');
        const sid = sessionIndex === 0 ? `logout-sid-${i}` : `logout-sid-${sessionIndex}-${i}`;
        statements.push(
          DB.prepare(
            'INSERT OR IGNORE INTO client(client_id,revision,active,sector_identifier) VALUES(?,1,1,?)',
          ).bind(clientId, `${clientId}.example.test`),
          DB.prepare('INSERT OR IGNORE INTO app_connection VALUES(?,?,1,1)').bind(
            account,
            clientId,
          ),
          DB.prepare(
            'INSERT INTO client_backchannel_logout_uri(client_id,logout_uri,active) VALUES(?,?,1) ON CONFLICT(client_id) DO UPDATE SET logout_uri=excluded.logout_uri,active=1',
          ).bind(clientId, `https://rp.example.test/${clientId}/backchannel`),
          DB.prepare('INSERT INTO client_session VALUES(?,?,?,?,?,1,0)').bind(
            clientId,
            sid,
            session.sso,
            account,
            sessionIndex === 0 ? `pairwise-sub-${i}` : `pairwise-sub-${sessionIndex}-${i}`,
          ),
        );
      }
    }
    for (let offset = 0; offset < statements.length; offset += 80) {
      await DB.batch(statements.slice(offset, offset + 80));
    }

    const logoutFor = async (cookie: string) => {
      const initial = await worker.fetch(`${issuer}/logout`, {
        headers: { Cookie: `__Host-op-sso=${cookie}` },
      });
      assert.equal(initial.status, 200);
      const html = await initial.text();
      const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1];
      assert.ok(csrf, 'logout confirmation must issue a CSRF value');
      const logoutCookie = /__Host-op-logout=([^;, ]+)/.exec(
        initial.headers.get('set-cookie') ?? '',
      )?.[1];
      assert.ok(logoutCookie, 'logout confirmation must set its cookie');
      const started = performance.now();
      const response = await worker.fetch(`${issuer}/logout`, {
        method: 'POST',
        headers: {
          Cookie: `__Host-op-sso=${cookie}; __Host-op-logout=${logoutCookie}`,
          Origin: issuer,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ csrf }).toString(),
      });
      return { response, elapsedMs: performance.now() - started };
    };
    const logout = () => logoutFor(sessions[0]!.cookie);
    const ssoState = async () =>
      DB.prepare('SELECT revoked FROM sso_session WHERE sso_id=?')
        .bind(sessions[0]!.sso)
        .first('revoked');
    const deliveryRows = async () =>
      (
        await DB.prepare(
          'SELECT event_id,client_id,sid,state,attempts,next_at,last_status FROM logout_delivery ORDER BY client_id,sid',
        ).all()
      ).results as Array<Record<string, unknown>>;
    const deliveryRowsForSession = async (sso: string) =>
      (
        await DB.prepare(
          'SELECT d.event_id,d.client_id,d.sid,d.state,d.attempts,d.next_at,d.last_status FROM logout_delivery d JOIN sso_logout_event e ON e.event_id=d.event_id WHERE e.sso_id=? ORDER BY d.client_id,d.sid',
        )
          .bind(sso)
          .all()
      ).results as Array<Record<string, unknown>>;
    const queueObservations = async () => {
      const response = await worker.fetch(`${issuer}/__test/queue-observations`);
      assert.equal(response.status, 200);
      return (await response.json()) as {
        sourceAttempts: number;
        deadLetterMessages: number;
      };
    };
    const close = async () => {
      globalThis.fetch = originalFetch;
      await harness.close();
    };
    return {
      worker,
      DB,
      sessions,
      cookie: sessions[0]!.cookie,
      logout,
      logoutFor,
      ssoState,
      deliveryRows,
      deliveryRowsForSession,
      queueObservations,
      close,
    };
  } catch (error) {
    globalThis.fetch = originalFetch;
    await harness.close();
    throw error;
  }
}

async function until<T>(
  read: () => Promise<T>,
  done: (value: T) => boolean,
  message: string,
  timeoutMs = 5000,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await read();
    if (done(value)) return value;
    await delay(20);
  }
  assert.fail(`Timed out waiting for ${message}`);
}

test('browser logout commits revocation and returns while real queued RP delivery is still blocked', async () => {
  let captureResolve!: (value: CapturedLogout) => void;
  const captured = new Promise<CapturedLogout>((resolve) => (captureResolve = resolve));
  let releaseResolve!: (response: Response) => void;
  const release = new Promise<Response>((resolve) => (releaseResolve = resolve));
  let dispatch: Parameters<typeof journeyServer>[0] = async () => {
    throw new Error('Logout browser bridge is not ready');
  };
  const server = await journeyServer((url, init) => dispatch(url, init));
  const issuer = `https://mikaki.test:${server.port}`;
  const instance = await startInstance({
    queue: true,
    issuer,
    backchannel: async (_request, token) => {
      captureResolve(token);
      return release;
    },
  });
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  try {
    dispatch = async (url, init) => {
      assert.equal(new URL(url).origin, issuer);
      return instance.worker.fetch(url, {
        method: init.method,
        headers: init.headers,
        ...(init.body ? { body: init.body } : {}),
        redirect: 'manual',
      });
    };
    browser = await chromium.launch({
      headless: true,
      args: ['--host-resolver-rules=MAP mikaki.test 127.0.0.1', '--no-proxy-server'],
    });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    await context.addCookies([
      {
        url: issuer,
        name: '__Host-op-sso',
        value: instance.cookie,
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
      },
    ]);
    const page = await context.newPage();
    await page.goto(`${issuer}/logout`, { waitUntil: 'domcontentloaded' });
    assert.match(await page.content(), /name="csrf"/);
    const postResponsePromise = page.waitForResponse((response) => {
      const request = response.request();
      return request.method() === 'POST' && new URL(response.url()).pathname === '/logout';
    });
    await page.locator('form[action^="/logout"] button[type="submit"]').click();
    const notification = await within(captured, 'queued RP POST');
    const response = await within(postResponsePromise, 'browser logout response');
    assert.equal(response.status(), 200);
    assert.equal(response.headers()['cache-control'], 'no-store');
    assert.match(await page.locator('body').innerText(), /logged out|ログアウトしました/i);
    assert.equal(await instance.ssoState(), 1, 'D1 revocation must commit before response');
    assert.ok(notification.jti.length > 0);
    assert.equal(notification.aud, 'logout-rp-a');
    assert.equal(notification.sid, 'logout-sid-0');
    const rows = await instance.deliveryRows();
    assert.equal(rows.length, 1);
    assert.equal(rows[0]?.state, 'leased', 'the RP request is deliberately still pending');
    releaseResolve(new Response(null, { status: 204 }));
    await until(
      instance.deliveryRows,
      (value) => value[0]?.state === 'delivered',
      'queued RP delivery receipt',
    );
  } finally {
    releaseResolve(new Response(null, { status: 503 }));
    await browser?.close();
    await instance.close();
    await server.close();
  }
});

test('concurrent cron cannot claim an RP delivery that is already leased by the Queue consumer', async () => {
  let captureResolve!: (value: CapturedLogout) => void;
  const captured = new Promise<CapturedLogout>((resolve) => (captureResolve = resolve));
  let releaseResolve!: (response: Response) => void;
  const release = new Promise<Response>((resolve) => (releaseResolve = resolve));
  let postCount = 0;
  const instance = await startInstance({
    queue: true,
    backchannel: async (_request, token) => {
      postCount++;
      captureResolve(token);
      return release;
    },
  });
  try {
    const pendingLogout = instance.logout();
    await within(captured, 'leased RP POST');
    const response = await Promise.race([pendingLogout, delay(1000).then(() => null)]);
    assert.ok(response, 'logout must not wait for the leased delivery');
    assert.equal(response.response.status, 200);
    await instance.worker.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
    assert.equal(postCount, 1, 'the lease prevents a concurrent cron duplicate POST');
    const rows = await instance.deliveryRows();
    assert.equal(rows[0]?.attempts, 1);
    assert.equal(rows[0]?.state, 'leased');
  } finally {
    releaseResolve(new Response(null, { status: 204 }));
    await instance.close();
  }
});

test('a missing Queue binding cannot roll back logout; minute cron drains the D1 outbox', async () => {
  const postedTokens: CapturedLogout[] = [];
  const instance = await startInstance({
    queue: false,
    backchannel: async (_request, token) => {
      postedTokens.push(token);
      return new Response(null, { status: 204 });
    },
  });
  try {
    const posted = await instance.logout();
    assert.equal(posted.response.status, 200);
    assert.equal(await instance.ssoState(), 1);
    const pending = await instance.deliveryRows();
    assert.equal(pending.length, 1);
    assert.equal(pending[0]?.state, 'pending');
    await instance.worker.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
    assert.equal((await instance.deliveryRows())[0]?.state, 'delivered');
    assert.equal(postedTokens.length, 1);
  } finally {
    await instance.close();
  }
});

test('a D1 logout-batch failure leaves SSO, RP leases, and outbox untouched', async () => {
  let postCount = 0;
  const instance = await startInstance({
    queue: true,
    backchannel: async () => {
      postCount++;
      return new Response(null, { status: 204 });
    },
  });
  try {
    await instance.DB.prepare(
      "CREATE TRIGGER reject_logout_delivery BEFORE INSERT ON logout_delivery BEGIN SELECT RAISE(ABORT,'test_logout_delivery_failure'); END",
    ).run();
    const result = await instance.logout();
    assert.equal(result.response.status, 400);
    assert.equal(await instance.ssoState(), 0);
    assert.equal(
      await instance.DB.prepare('SELECT revoked FROM client_session WHERE sid=?')
        .bind('logout-sid-0')
        .first('revoked'),
      0,
    );
    assert.equal(
      await instance.DB.prepare('SELECT count(*) AS n FROM sso_logout_event').first('n'),
      0,
    );
    assert.equal((await instance.deliveryRows()).length, 0);
    assert.equal(postCount, 0, 'no RP request may escape a rolled-back D1 logout');
  } finally {
    await instance.close();
  }
});

test('expired outbox deliveries become terminal without contacting the RP', async () => {
  let postCount = 0;
  const instance = await startInstance({
    queue: false,
    backchannel: async () => {
      postCount++;
      return new Response(null, { status: 204 });
    },
  });
  try {
    const now = Math.floor(Date.now() / 1000);
    const event = opaque();
    await instance.DB.batch([
      instance.DB.prepare(
        'INSERT INTO sso_logout_event(event_id,sso_id,created_at,deadline) VALUES(?,?,?,?)',
      ).bind(event, 'logout-queue-sso', now - 2, now - 1),
      instance.DB.prepare(
        'INSERT INTO logout_delivery(event_id,client_id,sid,sub,logout_uri,next_at) VALUES(?,?,?,?,?,?)',
      ).bind(
        event,
        'logout-rp-a',
        'expired-sid',
        'expired-sub',
        'https://rp.example.test/logout-rp-a/backchannel',
        now - 1,
      ),
    ]);
    await instance.worker.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
    assert.equal((await instance.deliveryRows())[0]?.state, 'expired');
    assert.equal(postCount, 0);
  } finally {
    await instance.close();
  }
});

test('new RP receives a delivery before large older RP backlogs drain', async () => {
  const clients = [
    ...Array.from({ length: 20 }, () => 'logout-rp-a'),
    ...Array.from({ length: 20 }, () => 'logout-rp-b'),
    'logout-rp-c',
  ];
  let firstTwoResolve!: () => void;
  const firstTwo = new Promise<void>((resolve) => (firstTwoResolve = resolve));
  let newClientResolve!: (token: CapturedLogout) => void;
  const newClient = new Promise<CapturedLogout>((resolve) => (newClientResolve = resolve));
  let releaseOldResolve!: () => void;
  const releaseOld = new Promise<void>((resolve) => (releaseOldResolve = resolve));
  const oldArrivals = new Set<string>();
  const instance = await startInstance({
    queue: true,
    recipientCount: clients.length,
    recipientClients: clients,
    backchannel: async (request, token) => {
      const clientId = new URL(request.url).pathname.split('/')[1]!;
      if (clientId === 'logout-rp-c') {
        newClientResolve(token);
        return new Response(null, { status: 204 });
      }
      oldArrivals.add(clientId);
      if (oldArrivals.size === 2) firstTwoResolve();
      await releaseOld;
      return new Response(null, { status: 204 });
    },
  });
  try {
    const posted = await instance.logout();
    assert.equal(posted.response.status, 200);
    await within(firstTwo, 'initial old-client RP leases');
    releaseOldResolve();
    const token = await within(newClient, 'new RP selected while old backlogs remain');
    assert.equal(token.aud, 'logout-rp-c');
    const rows = await until(
      instance.deliveryRows,
      (value) => value.some((row) => row.client_id === 'logout-rp-c' && row.state === 'delivered'),
      'new RP durable delivery',
    );
    assert.ok(rows.some((row) => row.client_id === 'logout-rp-a' && row.state === 'delivered'));
    assert.ok(rows.some((row) => row.client_id === 'logout-rp-b' && row.state === 'delivered'));
    assert.equal(
      rows.filter((row) => row.client_id === 'logout-rp-c' && row.state === 'delivered').length,
      1,
    );
    assert.ok(rows.some((row) => row.client_id === 'logout-rp-a' && row.state === 'pending'));
    assert.ok(rows.some((row) => row.client_id === 'logout-rp-b' && row.state === 'pending'));
  } finally {
    releaseOldResolve();
    await instance.close();
  }
});

test('more than sixteen recipients across RP clients converge without starving either RP', async () => {
  const byClient = new Map<string, number>();
  const instance = await startInstance({
    queue: true,
    recipientCount: 17,
    backchannel: async (request, token) => {
      const path = new URL(request.url).pathname;
      const clientId = path.split('/')[1]!;
      assert.equal(token.aud, clientId);
      byClient.set(clientId, (byClient.get(clientId) ?? 0) + 1);
      return new Response(null, { status: 204 });
    },
  });
  try {
    const posted = await instance.logout();
    assert.equal(posted.response.status, 200);
    const rows = await until(
      instance.deliveryRows,
      (value) => value.length === 17 && value.every((row) => row.state === 'delivered'),
      'all fanout recipients',
      60_000,
    );
    assert.equal(rows.length, 17);
    assert.equal(rows.filter((row) => row.client_id === 'logout-rp-a').length, 9);
    assert.equal(rows.filter((row) => row.client_id === 'logout-rp-b').length, 8);
    assert.equal(byClient.get('logout-rp-a'), 9);
    assert.equal(byClient.get('logout-rp-b'), 8);
  } finally {
    await instance.close();
  }
});

test('failed RP delivery retries from D1 with a stable logout-token jti and terminal replays do not redeliver', async () => {
  const tokens: CapturedLogout[] = [];
  const instance = await startInstance({
    queue: true,
    backchannel: async (_request, token) => {
      tokens.push(token);
      return new Response(null, { status: tokens.length === 1 ? 503 : 204 });
    },
  });
  try {
    const posted = await instance.logout();
    assert.equal(posted.response.status, 200);
    await until(
      instance.deliveryRows,
      (value) => value[0]?.state === 'pending',
      'retryable D1 delivery after RP 503',
    );
    const event = await instance.DB.prepare('SELECT event_id FROM sso_logout_event WHERE sso_id=?')
      .bind('logout-queue-sso')
      .first('event_id');
    assert.equal(typeof event, 'string');
    await instance.DB.prepare('UPDATE logout_delivery SET next_at=unixepoch()-1 WHERE event_id=?')
      .bind(event)
      .run();
    await instance.worker.scheduled({ cron: '* * * * *', scheduledTime: new Date() });
    assert.equal((await instance.deliveryRows())[0]?.state, 'delivered');
    assert.equal(tokens.length, 2);
    assert.equal(tokens[0]?.jti, tokens[1]?.jti);

    const { LOGOUT_QUEUE } = (await instance.worker.getEnv()) as { LOGOUT_QUEUE: Queue };
    await LOGOUT_QUEUE.send({ version: 1, event_id: event });
    await delay(250);
    assert.equal(
      tokens.length,
      2,
      'a replay for a durable terminal row must ack without reposting',
    );
  } finally {
    await instance.close();
  }
});

test('a Queue ack lost after D1 and RP success retries without duplicate RP delivery and reaches DLQ', async () => {
  const tokens: CapturedLogout[] = [];
  const instance = await startInstance({
    queue: true,
    ackLoss: true,
    backchannel: async (_request, token) => {
      tokens.push(token);
      return new Response(null, { status: 204 });
    },
  });
  try {
    const posted = await instance.logout();
    assert.equal(posted.response.status, 200);
    const rows = await until(
      instance.deliveryRows,
      (value) => value[0]?.state === 'delivered',
      'D1 delivery receipt before injected Queue acknowledgement loss',
    );
    assert.equal(rows[0]?.state, 'delivered');
    const observations = await until(
      instance.queueObservations,
      (value) => value.sourceAttempts >= 2 && value.deadLetterMessages >= 1,
      'Queue retry and dead-letter receipt',
      10_000,
    );
    assert.ok(observations.sourceAttempts >= 2);
    assert.ok(observations.deadLetterMessages >= 1);
    assert.equal(tokens.length, 1, 'the redelivered wake-up must not repeat a durable RP delivery');
  } finally {
    await instance.close();
  }
});

// Opt-in local capacity probe. Run with:
// MIKAKI_LOGOUT_BENCHMARK=1 node --test --test-concurrency=1 \
//   --test-name-pattern='local-only logout benchmark' local/conformance/logout-queue.test.ts
// This measures the real local workerd/D1/Queue path; it is not production capacity evidence.
if (process.env.MIKAKI_LOGOUT_BENCHMARK === '1') {
  test('local-only logout benchmark reports browser, first-delivery, and D1 terminal latency', async () => {
    const warmupCount = 2;
    const sampleCount = 20;
    const batchSize = 4;
    const observationIntervalMs = 100;
    const scenarios = [
      { name: 'single-rp', clients: ['logout-rp-a'] },
      {
        name: 'balanced-8',
        clients: [
          'logout-rp-a',
          'logout-rp-b',
          'logout-rp-c',
          'logout-rp-d',
          'logout-rp-a',
          'logout-rp-b',
          'logout-rp-c',
          'logout-rp-d',
        ],
      },
      {
        name: 'skewed-24-22-to-2',
        clients: [...Array.from({ length: 22 }, () => 'logout-rp-a'), 'logout-rp-b', 'logout-rp-b'],
      },
    ];
    const percentile = (values: number[], fraction: number) => {
      const sorted = [...values].sort((left, right) => left - right);
      return sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] ?? null;
    };
    const rounded = (value: number | null) =>
      value === null ? null : Math.round(value * 1000) / 1000;
    const reports: Array<Record<string, unknown>> = [];
    const failures: string[] = [];

    for (const scenario of scenarios) {
      const sidToSession = new Map<string, string>();
      const startedAt = new Map<string, number>();
      const firstDeliveryAt = new Map<string, number>();
      const terminalObservedAt = new Map<string, number>();
      const measured: Array<{
        responseMs: number;
        firstDeliveryMs: number;
        firstDeliveryVsResponseMs: number;
        d1TerminalObservedMs: number;
        responseStatus: number;
        rpSuccesses: number;
        rpRetries: number;
        rpFailures: number;
        rpExpired: number;
        rpAttempts: number;
      }> = [];
      let successfulResponses = 0;
      let instance: Awaited<ReturnType<typeof startInstance>> | undefined;
      let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
      let server: Awaited<ReturnType<typeof journeyServer>> | undefined;
      let peakPending = 0;
      let peakLeased = 0;
      let backlogReads = 0;
      const contexts: BrowserContext[] = [];
      try {
        let dispatch: Parameters<typeof journeyServer>[0] = async () => {
          throw new Error('Logout benchmark bridge is not ready');
        };
        server = await journeyServer((url, init) => dispatch(url, init));
        const issuer = `https://mikaki.test:${server.port}`;
        const fanout = scenario.clients.length;
        instance = await startInstance({
          queue: true,
          issuer,
          recipientCount: fanout,
          recipientClients: scenario.clients,
          sessionCount: sampleCount + warmupCount,
          backchannel: async (_request, token) => {
            const sid = String(token.sid);
            const sso = sidToSession.get(sid);
            if (sso) {
              if (!firstDeliveryAt.has(sso)) firstDeliveryAt.set(sso, performance.now());
            }
            return new Response(null, { status: 204 });
          },
        });
        dispatch = async (url, init) => {
          assert.equal(new URL(url).origin, issuer);
          return instance!.worker.fetch(url, {
            method: init.method,
            headers: init.headers,
            ...(init.body ? { body: init.body } : {}),
            redirect: 'manual',
          });
        };
        for (const [sessionIndex, session] of instance.sessions.entries()) {
          for (let recipientIndex = 0; recipientIndex < fanout; recipientIndex++) {
            const sid =
              sessionIndex === 0
                ? `logout-sid-${recipientIndex}`
                : `logout-sid-${sessionIndex}-${recipientIndex}`;
            sidToSession.set(sid, session.sso);
          }
        }
        browser = await chromium.launch({
          headless: true,
          args: ['--host-resolver-rules=MAP mikaki.test 127.0.0.1', '--no-proxy-server'],
        });
        const pages: Page[] = [];
        for (let lane = 0; lane < batchSize; lane++) {
          const context = await browser.newContext({ ignoreHTTPSErrors: true });
          contexts.push(context);
          pages.push(await context.newPage());
        }

        const observeBacklog = async () => {
          const ids = instance!.sessions.map((session) => session.sso);
          const placeholders = ids.map((_, index) => `?${index + 1}`).join(',');
          const results = await instance!.DB.prepare(
            `SELECT e.sso_id,COUNT(*) AS deliveries, \
               SUM(CASE WHEN d.state IN ('delivered','failed','expired') THEN 1 ELSE 0 END) AS terminal, \
               SUM(CASE WHEN d.state='pending' THEN 1 ELSE 0 END) AS pending, \
               SUM(CASE WHEN d.state='leased' THEN 1 ELSE 0 END) AS leased \
             FROM logout_delivery d JOIN sso_logout_event e ON e.event_id=d.event_id \
             WHERE e.sso_id IN (${placeholders}) GROUP BY e.sso_id`,
          )
            .bind(...ids)
            .all<{
              sso_id: string;
              deliveries: number;
              terminal: number;
              pending: number;
              leased: number;
            }>();
          let pending = 0;
          let leased = 0;
          for (const result of results.results) {
            pending += Number(result.pending);
            leased += Number(result.leased);
            if (
              Number(result.deliveries) === fanout &&
              Number(result.terminal) === fanout &&
              !terminalObservedAt.has(result.sso_id)
            ) {
              terminalObservedAt.set(result.sso_id, performance.now());
            }
          }
          peakPending = Math.max(peakPending, pending);
          peakLeased = Math.max(peakLeased, leased);
          backlogReads++;
          return { pending, leased };
        };
        const batches = [
          Array.from({ length: warmupCount }, (_, index) => index),
          ...Array.from({ length: Math.ceil(sampleCount / batchSize) }, (_, batch) =>
            Array.from(
              { length: Math.min(batchSize, sampleCount - batch * batchSize) },
              (_, index) => warmupCount + batch * batchSize + index,
            ),
          ),
        ];
        for (const batch of batches) {
          await observeBacklog();
          const responses = await Promise.all(
            batch.map(async (index) => {
              const session = instance!.sessions[index]!;
              const sso = session.sso;
              const lane = index % batchSize;
              const page = pages[lane]!;
              await contexts[lane]!.addCookies([
                {
                  url: issuer,
                  name: '__Host-op-sso',
                  value: session.cookie,
                  secure: true,
                  httpOnly: true,
                  sameSite: 'Lax',
                },
              ]);
              await page.goto(`${issuer}/logout`, {
                waitUntil: 'domcontentloaded',
                timeout: 10_000,
              });
              assert.match(await page.content(), /name="csrf"/);
              const formStarted = performance.now();
              startedAt.set(sso, formStarted);
              const responsePromise = page
                .waitForResponse((response) => {
                  const request = response.request();
                  return (
                    request.method() === 'POST' && new URL(response.url()).pathname === '/logout'
                  );
                })
                .then((response) => ({ response, responseAt: performance.now() }));
              await page
                .locator('form[action^="/logout"] button[type="submit"]')
                .click({ timeout: 10_000 });
              const { response, responseAt } = await within(
                responsePromise,
                'browser logout response',
                10_000,
              );
              return { index, sso, responseAt, responseStatus: response.status() };
            }),
          );
          successfulResponses += responses.filter(
            (item) => item.index >= warmupCount && item.responseStatus === 200,
          ).length;
          const successful = responses.filter((item) => item.responseStatus === 200);
          const terminalRows = new Map<string, Array<Record<string, unknown>>>();
          if (successful.length > 0) {
            const deadline = Date.now() + 45_000;
            while (
              successful.some((item) => !terminalObservedAt.has(item.sso)) &&
              Date.now() < deadline
            ) {
              await observeBacklog();
              if (successful.every((item) => terminalObservedAt.has(item.sso))) break;
              await delay(observationIntervalMs);
            }
            if (successful.some((item) => !terminalObservedAt.has(item.sso))) {
              failures.push(`Timed out waiting for D1 terminal state in ${scenario.name}`);
            }
            for (const item of successful) {
              terminalRows.set(item.sso, await instance!.deliveryRowsForSession(item.sso));
            }
          }
          for (const item of responses) {
            if (item.index < warmupCount || item.responseStatus !== 200) continue;
            const formStarted = startedAt.get(item.sso)!;
            const firstDelivery = firstDeliveryAt.get(item.sso);
            const terminalAt = terminalObservedAt.get(item.sso);
            const rows = terminalRows.get(item.sso) ?? [];
            if (firstDelivery === undefined || terminalAt === undefined || rows.length !== fanout) {
              failures.push(`Missing RP timing or D1 rows for ${scenario.name}`);
              continue;
            }
            measured.push({
              responseMs: item.responseAt - formStarted,
              firstDeliveryMs: firstDelivery! - formStarted,
              firstDeliveryVsResponseMs: firstDelivery! - item.responseAt,
              d1TerminalObservedMs: terminalAt - formStarted,
              responseStatus: item.responseStatus,
              rpSuccesses: rows.filter((row) => row.state === 'delivered').length,
              rpRetries: rows.reduce((sum, row) => sum + Math.max(0, Number(row.attempts) - 1), 0),
              rpFailures: rows.filter((row) => row.state === 'failed').length,
              rpExpired: rows.filter((row) => row.state === 'expired').length,
              rpAttempts: rows.reduce((sum, row) => sum + Number(row.attempts), 0),
            });
          }
        }
        const finalBacklog = await observeBacklog();
        const series = (field: keyof (typeof measured)[number]) =>
          measured.map((sample) => Number(sample[field]));
        const responseSeries = series('responseMs');
        const deliverySeries = series('firstDeliveryMs');
        const deliveryResponseSeries = series('firstDeliveryVsResponseMs');
        const terminalSeries = series('d1TerminalObservedMs');
        const percentileSummary = (values: number[]) => ({
          p50_ms: rounded(percentile(values, 0.5)),
          p95_ms: rounded(percentile(values, 0.95)),
          p99_ms: rounded(percentile(values, 0.99)),
        });
        const rpSuccesses = measured.reduce((sum, sample) => sum + sample.rpSuccesses, 0);
        const rpRetries = measured.reduce((sum, sample) => sum + sample.rpRetries, 0);
        const rpFailures = measured.reduce((sum, sample) => sum + sample.rpFailures, 0);
        const rpExpired = measured.reduce((sum, sample) => sum + sample.rpExpired, 0);
        reports.push({
          scenario: scenario.name,
          recipient_fanout: fanout,
          sample_count: sampleCount,
          valid_latency_samples: measured.length,
          complete:
            measured.length === sampleCount &&
            successfulResponses === sampleCount &&
            rpFailures + rpExpired === 0 &&
            finalBacklog.pending + finalBacklog.leased === 0,
          warmup_count: warmupCount,
          warmup_policy:
            'two logout events per scenario; excluded from latency percentiles and outcome counts',
          percentiles: {
            browser_logout_response: percentileSummary(responseSeries),
            first_rp_post_from_form_submit: percentileSummary(deliverySeries),
            first_rp_post_minus_browser_response: percentileSummary(deliveryResponseSeries),
            d1_terminal_observation_from_form_submit: percentileSummary(terminalSeries),
          },
          logout: {
            successful: successfulResponses,
            failed: sampleCount - successfulResponses,
            valid_latency_samples: measured.length,
            response_success_rate: Number((successfulResponses / sampleCount).toFixed(4)),
          },
          rp_delivery: {
            successful: rpSuccesses,
            retried_attempts: rpRetries,
            failed_terminal: rpFailures,
            expired_terminal: rpExpired,
            attempt_count: measured.reduce((sum, sample) => sum + sample.rpAttempts, 0),
          },
          backlog: {
            peak_pending_observed: peakPending,
            peak_leased_observed: peakLeased,
            final_pending: finalBacklog.pending,
            final_leased: finalBacklog.leased,
            observation_interval_ms: observationIntervalMs,
            observations: backlogReads,
          },
          sample_rows: measured,
          qualification:
            'local-only workerd/Miniflare/D1/Queue result; not production capacity or SLO evidence',
        });
        if (measured.length !== sampleCount)
          failures.push(`Incomplete samples in ${scenario.name}`);
        if (successfulResponses !== sampleCount)
          failures.push(`Logout HTTP failures in ${scenario.name}`);
        if (rpFailures + rpExpired !== 0) failures.push(`Terminal RP failures in ${scenario.name}`);
        if (finalBacklog.pending + finalBacklog.leased !== 0) {
          failures.push(`Outbox backlog in ${scenario.name}`);
        }
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        failures.push(`${scenario.name}: ${detail}`);
        reports.push({
          scenario: scenario.name,
          recipient_fanout: scenario.clients.length,
          sample_count: sampleCount,
          valid_latency_samples: measured.length,
          complete: false,
          failure: detail,
          observed_peak_pending: peakPending,
          observed_peak_leased: peakLeased,
        });
      } finally {
        for (const context of contexts) await context.close();
        await browser?.close();
        await instance?.close();
        await server?.close();
      }
    }

    console.log(
      `MIKAKI_LOGOUT_BENCHMARK_JSON ${JSON.stringify({
        schema_version: 1,
        measured_at: new Date().toISOString(),
        local_only: true,
        production_capacity_qualified: false,
        percentile_method:
          'nearest-rank; with 20 samples p95/p99 are near the observed maximum, not stable tail-SLO estimates',
        scenarios: reports,
      })}`,
    );
    assert.deepEqual(failures, [], `Local logout benchmark failures: ${failures.join('; ')}`);
  });
}
