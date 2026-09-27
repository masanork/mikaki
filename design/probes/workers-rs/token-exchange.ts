import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createTestHarness } from 'wrangler';
import { decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import { activateWorkerPolicy } from '../../../scripts/worker-policy-store.ts';

const root = fileURLToPath(new URL('../../..', import.meta.url));
const workerConfig = fileURLToPath(
  new URL('../../../crates/worker/wrangler.jsonc', import.meta.url),
);
const policy = JSON.parse(
  await readFile(new URL('../../../local/generated/worker-policy.json', import.meta.url), 'utf8'),
);
const issuer = 'https://issuer.example';
const clientId = 'oidc-local-test-client';
const redirectUri = 'https://rp.example/callback';
const clientKid = 'oidc-local-client-key';
const opKid = 'oidc-local-op-key';

async function signingKey(kid: string) {
  const pair = await generateKeyPair('ES256', { extractable: true });
  const privateJwk = { ...(await exportJWK(pair.privateKey)), kid, alg: 'ES256', use: 'sig' };
  const publicJwk = { ...(await exportJWK(pair.publicKey)), kid, alg: 'ES256', use: 'sig' };
  assert.ok(publicJwk.x && publicJwk.y);
  const publicBytes = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(publicJwk.x, 'base64url'),
    Buffer.from(publicJwk.y, 'base64url'),
  ]);
  return { pair, privateJwk, publicJwk, publicBytes };
}

async function makeClientAssertion(now: number) {
  return new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: clientKid, typ: 'JWT' })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(`${issuer}/token`)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + 60)
    .sign(client.pair.privateKey);
}

const op = await signingKey(opKid);
const client = await signingKey(clientKid);
const cookie = randomBytes(32).toString('base64url');
const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
const harness = createTestHarness({
  root,
  workers: [
    {
      configPath: workerConfig,
      vars: { MIKAKI_ISSUER: issuer },
      secrets: { OP_PRIVATE_JWK: JSON.stringify(op.privateJwk) },
    },
  ],
});

try {
  await harness.listen();
  const worker = harness.getWorker('mikaki-op-worker');
  await worker.applyD1Migrations('DB');
  const env = await worker.getEnv();
  const unavailable = await worker.fetch(`${issuer}/authorize`);
  assert.equal(unavailable.status, 500, 'authorization must fail closed before policy activation');
  await activateWorkerPolicy(env.DB, policy, {
    actor: 'local-integration-test',
    reason: 'initial policy',
  });
  const now = Math.floor(Date.now() / 1000);
  const cookieHash = createHash('sha256').update(cookie).digest('base64url');
  await env.DB.batch([
    env.DB.prepare('INSERT INTO account_security(account_id,epoch,active) VALUES(?,1,1)').bind(
      'oidc-test-account',
    ),
    env.DB.prepare('INSERT INTO credential(credential_id,account_id,active) VALUES(?,?,1)').bind(
      'oidc-test-credential',
      'oidc-test-account',
    ),
    env.DB.prepare(
      'INSERT INTO client(client_id,revision,active,sector_identifier) VALUES(?,1,1,?)',
    ).bind(clientId, 'https://rp.example'),
    env.DB.prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)').bind(
      clientId,
      redirectUri,
    ),
    env.DB.prepare(
      'INSERT INTO client_post_logout_redirect_uri(client_id,redirect_uri,active) VALUES(?,?,1)',
    ).bind(clientId, 'https://rp.example/logout/callback'),
    env.DB.prepare(
      'INSERT INTO client_backchannel_logout_uri(client_id,logout_uri,active) VALUES(?,?,1)',
    ).bind(clientId, 'https://rp.example/backchannel'),
    env.DB.prepare(
      "INSERT INTO client_key(client_id,kid,revision,active,algorithm,public_key_sec1) VALUES(?,?,1,1,'ES256',?)",
    ).bind(clientId, clientKid, client.publicBytes),
    env.DB.prepare(
      "INSERT INTO signing_key(kid,generation,active,algorithm,public_jwk) VALUES(?,1,1,'ES256',?)",
    ).bind(opKid, JSON.stringify(op.publicJwk)),
    env.DB.prepare(
      'INSERT INTO app_connection(account_id,client_id,grant_version,active) VALUES(?,?,1,1)',
    ).bind('oidc-test-account', clientId),
    env.DB.prepare(
      'INSERT INTO sso_session(sso_id,account_id,credential_id,epoch,expires_at,revoked) VALUES(?,?,?,1,?,0)',
    ).bind('oidc-test-sso', 'oidc-test-account', 'oidc-test-credential', now + 900),
    env.DB.prepare('INSERT INTO sso_context(sso_id,secret_hash,auth_time) VALUES(?,?,?)').bind(
      'oidc-test-sso',
      cookieHash,
      now - 30,
    ),
  ]);

  const authorization = new URL('/authorize', issuer);
  authorization.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid',
    state: 'local-integration-state',
    nonce: 'local-integration-nonce',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();
  const authorizationResponse = await worker.fetch(authorization, {
    headers: { cookie: `__Host-op-sso=${cookie}` },
    redirect: 'manual',
  });
  assert.equal(authorizationResponse.status, 302);
  const location = authorizationResponse.headers.get('location');
  assert.ok(location);
  const callback = new URL(location);
  assert.equal(callback.origin + callback.pathname, redirectUri);
  assert.equal(callback.searchParams.get('state'), 'local-integration-state');
  assert.equal(callback.searchParams.get('iss'), issuer);
  const code = callback.searchParams.get('code');
  assert.ok(code);
  assert.match(code, /^[A-Za-z0-9_-]{43}$/);

  const tokenEndpoint = `${issuer}/token`;
  const assertion = await makeClientAssertion(now);
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: assertion,
  });
  const tokenResponse = await worker.fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  const tokenBody = await tokenResponse.text();
  assert.equal(tokenResponse.status, 200, tokenBody);
  const tokens = JSON.parse(tokenBody);
  assert.equal(tokens.token_type, 'Bearer');
  assert.equal(tokens.scope, 'openid');
  assert.ok(tokens.access_token);
  assert.equal(decodeProtectedHeader(tokens.id_token).alg, 'ES256');
  const { payload } = await jwtVerify(tokens.id_token, op.pair.publicKey, {
    issuer,
    audience: clientId,
  });
  assert.equal(payload.nonce, 'local-integration-nonce');
  assert.equal(payload.auth_time, now - 30);
  assert.equal(typeof payload.sub, 'string');
  assert.equal(typeof payload.sid, 'string');
  const issued = (await env.DB.prepare(
    'SELECT ti.id_token_hash FROM token_issue ti JOIN authorization_code ac ON ac.code_hash=ti.code_hash WHERE ac.client_id=? AND ac.sid=?',
  )
    .bind(clientId, payload.sid)
    .first()) as { id_token_hash: string } | null;
  assert.equal(
    issued?.id_token_hash,
    createHash('sha256').update(tokens.id_token).digest('base64url'),
  );

  const changedPolicy = {
    ...policy,
    policy_revision: createHash('sha256').update('local-second-policy').digest('hex'),
    authorization_code_ttl_seconds: 30,
  };
  delete changedPolicy.projection_revision;
  const canonical = Object.fromEntries(
    Object.entries(changedPolicy).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
  changedPolicy.projection_revision = createHash('sha256')
    .update(JSON.stringify(canonical), 'ascii')
    .digest('hex');
  await activateWorkerPolicy(env.DB, changedPolicy, {
    expectedRevision: policy.projection_revision,
    actor: 'local-integration-test',
    reason: 'shorter code lifetime',
  });
  await assert.rejects(
    activateWorkerPolicy(env.DB, policy, {
      expectedRevision: policy.projection_revision,
      actor: 'local-integration-test',
      reason: 'stale update',
    }),
  );
  await assert.rejects(
    activateWorkerPolicy(
      env.DB,
      { ...policy, authorization_code_ttl_seconds: 15 },
      {
        expectedRevision: changedPolicy.projection_revision,
        actor: 'local-integration-test',
        reason: 'invalid projection hash',
      },
    ),
    /hash mismatch/,
  );
  const activePolicy = await env.DB.prepare(
    'SELECT projection_revision,generation FROM runtime_policy_active WHERE id=1',
  ).first();
  assert.equal(activePolicy.projection_revision, changedPolicy.projection_revision);
  assert.equal(activePolicy.generation, 2);
  const policyAudits = await env.DB.prepare(
    'SELECT COUNT(*) AS total FROM runtime_policy_audit',
  ).first();
  assert.equal(policyAudits.total, 2);
  const nextPolicies = ['candidate-a', 'candidate-b'].map((label) => {
    const candidate = {
      ...changedPolicy,
      policy_revision: createHash('sha256').update(label).digest('hex'),
    };
    delete candidate.projection_revision;
    const ordered = Object.fromEntries(
      Object.entries(candidate).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
    );
    candidate.projection_revision = createHash('sha256')
      .update(JSON.stringify(ordered), 'ascii')
      .digest('hex');
    return candidate;
  });
  const competingUpdates = await Promise.allSettled(
    nextPolicies.map((candidate) =>
      activateWorkerPolicy(env.DB, candidate, {
        expectedRevision: changedPolicy.projection_revision,
        actor: 'local-integration-test',
        reason: 'competing update',
      }),
    ),
  );
  assert.equal(competingUpdates.filter((outcome) => outcome.status === 'fulfilled').length, 1);
  assert.equal(competingUpdates.filter((outcome) => outcome.status === 'rejected').length, 1);
  const activeAfterRace = await env.DB.prepare(
    'SELECT projection_revision,generation FROM runtime_policy_active WHERE id=1',
  ).first();
  assert.equal(activeAfterRace.generation, 3);
  assert.ok(
    nextPolicies.some(
      (candidate) => candidate.projection_revision === activeAfterRace.projection_revision,
    ),
  );
  const auditsAfterRace = await env.DB.prepare(
    'SELECT COUNT(*) AS total FROM runtime_policy_audit',
  ).first();
  assert.equal(auditsAfterRace.total, 3);
  await assert.rejects(
    env.DB.prepare(
      'UPDATE runtime_policy_version SET policy_revision=? WHERE projection_revision=?',
    )
      .bind(policy.policy_revision, activeAfterRace.projection_revision)
      .run(),
  );

  const userinfo = await worker.fetch(`${issuer}/userinfo`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  const userinfoBody = await userinfo.text();
  assert.equal(userinfo.status, 200, userinfoBody);
  assert.deepEqual(JSON.parse(userinfoBody), { sub: payload.sub });
  const replayAssertion = await makeClientAssertion(now);
  form.set('client_assertion', replayAssertion);
  const replay = await worker.fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  assert.equal(replay.status, 400);
  assert.equal(((await replay.json()) as { error: string }).error, 'invalid_grant');
  const revokedUserinfo = await worker.fetch(`${issuer}/userinfo`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  assert.equal(revokedUserinfo.status, 401);

  const concurrentVerifier = randomBytes(32).toString('base64url');
  const concurrentChallenge = createHash('sha256').update(concurrentVerifier).digest('base64url');
  const concurrentAuthorization = new URL('/authorize', issuer);
  concurrentAuthorization.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid',
    state: 'concurrent-integration-state',
    code_challenge: concurrentChallenge,
    code_challenge_method: 'S256',
  }).toString();
  const concurrentAuthorizationResponse = await worker.fetch(concurrentAuthorization, {
    headers: { cookie: `__Host-op-sso=${cookie}` },
    redirect: 'manual',
  });
  assert.equal(concurrentAuthorizationResponse.status, 302);
  const concurrentLocation = concurrentAuthorizationResponse.headers.get('location');
  assert.ok(concurrentLocation);
  const concurrentCode = new URL(concurrentLocation).searchParams.get('code');
  assert.ok(concurrentCode);
  const concurrentCodeHash = createHash('sha256')
    .update(Buffer.from(concurrentCode, 'base64url'))
    .digest('base64url');
  const storedCode = await env.DB.prepare(
    'SELECT expires_at FROM authorization_code WHERE code_hash=?',
  )
    .bind(concurrentCodeHash)
    .first();
  assert.ok(storedCode.expires_at - Math.floor(Date.now() / 1000) <= 30);
  assert.ok(storedCode.expires_at - Math.floor(Date.now() / 1000) >= 25);
  const concurrentBodies = await Promise.all(
    [1, 2].map(async () =>
      new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        code: concurrentCode,
        redirect_uri: redirectUri,
        code_verifier: concurrentVerifier,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: await makeClientAssertion(now),
      }).toString(),
    ),
  );
  const concurrentResponses = await Promise.all(
    concurrentBodies.map((body) =>
      worker.fetch(tokenEndpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body,
      }),
    ),
  );
  assert.equal(concurrentResponses.filter((response) => response.status === 200).length, 1);
  const concurrentLoser = concurrentResponses.find((response) => response.status !== 200);
  assert.ok(concurrentLoser);
  const concurrentLoserBody = await concurrentLoser.text();
  assert.equal(concurrentLoser.status, 400, concurrentLoserBody);
  assert.equal(JSON.parse(concurrentLoserBody).error, 'invalid_grant');
  const concurrentWinner = concurrentResponses.find((response) => response.status === 200);
  assert.ok(concurrentWinner);
  const concurrentTokens = (await concurrentWinner.json()) as { id_token: string };
  const { payload: concurrentPayload } = await jwtVerify(
    concurrentTokens.id_token,
    op.pair.publicKey,
    {
      issuer,
      audience: clientId,
    },
  );
  assert.equal(Object.hasOwn(concurrentPayload, 'nonce'), false);

  const logoutVerifier = randomBytes(32).toString('base64url');
  const logoutAuthorization = new URL('/authorize', issuer);
  logoutAuthorization.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid',
    state: 'logout-integration-state',
    code_challenge: createHash('sha256').update(logoutVerifier).digest('base64url'),
    code_challenge_method: 'S256',
  }).toString();
  const logoutAuthorizationResponse = await worker.fetch(logoutAuthorization, {
    headers: { cookie: `__Host-op-sso=${cookie}` },
    redirect: 'manual',
  });
  assert.equal(logoutAuthorizationResponse.status, 302);
  const logoutCode = new URL(logoutAuthorizationResponse.headers.get('location')!).searchParams.get(
    'code',
  );
  assert.ok(logoutCode);
  const logoutExchange = await worker.fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      code: logoutCode,
      redirect_uri: redirectUri,
      code_verifier: logoutVerifier,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: await makeClientAssertion(now),
    }).toString(),
  });
  assert.equal(logoutExchange.status, 200, await logoutExchange.clone().text());
  const logoutTokens = (await logoutExchange.json()) as { id_token: string };
  const { payload: logoutPayload } = await jwtVerify(logoutTokens.id_token, op.pair.publicKey, {
    issuer,
    audience: clientId,
  });
  assert.equal(
    (
      await env.DB.prepare(
        'SELECT COUNT(*) AS count FROM valid_client_session WHERE client_id=? AND sid=?',
      )
        .bind(clientId, logoutPayload.sid)
        .first()
    ).count,
    1,
  );

  const logoutUrl = new URL('/logout', issuer);
  logoutUrl.search = new URLSearchParams({
    id_token_hint: logoutTokens.id_token,
    post_logout_redirect_uri: 'https://rp.example/logout/callback',
    state: 'return-state',
  }).toString();
  const logoutGet = (url: URL, browserCookie = cookie) =>
    worker.fetch(url, { headers: { cookie: `__Host-op-sso=${browserCookie}` } });
  assert.equal(
    (await logoutGet(new URL(logoutUrl), randomBytes(32).toString('base64url'))).status,
    400,
  );
  const tampered = new URL(logoutUrl);
  tampered.searchParams.set('id_token_hint', `${logoutTokens.id_token}x`);
  assert.equal((await logoutGet(tampered)).status, 400);
  const wrongRedirect = new URL(logoutUrl);
  wrongRedirect.searchParams.set('post_logout_redirect_uri', 'https://rp.example/other');
  assert.equal((await logoutGet(wrongRedirect)).status, 400);
  const duplicate = new URL(logoutUrl);
  duplicate.searchParams.append('state', 'other');
  assert.equal((await logoutGet(duplicate)).status, 400);
  const noHint = new URL(logoutUrl);
  noHint.searchParams.delete('id_token_hint');
  assert.equal((await logoutGet(noHint)).status, 400);
  const noState = new URL(logoutUrl);
  noState.searchParams.delete('state');
  assert.equal((await logoutGet(noState)).status, 200);
  const noRedirect = new URL(logoutUrl);
  noRedirect.searchParams.delete('post_logout_redirect_uri');
  assert.equal((await logoutGet(noRedirect)).status, 200);
  const noParameters = new URL('/logout', issuer);
  assert.equal((await logoutGet(noParameters)).status, 200);
  const onlyState = new URL('/logout?state=local-state', issuer);
  assert.equal((await logoutGet(onlyState)).status, 200);
  const rpPost = await worker.fetch(`${issuer}/logout`, {
    method: 'POST',
    headers: {
      origin: 'https://rp.example',
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: logoutUrl.searchParams.toString(),
    redirect: 'manual',
  });
  assert.equal(rpPost.status, 303);
  assert.equal((await logoutGet(new URL(rpPost.headers.get('location')!))).status, 200);
  const invalidRpPost = await worker.fetch(`${issuer}/logout`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: `${logoutUrl.searchParams.toString()}&state=duplicate`,
    redirect: 'manual',
  });
  assert.equal(invalidRpPost.status, 400);
  const confirmation = await logoutGet(logoutUrl);
  const confirmationHtml = await confirmation.text();
  assert.equal(confirmation.status, 200, confirmationHtml);
  const csrf = confirmationHtml.match(/name="csrf" value="([A-Za-z0-9_-]{43})"/)?.[1];
  assert.ok(csrf);
  const logoutCookies = `__Host-op-sso=${cookie}; __Host-op-logout=${csrf}`;
  assert.equal(
    (
      await env.DB.prepare('SELECT COUNT(*) AS count FROM logout_transaction WHERE csrf_hash=?')
        .bind(createHash('sha256').update(csrf).digest('base64url'))
        .first()
    ).count,
    1,
  );
  const submit = (origin: string) =>
    worker.fetch(`${issuer}/logout`, {
      method: 'POST',
      headers: {
        origin,
        cookie: logoutCookies,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ csrf }).toString(),
      redirect: 'manual',
    });
  assert.equal((await submit('https://other.example')).status, 400);
  await env.DB.prepare(
    "CREATE TRIGGER fail_logout_delivery BEFORE INSERT ON logout_delivery BEGIN SELECT RAISE(ABORT, 'injected delivery failure'); END",
  ).run();
  assert.equal((await submit(issuer)).status, 400);
  assert.equal(
    (
      await env.DB.prepare('SELECT revoked FROM sso_session WHERE sso_id=?')
        .bind('oidc-test-sso')
        .first()
    ).revoked,
    0,
  );
  assert.equal(
    (await env.DB.prepare('SELECT COUNT(*) AS count FROM sso_logout_event').first()).count,
    0,
  );
  assert.equal(
    (
      await env.DB.prepare('SELECT COUNT(*) AS count FROM logout_transaction WHERE csrf_hash=?')
        .bind(createHash('sha256').update(csrf).digest('base64url'))
        .first()
    ).count,
    1,
  );
  await env.DB.prepare('DROP TRIGGER fail_logout_delivery').run();
  const submissions = await Promise.all([submit(issuer), submit(issuer)]);
  assert.deepEqual(submissions.map((response) => response.status).sort(), [302, 400]);
  const completed = submissions.find((response) => response.status === 302);
  assert.ok(completed);
  const completedUrl = new URL(completed.headers.get('location')!);
  assert.equal(completedUrl.origin + completedUrl.pathname, 'https://rp.example/logout/callback');
  assert.equal(completedUrl.searchParams.get('state'), 'return-state');
  assert.match(completed.headers.get('set-cookie') ?? '', /__Host-op-sso=; Max-Age=0/);
  assert.equal(
    (
      await env.DB.prepare('SELECT revoked FROM sso_session WHERE sso_id=?')
        .bind('oidc-test-sso')
        .first()
    ).revoked,
    1,
  );
  assert.equal(
    (
      await env.DB.prepare(
        'SELECT COUNT(*) AS count FROM client_session WHERE sso_id=? AND revoked=0',
      )
        .bind('oidc-test-sso')
        .first()
    ).count,
    0,
  );
  assert.equal(
    (
      await env.DB.prepare('SELECT COUNT(*) AS count FROM sso_logout_event WHERE sso_id=?')
        .bind('oidc-test-sso')
        .first()
    ).count,
    1,
  );
  const deliveries = (
    await env.DB.prepare(
      'SELECT client_id,sid,logout_uri,state,attempts FROM logout_delivery',
    ).all()
  ).results;
  const delivery = deliveries.find((row: { sid: string }) => row.sid === logoutPayload.sid);
  assert.ok(deliveries.length >= 1);
  assert.deepEqual(delivery, {
    client_id: clientId,
    sid: logoutPayload.sid,
    logout_uri: 'https://rp.example/backchannel',
    state: 'pending',
    attempts: 1,
  });
  await env.DB.prepare('UPDATE client_backchannel_logout_uri SET logout_uri=? WHERE client_id=?')
    .bind('https://rp.example/rotated-backchannel', clientId)
    .run();
  assert.equal(
    (await env.DB.prepare('SELECT logout_uri FROM logout_delivery').first()).logout_uri,
    'https://rp.example/backchannel',
  );
  assert.equal(
    (
      await env.DB.prepare(
        'SELECT COUNT(*) AS count FROM valid_client_session WHERE client_id=? AND sid=?',
      )
        .bind(clientId, logoutPayload.sid)
        .first()
    ).count,
    0,
  );
  assert.equal((await logoutGet(logoutUrl)).status, 400);

  console.log(
    'mikaki-worker: D1 policy activation, code exchange, UserInfo, replay revocation, concurrent exchange, and atomic logout outbox passed',
  );
} finally {
  await harness.close();
}
