import { webauthnDiagnostic } from './webauthn-errors.ts';
import { collect, retained } from './gc.ts';
import { deliver, logoutEvent } from './logout-delivery.ts';
import {
  initSync,
  register,
  authenticate,
  authorize,
  pkce,
  valid_json,
} from '../crates/browser-wasm/pkg/mikaki_browser_wasm.js';
import wasm from '../crates/browser-wasm/pkg/mikaki_browser_wasm_bg.wasm';
import exchangeSQL from '../design/sql/exchange-code.sql';
import acceptSQL from '../design/sql/accept-assertion.sql';
import {
  OP,
  RP,
  CLIENT,
  CALLBACK,
  ASSERTION_TYPE,
  p,
  now,
  uuid,
  random,
  b64,
  hash,
  check,
  fail,
  cookie,
  setCookie,
  json,
  redirect,
  response,
  query,
  row,
  guard,
  statements,
  body as readBody,
  sameOrigin,
  uniqueParams,
  localOnly,
  signed,
  verified,
  errors,
} from './shared.ts';

initSync({ module: wasm });
const body = (req, kind = 'json') => readBody(req, kind, valid_json);
const BROWSER = '__Host-op-browser',
  SSO = '__Host-op-sso';
const epochSQL = "CAST(strftime('%s','now') AS INTEGER)";

async function rate(db, bucket, limit) {
  const key = `${Math.floor(now() / p('rate_limit.window'))}:${bucket}`;
  const r = await row(
    db,
    'INSERT INTO rate_window VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1,gc_after=MAX(gc_after,excluded.gc_after) RETURNING count',
    [
      key,
      (Math.floor(now() / p('rate_limit.window')) + 1) * p('rate_limit.window') +
        p('retention.rate_key_ttl'),
    ],
  );
  check(r.count <= limit, 'rate_limited', 429);
}
async function login(db, req, id, csrf = undefined) {
  check(typeof id === 'string');
  const r = await row(
    db,
    `SELECT * FROM op_login WHERE id=? AND browser_hash=? AND consumed=0 AND expires_at>${epochSQL}`,
    [id, await hash(cookie(req, BROWSER))],
  );
  check(
    r && (req.method === 'GET' || (typeof csrf === 'string' && csrf === r.csrf)),
    'invalid_transaction',
  );
  return r;
}
async function sso(db, req) {
  return row(
    db,
    `SELECT s.*, x.auth_time FROM sso_context x JOIN sso_session s USING(sso_id)
    JOIN account_security a USING(account_id) JOIN credential c ON c.credential_id=s.credential_id AND c.account_id=s.account_id
    WHERE x.secret_hash=? AND s.revoked=0 AND a.active=1 AND a.epoch=s.epoch AND c.active=1 AND s.expires_at>${epochSQL}`,
    [await hash(cookie(req, SSO))],
  );
}
async function context(db, req, id) {
  const l = await login(db, req, id);
  const s = await sso(db, req);
  return json({ tx: l.id, csrf: l.csrf, client: 'Mikaki local RP', signed_in: !!s });
}
function transactionGuard(db, l) {
  return guard(
    db,
    `EXISTS(SELECT 1 FROM op_login WHERE id=? AND browser_hash=? AND consumed=0 AND expires_at>${epochSQL})`,
    [l.id, l.browser_hash],
  );
}

// Caller supplies authentication writes. This batch also rechecks live state at commit.
async function issueCode(
  db,
  l,
  session,
  prefix: unknown[] = [],
  newSecret: string | undefined = undefined,
) {
  const request = JSON.parse(l.request),
    code = random(),
    codeHash = await hash(code),
    sid = uuid();
  const commands = [
    ...prefix,
    ...transactionGuard(db, l),
    query(db, 'INSERT INTO subject VALUES(?,?,?) ON CONFLICT(account_id,sector) DO NOTHING', [
      session.account_id,
      new URL(CALLBACK).hostname,
      uuid(),
    ]),
    query(
      db,
      'INSERT INTO app_connection VALUES(?,?,1,1) ON CONFLICT(account_id,client_id) DO NOTHING',
      [session.account_id, CLIENT],
    ),
    query(
      db,
      `INSERT INTO client_session SELECT ?,?,?,s.account_id,sub.sub,g.grant_version,0 FROM sso_session s
      JOIN subject sub ON sub.account_id=s.account_id AND sub.sector=? JOIN app_connection g ON g.account_id=s.account_id AND g.client_id=?
      WHERE s.sso_id=? AND (SELECT COUNT(*) FROM client_session WHERE sso_id=s.sso_id AND client_id=? AND revoked=0)<?`,
      [
        CLIENT,
        sid,
        session.sso_id,
        new URL(CALLBACK).hostname,
        CLIENT,
        session.sso_id,
        CLIENT,
        p('limits.active_client_sessions_per_sso_client'),
      ],
    ),
    ...guard(db, `EXISTS(SELECT 1 FROM eligible_client_session WHERE client_id=? AND sid=?)`, [
      CLIENT,
      sid,
    ]),
    query(
      db,
      `INSERT INTO authorization_code SELECT ?,?,?,c.revision,?,?,MIN(?,v.expires_at),NULL,NULL FROM client c JOIN eligible_client_session v ON v.client_id=c.client_id WHERE c.client_id=? AND v.sid=?`,
      [
        codeHash,
        CLIENT,
        sid,
        CALLBACK,
        request.code_challenge,
        now() + p('oidc.authorization_code_ttl'),
        CLIENT,
        sid,
      ],
    ),
    query(db, 'INSERT INTO code_context VALUES(?,?)', [codeHash, request.nonce]),
    query(db, 'UPDATE op_login SET consumed=1 WHERE id=?', [l.id]),
    query(db, 'UPDATE sso_session SET gc_after=MAX(gc_after,?) WHERE sso_id=?', [
      retained(now() + p('retention.audit_ttl')),
      session.sso_id,
    ]),
  ];
  await db.batch(commands);
  const location = new URL(CALLBACK);
  location.searchParams.set('code', code);
  location.searchParams.set('state', request.state);
  location.searchParams.set('iss', OP);
  return {
    location: location.href,
    cookie: newSecret ? setCookie(SSO, newSecret, p('session.sso_absolute_ttl')) : null,
  };
}
async function beginAuthorization(db, req, url) {
  const params = uniqueParams(url.searchParams);
  check(
    authorize(
      JSON.stringify(params),
      CLIENT,
      CALLBACK,
      p('limits.state_bytes'),
      p('limits.nonce_bytes'),
    ),
  );
  let browser = cookie(req, BROWSER);
  if (!browser) browser = random();
  const browserHash = await hash(browser);
  await rate(db, `authorize:${browserHash}`, p('rate_limit.authorize_per_browser'));
  const pending = await row(
    db,
    `SELECT COUNT(*) AS n FROM op_login WHERE browser_hash=? AND consumed=0 AND expires_at>${epochSQL}`,
    [browserHash],
  );
  check(pending.n < p('limits.pending_login_per_browser'), 'too_many_transactions', 429);
  const l = {
    id: uuid(),
    browser_hash: browserHash,
    csrf: random(),
    request: JSON.stringify(params),
  };
  await query(
    db,
    'INSERT INTO op_login(id,browser_hash,csrf,request,expires_at,gc_after) VALUES(?,?,?,?,?,?)',
    [
      l.id,
      l.browser_hash,
      l.csrf,
      l.request,
      now() + p('oidc.login.transaction_ttl'),
      retained(now() + p('oidc.login.transaction_ttl')),
    ],
  ).run();
  const s = await sso(db, req);
  if (
    s &&
    (await row(db, 'SELECT 1 FROM app_connection WHERE account_id=? AND client_id=? AND active=1', [
      s.account_id,
      CLIENT,
    ]))
  ) {
    const result = await issueCode(db, l, s);
    return redirect(result.location);
  }
  return redirect(`${OP}/login?tx=${l.id}`, {
    'Set-Cookie': setCookie(BROWSER, browser, p('session.sso_absolute_ttl')),
  });
}
async function start(db, req) {
  sameOrigin(req, OP);
  const input = await body(req);
  const l = await login(db, req, input.tx, input.csrf);
  await rate(db, `start:${l.browser_hash}`, p('rate_limit.ceremony_start_per_browser'));
  check(['register', 'authenticate'].includes(input.purpose));
  let invitationHash: string | null = null,
    account: string | null = null;
  if (input.purpose === 'register') {
    check(typeof input.invitation === 'string' && /^[A-Za-z0-9_-]{43}$/.test(input.invitation));
    invitationHash = await hash(input.invitation);
    check(
      await row(
        db,
        `SELECT 1 FROM invitation i WHERE hash=? AND used_by IS NULL AND expires_at>${epochSQL} AND (kind='ordinary' OR EXISTS(SELECT 1 FROM bootstrap WHERE closed=0))`,
        [invitationHash],
      ),
      'invalid_invitation',
    );
    account = uuid();
  }
  const id = uuid(),
    challenge = random();
  await db.batch([
    ...transactionGuard(db, l),
    query(db, 'UPDATE ceremony SET consumed=1 WHERE login_id=? AND consumed=0', [l.id]),
    query(
      db,
      'INSERT INTO ceremony(id,login_id,purpose,challenge,account_id,invitation_hash,browser_hash,expires_at,gc_after) VALUES(?,?,?,?,?,?,?,?,?)',
      [
        id,
        l.id,
        input.purpose,
        challenge,
        account,
        invitationHash,
        l.browser_hash,
        now() + p('authentication.ceremony_ttl'),
        retained(now() + p('authentication.ceremony_ttl')),
      ],
    ),
  ]);
  const common = { challenge, timeout: p('authentication.ceremony_ttl') * 1000 };
  return json({
    ceremony: id,
    publicKey:
      input.purpose === 'register'
        ? {
            ...common,
            rp: { id: 'localhost', name: 'mikaki (local)' },
            user: {
              id: b64(new TextEncoder().encode(account ?? fail('invalid_account'))),
              name: account,
              displayName: 'mikaki account',
            },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            authenticatorSelection: {
              residentKey: 'required',
              requireResidentKey: true,
              userVerification: 'required',
            },
            attestation: 'none',
            extensions: { credProps: true },
          }
        : { ...common, rpId: 'localhost', userVerification: 'required' },
  });
}
async function finish(db, req) {
  sameOrigin(req, OP);
  const input = await body(req);
  const l = await login(db, req, input.tx, input.csrf);
  check(input.consent === true, 'consent_required');
  await rate(db, `finish:${l.browser_hash}`, p('rate_limit.ceremony_finish_per_browser'));
  const c = await row(db, 'SELECT * FROM ceremony WHERE id=? AND login_id=?', [
    input.ceremony,
    l.id,
  ]);
  check(c);
  const ceremony = {
    ...c,
    consumed: !!c.consumed,
    context: {
      challenge: c.challenge,
      origin: OP,
      rp_id: 'localhost',
      max_bytes: p('limits.webauthn_body_bytes'),
      max_depth: p('limits.webauthn_depth'),
    },
  };
  const args = JSON.stringify({
    ceremony,
    browser_hash: l.browser_hash,
    now: now(),
    max_failures: p('authentication.ceremony_max_failures'),
    response: input.response,
  });
  let proof,
    credential,
    account = c.account_id;
  try {
    if (c.purpose === 'register') proof = JSON.parse(register(args));
    else {
      credential = await row(
        db,
        'SELECT cr.account_id,d.*,a.epoch FROM credential cr JOIN credential_data d USING(credential_id) JOIN account_security a USING(account_id) WHERE cr.credential_id=? AND cr.active=1 AND a.active=1',
        [input.response.id],
      );
      check(credential, 'invalid_credential');
      account = credential.account_id;
      proof = JSON.parse(
        authenticate(
          args,
          JSON.stringify({
            ...credential,
            id: credential.credential_id,
            backup_eligible: !!credential.backup_eligible,
          }),
        ),
      );
    }
  } catch (error) {
    console.warn(
      JSON.stringify({
        event: 'webauthn_rejected',
        correlation: uuid(),
        ...webauthnDiagnostic(error),
      }),
    );
    await query(db, 'UPDATE ceremony SET failures=failures+1 WHERE id=? AND consumed=0', [
      c.id,
    ]).run();
    fail('invalid_credential');
  }
  const ssoId = uuid(),
    secret = random(),
    secretHash = await hash(secret);
  const commands = [
    ...transactionGuard(db, l),
    query(
      db,
      `UPDATE ceremony SET consumed=1 WHERE id=? AND browser_hash=? AND consumed=0 AND failures<? AND expires_at>${epochSQL}`,
      [c.id, l.browser_hash, p('authentication.ceremony_max_failures')],
    ),
    ...guard(db, 'changes()=1'),
  ];
  if (c.purpose === 'register') {
    const invitation = await row(db, 'SELECT kind FROM invitation WHERE hash=?', [
      c.invitation_hash,
    ]);
    check(invitation);
    commands.push(
      query(
        db,
        `UPDATE invitation SET used_by=? WHERE hash=? AND used_by IS NULL AND expires_at>${epochSQL}`,
        [account, c.invitation_hash],
      ),
      ...guard(db, 'changes()=1'),
    );
    if (invitation.kind === 'bootstrap')
      commands.push(
        query(db, 'UPDATE bootstrap SET closed=1 WHERE singleton=1 AND closed=0'),
        ...guard(db, 'changes()=1'),
      );
    commands.push(
      query(db, 'INSERT INTO account_security VALUES(?,0,1)', [account]),
      query(db, 'INSERT INTO credential VALUES(?,?,1)', [proof.id, account]),
      query(db, 'INSERT INTO credential_data VALUES(?,?,?,?,?,?,0)', [
        proof.id,
        proof.public_key,
        b64(new TextEncoder().encode(account)),
        proof.counter,
        +proof.backup_eligible,
        +proof.backup_state,
      ]),
    );
    if (invitation.kind === 'bootstrap')
      commands.push(query(db, "INSERT INTO account_role VALUES(?,'admin')", [account]));
  } else {
    commands.push(
      query(
        db,
        `UPDATE credential_data SET counter=?,backup_state=?,revision=revision+1 WHERE credential_id=? AND revision=?
      AND EXISTS(SELECT 1 FROM credential c JOIN account_security a USING(account_id) WHERE c.credential_id=? AND c.active=1 AND a.active=1 AND a.epoch=?)`,
        [
          proof.counter,
          +proof.backup_state,
          credential.credential_id,
          credential.revision,
          credential.credential_id,
          credential.epoch,
        ],
      ),
      ...guard(db, 'changes()=1'),
    );
  }
  const credId = c.purpose === 'register' ? proof.id : credential.credential_id;
  commands.push(
    query(
      db,
      `INSERT INTO sso_session(sso_id,account_id,credential_id,epoch,expires_at,revoked) SELECT ?,a.account_id,?,a.epoch,?,0 FROM account_security a WHERE a.account_id=? AND a.active=1 AND (SELECT COUNT(*) FROM sso_session WHERE account_id=a.account_id AND epoch=a.epoch AND revoked=0 AND expires_at>${epochSQL})<?`,
      [
        ssoId,
        credId,
        now() + p('session.sso_absolute_ttl'),
        account,
        p('limits.active_sso_per_account'),
      ],
    ),
    ...guard(db, 'changes()=1'),
    query(db, 'INSERT INTO sso_context VALUES(?,?,?)', [ssoId, secretHash, now()]),
    query(db, 'UPDATE sso_session SET gc_after=MAX(expires_at+?,?) WHERE sso_id=?', [
      retained(0),
      retained(now() + p('retention.audit_ttl')),
      ssoId,
    ]),
  );
  const result = await issueCode(db, l, { account_id: account, sso_id: ssoId }, commands, secret);
  return json({ location: result.location }, 200, { 'Set-Cookie': result.cookie });
}
async function acceptClient(db, env, req, input) {
  check(
    input.client_id === CLIENT && input.client_assertion_type === ASSERTION_TYPE,
    'invalid_client',
    401,
  );
  const endpoint = new URL(req.url).origin + new URL(req.url).pathname;
  const claims = await verified(env, 'rp', input.client_assertion, endpoint);
  check(
    claims.sub === CLIENT &&
      typeof claims.jti === 'string' &&
      claims.jti.length > 0 &&
      claims.jti.length <= p('limits.jti_bytes') &&
      typeof claims.exp === 'number' &&
      typeof claims.iat === 'number' &&
      claims.exp - claims.iat <= p('oidc.client_authentication.assertion_ttl'),
    'invalid_client',
    401,
  );
  const params = {
    client_id: CLIENT,
    client_kid: JSON.parse(env.RP_PUBLIC_JWK).kid,
    client_key_revision: 1,
    jti: claims.jti,
    endpoint,
    assertion_operation_id: uuid(),
    retain_until: claims.exp + p('oidc.validation.clock_skew'),
  };
  await db.batch([
    ...statements(db, acceptSQL, params),
    query(db, 'UPDATE assertion_use SET gc_after=? WHERE accepted_by=?', [
      retained(params.retain_until),
      params.assertion_operation_id,
    ]),
  ]);
  return params;
}
async function token(db, env, req) {
  const input = await body(req, 'form'),
    auth = await acceptClient(db, env, req, input);
  await rate(db, `token:${CLIENT}`, p('rate_limit.token_per_authenticated_client'));
  check(input.grant_type === 'authorization_code', 'unsupported_grant_type');
  check(
    typeof input.code === 'string' && input.code.length === 43 && input.redirect_uri === CALLBACK,
    'invalid_grant',
  );
  const codeHash = await hash(input.code),
    challenge = pkce(input.code_verifier ?? '');
  const code = await row(
    db,
    `SELECT ac.*,v.sub,v.expires_at AS parent_expiry,x.auth_time,cc.nonce FROM authorization_code ac
    JOIN eligible_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid JOIN client_session cs ON cs.client_id=ac.client_id AND cs.sid=ac.sid
    JOIN sso_context x ON x.sso_id=cs.sso_id JOIN code_context cc USING(code_hash) WHERE ac.code_hash=? AND ac.client_id=? AND ac.redirect_uri=? AND ac.pkce_challenge=?`,
    [codeHash, CLIENT, input.redirect_uri, challenge],
  );
  check(code, 'invalid_grant');
  if (code.consumed_by) {
    await query(db, 'UPDATE token_issue SET revoked=1 WHERE code_hash=?', [codeHash]).run();
    fail('invalid_grant');
  }
  const t = now(),
    access = random(),
    accessExpiry = Math.min(t + p('oidc.access_token.ttl'), code.parent_expiry);
  const idToken = await signed(
    env,
    'op',
    { sub: code.sub, nonce: code.nonce, sid: code.sid, auth_time: code.auth_time },
    CLIENT,
    Math.min(p('oidc.id_token_ttl'), code.parent_expiry - t),
  );
  await db.batch([
    ...statements(db, exchangeSQL, {
      ...auth,
      operation_id: uuid(),
      code_hash: codeHash,
      redirect_uri: input.redirect_uri,
      pkce_challenge: challenge,
      signing_kid: JSON.parse(env.OP_PUBLIC_JWK).kid,
      signing_generation: 1,
      access_hash: await hash(access),
      access_expires_at: accessExpiry,
    }),
    query(
      db,
      `UPDATE sso_session SET gc_after=MAX(gc_after,?) WHERE sso_id=(SELECT cs.sso_id FROM client_session cs JOIN authorization_code ac ON ac.client_id=cs.client_id AND ac.sid=cs.sid WHERE ac.code_hash=?)`,
      [retained(now() + p('retention.audit_ttl')), codeHash],
    ),
  ]);
  return json({
    token_type: 'Bearer',
    access_token: access,
    expires_in: accessExpiry - t,
    id_token: idToken,
  });
}
async function sessionCheck(db, env, req) {
  const input = await body(req, 'form');
  await acceptClient(db, env, req, input);
  await rate(db, `check:${CLIENT}`, p('rate_limit.session_check_per_authenticated_client'));
  // A fresh session: this single join is its FIRST read, so revocation is not read from a replica.
  const active = await row(
    env.DB.withSession('first-primary'),
    `SELECT v.sub,v.expires_at,x.auth_time FROM valid_client_session v JOIN client_session cs ON cs.client_id=v.client_id AND cs.sid=v.sid JOIN sso_context x ON x.sso_id=cs.sso_id WHERE v.client_id=? AND v.sid=?`,
    [CLIENT, input.sid ?? ''],
  );
  return json(
    active
      ? {
          active: true,
          sid: input.sid,
          ...active,
          lease_ttl: p('session.validation.lease_ttl'),
          app_idle_timeout: p('session.app_idle_timeout'),
          policy_revision: p('policy_revision'),
        }
      : { active: false },
  );
}
async function userInfo(db, req) {
  const bearer = req.headers.get('authorization');
  check(bearer?.startsWith('Bearer '), 'invalid_token', 401);
  const result = await row(
    db,
    `SELECT v.sub FROM token_issue ti JOIN authorization_code ac USING(code_hash) JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid WHERE ti.access_hash=? AND ti.revoked=0 AND ti.access_expires_at>${epochSQL}`,
    [await hash(bearer.slice(7))],
  );
  check(result, 'invalid_token', 401);
  return json(result);
}
async function logout(db, env, req, url, ctx) {
  if (req.method === 'GET') {
    const input = uniqueParams(url.searchParams);
    check(
      input.post_logout_redirect_uri === `${RP}/logout/callback` &&
        typeof input.state === 'string' &&
        input.state.length <= p('limits.state_bytes'),
    );
    const claims = await verified(env, 'op', input.id_token_hint, CLIENT, 'JWT', true);
    const s = await sso(db, req);
    check(
      s &&
        (await row(
          db,
          'SELECT 1 FROM client_session WHERE client_id=? AND sid=? AND sub=? AND sso_id=?',
          [CLIENT, claims.sid, claims.sub, s.sso_id],
        )),
      'invalid_logout',
    );
    const csrf = random(); // Bind confirmation to cookie and fixed registered return URI.
    await query(db, 'INSERT INTO logout_transaction VALUES(?,?,?,?,?,?)', [
      await hash(csrf),
      await hash(cookie(req, BROWSER)),
      s.sso_id,
      input.state,
      now() + p('oidc.login.transaction_ttl'),
      retained(now() + p('oidc.login.transaction_ttl')),
    ]).run();
    return response(
      `<!doctype html><meta charset="utf-8"><title>mikaki logout</title><h1>ログアウト / Sign out</h1><form method="post" action="/logout"><input type="hidden" name="csrf" value="${csrf}"><button>ログアウト / Sign out</button></form>`,
      200,
      {
        'Content-Type': 'text/html; charset=utf-8',
        'Referrer-Policy': 'same-origin',
        'Set-Cookie': setCookie('__Host-op-logout', csrf, p('oidc.login.transaction_ttl')),
      },
    );
  }
  sameOrigin(req, OP);
  const input = await body(req, 'form');
  check(input.csrf && input.csrf === cookie(req, '__Host-op-logout'), 'invalid_csrf', 403);
  const s = await sso(db, req);
  check(s, 'invalid_session', 401);
  const tx = await row(
    db,
    `SELECT * FROM logout_transaction WHERE csrf_hash=? AND browser_hash=? AND sso_id=? AND expires_at>${epochSQL}`,
    [await hash(input.csrf), await hash(cookie(req, BROWSER)), s.sso_id],
  );
  check(tx, 'invalid_transaction');
  await db.batch([
    query(db, `DELETE FROM logout_transaction WHERE csrf_hash=? AND expires_at>${epochSQL}`, [
      tx.csrf_hash,
    ]),
    ...guard(db, 'changes()=1'),
    logoutEvent(db, s.sso_id),
    query(db, 'UPDATE sso_session SET revoked=1 WHERE sso_id=?', [s.sso_id]),
    query(db, 'UPDATE client_session SET revoked=1 WHERE sso_id=?', [s.sso_id]),
  ]);
  ctx.waitUntil(deliver(env.DB.withSession('first-primary'), env));
  return redirect(`${RP}/logout/callback?state=${encodeURIComponent(tx.state)}`, {
    'Set-Cookie': setCookie(SSO, '', 0),
  });
}

export default {
  async fetch(req, env, ctx) {
    try {
      localOnly(req, env, OP);
      const url = new URL(req.url);
      const db = env.DB.withSession('first-primary');
      if (url.pathname === '/.well-known/openid-configuration' && req.method === 'GET')
        return json({
          issuer: OP,
          authorization_endpoint: `${OP}/authorize`,
          token_endpoint: `${OP}/token`,
          jwks_uri: `${OP}/jwks`,
          userinfo_endpoint: `${OP}/userinfo`,
          end_session_endpoint: `${OP}/logout`,
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code'],
          subject_types_supported: ['pairwise'],
          id_token_signing_alg_values_supported: ['ES256'],
          token_endpoint_auth_methods_supported: ['private_key_jwt'],
          token_endpoint_auth_signing_alg_values_supported: ['ES256'],
          code_challenge_methods_supported: ['S256'],
          scopes_supported: ['openid'],
          backchannel_logout_supported: true,
          backchannel_logout_session_supported: true,
          authorization_response_iss_parameter_supported: true,
        });
      if (url.pathname === '/jwks' && req.method === 'GET')
        return json({ keys: [JSON.parse(env.OP_PUBLIC_JWK)] });
      if (url.pathname === '/authorize' && req.method === 'GET')
        return await beginAuthorization(db, req, url);
      if (url.pathname === '/login/context' && req.method === 'GET')
        return await context(db, req, url.searchParams.get('tx'));
      if (url.pathname === '/ceremony/start' && req.method === 'POST') return await start(db, req);
      if (url.pathname === '/ceremony/finish' && req.method === 'POST')
        return await finish(db, req);
      if (url.pathname === '/consent' && req.method === 'POST') {
        sameOrigin(req, OP);
        const input = await body(req);
        check(input.consent === true);
        const l = await login(db, req, input.tx, input.csrf),
          s = await sso(db, req);
        check(s);
        const result = await issueCode(db, l, s);
        return json({ location: result.location });
      }
      if (url.pathname === '/token' && req.method === 'POST') return await token(db, env, req);
      if (url.pathname === '/session/check' && req.method === 'POST')
        return await sessionCheck(db, env, req);
      if (url.pathname === '/userinfo' && ['GET', 'POST'].includes(req.method))
        return await userInfo(db, req);
      if (url.pathname === '/logout' && ['GET', 'POST'].includes(req.method))
        return await logout(db, env, req, url, ctx);
      if (
        req.method === 'GET' &&
        (url.pathname === '/login' || url.pathname.startsWith('/assets/'))
      ) {
        const assetUrl = new URL(req.url);
        if (url.pathname === '/login') assetUrl.pathname = '/';
        const asset = await env.ASSETS.fetch(new Request(assetUrl, req));
        return response(asset.body, asset.status, {
          'Content-Type': asset.headers.get('content-type') ?? 'text/html',
        });
      }
      return json({ error: 'not_found' }, 404);
    } catch (error) {
      return errors(error);
    }
  },
  async scheduled(controller, env) {
    const db = env.DB.withSession('first-primary');
    if (controller.cron === '0 * * * *') await collect(db, 'op');
    else await deliver(db, env);
  },
};
