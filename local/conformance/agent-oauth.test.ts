import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { auth, type OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type { OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { agentKeyId, sealAgentSnapshot } from '../../crates/worker/ui/agent-crypto.ts';
import { sealAttribute } from '../../crates/worker/ui/vault-crypto.ts';
import { newOwnerNote } from '../../crates/worker/ui/vault-note.ts';
import { registration } from '../../crates/agent-worker/oauth-client.ts';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

const origin = 'https://agent.mikaki.test',
  resource = `${origin}/mcp`;
const callback = 'http://127.0.0.1:43123/callback';
const id = () => randomBytes(32).toString('base64url');
const hash = (v: string) => createHash('sha256').update(v).digest('base64url');

test('public-client registration requires exact HTTPS or IP loopback callbacks', () => {
  const input = {
    client_id: 'native-test',
    client_name: 'Native client',
    redirect_uris: [callback, 'https://client.test/callback'],
  };
  assert.deepEqual(registration(input), input);
  for (const uri of [
    'http://client.test/callback',
    'http://localhost:43123/callback',
    'https://client.test/callback#fragment',
    'https://user:password@client.test/callback',
    'https://client.test/callback?code=x',
    'https://client.test/callback?state=x',
    'https://client.test/callback?iss=x',
    'https://client.test/callback?error=x',
    'https://client.test',
  ])
    assert.throws(() => registration({ ...input, redirect_uris: [uri] }));
  assert.throws(() => registration({ ...input, redirect_uris: [callback, callback] }));
  assert.throws(() => registration({ ...input, token_endpoint_auth_method: 'client_secret_post' }));
});

test('public OAuth PKCE discovery, owner consent, SDK MCP, token isolation, rollback and browser review in workerd', async () => {
  const keys = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey),
    keyId = await agentKeyId(publicJwk);
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.agent-local.jsonc', import.meta.url)
          .pathname,
      },
      {
        configPath: new URL('../../crates/agent-worker/wrangler.local.jsonc', import.meta.url)
          .pathname,
        secrets: {
          AGENT_PRIVATE_JWK: JSON.stringify(await crypto.subtle.exportKey('jwk', keys.privateKey)),
        },
      },
    ],
  });
  let browser;
  const clients: Client[] = [];
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-agent-local'),
      agent = harness.getWorker('mikaki-agent-local');
    await op.applyD1Migrations('DB');
    const env = await op.getEnv(),
      time = Math.floor(Date.now() / 1000),
      cookie = id(),
      other = id();
    await activateWorkerPolicy(
      env.DB,
      JSON.parse(
        await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'test', reason: 'agent owner login' },
    );
    const credential = new TextEncoder().encode('oauth-owner-credential'),
      credentialId = Buffer.from(credential).toString('base64url');
    for (const [account, secret, cred] of [
      ['owner', cookie, credentialId],
      ['other', other, 'other-credential'],
    ]) {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(account),
        env.DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(cred, account),
        env.DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,?,0)').bind(
          `${account}-session`,
          account,
          cred,
          time + 3600,
        ),
        env.DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(
          `${account}-session`,
          hash(secret),
          time,
        ),
      ]);
    }
    const passkey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = passkey.publicKey.export({ format: 'jwk' });
    const cose = Buffer.concat([
      Buffer.from([0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20]),
      Buffer.from(jwk.x!, 'base64url'),
      Buffer.from([0x22, 0x58, 0x20]),
      Buffer.from(jwk.y!, 'base64url'),
    ]);
    const userHandle = randomBytes(32);
    await env.DB.prepare('INSERT INTO passkey_credential VALUES(?,?,?,0,0,0,1)')
      .bind(credentialId, cose.toString('base64url'), userHandle.toString('base64url'))
      .run();
    const expiredCookie = id();
    await env.DB.batch([
      env.DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,?,0)').bind(
        'expired-owner-session',
        'owner',
        credentialId,
        time - 1,
      ),
      env.DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(
        'expired-owner-session',
        hash(expiredCookie),
        time - 100,
      ),
    ]);
    await env.DB.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')").bind(keyId).run();
    for (const client of ['native-test', 'other-client', 'retire-test'])
      await env.DB.prepare('INSERT INTO agent_oauth_client VALUES(?,?,?,1)')
        .bind(client, client, JSON.stringify([callback]))
        .run();
    const ownerHeaders = {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: 'https://mikaki.test',
      'Content-Type': 'application/json',
    };
    const ownerCall = (
      path: string,
      body: unknown,
      secret = cookie,
      requestOrigin = 'https://mikaki.test',
    ) =>
      op.fetch(`https://mikaki.test/vault/agents/${path}`, {
        method: 'POST',
        headers: { ...ownerHeaders, Cookie: `__Host-op-sso=${secret}`, Origin: requestOrigin },
        body: JSON.stringify(body),
      });
    const sealed = await sealAttribute(
      new TextEncoder().encode('OAuth owner'),
      new Uint8Array(32).fill(0x35),
      credential,
      new Uint8Array(32).fill(0x57),
      'https://mikaki.test',
      'name',
      1,
    );
    assert.equal(
      (
        await op.fetch('https://mikaki.test/vault/attributes/name', {
          method: 'PUT',
          headers: { ...ownerHeaders, 'If-None-Match': '*', 'X-Operation-ID': id() },
          body: JSON.stringify(sealed),
        })
      ).status,
      200,
    );
    const createGrant = async (
      operations = ['list', 'search', 'read', 'propose', 'execute'],
      ttl = 3600,
    ) => {
      const grant_id = id(),
        token = `mag_${id()}`,
        expires_at = time + ttl;
      const envelope = await sealAgentSnapshot(
        [{ id: 'name', title: 'Name', source: 'vault:name:1', text: 'OAuth owner' }],
        { key_id: keyId, public_jwk: publicJwk, resource },
        { owner: 'owner', grant_id, key_id: keyId, resource, expires_at, source_revision: 1 },
      );
      const response = await ownerCall('grants', {
        grant_id,
        delegate: 'native-test',
        provider: 'Test provider',
        resource,
        source_revision: 1,
        recipient_key_id: keyId,
        operations,
        document_ids: ['name'],
        envelope,
        token_hash: hash(token),
        expires_at,
      });
      assert.equal(response.status, 200, await response.text());
      return { grant_id, token, expires_at };
    };
    const grant = await createGrant(),
      narrow = await createGrant(['list', 'read']);
    const challenge = await agent.fetch(resource);
    assert.equal(challenge.status, 401);
    assert.match(
      challenge.headers.get('WWW-Authenticate')!,
      /resource_metadata=.*scope="list search read"/,
    );
    const prm = await agent.fetch(`${origin}/.well-known/oauth-protected-resource/mcp`);
    assert.deepEqual(
      ((await prm.json()) as { authorization_servers: string[] }).authorization_servers,
      [origin],
    );
    const as = await agent.fetch(`${origin}/.well-known/oauth-authorization-server`);
    const metadata = (await as.json()) as {
      issuer: string;
      code_challenge_methods_supported: string[];
      registration_endpoint?: string;
      authorization_response_iss_parameter_supported: boolean;
      authorization_details_types_supported: string[];
    };
    assert.equal(metadata.issuer, origin);
    assert.deepEqual(metadata.code_challenge_methods_supported, ['S256']);
    assert.equal(metadata.registration_endpoint, undefined);
    assert.equal(metadata.authorization_response_iss_parameter_supported, true);
    assert.deepEqual(metadata.authorization_details_types_supported, ['mikaki_agent_snapshot']);
    assert.equal((await agent.fetch(`${origin}/oauth/register`, { method: 'POST' })).status, 404);
    assert.equal(
      (
        await agent.fetch(`${origin}/oauth-decide`, {
          method: 'POST',
          headers: { 'X-Mikaki-Account': 'owner' },
        })
      ).status,
      404,
    );
    const begin = async (changes: Record<string, string> = {}, extra = '') => {
      const verifier = id(),
        state = id(),
        query = new URLSearchParams({
          response_type: 'code',
          client_id: 'native-test',
          redirect_uri: callback,
          resource,
          scope: 'list read',
          state,
          code_challenge: hash(verifier),
          code_challenge_method: 'S256',
          ...changes,
        });
      const response = await agent.fetch(`${origin}/oauth/authorize?${query}${extra}`, {
        redirect: 'manual',
      });
      if (response.status !== 302)
        return { response, verifier, state, request_id: '', location: '' };
      const location = response.headers.get('Location')!;
      const dest = new URL(location);
      assert.equal(dest.origin, 'https://mikaki.test');
      assert.equal(dest.pathname, '/vault');
      return {
        response,
        verifier,
        state,
        request_id: dest.searchParams.get('agent_oauth_request')!,
        location,
      };
    };
    const invalidAuthorizations: Record<string, string>[] = [
      { client_id: 'unknown' },
      { redirect_uri: 'https://evil.test/callback' },
      { redirect_uri: callback + '?extra=1' },
      { resource: 'https://other.test/mcp' },
      { code_challenge_method: 'plain' },
      { scope: 'read read' },
      { scope: 'admin' },
      { response_type: 'token' },
    ];
    for (const changes of invalidAuthorizations)
      assert.equal((await begin(changes)).response.status, 400);
    assert.equal((await begin({}, '&client_id=other-client')).response.status, 400);
    const preview = async (r: Awaited<ReturnType<typeof begin>>, secret = cookie) =>
      ownerCall('oauth-request', { request_id: r.request_id }, secret);
    const consent = async (
      r: Awaited<ReturnType<typeof begin>>,
      selected = grant.grant_id,
      approve = true,
      secret = cookie,
    ) =>
      ownerCall(
        'oauth-decide',
        { request_id: r.request_id, grant_id: approve ? selected : null, approve },
        secret,
      );
    const approved = async (r: Awaited<ReturnType<typeof begin>>, selected = grant.grant_id) => {
      assert.equal((await preview(r)).status, 200);
      const response = await consent(r, selected);
      assert.equal(response.status, 200, await response.clone().text());
      const dest = new URL(((await response.json()) as { redirect: string }).redirect);
      assert.equal(dest.origin, new URL(callback).origin);
      assert.equal(dest.searchParams.get('state'), r.state);
      assert.equal(dest.searchParams.get('iss'), origin);
      return dest.searchParams.get('code')!;
    };
    const exchange = (
      r: Awaited<ReturnType<typeof begin>>,
      code: string,
      changes: Record<string, string> = {},
    ) =>
      agent.fetch(`${origin}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: 'native-test',
          redirect_uri: callback,
          resource,
          code_verifier: r.verifier,
          ...changes,
        }).toString(),
      });
    const detail = {
      type: 'mikaki_agent_snapshot',
      locations: [resource],
      actions: ['list', 'read'],
      document_id: 'name',
      source_revision: 1,
      purpose: 'Read the selected current name snapshot',
    };
    for (const changed of [
      { ...detail, type: 'unknown' },
      { ...detail, locations: ['https://other.test/mcp'] },
      { ...detail, actions: ['execute'] },
      { ...detail, unexpected: true },
    ]) {
      const invalid = await begin({ authorization_details: JSON.stringify([changed]) });
      assert.equal(invalid.response.status, 400);
      assert.equal(
        ((await invalid.response.json()) as { error: string }).error,
        'invalid_authorization_details',
      );
    }
    const rejected = await begin();
    assert.equal((await preview(rejected)).status, 200);
    const denied = await consent(rejected, grant.grant_id, false);
    assert.equal(denied.status, 200);
    const denial = new URL(((await denied.json()) as { redirect: string }).redirect);
    assert.equal(denial.searchParams.get('error'), 'access_denied');
    assert.equal(denial.searchParams.get('code'), null);
    assert.equal((await consent(rejected)).status, 409);
    const r = await begin();
    assert.equal(
      (
        await op.fetch('https://mikaki.test/vault/agents/oauth-request', {
          method: 'POST',
          headers: { Origin: 'https://mikaki.test', 'Content-Type': 'application/json' },
          body: JSON.stringify({ request_id: r.request_id }),
        })
      ).status,
      401,
    );
    assert.equal(
      (await ownerCall('oauth-request', { request_id: r.request_id }, cookie, 'https://evil.test'))
        .status,
      403,
    );
    assert.equal((await preview(r)).status, 200);
    assert.equal((await preview(r, other)).status, 409);
    assert.equal((await consent(r, grant.grant_id, true, other)).status, 409);
    const needsExecute = await begin({ scope: 'execute' });
    assert.equal((await preview(needsExecute)).status, 200);
    assert.equal((await consent(needsExecute, narrow.grant_id)).status, 409);
    await env.DB.prepare(
      "CREATE TRIGGER fail_oauth_consent BEFORE INSERT ON agent_audit WHEN NEW.operation='oauth-consent' BEGIN SELECT RAISE(ABORT,'audit failure'); END",
    ).run();
    assert.equal((await consent(r)).status, 409);
    assert.equal(
      (
        await env.DB.prepare('SELECT decision FROM agent_oauth_request WHERE request_id=?')
          .bind(r.request_id)
          .first()
      ).decision,
      null,
    );
    await env.DB.prepare('DROP TRIGGER fail_oauth_consent').run();
    const code = await approved(r);
    assert.equal((await consent(r)).status, 409);
    const invalidExchanges: Record<string, string>[] = [
      { code_verifier: id() },
      { client_id: 'other-client' },
      { redirect_uri: callback + '/wrong' },
      { resource: 'https://other.test/mcp' },
    ];
    for (const changed of invalidExchanges)
      assert.equal((await exchange(r, code, changed)).status, 400);
    await env.DB.prepare(
      "CREATE TRIGGER fail_oauth_token BEFORE INSERT ON agent_audit WHEN NEW.operation='oauth-token' BEGIN SELECT RAISE(ABORT,'audit failure'); END",
    ).run();
    assert.equal((await exchange(r, code)).status, 400);
    assert.equal(
      (
        await env.DB.prepare('SELECT redeemed_at FROM agent_oauth_request WHERE request_id=?')
          .bind(r.request_id)
          .first()
      ).redeemed_at,
      null,
    );
    assert.equal((await env.DB.prepare('SELECT count(*) n FROM agent_oauth_token').first()).n, 0);
    await env.DB.prepare('DROP TRIGGER fail_oauth_token').run();
    const responses = await Promise.all([exchange(r, code), exchange(r, code)]);
    assert.deepEqual(responses.map((v) => v.status).sort(), [200, 400]);
    const issued = (await responses.find((v) => v.status === 200)!.json()) as OAuthTokens;
    assert.equal(issued.scope, 'list read');
    assert.match(issued.access_token, /^moa_[A-Za-z0-9_-]{43}$/);
    assert.equal(issued.refresh_token, undefined);
    assert.ok(issued.expires_in! <= 3600);
    assert.equal((await exchange(r, code)).status, 400);
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT count(*) n FROM agent_audit WHERE grant_id=? AND operation='oauth-consent'",
        )
          .bind(grant.grant_id)
          .first()
      ).n,
      1,
    );
    const fetchFn: typeof fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init);
      assert.equal(new URL(req.url).origin, origin);
      const response = await agent.fetch(req.url, {
        method: req.method,
        headers: Object.fromEntries(req.headers),
        ...(req.method === 'GET' || req.method === 'HEAD' ? {} : { body: await req.text() }),
      });
      return new Response(await response.arrayBuffer(), {
        status: response.status,
        headers: Object.fromEntries(response.headers),
      });
    };
    const connect = async (token: string) => {
      const client = new Client({ name: 'oauth-qualification', version: '1' });
      clients.push(client);
      await client.connect(
        new StreamableHTTPClientTransport(new URL(resource), {
          fetch: fetchFn,
          requestInit: { headers: { Authorization: `Bearer ${token}` } },
        }),
      );
      return client;
    };
    const mcp = await connect(issued.access_token);
    assert.equal((await mcp.listTools()).tools.length, 6);
    const read = await mcp.callTool({ name: 'mikaki_read', arguments: { id: 'name' } });
    assert.ok(!read.isError);
    assert.match(JSON.stringify(read), /OAuth owner/);
    const disallowed = await mcp.callTool({
      name: 'mikaki_propose',
      arguments: { proposal_id: id(), document_id: 'name', title: 'No', text: 'No write scope' },
    });
    assert.equal(disallowed.isError, true);
    assert.equal((await env.DB.prepare('SELECT count(*) n FROM agent_proposal').first()).n, 0);
    const disallowedAttribute = await mcp.callTool({
      name: 'mikaki_propose_attribute',
      arguments: {},
    });
    assert.equal(disallowedAttribute.isError, true);
    const writeRequest = await begin({ scope: 'propose execute' });
    const writeCode = await approved(writeRequest);
    const writeResponse = await exchange(writeRequest, writeCode);
    assert.equal(writeResponse.status, 200);
    const writeToken = (await writeResponse.json()) as OAuthTokens;
    const writer = await connect(writeToken.access_token);
    const draftProposal = id();
    const proposed = await writer.callTool({
      name: 'mikaki_propose',
      arguments: {
        proposal_id: draftProposal,
        document_id: 'name',
        title: 'Consented draft',
        text: 'Private OAuth draft',
      },
    });
    assert.ok(!proposed.isError);
    const receipt = JSON.parse((proposed.content as { text: string }[])[0]!.text) as {
      request_hash: string;
    };
    assert.equal(
      (
        await ownerCall('decide', {
          proposal_id: draftProposal,
          request_hash: receipt.request_hash,
          approve: true,
        })
      ).status,
      200,
    );
    const execution = {
      name: 'mikaki_execute',
      arguments: { proposal_id: draftProposal, request_hash: receipt.request_hash },
    };
    assert.ok(!(await writer.callTool(execution)).isError);
    assert.ok(!(await writer.callTool(execution)).isError);
    assert.equal((await env.DB.prepare('SELECT count(*) n FROM agent_draft').first()).n, 1);
    assert.equal(
      (
        await ownerCall('attribute-capability', {
          grant_id: grant.grant_id,
          attribute_id: 'owner_note',
          base_revision: 0,
        })
      ).status,
      200,
    );
    const noteProposal = await writer.callTool({
      name: 'mikaki_propose_attribute',
      arguments: {
        proposal_id: id(),
        attribute_id: 'owner_note',
        base_revision: 0,
        expires_at: time + 500,
        value: newOwnerNote('OAuth proposal', 'Requires separate owner approval and encryption'),
      },
    });
    assert.ok(!noteProposal.isError, JSON.stringify(noteProposal));
    assert.equal(
      (await op.fetch('https://mikaki.test/vault/attributes/owner_note', { headers: ownerHeaders }))
        .status,
      404,
    );
    const revoke = (token: string, client_id = 'native-test') =>
      agent.fetch(`${origin}/oauth/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token, client_id }).toString(),
      });
    assert.equal((await revoke(issued.access_token, 'other-client')).status, 200);
    assert.equal(
      (await agent.fetch(resource, { headers: { Authorization: `Bearer ${issued.access_token}` } }))
        .status,
      406,
    );
    await env.DB.prepare(
      "CREATE TRIGGER fail_oauth_revoke BEFORE INSERT ON agent_audit WHEN NEW.outcome='revoked' AND NEW.operation='oauth-token' BEGIN SELECT RAISE(ABORT,'audit failure'); END",
    ).run();
    assert.equal((await revoke(issued.access_token)).status, 400);
    assert.equal(
      (
        await env.DB.prepare('SELECT revoked FROM agent_oauth_token WHERE token_hash=?')
          .bind(hash(issued.access_token))
          .first()
      ).revoked,
      0,
    );
    await env.DB.prepare('DROP TRIGGER fail_oauth_revoke').run();
    assert.equal((await revoke(issued.access_token)).status, 200);
    assert.equal((await revoke(issued.access_token)).status, 200);
    assert.equal(
      (await agent.fetch(resource, { headers: { Authorization: `Bearer ${issued.access_token}` } }))
        .status,
      401,
    );
    assert.equal(
      (await agent.fetch(resource, { headers: { Authorization: `Bearer ${grant.token}` } })).status,
      406,
    );

    // Official SDK obtains PKCE and both metadata documents, then Chromium performs owner review.
    assert.equal((await revoke(writeToken.access_token)).status, 200);
    await assert.rejects(
      writer.callTool({
        name: 'mikaki_propose',
        arguments: {
          proposal_id: id(),
          document_id: 'name',
          title: 'Revoked',
          text: 'Must not exist',
        },
      }),
    );
    assert.equal((await env.DB.prepare('SELECT count(*) n FROM agent_proposal').first()).n, 1);
    let oauthTokens: OAuthTokens | undefined,
      verifier = '',
      authorization: URL | undefined;
    const sdkState = id();
    const provider: OAuthClientProvider = {
      redirectUrl: callback,
      clientMetadata: {
        redirect_uris: [callback],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code'],
        response_types: ['code'],
      },
      clientInformation: () => ({ client_id: 'native-test', token_endpoint_auth_method: 'none' }),
      tokens: () => oauthTokens,
      saveTokens: (value) => {
        oauthTokens = value;
      },
      state: () => sdkState,
      redirectToAuthorization: (url) => {
        authorization = url;
      },
      saveCodeVerifier: (value) => {
        verifier = value;
      },
      codeVerifier: () => verifier,
    };
    assert.equal(
      await auth(provider, { serverUrl: resource, scope: 'list read', fetchFn }),
      'REDIRECT',
    );
    assert.ok(authorization);
    const sdkStart = await agent.fetch(authorization.href, { redirect: 'manual' });
    assert.equal(sdkStart.status, 302);
    const ownerLocation = sdkStart.headers.get('Location')!;
    const ownerRequest = new URL(ownerLocation).searchParams.get('agent_oauth_request')!;
    assert.equal((await op.fetch('https://mikaki.test/vault')).status, 401);
    for (const url of [
      ownerLocation + '&return_url=https://evil.test/',
      ownerLocation + '&agent_oauth_request=' + ownerRequest,
      ownerLocation + '&lang=unknown',
      ownerLocation.replace('mikaki.test', 'evil.test'),
    ])
      assert.equal((await op.fetch(url, { redirect: 'manual' })).status, 400);
    assert.equal(
      (
        await op.fetch('https://mikaki.test/vault?agent_oauth_request=' + id(), {
          redirect: 'manual',
        })
      ).status,
      409,
    );
    const unavailable = await begin();
    await env.DB.prepare(
      "UPDATE agent_oauth_request SET owner_origin='https://other.test' WHERE request_id=?",
    )
      .bind(unavailable.request_id)
      .run();
    assert.equal((await op.fetch(unavailable.location, { redirect: 'manual' })).status, 409);
    const timedOut = await begin();
    await env.DB.prepare(
      'UPDATE agent_oauth_request SET created_at=unixepoch()-601,expires_at=unixepoch()-1 WHERE request_id=?',
    )
      .bind(timedOut.request_id)
      .run();
    assert.equal((await op.fetch(timedOut.location, { redirect: 'manual' })).status, 409);
    const bound = await begin();
    for (let i = 0; i < 5; i++) {
      const login = await op.fetch(bound.location, { redirect: 'manual' });
      assert.equal(login.status, 302);
      assert.equal((await op.fetch(login.headers.get('Location')!)).status, 400);
    }
    assert.equal((await op.fetch(bound.location, { redirect: 'manual' })).status, 409);
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.context().addCookies([
      {
        name: '__Host-op-sso',
        value: expiredCookie,
        domain: 'mikaki.test',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
      },
    ]);
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    const authenticator = await cdp.send('WebAuthn.addVirtualAuthenticator', {
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
      authenticatorId: authenticator.authenticatorId,
      credential: {
        credentialId: Buffer.from(credential).toString('base64'),
        isResidentCredential: true,
        rpId: 'mikaki.test',
        userHandle: userHandle.toString('base64'),
        signCount: 0,
        privateKey: passkey.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
      },
    });
    let loginBody = '',
      loginHeaders: Record<string, string> = {};
    let testedLoginRollback = false;
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.route('https://mikaki.test/**', async (route) => {
      const req = route.request();
      const headers = await req.allHeaders();
      const forward = (override = headers) =>
        op.fetch(req.url(), {
          method: req.method(),
          headers: override,
          redirect: 'manual',
          ...(req.postData() ? { body: req.postData()! } : {}),
        });
      if (new URL(req.url()).pathname === '/login/finish') {
        loginBody = req.postData()!;
        loginHeaders = headers;
        assert.equal((await forward({ ...headers, origin: 'https://evil.test' })).status, 403);
        assert.equal(
          (await forward({ ...headers, cookie: '__Host-op-browser=' + id() })).status,
          400,
        );
        await env.DB.prepare(
          "CREATE TRIGGER fail_owner_login BEFORE INSERT ON sso_context BEGIN SELECT RAISE(ABORT,'login rollback'); END",
        ).run();
        assert.equal((await forward()).status, 500);
        const tx = JSON.parse(loginBody).tx;
        assert.equal(
          (
            await env.DB.prepare('SELECT consumed FROM owner_login_transaction WHERE tx_id=?')
              .bind(tx)
              .first()
          ).consumed,
          0,
        );
        assert.equal(
          (
            await env.DB.prepare('SELECT counter FROM passkey_credential WHERE credential_id=?')
              .bind(credentialId)
              .first()
          ).counter,
          0,
        );
        assert.equal((await env.DB.prepare('SELECT count(*) n FROM sso_session').first()).n, 3);
        await env.DB.prepare('DROP TRIGGER fail_owner_login').run();
        testedLoginRollback = true;
      }
      const response = await forward();
      // Playwright's route handler sees only the first request in an HTTP redirect chain.
      // Preserve the server cookie and make the same-origin hop a fresh navigation.
      if (response.status === 302) {
        const location = response.headers.get('Location')!;
        assert.equal(new URL(location).origin, 'https://mikaki.test');
        await route.fulfill({
          status: 200,
          headers: { ...Object.fromEntries(response.headers), 'Content-Type': 'text/html' },
          body: `<script>location.replace(${JSON.stringify(location)})</script>`,
        });
        return;
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    let returnUrl = '';
    await page.route(`${callback}**`, async (route) => {
      returnUrl = route.request().url();
      await route.fulfill({ status: 200, body: 'Returned to client' });
    });
    await page.goto(ownerLocation + '&lang=en');
    const panel = page.getByRole('region', { name: 'Connect an OAuth client' });
    await panel.getByText('native-test · native-test', { exact: true }).waitFor();
    assert.equal(testedLoginRollback, true);
    assert.ok(loginBody);
    assert.equal(
      (
        await op.fetch('https://mikaki.test/login/finish', {
          method: 'POST',
          headers: loginHeaders,
          body: loginBody,
        })
      ).status,
      400,
    );
    assert.equal((await env.DB.prepare('SELECT count(*) n FROM app_connection').first()).n, 0);
    assert.equal((await env.DB.prepare('SELECT count(*) n FROM authorization_code').first()).n, 0);
    const pendingConsent = await env.DB.prepare(
      'SELECT decision,owner_account FROM agent_oauth_request WHERE request_id=?',
    )
      .bind(ownerRequest)
      .first();
    assert.equal(pendingConsent.decision, null);
    assert.equal(pendingConsent.owner_account, 'owner');
    assert.equal(
      (
        await env.DB.prepare(
          'SELECT count(*) n FROM agent_oauth_token t JOIN agent_oauth_request r ON t.request_id=r.request_id WHERE r.request_id=?',
        )
          .bind(ownerRequest)
          .first()
      ).n,
      0,
    );
    assert.match((await panel.textContent())!, /127\.0\.0\.1:43123/);
    const allow = panel.getByRole('button', { name: 'Allow and return to client' });
    assert.equal(await allow.isEnabled(), false);
    await panel.getByLabel('Shared connection').selectOption(grant.grant_id);
    assert.equal(await allow.isEnabled(), false);
    await panel.getByRole('checkbox', { name: 'I approve this client' }).check();
    await allow.click();
    await page.waitForURL(`${callback}**`);
    const returned = new URL(returnUrl);
    assert.equal(returned.searchParams.get('state'), sdkState);
    assert.equal(returned.searchParams.get('iss'), origin);
    assert.equal(
      await auth(provider, {
        serverUrl: resource,
        authorizationCode: returned.searchParams.get('code')!,
        fetchFn,
      }),
      'AUTHORIZED',
    );
    assert.ok(oauthTokens);
    const sdkClient = await connect(oauthTokens.access_token);
    assert.ok(!(await sdkClient.callTool({ name: 'mikaki_list', arguments: {} })).isError);
    assert.deepEqual(errors, []);

    const expiredRequest = await begin();
    await env.DB.prepare(
      'UPDATE agent_oauth_request SET created_at=unixepoch()-601,expires_at=unixepoch()-1 WHERE request_id=?',
    )
      .bind(expiredRequest.request_id)
      .run();
    assert.equal((await preview(expiredRequest)).status, 409);

    const expired = await begin();
    const expiredCode = await approved(expired);
    await env.DB.prepare(
      'UPDATE agent_oauth_request SET code_expires_at=unixepoch()-1 WHERE request_id=?',
    )
      .bind(expired.request_id)
      .run();
    assert.equal((await exchange(expired, expiredCode)).status, 400);
    const expiryToken = await begin(),
      expiryCode = await approved(expiryToken);
    const expiryResponse = await exchange(expiryToken, expiryCode);
    const expiring = (await expiryResponse.json()) as OAuthTokens;
    await env.DB.prepare('UPDATE agent_oauth_token SET expires_at=created_at WHERE token_hash=?')
      .bind(hash(expiring.access_token))
      .run()
      .then(
        () => assert.fail('constraint permits empty lifetime'),
        () => {},
      );
    await env.DB.prepare(
      'UPDATE agent_oauth_token SET created_at=unixepoch()-120,expires_at=unixepoch()-1 WHERE token_hash=?',
    )
      .bind(hash(expiring.access_token))
      .run();
    assert.equal(
      (
        await agent.fetch(resource, {
          headers: { Authorization: `Bearer ${expiring.access_token}` },
        })
      ).status,
      401,
    );
    const retire = await begin({ client_id: 'retire-test' }),
      retireCode = await approved(retire);
    const retireResponse = await exchange(retire, retireCode, { client_id: 'retire-test' }),
      retired = (await retireResponse.json()) as OAuthTokens;
    assert.equal(retireResponse.status, 200);
    await env.DB.prepare(
      "UPDATE agent_oauth_client SET active=0 WHERE client_id='retire-test'",
    ).run();
    assert.equal(
      (
        await agent.fetch(resource, {
          headers: { Authorization: `Bearer ${retired.access_token}` },
        })
      ).status,
      401,
    );
    await assert.rejects(
      env.DB.prepare("UPDATE agent_oauth_client SET active=1 WHERE client_id='retire-test'").run(),
    );
    const staleDetail = await begin({
      authorization_details: JSON.stringify([{ ...detail, source_revision: 2 }]),
    });
    assert.equal((await preview(staleDetail)).status, 200);
    assert.equal((await consent(staleDetail)).status, 409);
    const detailed = await begin({ authorization_details: JSON.stringify([detail]) });
    const detailedPreview = await preview(detailed);
    assert.equal(detailedPreview.status, 200);
    assert.deepEqual(
      ((await detailedPreview.json()) as { authorization_details: unknown }).authorization_details,
      [detail],
    );
    const detailedCode = await approved(detailed);
    const detailedToken = await exchange(detailed, detailedCode);
    assert.equal(detailedToken.status, 200, await detailedToken.clone().text());
    assert.deepEqual(
      ((await detailedToken.json()) as { authorization_details: unknown }).authorization_details,
      [detail],
    );
    const revokedRequest = await begin(),
      revokedCode = await approved(revokedRequest);
    assert.equal((await ownerCall('revoke', { grant_id: grant.grant_id })).status, 200);
    assert.equal((await exchange(revokedRequest, revokedCode)).status, 400);
    assert.equal(
      (
        await agent.fetch(resource, {
          headers: { Authorization: `Bearer ${oauthTokens.access_token}` },
        })
      ).status,
      401,
    );
    assert.equal(
      (await agent.fetch(resource, { headers: { Authorization: `Bearer ${grant.token}` } })).status,
      401,
    );
  } finally {
    for (const client of clients) await client.close().catch(() => {});
    await browser?.close();
    await harness.close();
  }
});
