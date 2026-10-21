/** SEC-06/09 subset: actual OP package, Agent Worker, service bindings and D1/R2. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { agentQueries } from '../../crates/worker/service/agent-catalog.ts';
import { agentKeyId } from '../../crates/worker/ui/agent-crypto.ts';
import { sealRecordAgentSnapshot } from '../../crates/worker/ui/agent-record-crypto.ts';
import {
  createOwnerKey,
  sealOwnerRecord,
  OWNER_KEY_SUITE,
} from '../../crates/worker/ui/vault-owner-crypto.ts';

const root = new URL('../../', import.meta.url).pathname;
const origin = 'https://mikaki.test';
const resource = 'https://agent.mikaki.test/mcp';
const opaque = () => randomBytes(32).toString('base64url');
const hash = (value: string | Uint8Array) => createHash('sha256').update(value).digest('base64url');
const pair = await crypto.subtle.generateKey(
  {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  },
  true,
  ['encrypt', 'decrypt'],
);
const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
const keyId = await agentKeyId(publicJwk);

const capability = (prefix: string) => {
  const entries = Object.entries(agentQueries).filter(([, sql]) => sql.startsWith(prefix));
  assert.equal(entries.length, 1, `expected one actual product capability: ${prefix}`);
  return entries[0]![0];
};

async function json(response: { status: number; text(): Promise<string> }, status = 200) {
  const text = await response.text();
  assert.equal(response.status, status, text);
  return JSON.parse(text);
}

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-security-grant-'));
  const main = join(directory, 'op.mjs');
  // This fixture schedules genuine D1 authority changes at named-service I/O
  // boundaries. It never substitutes catalogued SQL, rows, or authorization.
  await writeFile(
    main,
    `
    import Op, {AgentStore as Store} from ${JSON.stringify(`${root}crates/worker/build/worker/service.mjs`)};
    export default Op;
    export class AgentStore extends Store {
      async fetch(request) {
        if (request.method !== 'POST' || new URL(request.url).pathname !== '/statements') return super.fetch(request);
        const bytes = await request.arrayBuffer();
        const input = JSON.parse(new TextDecoder().decode(bytes));
        const fault = await this.env.DB.prepare('SELECT * FROM security_test_fault WHERE id=1').first();
        const matched = fault.phase && input.statements.some(statement => statement.id === fault.capability);
        let fire = false;
        if (matched) {
          await this.env.DB.prepare('UPDATE security_test_fault SET seen=seen+1 WHERE id=1').run();
          fire = fault.seen + 1 === fault.occurrence;
        }
        const trip = async () => {
          await this.env.DB.prepare("UPDATE security_test_fault SET phase='' WHERE id=1").run();
          if (fault.statement) await this.env.DB.exec(fault.statement);
          await this.env.DB.prepare('UPDATE security_test_fault SET hits=hits+1 WHERE id=1').run();
        };
        if (fire && fault.phase === 'before') await trip();
        const response = await super.fetch(new Request(request.url, {method: request.method,headers: request.headers,body: bytes}));
        if (fire && fault.phase === 'after') await trip();
        if (fire && fault.phase === 'drop') {
          await response.arrayBuffer();
          await trip();
          throw new Error('synthetic lost service acknowledgement');
        }
        return response;
      }
    }
  `,
  );
  const harness = createTestHarness({
    root,
    workers: [
      {
        config: {
          name: 'security-grant-op',
          main,
          compatibility_date: '2026-09-23',
          compatibility_flags: ['global_fetch_strictly_public'],
          vars: { MIKAKI_ISSUER: origin },
          version_metadata: { binding: 'CF_VERSION_METADATA' },
          d1_databases: [
            {
              binding: 'DB',
              database_name: 'security-grant-op',
              database_id: '00000000-0000-0000-0000-000000000000',
              migrations_dir: `${root}crates/worker/migrations`,
              remote: false,
            },
          ],
          r2_buckets: [{ binding: 'VAULT_BLOBS', bucket_name: 'security-grant-op', remote: false }],
          services: [
            { binding: 'AGENT_ACCESS', service: 'security-grant-agent', entrypoint: 'OwnerAgents' },
          ],
        },
      },
      {
        config: {
          name: 'security-grant-agent',
          main: `${root}crates/agent-worker/worker.ts`,
          compatibility_date: '2026-09-28',
          compatibility_flags: ['nodejs_compat'],
          vars: { AGENT_RESOURCE: resource, AGENT_OWNER_URL: `${origin}/vault` },
          services: [
            { binding: 'AUTH_STORE', service: 'security-grant-op', entrypoint: 'AgentStore' },
          ],
        },
        secrets: { AGENT_PRIVATE_JWK: JSON.stringify(privateJwk) },
      },
    ],
  });
  const close = async () => {
    try {
      await harness.close();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  };
  try {
    await harness.listen();
    const op = harness.getWorker('security-grant-op'),
      agent = harness.getWorker('security-grant-agent');
    await op.applyD1Migrations('DB');
    const { DB, VAULT_BLOBS } = await op.getEnv();
    const agentEnv = await agent.getEnv();
    assert.equal('DB' in agentEnv, false);
    assert.equal('VAULT_BLOBS' in agentEnv, false);
    await DB.exec(
      "CREATE TABLE security_test_fault(id INTEGER PRIMARY KEY,capability TEXT,phase TEXT,statement TEXT,occurrence INTEGER,seen INTEGER,hits INTEGER); INSERT INTO security_test_fault VALUES(1,'','','',1,0,0)",
    );
    const version = await json(await op.fetch(`${origin}/version`));
    assert.equal(
      version.source_commit,
      execFileSync('/usr/bin/git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
      'rebuild the emitted OP for this checkout',
    );
    await DB.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')").bind(keyId).run();
    await DB.prepare(
      "INSERT INTO agent_oauth_client VALUES('security-client','Synthetic client',?,1)",
    )
      .bind('["https://client.test/callback"]')
      .run();
    const arm = (phase: string, prefix: string, statement = '', occurrence = 1) =>
      DB.prepare(
        'UPDATE security_test_fault SET phase=?,capability=?,statement=?,occurrence=?,seen=0,hits=0 WHERE id=1',
      )
        .bind(phase, capability(prefix), statement, occurrence)
        .run();
    const hits = () => DB.prepare('SELECT hits FROM security_test_fault WHERE id=1').first('hits');
    const owner = async (account: string) => {
      const credential = opaque(),
        session = opaque(),
        cookie = opaque(),
        now = Math.floor(Date.now() / 1000);
      await DB.batch([
        DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(account),
        DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(credential, account),
        DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,?,0)').bind(
          session,
          account,
          credential,
          now + 3600,
        ),
        DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(session, hash(cookie), now),
      ]);
      const context = { origin, ownerId: account, vaultId: 'selected-vault', keyGeneration: 1 };
      const created = await createOwnerKey(
        context,
        new Uint8Array(Buffer.from(credential, 'base64url')),
        new Uint8Array(randomBytes(32)),
        new Uint8Array(randomBytes(32)),
      );
      const headers = {
        Cookie: `__Host-op-sso=${cookie}`,
        Origin: origin,
        'Content-Type': 'application/json',
      };
      await json(
        await op.fetch(`${origin}/vault/owner-key`, {
          method: 'PUT',
          headers: { ...headers, 'If-None-Match': '*', 'X-Operation-ID': opaque() },
          body: JSON.stringify({
            format_version: 2,
            suite: OWNER_KEY_SUITE,
            vault_id: context.vaultId,
            key_generation: 1,
            owner_envelope: created.envelope,
          }),
        }),
      );
      const plaintext = `SEC09 private selected name ${account} ${opaque()}`;
      const sealed = await sealOwnerRecord(
        new TextEncoder().encode(plaintext),
        created.key,
        context,
        { collectionId: 'personal', recordId: 'name', kind: 'name', revision: 1 },
      );
      await json(
        await op.fetch(`${origin}/vault/records/personal/name`, {
          method: 'PUT',
          headers: { ...headers, 'If-None-Match': '*', 'X-Operation-ID': opaque() },
          body: JSON.stringify({
            ...sealed,
            vault_id: context.vaultId,
            key_generation: 1,
            owner_key_revision: 1,
            kind: 'name',
            revision: 1,
          }),
        }),
      );
      const head = await DB.prepare(
        "SELECT * FROM vault_owner_record_head WHERE account_id=? AND collection_id='personal' AND record_id='name'",
      )
        .bind(account)
        .first();
      assert.ok(head);
      const source = {
        storage_version: 2 as const,
        origin,
        owner_id: account,
        vault_id: context.vaultId,
        collection_id: 'personal' as const,
        record_id: 'name' as const,
        kind: 'name' as const,
        revision: 1,
        ciphertext_sha256: head.ciphertext_sha256 as string,
      };
      const authority = { key_generation: 1, owner_key_revision: 1 };
      const token = `mag_${opaque()}`,
        grantId = opaque(),
        expires = now + 600;
      const input = {
        storage_version: 2,
        grant_id: grantId,
        delegate: 'synthetic-security',
        provider: 'Synthetic provider',
        resource,
        source,
        authority,
        recipient_key_id: keyId,
        operations: ['list', 'search', 'read', 'propose', 'execute'],
        document_ids: ['name'],
        envelope: await sealRecordAgentSnapshot(
          [{ id: 'name', title: 'Selected name', source: 'untrusted label', text: plaintext }],
          { public_jwk: publicJwk, key_id: keyId, resource },
          {
            owner: account,
            grant_id: grantId,
            key_id: keyId,
            resource,
            expires_at: expires,
            source,
            authority,
          },
        ),
        token_hash: hash(token),
        expires_at: expires,
      };
      const request = (path: string, body?: unknown) =>
        op.fetch(`${origin}/vault/agents/${path}`, {
          method: body === undefined ? 'GET' : 'POST',
          headers,
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
      await json(await request('grants', input));
      return {
        account,
        credential,
        session,
        headers,
        plaintext,
        source,
        authority,
        token,
        grantId,
        input,
        request,
      };
    };
    const rpc = async (token: string, name: string, args: unknown) => {
      const response = await agent.fetch(resource, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          'MCP-Protocol-Version': '2025-11-25',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: `mikaki_${name}`, arguments: args },
        }),
      });
      const text = await response.text();
      return {
        status: response.status,
        data: text === '' ? null : JSON.parse(text),
        challenge: response.headers.get('WWW-Authenticate'),
      };
    };
    const authorize = async (
      who: Awaited<ReturnType<typeof owner>>,
      actions = ['read'],
      detailChanges: Record<string, unknown> = {},
    ) => {
      const verifier = opaque(),
        url = new URL('https://agent.mikaki.test/oauth/authorize');
      const detail = {
        type: 'mikaki_agent_snapshot',
        storage_version: 2,
        locations: [resource],
        actions,
        document_id: 'name',
        source: who.source,
        authority: who.authority,
        purpose: 'Synthetic exact selected name',
        ...detailChanges,
      };
      for (const [key, value] of Object.entries({
        response_type: 'code',
        client_id: 'security-client',
        redirect_uri: 'https://client.test/callback',
        resource,
        scope: actions.join(' '),
        state: opaque(),
        code_challenge: hash(verifier),
        code_challenge_method: 'S256',
        authorization_details: JSON.stringify([detail]),
      }))
        url.searchParams.set(key, value);
      const response = await agent.fetch(url.href, { redirect: 'manual' });
      assert.equal(response.status, 302, await response.text());
      const requestId = new URL(response.headers.get('Location')!).searchParams.get(
        'agent_oauth_request',
      );
      assert.ok(requestId);
      await json(await who.request('oauth-request', { request_id: requestId }));
      return { verifier, requestId, detail };
    };
    const approve = async (
      who: Awaited<ReturnType<typeof owner>>,
      pending: Awaited<ReturnType<typeof authorize>>,
    ) => {
      const result = await json(
        await who.request('oauth-decide', {
          request_id: pending.requestId,
          approve: true,
          grant_id: who.grantId,
        }),
      );
      const code = new URL(result.redirect).searchParams.get('code');
      assert.ok(code);
      return new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: 'security-client',
        redirect_uri: 'https://client.test/callback',
        resource,
        code_verifier: pending.verifier,
      }).toString();
    };
    const redeem = (form: string) =>
      agent.fetch('https://agent.mikaki.test/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form,
      });
    const oauth = async (who: Awaited<ReturnType<typeof owner>>, actions = ['read']) => {
      const pending = await authorize(who, actions);
      const result = await json(await redeem(await approve(who, pending)));
      assert.deepEqual(result.authorization_details, [pending.detail]);
      assert.equal(result.scope, actions.join(' '));
      return result.access_token as string;
    };
    const vault = async () => {
      const heads = (
        await DB.prepare(
          'SELECT * FROM vault_owner_record_head ORDER BY account_id,record_id',
        ).all()
      ).results;
      const receipts = (
        await DB.prepare(
          'SELECT * FROM vault_owner_record_mutation ORDER BY account_id,operation_id',
        ).all()
      ).results;
      const listing = await VAULT_BLOBS.list();
      assert.equal(listing.truncated, false);
      const blobs = [];
      for (const item of listing.objects) {
        const object = await VAULT_BLOBS.get(item.key);
        assert.ok(object);
        blobs.push({ key: item.key, sha256: hash(new Uint8Array(await object.arrayBuffer())) });
      }
      return { heads, receipts, blobs };
    };
    const count = async (table: 'agent_proposal' | 'agent_draft', grantId?: string) => {
      const sql =
        table === 'agent_draft'
          ? 'SELECT count(*) n FROM agent_draft'
          : 'SELECT count(*) n FROM agent_proposal WHERE grant_id=?';
      const stmt = DB.prepare(sql);
      return (table === 'agent_draft' ? stmt : stmt.bind(grantId)).first('n');
    };
    return {
      op,
      agent,
      DB,
      owner,
      rpc,
      authorize,
      approve,
      redeem,
      oauth,
      arm,
      hits,
      vault,
      count,
      close,
      version,
    };
  } catch (error) {
    await close();
    throw error;
  }
}

type Fixture = Awaited<ReturnType<typeof fixture>>;
type Owner = Awaited<ReturnType<Fixture['owner']>>;
function denied(result: Awaited<ReturnType<Fixture['rpc']>>, secret: string) {
  assert.equal(result.status, 200);
  assert.deepEqual(result.data.result, {
    isError: true,
    content: [{ type: 'text', text: 'Access denied or unavailable' }],
  });
  assert.equal(
    JSON.stringify(result).includes(secret),
    false,
    'private snapshot must not escape in any response field',
  );
}
async function approvedProposal(f: Fixture, a: Owner, token: string) {
  const proposalId = opaque();
  const proposed = await f.rpc(token, 'propose', {
    proposal_id: proposalId,
    document_id: 'name',
    title: 'Exact private draft',
    text: 'Synthetic approved private draft',
  });
  assert.equal(proposed.data.result.isError, undefined, JSON.stringify(proposed));
  const requestHash = proposed.data.result.structuredContent.request_hash as string;
  await json(
    await a.request('decide', {
      proposal_id: proposalId,
      request_hash: requestHash,
      approve: true,
    }),
  );
  return { proposal_id: proposalId, request_hash: requestHash };
}

test('SEC-06/09 Agent grant disclosure and commit matrix', async (t) => {
  const run = async (name: string, body: (f: Fixture) => Promise<void>) =>
    t.test(name, async () => {
      const f = await fixture();
      try {
        await body(f);
      } finally {
        await f.close();
      }
    });
  await run('read-only OAuth stays selected and owners cannot revoke each other', async (f) => {
    t.diagnostic(
      JSON.stringify({
        sourceCommit: f.version.source_commit,
        buildSourceClean: f.version.source_clean,
        profile: 'default OP and actual Agent Worker',
        authentication: 'synthetic SSO; HTTP owner-key/record/grant and OAuth',
        storage: 'disposable local D1/R2; no downstream DB/R2',
      }),
    );
    const a = await f.owner('owner-a'),
      b = await f.owner('owner-b');
    const token = await f.oauth(a);
    const before = await f.vault();
    assert.equal(
      (await f.rpc(token, 'read', { id: 'name' })).data.result.structuredContent.text,
      a.plaintext,
    );
    assert.equal(
      (await f.rpc(b.token, 'read', { id: 'name' })).data.result.structuredContent.text,
      b.plaintext,
    );
    denied(await f.rpc(token, 'list', {}), a.plaintext);
    denied(
      await f.rpc(token, 'propose', {
        proposal_id: opaque(),
        document_id: 'name',
        title: 'Denied',
        text: 'No proposal',
      }),
      a.plaintext,
    );
    const prior = await f.DB.prepare('SELECT * FROM agent_grant WHERE grant_id=?')
      .bind(a.grantId)
      .first();
    await json(await b.request('revoke', { grant_id: a.grantId }));
    assert.deepEqual(
      await f.DB.prepare('SELECT * FROM agent_grant WHERE grant_id=?').bind(a.grantId).first(),
      prior,
    );
    const status = await json(await b.request('record-status'));
    assert.deepEqual(
      status.grants.map((row: { grant_id: string }) => row.grant_id),
      [b.grantId],
    );
    assert.equal(await f.count('agent_proposal', a.grantId), 0);
    assert.equal(await f.count('agent_draft'), 0);
    assert.deepEqual(await f.vault(), before);
  });
  await run(
    'OAuth consent cannot change the selected owner, digest or key authority',
    async (f) => {
      const a = await f.owner('owner-a'),
        b = await f.owner('owner-b');
      const before = await f.vault();
      for (const change of [
        { source: b.source },
        { source: { ...a.source, ciphertext_sha256: opaque() } },
        { authority: { key_generation: 1, owner_key_revision: 2 } },
      ]) {
        const pending = await f.authorize(a, ['read'], change);
        await json(
          await a.request('oauth-decide', {
            request_id: pending.requestId,
            approve: true,
            grant_id: a.grantId,
          }),
          409,
        );
        const row = await f.DB.prepare(
          'SELECT decision,code_hash,grant_id FROM agent_oauth_request WHERE request_id=?',
        )
          .bind(pending.requestId)
          .first();
        assert.deepEqual(row, { decision: null, code_hash: null, grant_id: null });
      }
      assert.equal(await f.DB.prepare('SELECT count(*) n FROM agent_oauth_token').first('n'), 0);
      assert.deepEqual(await f.vault(), before);
      const control = await f.oauth(a);
      assert.equal(
        (await f.rpc(control, 'read', { id: 'name' })).data.result.structuredContent.text,
        a.plaintext,
      );
    },
  );
  await run(
    'concurrent redemption issues one token and replay leaves that token usable',
    async (f) => {
      const a = await f.owner('owner-a'),
        pending = await f.authorize(a);
      const form = await f.approve(a, pending);
      const results = await Promise.all([f.redeem(form), f.redeem(form)]);
      const bodies = await Promise.all(
        results.map(async (response) => ({
          status: response.status,
          data: JSON.parse(await response.text()),
        })),
      );
      assert.deepEqual(
        bodies.map((row) => row.status).sort((a, b) => a - b),
        [200, 400],
      );
      const issued = bodies.find((row) => row.status === 200)!;
      assert.deepEqual(bodies.find((row) => row.status === 400)!.data, { error: 'invalid_grant' });
      assert.equal(await f.DB.prepare('SELECT count(*) n FROM agent_oauth_token').first('n'), 1);
      assert.equal(
        (await f.rpc(issued.data.access_token, 'read', { id: 'name' })).data.result
          .structuredContent.text,
        a.plaintext,
      );
    },
  );
  await run('expired grants reject both direct and OAuth tokens before disclosure', async (f) => {
    const a = await f.owner('owner-a'),
      token = await f.oauth(a),
      before = await f.vault();
    await f.DB.prepare(
      'UPDATE agent_grant SET created_at=unixepoch()-600,expires_at=unixepoch()-1 WHERE grant_id=?',
    )
      .bind(a.grantId)
      .run();
    for (const credential of [a.token, token]) {
      const response = await f.rpc(credential, 'read', { id: 'name' });
      assert.equal(response.status, 401);
      assert.equal(response.data, null);
      assert.equal(
        response.challenge,
        'Bearer resource_metadata="https://agent.mikaki.test/.well-known/oauth-protected-resource/mcp", scope="list search read"',
      );
    }
    assert.equal(await f.count('agent_draft'), 0);
    assert.deepEqual(await f.vault(), before);
  });
  await run('owner approval cannot be rebound to another hash or grant', async (f) => {
    const a = await f.owner('owner-a'),
      b = await f.owner('owner-b'),
      token = await f.oauth(a, ['propose', 'execute']);
    const args = await approvedProposal(f, a, token),
      before = await f.vault();
    denied(await f.rpc(token, 'execute', { ...args, request_hash: opaque() }), a.plaintext);
    denied(await f.rpc(b.token, 'execute', args), a.plaintext);
    assert.equal(await f.count('agent_draft'), 0);
    const proposal = await f.DB.prepare(
      'SELECT state,request_hash,result_id FROM agent_proposal WHERE proposal_id=?',
    )
      .bind(args.proposal_id)
      .first();
    assert.deepEqual(proposal, {
      state: 'approved',
      request_hash: args.request_hash,
      result_id: null,
    });
    const result = await f.rpc(token, 'execute', args);
    assert.equal(result.data.result.structuredContent.state, 'executed');
    assert.equal(await f.count('agent_draft'), 1);
    const draft = await f.DB.prepare(
      'SELECT account_id,proposal_id,title,text FROM agent_draft',
    ).first();
    assert.deepEqual(draft, {
      account_id: a.account,
      proposal_id: args.proposal_id,
      title: 'Exact private draft',
      text: 'Synthetic approved private draft',
    });
    assert.deepEqual(await f.vault(), before);
  });
  const disclosureFaults = {
    token: 'UPDATE agent_oauth_token SET revoked=1',
    client: 'UPDATE agent_oauth_client SET active=0',
    source: "UPDATE vault_owner_record_head SET revision=2 WHERE account_id='owner-a'",
    recipient: "UPDATE agent_recipient_key SET state='disabled'",
    credential: "UPDATE credential SET active=0 WHERE account_id='owner-a'",
    account: "UPDATE account_security SET epoch=2 WHERE account_id='owner-a'",
  };
  for (const [name, statement] of Object.entries(disclosureFaults))
    await run(`post-audit ${name} invalidation suppresses decrypted disclosure`, async (f) => {
      const a = await f.owner('owner-a'),
        token = await f.oauth(a);
      const before = await f.vault();
      await f.arm('after', "INSERT INTO agent_audit SELECT ?,g.grant_id,?,'authorized'", statement);
      denied(await f.rpc(token, 'read', { id: 'name' }), a.plaintext);
      assert.equal(await f.hits(), 1);
      assert.equal(
        await f.DB.prepare(
          "SELECT count(*) n FROM agent_audit WHERE grant_id=? AND operation='read' AND outcome='authorized'",
        )
          .bind(a.grantId)
          .first('n'),
        1,
      );
      assert.equal(
        await f.DB.prepare(
          "SELECT count(*) n FROM agent_audit WHERE grant_id=? AND operation='read' AND outcome='denied'",
        )
          .bind(a.grantId)
          .first('n'),
        1,
      );
      assert.equal((await f.rpc(token, 'read', { id: 'name' })).status, 401);
      const grant = await f.DB.prepare(
        'SELECT revoked,encrypted_snapshot FROM agent_grant WHERE grant_id=?',
      )
        .bind(a.grantId)
        .first();
      if (name === 'token' || name === 'client') {
        assert.equal(grant.revoked, 0);
        assert.equal(
          (await f.rpc(a.token, 'read', { id: 'name' })).data.result.structuredContent.text,
          a.plaintext,
        );
      } else assert.deepEqual(grant, { revoked: 1, encrypted_snapshot: null });
      assert.equal(await f.count('agent_proposal', a.grantId), 0);
      assert.equal(await f.count('agent_draft'), 0);
      const after = await f.vault();
      assert.deepEqual(after.blobs, before.blobs);
      assert.deepEqual(after.receipts, before.receipts);
      if (name === 'source')
        assert.deepEqual(
          after.heads,
          before.heads.map((row: Record<string, unknown>) => ({ ...row, revision: 2 })),
        );
      else assert.deepEqual(after.heads, before.heads);
    });
  for (const [name, statement] of Object.entries({
    token: 'UPDATE agent_oauth_token SET revoked=1',
    grant: 'UPDATE agent_grant SET revoked=1',
    client: 'UPDATE agent_oauth_client SET active=0',
  }))
    await run(
      `pre-commit ${name} invalidation cannot create an approved private draft`,
      async (f) => {
        const a = await f.owner('owner-a'),
          token = await f.oauth(a, ['propose', 'execute']);
        const args = await approvedProposal(f, a, token),
          before = await f.vault();
        await f.arm('before', 'INSERT INTO agent_draft SELECT', statement);
        denied(await f.rpc(token, 'execute', args), a.plaintext);
        assert.equal(await f.hits(), 1);
        if (name === 'token')
          assert.equal(
            await f.DB.prepare('SELECT revoked FROM agent_oauth_token WHERE token_hash=?')
              .bind(hash(token))
              .first('revoked'),
            1,
          );
        if (name === 'client')
          assert.equal(
            await f.DB.prepare(
              "SELECT active FROM agent_oauth_client WHERE client_id='security-client'",
            ).first('active'),
            0,
          );
        assert.equal(await f.count('agent_draft'), 0);
        const proposal = await f.DB.prepare(
          'SELECT state,result_id FROM agent_proposal WHERE proposal_id=?',
        )
          .bind(args.proposal_id)
          .first();
        assert.deepEqual(proposal, {
          state: name === 'grant' ? 'rejected' : 'approved',
          result_id: null,
        });
        assert.equal(
          await f.DB.prepare(
            "SELECT count(*) n FROM agent_audit WHERE grant_id=? AND operation='execute' AND outcome='executed'",
          )
            .bind(a.grantId)
            .first('n'),
          0,
        );
        assert.deepEqual(await f.vault(), before);
      },
    );
  await run('a lost execute acknowledgement reconciles one exact private draft', async (f) => {
    const a = await f.owner('owner-a'),
      token = await f.oauth(a, ['propose', 'execute']);
    const args = await approvedProposal(f, a, token),
      before = await f.vault();
    await f.arm('drop', 'INSERT INTO agent_draft SELECT');
    denied(await f.rpc(token, 'execute', args), a.plaintext);
    assert.equal(await f.hits(), 1);
    assert.equal(
      await f.count('agent_draft'),
      1,
      'the lost response cannot be mistaken for no commit',
    );
    const draft = await f.DB.prepare('SELECT * FROM agent_draft').first();
    assert.deepEqual(
      {
        account_id: draft.account_id,
        proposal_id: draft.proposal_id,
        title: draft.title,
        text: draft.text,
      },
      {
        account_id: a.account,
        proposal_id: args.proposal_id,
        title: 'Exact private draft',
        text: 'Synthetic approved private draft',
      },
    );
    const attempts = await Promise.all([
      f.rpc(token, 'execute', args),
      f.rpc(token, 'execute', args),
    ]);
    for (const result of attempts) {
      assert.equal(result.data.result.isError, undefined, JSON.stringify(result));
      assert.deepEqual(result.data.result.structuredContent, {
        draft_id: draft.draft_id,
        state: 'executed',
        result_version: 1,
        untrusted_content: true,
      });
    }
    assert.equal(await f.count('agent_draft'), 1);
    assert.deepEqual(await f.DB.prepare('SELECT * FROM agent_draft').first(), draft);
    assert.deepEqual(await f.vault(), before);
  });
  await run('an unavailable authorized-access audit cannot release plaintext', async (f) => {
    const a = await f.owner('owner-a'),
      token = await f.oauth(a),
      before = await f.vault();
    await f.arm(
      'before',
      "INSERT INTO agent_audit SELECT ?,g.grant_id,?,'authorized'",
      "CREATE TRIGGER security_fail_audit BEFORE INSERT ON agent_audit WHEN NEW.outcome='authorized' BEGIN SELECT RAISE(ABORT,'synthetic unavailable audit'); END",
    );
    denied(await f.rpc(token, 'read', { id: 'name' }), a.plaintext);
    assert.equal(await f.hits(), 1);
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) n FROM agent_audit WHERE operation='read' AND outcome='authorized'",
      ).first('n'),
      0,
    );
    await f.DB.exec('DROP TRIGGER security_fail_audit');
    assert.equal(
      (await f.rpc(token, 'read', { id: 'name' })).data.result.structuredContent.text,
      a.plaintext,
    );
    assert.deepEqual(await f.vault(), before);
  });
});
