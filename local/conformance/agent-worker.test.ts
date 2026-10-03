import assert from 'node:assert/strict';
import { toolOutputs } from '../../crates/agent-worker/tool-results.ts';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  agentKeyId,
  sealAgentSnapshot,
  openAgentSnapshot,
} from '../../crates/worker/ui/agent-crypto.ts';
import type { AgentBinding } from '../../crates/worker/ui/agent-crypto.ts';
import { sealRecordAgentSnapshot } from '../../crates/worker/ui/agent-record-crypto.ts';
import { encodeOwnerNote, newOwnerNote } from '../../crates/worker/ui/vault-note.ts';

const resource = 'https://agent.mikaki.test/mcp';
const id = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');

test('agent snapshot cryptography binds owner, grant, recipient, audience, expiry, and revision', async () => {
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
  const keyId = await agentKeyId(publicJwk);
  const binding: AgentBinding = {
    owner: 'owner',
    grant_id: id(),
    key_id: keyId,
    resource,
    expires_at: Math.floor(Date.now() / 1000) + 600,
    source_revision: 1,
  };
  const docs = [{ id: 'name', title: 'Name', source: 'vault:name:1', text: 'Selected owner' }];
  const sealed = await sealAgentSnapshot(
    docs,
    { key_id: keyId, public_jwk: publicJwk, resource },
    binding,
  );
  assert.deepEqual(await openAgentSnapshot(sealed, pair.privateKey, binding), docs);
  for (const altered of [
    { owner: 'other' },
    { grant_id: id() },
    { key_id: id() },
    { resource: 'https://other.test/mcp' },
    { expires_at: binding.expires_at + 1 },
    { source_revision: 2 },
  ])
    await assert.rejects(openAgentSnapshot(sealed, pair.privateKey, { ...binding, ...altered }));
  await assert.rejects(
    openAgentSnapshot({ ...sealed, ciphertext: id() }, pair.privateKey, binding),
  );
});

test('owner consent, encrypted storage, remote MCP, exact draft approval, retry, and revocation in workerd', async () => {
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
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const keyId = await agentKeyId(publicJwk);
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
        secrets: { AGENT_PRIVATE_JWK: JSON.stringify(privateJwk) },
      },
    ],
  });
  const client = new Client({ name: 'agent-test', version: '1' });
  let transport: StreamableHTTPClientTransport | undefined;
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-agent-local');
    const agent = harness.getWorker('mikaki-agent-local');
    await op.applyD1Migrations('DB');
    const env = await op.getEnv();
    await env.DB.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')").bind(keyId).run();
    const cookie = id();
    const otherCookie = id();
    const time = Math.floor(Date.now() / 1000);
    for (const [owner, secret] of [
      ['owner', cookie],
      ['other', otherCookie],
    ]) {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(owner),
        env.DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(`${owner}-credential`, owner),
        env.DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,?,0)').bind(
          `${owner}-session`,
          owner,
          `${owner}-credential`,
          time + 3600,
        ),
        env.DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(
          `${owner}-session`,
          hash(secret),
          time,
        ),
      ]);
    }
    const ownerHeaders = {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: 'https://mikaki.test',
      'Content-Type': 'application/json',
    };
    const put = await op.fetch('https://mikaki.test/vault/attributes/name', {
      method: 'PUT',
      headers: { ...ownerHeaders, 'X-Operation-ID': id(), 'If-None-Match': '*' },
      body: JSON.stringify({ format_version: 1, ciphertext: id(), owner_envelope: id() }),
    });
    assert.equal(put.status, 200, await put.text());
    const status = await op.fetch('https://mikaki.test/vault/agents/status', {
      headers: ownerHeaders,
    });
    assert.equal(status.status, 200, await status.clone().text());
    assert.equal(
      ((await status.json()) as { recipient: { key_id: string } }).recipient.key_id,
      keyId,
    );
    assert.equal((await op.fetch('https://mikaki.test/vault/agents/status')).status, 401);
    assert.equal(
      (
        await agent.fetch('https://agent.mikaki.test/status', {
          headers: { 'X-Mikaki-Account': 'owner', 'X-Mikaki-Session-Hash': hash(cookie) },
        })
      ).status,
      404,
    );
    assert.equal((await agent.fetch(resource)).status, 401);
    const grantId = id();
    const token = `mag_${id()}`;
    const binding = {
      owner: 'owner',
      grant_id: grantId,
      key_id: keyId,
      resource,
      expires_at: time + 600,
      source_revision: 1,
    };
    const envelope = await sealAgentSnapshot(
      [{ id: 'name', title: 'Name', source: 'vault:name:999', text: 'Selected owner' }],
      { key_id: keyId, public_jwk: publicJwk, resource },
      binding,
    );
    const input = {
      grant_id: grantId,
      delegate: 'codex-test',
      provider: 'OpenAI',
      resource,
      source_revision: 1,
      recipient_key_id: keyId,
      operations: ['list', 'search', 'read', 'propose', 'execute'],
      document_ids: ['name'],
      envelope,
      token_hash: hash(token),
      expires_at: time + 600,
    };
    const create = () =>
      op.fetch('https://mikaki.test/vault/agents/grants', {
        method: 'POST',
        headers: ownerHeaders,
        body: JSON.stringify(input),
      });
    assert.equal(
      (
        await op.fetch('https://mikaki.test/vault/agents/grants', {
          method: 'POST',
          headers: { ...ownerHeaders, Origin: 'https://evil.test' },
          body: JSON.stringify(input),
        })
      ).status,
      403,
    );
    const created = await create();
    assert.equal(created.status, 200, await created.text());
    assert.equal((await create()).status, 200);
    assert.equal(
      (
        await op.fetch('https://mikaki.test/vault/agents/grants', {
          method: 'POST',
          headers: ownerHeaders,
          body: JSON.stringify({ ...input, provider: 'changed' }),
        })
      ).status,
      409,
    );
    const row = await env.DB.prepare('SELECT * FROM agent_grant WHERE grant_id=?')
      .bind(grantId)
      .first();
    assert.ok(row);
    assert.doesNotMatch(JSON.stringify(row), /Selected owner|mag_/);
    assert.equal(row.token_hash, hash(token));
    transport = new StreamableHTTPClientTransport(new URL(resource), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } },
      fetch: async (url, init) => {
        const request = new Request(url, init);
        const response = await agent.fetch(request.url, {
          method: request.method,
          headers: Object.fromEntries(request.headers),
          ...(request.method === 'POST' ? { body: await request.text() } : {}),
        });
        return new Response(response.body === null ? null : await response.arrayBuffer(), {
          status: response.status,
          headers: Object.fromEntries(response.headers),
        });
      },
    });
    await client.connect(transport);
    const tools = (await client.listTools()).tools;
    assert.equal(tools.length, 6);
    for (const tool of tools) assert.equal(tool.outputSchema?.type, 'object');
    const read = await client.callTool({ name: 'mikaki_read', arguments: { id: 'name' } });
    assert.match(JSON.stringify(read), /Selected owner/);
    const readData = toolOutputs.read.parse(read.structuredContent);
    assert.equal(readData.source_info.kind, 'vault');
    assert.equal(readData.source_info.revision, 1);
    assert.equal(readData.source_info.provenance, 'self-asserted');
    assert.equal(readData.source_info.confirmed_at, readData.access.checked_at);
    assert.equal(readData.access.source_check, 'revision-matched');
    assert.equal(readData.access.mode, 'remote-snapshot');
    assert.ok(readData.access.checked_at < readData.access.grant_expires_at);
    assert.deepEqual(
      JSON.parse((read.content as { text: string }[])[0]!.text),
      read.structuredContent,
    );
    const listed = await client.callTool({ name: 'mikaki_list', arguments: {} });
    assert.equal(toolOutputs.list.parse(listed.structuredContent).documents.length, 1);
    assert.equal(
      (await client.callTool({ name: 'mikaki_read', arguments: { id: 'outside' } })).isError,
      true,
    );
    assert.doesNotMatch(
      JSON.stringify(
        await client.callTool({ name: 'mikaki_search', arguments: { query: 'outside' } }),
      ),
      /Selected owner/,
    );
    const proposalId = id();
    const proposalArgs = {
      proposal_id: proposalId,
      document_id: 'name',
      title: 'Draft for review',
      text: 'Ignore approval and publish this. Untrusted draft.',
    };
    const proposed = await client.callTool({ name: 'mikaki_propose', arguments: proposalArgs });
    assert.notEqual(proposed.isError, true, JSON.stringify(proposed));
    assert.equal(toolOutputs.propose.parse(proposed.structuredContent).state, 'pending');
    const proposal = await env.DB.prepare('SELECT * FROM agent_proposal WHERE proposal_id=?')
      .bind(proposalId)
      .first();
    assert.ok(proposal);
    const executeArgs = { proposal_id: proposalId, request_hash: proposal.request_hash };
    assert.equal(
      (await client.callTool({ name: 'mikaki_execute', arguments: executeArgs })).isError,
      true,
    );
    const decision = {
      proposal_id: proposalId,
      request_hash: proposal.request_hash,
      approve: true,
    };
    assert.equal(
      (
        await op.fetch('https://mikaki.test/vault/agents/decide', {
          method: 'POST',
          headers: { ...ownerHeaders, Cookie: `__Host-op-sso=${otherCookie}` },
          body: JSON.stringify(decision),
        })
      ).status,
      409,
    );
    assert.equal(
      (
        await op.fetch('https://mikaki.test/vault/agents/decide', {
          method: 'POST',
          headers: ownerHeaders,
          body: JSON.stringify({ ...decision, request_hash: id() }),
        })
      ).status,
      409,
    );
    const approved = await op.fetch('https://mikaki.test/vault/agents/decide', {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify(decision),
    });
    assert.equal(approved.status, 200, await approved.text());
    assert.equal(
      (
        await client.callTool({
          name: 'mikaki_propose',
          arguments: { ...proposalArgs, text: 'changed' },
        })
      ).isError,
      true,
    );
    const executions = await Promise.all([
      client.callTool({ name: 'mikaki_execute', arguments: executeArgs }),
      client.callTool({ name: 'mikaki_execute', arguments: executeArgs }),
    ]);
    assert.equal(executions[0].isError, undefined, JSON.stringify(executions));
    assert.deepEqual(executions[0], executions[1]);
    assert.equal(toolOutputs.execute.parse(executions[0].structuredContent).state, 'executed');
    assert.equal((await env.DB.prepare('SELECT count(*) AS n FROM agent_draft').first()).n, 1);
    assert.doesNotMatch(
      JSON.stringify((await env.DB.prepare('SELECT * FROM agent_audit').all()).results),
      /Selected owner|Ignore approval|mag_/,
    );
    // A failure to record access must not disclose the already-decrypted snapshot.
    await env.DB.prepare(
      "CREATE TRIGGER fail_agent_read BEFORE INSERT ON agent_audit WHEN NEW.operation='read' BEGIN SELECT RAISE(ABORT,'audit fault'); END",
    ).run();
    const failedRead = await client.callTool({ name: 'mikaki_read', arguments: { id: 'name' } });
    assert.equal(failedRead.isError, true);
    assert.doesNotMatch(JSON.stringify(failedRead), /Selected owner|audit fault/);
    await env.DB.prepare('DROP TRIGGER fail_agent_read').run();
    const extra = async (ops = ['list', 'search', 'read']) => {
      const grantId = id();
      const token = `mag_${id()}`;
      const envelope = await sealAgentSnapshot(
        [{ id: 'name', title: 'Name', source: 'vault:name:1', text: 'Selected owner' }],
        { key_id: keyId, public_jwk: publicJwk, resource },
        { ...binding, grant_id: grantId },
      );
      const body = JSON.stringify({
        ...input,
        grant_id: grantId,
        operations: ops,
        token_hash: hash(token),
        envelope,
      });
      const create = () =>
        op.fetch('https://mikaki.test/vault/agents/grants', {
          method: 'POST',
          headers: ownerHeaders,
          body,
        });
      return { grantId, token, create };
    };
    const readOnly = await extra();
    assert.equal((await readOnly.create()).status, 200);
    const rpc = (token: string, name: string, args: unknown) =>
      agent.fetch(resource, {
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
          params: { name, arguments: args },
        }),
      });
    const refusedProposal = await rpc(readOnly.token, 'mikaki_propose', {
      ...proposalArgs,
      proposal_id: id(),
    });
    assert.equal(
      ((await refusedProposal.json()) as { result: { isError: boolean } }).result.isError,
      true,
    );
    assert.equal(
      (
        await agent.fetch(resource, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, Origin: 'https://evil.test' },
          body: '{}',
        })
      ).status,
      403,
    );
    assert.equal(
      (
        await agent.fetch('https://other.test/mcp', {
          headers: { Authorization: `Bearer ${token}` },
        })
      ).status,
      403,
    );
    const rollback = await extra();
    await env.DB.prepare(
      "CREATE TRIGGER fail_agent_grant BEFORE INSERT ON agent_audit WHEN NEW.operation='grant' BEGIN SELECT RAISE(ABORT,'grant audit fault'); END",
    ).run();
    assert.equal((await rollback.create()).status, 409);
    assert.equal(
      await env.DB.prepare('SELECT * FROM agent_grant WHERE grant_id=?')
        .bind(rollback.grantId)
        .first(),
      null,
    );
    await env.DB.prepare('DROP TRIGGER fail_agent_grant').run();
    assert.equal((await rollback.create()).status, 200);
    await env.DB.prepare('UPDATE agent_grant SET created_at=?,expires_at=? WHERE grant_id=?')
      .bind(time - 600, time - 1, readOnly.grantId)
      .run();
    assert.equal((await rpc(readOnly.token, 'mikaki_read', { id: 'name' })).status, 401);
    // Source changes are monotonic invalidation; reverting test state must not revive the token.
    await env.DB.prepare(
      "UPDATE vault_attribute_head SET revision=2 WHERE account_id='owner' AND attribute_id='name'",
    ).run();
    assert.equal((await rpc(token, 'mikaki_read', { id: 'name' })).status, 401);
    await env.DB.prepare(
      "UPDATE vault_attribute_head SET revision=1 WHERE account_id='owner' AND attribute_id='name'",
    ).run();
    assert.equal((await rpc(token, 'mikaki_read', { id: 'name' })).status, 401);
    const stopped = await extra();
    assert.equal((await stopped.create()).status, 200);
    await env.DB.prepare(
      "UPDATE credential SET active=0 WHERE credential_id='owner-credential'",
    ).run();
    await env.DB.prepare(
      "UPDATE credential SET active=1 WHERE credential_id='owner-credential'",
    ).run();
    assert.equal((await rpc(stopped.token, 'mikaki_read', { id: 'name' })).status, 401);
    const stillActiveA = await extra();
    const stillActiveB = await extra();
    assert.equal((await stillActiveA.create()).status, 200);
    assert.equal((await stillActiveB.create()).status, 200);
    const revoked = await op.fetch('https://mikaki.test/vault/agents/revoke', {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ grant_id: null }),
    });
    assert.equal(revoked.status, 200, await revoked.text());
    assert.equal(
      (
        await agent.fetch(resource, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: '{}',
        })
      ).status,
      401,
    );
    assert.equal(
      (
        await env.DB.prepare('SELECT encrypted_snapshot FROM agent_grant WHERE grant_id=?')
          .bind(grantId)
          .first()
      ).encrypted_snapshot,
      null,
    );
    assert.equal((await rpc(stillActiveA.token, 'mikaki_read', { id: 'name' })).status, 401);
    assert.equal((await rpc(stillActiveB.token, 'mikaki_read', { id: 'name' })).status, 401);
    // Account-wide epoch advancement clears a grant in the same transaction.
    const epochGrant = await extra();
    assert.equal((await epochGrant.create()).status, 200);
    await env.DB.prepare("UPDATE account_security SET epoch=2 WHERE account_id='owner'").run();
    assert.equal((await rpc(epochGrant.token, 'mikaki_read', { id: 'name' })).status, 401);
    assert.equal(
      (
        await env.DB.prepare('SELECT encrypted_snapshot FROM agent_grant WHERE grant_id=?')
          .bind(epochGrant.grantId)
          .first()
      ).encrypted_snapshot,
      null,
    );
    // A stopped recipient cannot be revived by redeploying its old private key.
    await env.DB.prepare("UPDATE account_security SET epoch=1 WHERE account_id='owner'").run();
    const keyGrant = await extra();
    assert.equal((await keyGrant.create()).status, 200);
    await env.DB.prepare("UPDATE agent_recipient_key SET state='disabled' WHERE key_id=?")
      .bind(keyId)
      .run();
    assert.equal((await rpc(keyGrant.token, 'mikaki_read', { id: 'name' })).status, 401);
    await assert.rejects(
      env.DB.prepare("UPDATE agent_recipient_key SET state='active' WHERE key_id=?")
        .bind(keyId)
        .run(),
    );
    await assert.rejects(
      env.DB.prepare('DELETE FROM agent_recipient_key WHERE key_id=?').bind(keyId).run(),
    );
    const disabledStatus = await op.fetch('https://mikaki.test/vault/agents/status', {
      headers: ownerHeaders,
    });
    assert.equal(disabledStatus.status, 200);
    assert.equal(
      ((await disabledStatus.json()) as { recipient: { enabled: boolean } }).recipient.enabled,
      false,
    );
    assert.equal((await (await extra()).create()).status, 409);
    // Cleanup removes expired snapshots/proposals and old draft/audit metadata atomically.
    await env.DB.prepare('UPDATE agent_proposal SET expires_at=? WHERE proposal_id=?')
      .bind(time - 1, proposalId)
      .run();
    await env.DB.prepare('UPDATE agent_draft SET created_at=? WHERE proposal_id=?')
      .bind(time - 31 * 86400, proposalId)
      .run();
    await agent.scheduled({ cron: '0 * * * *', scheduledTime: new Date() });
    assert.equal((await env.DB.prepare('SELECT count(*) AS n FROM agent_draft').first()).n, 0);
    assert.equal(
      (
        await env.DB.prepare('SELECT text FROM agent_proposal WHERE proposal_id=?')
          .bind(proposalId)
          .first()
      ).text,
      null,
    );
  } finally {
    await client.close();
    await transport?.close();
    await harness.close();
  }
});

test('v2 selected record grants cross the private OP bridge with exact OAuth and post-audit invalidation in workerd', async () => {
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
  const keyId = await agentKeyId(publicJwk);
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
          AGENT_PRIVATE_JWK: JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey)),
        },
      },
    ],
  });
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-agent-local'),
      agent = harness.getWorker('mikaki-agent-local');
    await op.applyD1Migrations('DB');
    const env = await op.getEnv();
    const time = Math.floor(Date.now() / 1000),
      cookie = id(),
      origin = 'https://mikaki.test';
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('record-owner',1,1)"),
      env.DB.prepare("INSERT INTO credential VALUES('record-passkey','record-owner',1)"),
      env.DB.prepare(
        "INSERT INTO sso_session VALUES('record-session','record-owner','record-passkey',1,?,0)",
      ).bind(time + 3600),
      env.DB.prepare("INSERT INTO sso_context VALUES('record-session',?,?)").bind(
        hash(cookie),
        time,
      ),
      env.DB.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')").bind(keyId),
      env.DB.prepare(
        `INSERT INTO vault_owner_key_head VALUES('record-owner','selected-vault',?,1,1,2,
        'PRF-HKDF-SHA256-AES256GCM-v2',?,?,?)`,
      ).bind(origin, id(), id(), time),
      env.DB.prepare(
        `INSERT INTO vault_owner_record_head VALUES('record-owner','selected-vault','personal',
        'name','name',1,1,2,'selected-name',?,?,0,?)`,
      ).bind(hash('name'), 'e'.repeat(82), time),
      env.DB.prepare(
        `INSERT INTO vault_owner_record_head VALUES('record-owner','selected-vault','personal',
        'owner_note','owner_note',1,1,2,'selected-note',?,?,0,?)`,
      ).bind(hash('owner_note'), 'e'.repeat(82), time),
      env.DB.prepare(
        "INSERT INTO agent_oauth_client VALUES('record-client','Synthetic record client',?,1)",
      ).bind('["https://record-client.test/callback"]'),
    ]);
    const headers = {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: origin,
      'Content-Type': 'application/json',
    };
    const owner = (path: string, body: unknown) =>
      op.fetch(`${origin}/vault/agents/${path}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      });
    const makeGrant = async (record: 'name' | 'owner_note') => {
      const grantId = id(),
        token = `mag_${id()}`;
      const source = {
        storage_version: 2 as const,
        origin,
        owner_id: 'record-owner',
        vault_id: 'selected-vault',
        collection_id: 'personal' as const,
        record_id: record,
        kind: record,
        revision: 1,
        ciphertext_sha256: hash(record),
      };
      const authority = { key_generation: 1, owner_key_revision: 1 };
      const text =
        record === 'name'
          ? 'Only the selected v2 name'
          : new TextDecoder().decode(
              encodeOwnerNote(newOwnerNote('Selected note', 'Only the selected v2 note')),
            );
      const envelope = await sealRecordAgentSnapshot(
        [{ id: record, title: 'Selected record', source: 'vault:name:999', text }],
        { public_jwk: publicJwk, key_id: keyId, resource },
        {
          owner: 'record-owner',
          grant_id: grantId,
          key_id: keyId,
          resource,
          expires_at: time + 600,
          source,
          authority,
        },
      );
      const input = {
        storage_version: 2,
        grant_id: grantId,
        delegate: 'synthetic-record',
        provider: 'Synthetic provider',
        resource,
        source,
        authority,
        recipient_key_id: keyId,
        operations: ['list', 'search', 'read', 'propose', 'execute'],
        document_ids: [record],
        envelope,
        token_hash: hash(token),
        expires_at: time + 600,
      };
      return { token, input, text };
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
      return {
        status: response.status,
        data:
          response.status === 200
            ? ((await response.json()) as {
                result: { isError?: boolean; structuredContent: Record<string, unknown> };
              })
            : null,
      };
    };
    const name = await makeGrant('name'),
      note = await makeGrant('owner_note');
    for (const grant of [name, note]) {
      const result = await owner('grants', grant.input);
      assert.equal(result.status, 200, await result.text());
    }
    const shown = await rpc(note.token, 'read', { id: 'owner_note' });
    const content = toolOutputs.read.parse(shown.data?.result.structuredContent);
    assert.equal(content.text, note.text);
    assert.equal(content.source_info.kind, 'vault-record');
    if (content.source_info.kind !== 'vault-record') throw new Error('Expected v2 source');
    assert.deepEqual(content.source_info.source, note.input.source);
    assert.equal(content.access.source_check, 'record-matched');
    assert.equal((await rpc(note.token, 'read', { id: 'name' })).data?.result.isError, true);
    assert.equal(
      (
        await owner('attribute-capability', {
          grant_id: note.input.grant_id,
          attribute_id: 'owner_note',
          base_revision: 0,
        })
      ).status,
      409,
    );
    // Exercise the deepest authorization SQL in actual D1/workerd for v2, too.
    // Exact owner approval and concurrent retries must create only one private draft.
    const proposalId = id();
    const proposed = await rpc(note.token, 'propose', {
      proposal_id: proposalId,
      document_id: 'owner_note',
      title: 'Private selected-record draft',
      text: 'This draft cannot modify the selected Vault note.',
    });
    const receipt = toolOutputs.propose.parse(proposed.data?.result.structuredContent);
    const executeArgs = { proposal_id: proposalId, request_hash: receipt.request_hash };
    assert.equal((await rpc(note.token, 'execute', executeArgs)).data?.result.isError, true);
    const decision = await owner('decide', { ...executeArgs, approve: true });
    assert.equal(decision.status, 200, await decision.text());
    assert.equal(
      (await rpc(note.token, 'execute', { ...executeArgs, request_hash: id() })).data?.result
        .isError,
      true,
    );
    const executions = await Promise.all([
      rpc(note.token, 'execute', executeArgs),
      rpc(note.token, 'execute', executeArgs),
    ]);
    assert.equal(executions[0]!.data?.result.isError, undefined, JSON.stringify(executions));
    assert.deepEqual(executions[0], executions[1]);
    assert.equal(
      toolOutputs.execute.parse(executions[0]!.data?.result.structuredContent).state,
      'executed',
    );
    assert.equal((await env.DB.prepare('SELECT count(*) n FROM agent_draft').first()).n, 1);
    assert.equal(
      (await rpc(note.token, 'read', { id: 'owner_note' })).data?.result.structuredContent.text,
      note.text,
    );
    // The default dashboard remains exclusively v1 so old clients cannot relabel v2 grants.
    const status = await op.fetch(`${origin}/vault/agents/status`, { headers });
    const statusBody = (await status.json()) as { grants: unknown[] };
    assert.deepEqual(statusBody.grants, []);
    const recordStatus = await op.fetch(`${origin}/vault/agents/record-status`, { headers });
    assert.equal(recordStatus.status, 200, await recordStatus.clone().text());
    const recordStatusBody = (await recordStatus.json()) as {
      storage_version: number;
      grants: { storage_version: number; source_record_id: string }[];
    };
    assert.equal(recordStatusBody.storage_version, 2);
    assert.deepEqual(recordStatusBody.grants.map((grant) => grant.source_record_id).sort(), [
      'name',
      'owner_note',
    ]);
    assert.ok(recordStatusBody.grants.every((grant) => grant.storage_version === 2));

    const detail = {
      type: 'mikaki_agent_snapshot',
      storage_version: 2,
      locations: [resource],
      actions: ['read'],
      document_id: 'owner_note',
      source: note.input.source,
      authority: note.input.authority,
      purpose: 'Read precisely this note',
    };
    const authorize = async (requested: unknown) => {
      const verifier = id(),
        url = new URL('https://agent.mikaki.test/oauth/authorize');
      for (const [key, value] of Object.entries({
        response_type: 'code',
        client_id: 'record-client',
        redirect_uri: 'https://record-client.test/callback',
        resource,
        scope: 'read',
        state: id(),
        code_challenge: hash(verifier),
        code_challenge_method: 'S256',
        ...(requested === null ? {} : { authorization_details: JSON.stringify(requested) }),
      }))
        url.searchParams.set(key, value);
      // The redirect targets the synthetic owner origin, never public DNS.
      const response = await agent.fetch(url.href, { redirect: 'manual' });
      assert.equal(response.status, 302, await response.text());
      return {
        verifier,
        request_id: new URL(response.headers.get('Location')!).searchParams.get(
          'agent_oauth_request',
        )!,
      };
    };
    for (const requested of [
      null,
      [{ ...detail, authority: { key_generation: 1, owner_key_revision: 2 } }],
    ]) {
      const pending = await authorize(requested);
      assert.equal((await owner('oauth-request', { request_id: pending.request_id })).status, 200);
      assert.equal(
        (
          await owner('oauth-decide', {
            request_id: pending.request_id,
            approve: true,
            grant_id: note.input.grant_id,
          })
        ).status,
        409,
      );
    }
    const pending = await authorize([detail]);
    assert.equal((await owner('oauth-request', { request_id: pending.request_id })).status, 200);
    const approved = await owner('oauth-decide', {
      request_id: pending.request_id,
      approve: true,
      grant_id: note.input.grant_id,
    });
    assert.equal(approved.status, 200, await approved.clone().text());
    const callback = new URL(((await approved.json()) as { redirect: string }).redirect);
    const issued = await agent.fetch('https://agent.mikaki.test/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: callback.searchParams.get('code')!,
        client_id: 'record-client',
        redirect_uri: 'https://record-client.test/callback',
        resource,
        code_verifier: pending.verifier,
      }).toString(),
    });
    assert.equal(issued.status, 200, await issued.clone().text());
    const token = (await issued.json()) as {
      access_token: string;
      authorization_details: unknown[];
    };
    assert.deepEqual(token.authorization_details, [detail]);
    assert.equal(
      (await rpc(token.access_token, 'read', { id: 'owner_note' })).data?.result.structuredContent
        .text,
      note.text,
    );
    assert.equal((await rpc(token.access_token, 'list', {})).data?.result.isError, true);
    // Revocation committed by the authorized-access audit must still suppress the decrypted copy.
    await env.DB.prepare(
      `CREATE TRIGGER revoke_record_during_audit AFTER INSERT ON agent_audit
      WHEN NEW.operation='read' AND NEW.outcome='authorized' AND NEW.grant_id='${note.input.grant_id}'
      BEGIN UPDATE vault_owner_record_head SET revision=2 WHERE record_id='owner_note'; END`,
    ).run();
    const stopped = await rpc(token.access_token, 'read', { id: 'owner_note' });
    assert.equal(stopped.data?.result.isError, true);
    assert.doesNotMatch(JSON.stringify(stopped), /Only the selected v2 note/);
    await env.DB.prepare(
      "UPDATE vault_owner_record_head SET revision=1 WHERE record_id='owner_note'",
    ).run();
    assert.equal((await owner('grants', note.input)).status, 200);
    assert.equal((await rpc(note.token, 'read', { id: 'owner_note' })).status, 401);
    assert.equal(
      (await rpc(name.token, 'read', { id: 'name' })).data?.result.structuredContent.text,
      name.text,
    );
    await env.DB.prepare('UPDATE vault_owner_key_head SET revision=2').run();
    assert.equal((await rpc(name.token, 'read', { id: 'name' })).status, 401);
    const cleared = await env.DB.prepare(
      'SELECT encrypted_snapshot,revoked FROM agent_grant WHERE grant_id=?',
    )
      .bind(name.input.grant_id)
      .first();
    assert.equal(cleared.encrypted_snapshot, null);
    assert.equal(cleared.revoked, 1);
  } finally {
    await harness.close();
  }
});
