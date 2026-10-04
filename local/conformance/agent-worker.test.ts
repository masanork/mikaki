import assert from 'node:assert/strict';
import { toolOutputs } from '../../crates/agent-worker/tool-results.ts';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import { agentKeyId } from '../../crates/worker/ui/agent-crypto.ts';
import { sealRecordAgentSnapshot } from '../../crates/worker/ui/agent-record-crypto.ts';
import { encodeOwnerNote, newOwnerNote } from '../../crates/worker/ui/vault-note.ts';

const resource = 'https://agent.mikaki.test/mcp';
const id = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');

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
      (await owner('attribute-capability', { grant_id: note.input.grant_id })).status,
      404,
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
    // The legacy status view may show old rows for revocation, while source access remains v2-only.
    const status = await op.fetch(`${origin}/vault/agents/status`, { headers });
    const statusBody = (await status.json()) as { grants: { storage_version: number }[] };
    assert.ok(statusBody.grants.every((grant) => grant.storage_version === 2));
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
