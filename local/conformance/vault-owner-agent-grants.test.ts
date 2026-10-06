import assert from 'node:assert/strict';
import { test } from 'node:test';
import { agentKeyId } from '../../crates/worker/ui/agent-crypto.ts';
import { OwnerAgentGrants } from '../../crates/worker/ui/vault-owner-agent-grants.ts';
import { encodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';
import type { OwnerVaultController } from '../../crates/worker/ui/vault-owner-controller.ts';

const origin = 'https://mikaki.test';
const authority = { key_generation: 1, owner_key_revision: 4 };
const opaque = () => encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
function response(value: unknown, status = 200, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json', ...Object.fromEntries(new Headers(headers)) },
  });
}

async function fixture(
  options: {
    enabled?: boolean;
    active?: boolean;
    failCapability?: number;
    tombstoneRevision?: number;
    guardConcurrentVerify?: boolean;
  } = {},
) {
  const rsa = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', rsa.publicKey),
    keyId = await agentKeyId(publicJwk);
  const grantId = opaque(),
    expiresAt = Math.floor(Date.now() / 1000) + 3600;
  const activeGrant = {
    grant_id: grantId,
    account_id: 'owner',
    delegate: 'writer',
    provider: 'self-entered label',
    resource: 'https://agent.example/mcp',
    source_revision: 1,
    operations: '["read","list","propose"]',
    document_ids: '["owner_note"]',
    created_at: expiresAt - 600,
    expires_at: expiresAt,
    revoked: 0,
    revision: 1,
    recipient_key_id: keyId,
    storage_version: 2,
    source_origin: origin,
    source_vault_id: 'vault',
    source_collection_id: 'personal',
    source_record_id: 'owner_note',
    source_kind: 'owner_note',
    source_ciphertext_sha256: opaque(),
    source_key_generation: 1,
    source_owner_key_revision: 4,
    active: 1,
  };
  const grants =
    options.active === false
      ? []
      : [
          activeGrant,
          {
            ...activeGrant,
            grant_id: opaque(),
            expires_at: expiresAt - 1,
            revoked: 1,
            active: 0,
          },
        ];
  const requests: { path: string; body: string }[] = [];
  let capCalls = 0;
  let statusAvailable = true;
  let verifyingAuthority = false;
  const scope = {
    identity: { account_id: 'owner' },
    signal: new AbortController().signal,
    request: async (path: string, init: RequestInit = {}) => {
      const body = typeof init.body === 'string' ? init.body : '';
      requests.push({ path, body });
      if (path === '/vault/records/personal/owner_note' && options.tombstoneRevision !== undefined)
        return response({ error: 'not_found', deleted: true }, 404, {
          ETag: `"${options.tombstoneRevision}"`,
        });
      if (path === '/vault/records/personal/name' || path === '/vault/records/personal/owner_note')
        return response({ error: 'not_found' }, 404);
      if (path === '/vault/agents/record-status' && !statusAvailable)
        return response({ error: 'temporarily_unavailable' }, 503);
      if (path === '/vault/agents/record-status')
        return response({
          storage_version: 2,
          grants,
          audit: [],
          proposals: [],
          drafts: [],
          record_proposals: [],
          recipient: {
            public_jwk: publicJwk,
            key_id: keyId,
            resource: 'https://agent.example/mcp',
            enabled: options.enabled ?? true,
          },
        });
      if (path === '/vault/agents/record-capability') {
        capCalls++;
        if (capCalls <= (options.failCapability ?? 0)) throw new Error('lost response');
        const input = JSON.parse(body) as { grant_id: string; target: unknown; authority: unknown };
        return response({
          ...input,
          expires_at: Math.min(expiresAt, Math.floor(Date.now() / 1000) + 3600),
        });
      }
      return response({ error: 'not_found' }, 404);
    },
    verify: async () => {},
    ensure: async () => {},
    assert: () => {},
  };
  const stored = {
    context: { origin, ownerId: 'owner', vaultId: 'vault', keyGeneration: 1 },
    revision: 4,
  };
  const owner = {
    scope,
    origin,
    checkpoint: () => {
      if (options.guardConcurrentVerify && verifyingAuthority)
        throw new Error('lease checked during authority verification');
      return 1;
    },
    assertCurrent: () => {},
    verifyAuthority: async () => {
      if (options.guardConcurrentVerify) {
        verifyingAuthority = true;
        await Promise.resolve();
        verifyingAuthority = false;
      }
    },
    lease: () => {
      if (options.guardConcurrentVerify && verifyingAuthority)
        throw new Error('lease checked during authority verification');
      return { stored, session: { open: async () => new TextEncoder().encode('unused') } };
    },
  } as unknown as OwnerVaultController;
  return {
    owner,
    requests,
    grantId,
    expiresAt,
    get capCalls() {
      return capCalls;
    },
    setStatusAvailable(value: boolean) {
      statusAvailable = value;
    },
  };
}

test('strict status parser retains historical grants and capability is separate, exact, and session-only', async () => {
  const f = await fixture({ failCapability: 1 });
  const helper = new OwnerAgentGrants(f.owner),
    snapshot = await helper.load();
  assert.equal(snapshot.grants[0]?.delegate, 'writer');
  assert.deepEqual(snapshot.grants[0]?.operations, ['read', 'list', 'propose']);
  assert.deepEqual(snapshot.grants[0]?.document_ids, ['owner_note']);
  assert.equal(
    snapshot.grants[1]?.active,
    false,
    'revoked v2 history remains parseable and visible',
  );
  assert.equal(snapshot.grants[0]?.capability.state, 'unknown');
  const operation = await helper.prepareCapability(snapshot, f.grantId);
  await assert.rejects(helper.commitCapability(operation), /capability_unavailable/);
  const firstBody = f.requests.find(
    (request) => request.path === '/vault/agents/record-capability',
  )?.body;
  const result = await helper.commitCapability(operation);
  const capRequests = f.requests.filter(
    (request) => request.path === '/vault/agents/record-capability',
  );
  assert.equal(capRequests[1]?.body, firstBody, 'unknown result retries exact prepared body');
  assert.equal(result.snapshot.grants[0]?.capability.state, 'active');
  assert.equal(f.capCalls, 2);
  assert.equal(
    JSON.parse(firstBody ?? '{}').target.revision,
    0,
    'never-created revision-zero target is allowed',
  );
  assert.equal(
    (await new OwnerAgentGrants(f.owner).load()).grants[0]?.capability.state,
    'unknown',
    'reload cannot infer capability status without a listing endpoint',
  );
});

test('disabled recipient and grants without propose cannot prepare a capability', async () => {
  const disabled = await fixture({ enabled: false });
  const disabledHelper = new OwnerAgentGrants(disabled.owner),
    disabledSnapshot = await disabledHelper.load();
  await assert.rejects(
    disabledHelper.prepareCapability(disabledSnapshot, disabled.grantId),
    /recipient_disabled/,
  );

  const noGrant = await fixture({ active: false });
  const helper = new OwnerAgentGrants(noGrant.owner),
    snapshot = await helper.load();
  await assert.rejects(helper.prepareCapability(snapshot, noGrant.grantId), /grant_unavailable/);
});

test('revoke preparation uses the owned grant snapshot without rereading source or recipient', async () => {
  const f = await fixture(),
    helper = new OwnerAgentGrants(f.owner),
    snapshot = await helper.load();
  const statusReads = f.requests.filter(
    (request) => request.path === '/vault/agents/record-status',
  ).length;
  f.setStatusAvailable(false);
  const revoke = await helper.prepareRevoke(snapshot, f.grantId);
  assert.ok(revoke);
  assert.equal(
    f.requests.filter((request) => request.path === '/vault/agents/record-status').length,
    statusReads,
  );
});

test('load serializes readers that share the verified owner lease', async () => {
  const f = await fixture({ guardConcurrentVerify: true });
  const snapshot = await new OwnerAgentGrants(f.owner).load();
  assert.equal(snapshot.sources.name.revision, 0);
  assert.equal(snapshot.sources.owner_note.revision, 0);
});

test('capability binds a positive tombstone revision exactly', async () => {
  const f = await fixture({ tombstoneRevision: 7 });
  const helper = new OwnerAgentGrants(f.owner),
    snapshot = await helper.load();
  assert.equal(snapshot.sources.owner_note.available, false);
  assert.equal(snapshot.sources.owner_note.target.revision, 7);
  assert.equal(snapshot.sources.owner_note.target.deleted, true);
  const operation = await helper.prepareCapability(snapshot, f.grantId);
  const result = await helper.commitCapability(operation);
  assert.equal(result.snapshot.grants[0]?.capability.target?.revision, 7);
  assert.equal(result.snapshot.grants[0]?.capability.target?.deleted, true);
});
